"""honeywatch pipeline: ties scanning, fingerprinting, analysis, and scoring together."""

from __future__ import annotations

import asyncio
import os
import sqlite3
import sys
import warnings
from collections import Counter, defaultdict

from honeywatch.ai.scorer import AiScorer, profile_key
from honeywatch.fingerprint.features import analyze
from honeywatch.fingerprint.probe import is_ssh, probe_many
from honeywatch.models import Fingerprint, HostHit, Score
from honeywatch.scorers import compute_priority_score, compute_vulnerability_score


def _make_progress_reporter(every: int = 1000):
    """Return a per-probe callback that prints a heartbeat every ``every`` hosts."""
    state = {"count": 0, "ssh": 0}

    def _report(fp: Fingerprint) -> None:
        state["count"] += 1
        if is_ssh(fp):
            state["ssh"] += 1
        if state["count"] % every == 0:
            print(
                f"honeywatch: probed {state['count']} hosts "
                f"({state['ssh']} SSH)",
                file=sys.stderr,
                flush=True,
            )

    return _report



def _classify(confidence: float) -> str:
    """Map a confidence score to a human label.

    Thresholds:
      < 0.2 -> "real"
      < 0.4 -> "likely_real"
      < 0.6 -> "uncertain"
      < 0.8 -> "likely_honeypot"
      else  -> "honeypot"
    """
    if confidence < 0.2:
        return "real"
    if confidence < 0.4:
        return "likely_real"
    if confidence < 0.6:
        return "uncertain"
    if confidence < 0.8:
        return "likely_honeypot"
    return "honeypot"


class Pipeline:
    """Coordinates the end-to-end honeypot scan flow."""

    def __init__(self, config, store=None, ai_client=None):
        self.config = config
        self.store = store
        self.ai_client = ai_client

        # Build the AI client from config when AI is enabled and none was supplied.
        ai_cfg = getattr(config, "ai", None)
        if self.ai_client is None and (
            ai_cfg is None or bool(getattr(ai_cfg, "enabled", True))
        ):
            from honeywatch.ai.ollama import OllamaClient

            self.ai_client = OllamaClient(
                base_url=getattr(ai_cfg, "base_url", "https://ollama.com/v1"),
                api_key=(
                    getattr(ai_cfg, "api_key", None)
                    or os.environ.get(getattr(ai_cfg, "api_key_env", "OLLAMA_API_KEY"))
                ),
                model=getattr(ai_cfg, "model", "llama3.1:8b"),
                timeout=getattr(ai_cfg, "timeout_s", 120),
                temperature=getattr(ai_cfg, "temperature", 0.0),
            )

    # ------------------------------------------------------------------ #
    # Probing
    # ------------------------------------------------------------------ #
    async def probe_hosts(
        self,
        hosts: list[HostHit],
        port: int | None = None,
        only_ssh: bool | None = None,
        on_result=None,
    ) -> list[Fingerprint]:
        """Probe every unique (ip, port) pair using config.probe settings.

        When ``only_ssh`` is true (default: config ``scan.only_ssh``), only
        fingerprints that captured a real SSH banner are kept; unreachable
        hosts, refused connections and non-SSH services are dropped.
        ``on_result`` (optional) is forwarded to :func:`probe_many` as a
        per-completed-probe callback (used for live progress reporting).
        """
        if only_ssh is None:
            scan_cfg = getattr(self.config, "scan", None)
            only_ssh = bool(getattr(scan_cfg, "only_ssh", True)) if scan_cfg else True

        probe_cfg = getattr(self.config, "probe", None)
        level = getattr(probe_cfg, "level", "fast")
        timeout = getattr(probe_cfg, "timeout_s", 6.0)
        auth_probe = bool(getattr(probe_cfg, "auth_probe", False))
        concurrency = int(getattr(probe_cfg, "concurrency", 512))

        # Group host IPs by the effective port so we can hand each group
        # to probe_many in a single async call.
        by_port: dict[int, list[str]] = defaultdict(list)
        for hit in hosts:
            p = port if port is not None else hit.port
            by_port[p].append(hit.ip)

        results: list[Fingerprint] = []
        for p, ips in by_port.items():
            unique_ips = list(dict.fromkeys(ips))  # dedupe, keep order
            if not unique_ips:
                continue
            fps = await probe_many(
                unique_ips,
                port=p,
                level=level,
                timeout=timeout,
                auth_probe=auth_probe,
                concurrency=concurrency,
                on_result=on_result,
            )
            results.extend(fps)
        if only_ssh:
            results = [fp for fp in results if is_ssh(fp)]
        return results

    # ------------------------------------------------------------------ #
    # Analysis / scoring
    # ------------------------------------------------------------------ #
    async def analyze_and_score(
        self, fingerprints: list[Fingerprint]
    ) -> list[Score]:
        """Build Signals, ask the AI for per-profile verdicts, and fuse scores.

        Host-key fingerprints only count as in-scan farm evidence when the same
        hash appeared on 2+ distinct hosts (every host's own key would otherwise
        be "known", flagging the whole scan as a farm). On top of that, any
        host-key hash a *previous* scan learned as a honeypot (persisted in the
        store's ``known_keys`` table) is folded in, so detection sharpens run
        over run instead of resetting each scan.
        """
        hash_counts = Counter(
            fp.host_key_sha256 for fp in fingerprints if fp.host_key_sha256
        )
        known_hashes = {h for h, n in hash_counts.items() if n >= 2}
        if self.store is not None:
            try:
                known_hashes |= self.store.known_key_set()
            except sqlite3.Error as exc:
                # A corrupt/read-only store must never block scoring, but a
                # silent pass hides the degradation — warn so the operator
                # knows honeypot-key learning is offline for this run.
                warnings.warn(f"honeywatch: known_key_set failed: {exc}")

        signals = [analyze(fp, known_hashes) for fp in fingerprints]

        ai_verdicts: dict[str, "AiVerdict"] = {}
        if self.ai_client is not None:
            profiles: dict[str, list[tuple[Fingerprint, object]]] = defaultdict(list)
            for fp, sig in zip(fingerprints, signals):
                profiles[profile_key(fp)].append((fp, sig))
            # One representative fingerprint+signals per profile.
            representatives = {k: v[0] for k, v in profiles.items()}
            ai_cfg = getattr(self.config, "ai", None)
            batch_size = int(getattr(ai_cfg, "batch_size", 100)) if ai_cfg else 100
            retries = int(getattr(ai_cfg, "retries", 3)) if ai_cfg else 3
            retry_base = float(getattr(ai_cfg, "retry_base_delay", 1.0)) if ai_cfg else 1.0
            scorer = AiScorer(
                self.ai_client,
                batch=bool(
                    getattr(getattr(self.config, "ai", None), "batch_profiles", True)
                ),
                batch_size=batch_size,
                retries=retries,
                retry_base_delay=retry_base,
            )
            ai_verdicts = await scorer.score(representatives)

            if not ai_verdicts:
                print(
                    "honeywatch: warning: AI stage unavailable (Ollama Cloud "
                    "unreachable or missing OLLAMA_API_KEY); using heuristic "
                    "scores only.",
                    file=sys.stderr,
                )

        scores: list[Score] = []
        for fp, sig in zip(fingerprints, signals):
            ai = ai_verdicts.get(profile_key(fp)) if self.ai_client else None
            if ai is not None:
                confidence = ai.confidence * 0.6 + sig.heuristic_score * 0.4
            else:
                # No AI available -> pure heuristic score.
                confidence = sig.heuristic_score
            confidence = round(float(confidence), 4)

            # Compute vulnerability and priority scores from fingerprint
            # signals. Higher vulnerability = more exploitable; higher
            # priority = more valuable target (low honeypot confidence +
            # high vulnerability).
            vuln_score = compute_vulnerability_score(
                software_version=fp.software_version if fp else None,
                enc_c2s=fp.enc_c2s if fp else None,
                enc_s2c=fp.enc_s2c if fp else None,
                host_key_type=fp.host_key_type if fp else None,
                flags=set(sig.flags) if sig else set(),
            )
            prio_score = compute_priority_score(confidence, vuln_score)

            scores.append(
                Score(
                    ip=fp.ip,
                    port=fp.port,
                    fingerprint=fp,
                    signals=sig,
                    ai=ai,
                    final_confidence=confidence,
                    final_label=_classify(confidence),
                    vulnerability_score=vuln_score,
                    priority_score=prio_score,
                )
            )

        # Learn honeypot host-key hashes for future runs. A failure here must
        # never invalidate a completed scan, but a silent pass hides the
        # degradation — warn so the operator knows learning is offline.
        if self.store is not None:
            try:
                self.store.learn_from_scores(scores)
            except sqlite3.Error as exc:
                warnings.warn(f"honeywatch: learn_from_scores failed: {exc}")
        return scores

    # ------------------------------------------------------------------ #
    # VPN gate
    # ------------------------------------------------------------------ #
    def _require_vpn(self, skip: bool) -> None:
        """Enforce the Mullvad gate for programmatic scans.

        Honors ``--skip-vpn-check``-style opt-outs via the ``skip`` argument,
        ``vpn.required = false`` in the config, or ``HONEYWATCH_SKIP_VPN`` in
        the environment. Raises :class:`honeywatch.vpn.VpnError` when the gate
        blocks the scan.
        """
        from honeywatch.vpn import DEFAULT_TIMEOUT, VpnError, require_mullvad

        vpn_cfg = getattr(self.config, "vpn", None)
        required = bool(getattr(vpn_cfg, "required", True)) if vpn_cfg else True
        if skip or not required:
            return
        timeout = (
            getattr(vpn_cfg, "timeout_s", DEFAULT_TIMEOUT) if vpn_cfg else DEFAULT_TIMEOUT
        )
        if not require_mullvad(timeout=timeout, quiet=True):
            raise VpnError(
                "Mullvad VPN is not connected. Connect Mullvad first, or pass "
                "--skip-vpn-check / set HONEYWATCH_SKIP_VPN=1 for controlled "
                "offline testing."
            )

    # ------------------------------------------------------------------ #
    # Full scan flow
    # ------------------------------------------------------------------ #
    async def scan(
        self,
        targets: list[str],
        tool: str = "masscan",
        ports: list[int] | None = None,
        rate: int | None = None,
        max_hosts: int | None = None,
        skip_vpn_check: bool = False,
        resume: bool = False,
        progress: bool = False,
    ) -> list[Score]:
        """Run an external scanner, probe the hits, score, and persist.

        ``resume=True`` skips hosts a previous (interrupted) run already
        scored, reading the finished ``(ip, port)`` set from the store so a
        planet-scale sweep killed at 40% picks up where it left off.
        ``progress=True`` prints a heartbeat as probes complete.
        """
        if tool not in ("masscan", "zmap"):
            raise ValueError(f"unknown scan tool: {tool!r}")

        self._require_vpn(skip_vpn_check)

        if isinstance(targets, str):
            targets = [targets]

        scanners_cfg = getattr(self.config, "scanners", None)
        scanner_cfg = getattr(scanners_cfg, tool, None) if scanners_cfg else None
        bin_path = getattr(scanner_cfg, "bin", tool) if scanner_cfg else tool
        if rate is None:
            rate = (
                getattr(getattr(scanners_cfg, "masscan", None), "rate", 1000)
                if scanners_cfg
                else 1000
            )
        # Scanner subprocess bound (None = no timeout). Configurable per tool
        # via ``scanners.<tool>.timeout_s`` so a hung scan cannot block the
        # interval loop forever.
        timeout_s = getattr(scanner_cfg, "timeout_s", None) if scanner_cfg else None

        if ports is None:
            ports = [22]

        if tool == "masscan":
            from honeywatch.scanners import masscan

            runner = masscan.run
        else:
            from honeywatch.scanners import zmap

            runner = zmap.run

        # masscan-only: extra ranges to skip (RFC1918, your own egress IP...).
        run_kwargs: dict = {}
        if tool == "masscan":
            excludes = getattr(scanner_cfg, "exclude", None) if scanner_cfg else None
            if excludes:
                run_kwargs["excludes"] = list(excludes)
            wait_s = getattr(scanner_cfg, "wait_s", 3) if scanner_cfg else 3
            run_kwargs["wait_s"] = int(wait_s)

        # The scanner helpers block on subprocesses; keep the event loop free.
        hosts = await asyncio.to_thread(
            runner,
            targets,
            ports,
            int(rate),
            timeout_s,
            bin_path,
            **run_kwargs,
        )

        if max_hosts is not None and max_hosts > 0:
            hosts = hosts[:max_hosts]

        # Resume: drop hosts the store already scored so we don't re-probe
        # (and re-charge the LLM for) work a prior run finished. Done in SQL via
        # a temp-table join so a resume over millions of hosts does not load
        # the whole store into memory.
        if resume and self.store is not None:
            try:
                before = len(hosts)
                hosts = self.store.filter_unscored(hosts)
                skipped = before - len(hosts)
            except Exception:
                skipped = 0
            if skipped:
                print(
                    f"honeywatch: resume - skipping {skipped} host(s) already scored",
                    file=sys.stderr,
                )

        on_result = None
        if progress:
            on_result = _make_progress_reporter()

        # Probe each host on the port the scanner actually reported open.
        fingerprints = await self.probe_hosts(hosts, on_result=on_result)
        scores = await self.analyze_and_score(fingerprints)

        if self.store is not None:
            self.store.upsert_scores(scores)

        return scores

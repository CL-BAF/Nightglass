"""Internal certificate authority for honeywatch C2 mutual TLS.

The controller/worker plane has historically been either plaintext (lab) or
fronted by a self-signed server cert with no client authentication. That lets
anyone who can reach the controller claim tasks. This module provides an
internal CA so the controller can require worker client certificates (mTLS):
the CA signs each worker cert, the controller trusts only that CA, and a
worker pins the CA fingerprint so a swapped CA file or a public-CA-issued
impostor is rejected. The bearer token stays as a second factor (mTLS is
something you have, the token is something you know).

All crypto is done with the ``openssl`` binary (matching ``c2/tls.py``) so the
runtime stays stdlib-only; ``cryptography`` is not required. Every function
raises ``RuntimeError`` with a clear message if ``openssl`` is missing.

Everything here is opt-in. The default controller/worker still run without a
CA, preserving the plaintext lab behaviour and the existing test harness.
"""

from __future__ import annotations

import hashlib
import os
import ssl
import subprocess
from pathlib import Path

__all__ = [
    "generate_ca",
    "sign_worker_cert",
    "sign_server_cert",
    "cert_fingerprint",
    "ca_pin_from_cert",
    "cert_serial",
    "rotate_ca",
]


class CAError(RuntimeError):
    """Raised when openssl is missing or a CA/cert operation fails."""


def _run_openssl(args: list[str]) -> bytes:
    """Run an openssl command, returning stdout. Raises CAError on failure."""
    try:
        proc = subprocess.run(
            ["openssl", *args],
            check=True,
            capture_output=True,
        )
    except FileNotFoundError as exc:
        raise CAError(
            "openssl not found on PATH; install openssl to use C2 mTLS"
        ) from exc
    except subprocess.CalledProcessError as exc:
        raise CAError(
            f"openssl {' '.join(args[:2])} failed: "
            f"{exc.stderr.decode('utf-8', 'replace').strip() or exc}"
        ) from exc
    return proc.stdout


def _ensure_parent(path: str) -> None:
    parent = os.path.dirname(os.path.abspath(path))
    os.makedirs(parent or ".", exist_ok=True)


def generate_ca(
    ca_cert: str,
    ca_key: str,
    days: int = 3650,
    cn: str = "honeywatch-internal-ca",
) -> None:
    """Generate a self-signed root CA cert/key pair.

    The CA has ``basicConstraints=critical,CA:TRUE`` and
    ``keyUsage=critical,keyCertSign,cRLSign`` so it can sign worker certs.
    """
    ca_cert = os.path.abspath(ca_cert)
    ca_key = os.path.abspath(ca_key)
    _ensure_parent(ca_cert)
    _ensure_parent(ca_key)
    _run_openssl(
        [
            "req", "-x509", "-nodes", "-newkey", "rsa:2048",
            "-keyout", ca_key, "-out", ca_cert, "-days", str(days),
            "-subj", f"/CN={cn}",
            "-addext", "basicConstraints=critical,CA:TRUE,pathlen:1",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign",
        ]
    )


def _sign_cert_with_ca(
    ca_cert: str,
    ca_key: str,
    out_cert: str,
    out_key: str,
    cn: str,
    ext_section: str,
    ext_body: str,
    days: int,
) -> None:
    """Shared core: generate a key+CSR for ``cn``, sign it with the CA, apply extensions.

    ``ext_section`` names a section in the extension file (OpenSSL 3.x only
    applies ``-extfile`` extensions when a section is named via ``-extensions``;
    top-level keys are silently ignored) and ``ext_body`` is that section's body
    (EKU / basicConstraints / SAN). Temp CSR + ext files are cleaned up in
    finally. Raises CAError via ``_run_openssl`` on any openssl failure.
    """
    ca_cert = os.path.abspath(ca_cert)
    ca_key = os.path.abspath(ca_key)
    out_cert = os.path.abspath(out_cert)
    out_key = os.path.abspath(out_key)
    _ensure_parent(out_cert)
    _ensure_parent(out_key)
    _run_openssl(["genrsa", "-out", out_key, "2048"])
    tag = cn or "cert"
    csr = os.path.join(os.path.dirname(out_cert), f".{tag}.csr")
    ext = os.path.join(os.path.dirname(out_cert), f".{tag}.ext")
    try:
        _run_openssl(
            ["req", "-new", "-key", out_key, "-out", csr, "-subj", f"/CN={cn}"]
        )
        Path(ext).write_text(f"[{ext_section}]\n{ext_body}", encoding="utf-8")
        _run_openssl(
            ["x509", "-req", "-in", csr,
             "-CA", ca_cert, "-CAkey", ca_key, "-CAcreateserial",
             "-out", out_cert, "-days", str(days),
             "-extfile", ext, "-extensions", ext_section]
        )
    finally:
        for tmp in (csr, ext):
            try:
                os.remove(tmp)
            except OSError:
                pass


def sign_worker_cert(
    ca_cert: str,
    ca_key: str,
    out_cert: str,
    out_key: str,
    worker_id: str,
    days: int = 365,
) -> None:
    """Sign a worker client certificate with the internal CA.

    Generates a fresh worker key + CSR, signs it with ``ca_cert``/``ca_key``
    for ``days``, and writes the worker cert/key to ``out_cert``/``out_key``.
    The cert is marked ``clientAuth`` (EKU) and ``CA:FALSE`` so it can only
    authenticate as a TLS client, never sign further certs.
    """
    safe_id = "".join(c for c in worker_id if c.isalnum() or c in "-_") or "worker"
    _sign_cert_with_ca(
        ca_cert, ca_key, out_cert, out_key, cn=safe_id,
        ext_section="v3_client",
        ext_body="extendedKeyUsage = clientAuth\n"
                  "basicConstraints = critical, CA:FALSE\n",
        days=days,
    )


def sign_server_cert(
    ca_cert: str,
    ca_key: str,
    out_cert: str,
    out_key: str,
    hostname: str = "honeywatch.local",
    days: int = 365,
) -> None:
    """Sign a controller *server* certificate with the internal CA.

    The worker's CA-pinned client context trusts ONLY the CA, so the
    controller's server cert must chain to that CA -- a self-signed server
    cert would be rejected at the TLS handshake. This signs a server cert
    with ``serverAuth`` EKU, ``CA:FALSE``, and SANs for localhost / 127.0.0.1
    / the given hostname so a CA-pinned worker (check_hostname disabled) can
    verify the chain. ``hostname`` is constrained to a safe CN subset.
    """
    safe_host = "".join(c for c in hostname if c.isalnum() or c in "-_.") or "controller"
    # SAN covers localhost + loopback + the operator hostname; the worker
    # disables hostname checking (the CA pin is the trust anchor) but a SAN
    # keeps standard clients from rejecting the cert too.
    _sign_cert_with_ca(
        ca_cert, ca_key, out_cert, out_key, cn=safe_host,
        ext_section="v3_server",
        ext_body="extendedKeyUsage = serverAuth\n"
                  "basicConstraints = critical, CA:FALSE\n"
                  f"subjectAltName = DNS:{safe_host},DNS:localhost,IP:127.0.0.1\n",
        days=days,
    )


def _read_pem_cert(cert_path: str) -> str:
    """Read a PEM cert file, returning the PEM text (whitespace-trimmed)."""
    with open(cert_path, "r", encoding="utf-8") as fh:
        return fh.read().strip()


def cert_fingerprint(cert_path: str) -> str:
    """SHA-256 fingerprint of a cert, as ``sha256:<hex>``.

    Computed from the DER (stdlib ``ssl.PEM_cert_to_DER_cert``), so no openssl
    call is needed -- the fingerprint is stable and comparable across hosts.
    """
    pem = _read_pem_cert(cert_path)
    der = ssl.PEM_cert_to_DER_cert(pem)
    if der is None:
        raise CAError(f"could not parse DER from {cert_path!r}")
    return "sha256:" + hashlib.sha256(der).hexdigest()


def ca_pin_from_cert(ca_cert_path: str) -> str:
    """The CA pin string to configure on workers (alias of cert_fingerprint)."""
    return cert_fingerprint(ca_cert_path)


def cert_serial(cert_path: str) -> int:
    """The decimal serial number of a cert (for revocation).

    Uses ``openssl x509 -serial`` (serials aren't exposed by stdlib ssl for a
    cert *file*, only over a live connection via ``getpeercert``). The serial is
    returned as a plain Python int so it can be stored/compared in a revoked-set.
    """
    out = _run_openssl(["x509", "-in", cert_path, "-noout", "-serial"])
    text = out.decode("utf-8", "replace").strip()
    # "serial=ABCDEF0123..." -> parse hex (may be uppercase).
    if not text.startswith("serial="):
        raise CAError(f"unexpected openssl x509 -serial output: {text!r}")
    hex_serial = text[len("serial="):].strip()
    return int(hex_serial, 16)


def rotate_ca(
    old_ca_cert: str,
    old_ca_key: str,
    new_ca_cert: str,
    new_ca_key: str,
    days: int = 3650,
    cn: str = "honeywatch-internal-ca",
) -> dict:
    """Generate a new CA and cross-sign it with the old CA for rotation.

    Creates a new root CA key+cert, then signs the new CA's public key with
    the *old* CA to produce a cross-signed certificate. Workers that trust
    the old CA will accept the cross-signed cert during the transition
    window; new workers trust the new CA directly.

    Returns a dict with:
        - ``new_ca_cert``: path to the new CA cert
        - ``new_ca_key``: path to the new CA key
        - ``cross_cert``: path to the cross-signed cert (new key, old CA signature)
        - ``new_pin``: SHA-256 fingerprint of the new CA cert
        - ``old_pin``: SHA-256 fingerprint of the old CA cert
    """
    old_ca_cert = os.path.abspath(old_ca_cert)
    old_ca_key = os.path.abspath(old_ca_key)
    new_ca_cert = os.path.abspath(new_ca_cert)
    new_ca_key = os.path.abspath(new_ca_key)
    _ensure_parent(new_ca_cert)
    _ensure_parent(new_ca_key)

    # Step 1: Generate the new root CA key + self-signed cert.
    generate_ca(new_ca_cert, new_ca_key, days=days, cn=cn)

    # Step 2: Create a cross-signed cert — the new CA's public key signed
    # by the old CA. Workers that only have the old CA in their trust store
    # will accept this cross-signed cert during the transition window.
    cross_cert = os.path.join(os.path.dirname(new_ca_cert), "ca-cross.pem")
    # Generate a CSR from the new key, then sign it with the old CA.
    csr_path = os.path.join(os.path.dirname(new_ca_cert), ".ca-rotate.csr")
    ext_path = os.path.join(os.path.dirname(new_ca_cert), ".ca-rotate.ext")
    try:
        _run_openssl(
            ["req", "-new", "-key", new_ca_key, "-out", csr_path,
             "-subj", f"/CN={cn}"]
        )
        Path(ext_path).write_text(
            "[v3_cross]\n"
            "basicConstraints = critical, CA:TRUE, pathlen:1\n"
            "keyUsage = critical, keyCertSign, cRLSign\n",
            encoding="utf-8",
        )
        _run_openssl(
            ["x509", "-req", "-in", csr_path,
             "-CA", old_ca_cert, "-CAkey", old_ca_key, "-CAcreateserial",
             "-out", cross_cert, "-days", str(days),
             "-extfile", ext_path, "-extensions", "v3_cross"]
        )
    finally:
        for tmp in (csr_path, ext_path):
            try:
                os.remove(tmp)
            except OSError:
                pass

    return {
        "new_ca_cert": new_ca_cert,
        "new_ca_key": new_ca_key,
        "cross_cert": cross_cert,
        "new_pin": cert_fingerprint(new_ca_cert),
        "old_pin": cert_fingerprint(old_ca_cert),
    }
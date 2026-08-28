"""Tests for the tamper-evident audit chain (Phase 2)."""

from __future__ import annotations

import json
import sqlite3
import pytest

from honeywatch.audit import (
    AuditRecord,
    AuditStore,
    _redact_args,
    _redact_result,
    _mask_secret_value,
    _GENESIS_HASH,
    script_sha256,
)


@pytest.fixture
def store(tmp_path):
    return AuditStore(str(tmp_path / "test.db"))


# --------------------------------------------------------------------------- #
# Redaction
# --------------------------------------------------------------------------- #


class TestRedaction:
    def test_secret_arg_names_masked(self):
        out = _redact_args({"password": "secret123", "host": "10.0.0.5"})
        assert out["password"] == "***"
        assert out["host"] == "10.0.0.5"

    def test_ssh_pass_masked(self):
        out = _redact_args({"ssh_pass": "mypass", "ssh_key": "keydata"})
        assert out["ssh_pass"] == "***"
        assert out["ssh_key"] == "***"

    def test_url_credential_masked(self):
        out = _redact_args({"url": "http://admin:secretpass@host"})
        assert "secretpass" not in out["url"]
        assert "***" in out["url"]

    def test_bearer_token_masked(self):
        out = _redact_args({"header": "Authorization: Bearer sk-abc123"})
        assert "sk-abc123" not in out["header"]
        assert "***" in out["header"]

    def test_password_flag_masked(self):
        out = _redact_args({"cmd": "ssh --password mypass host"})
        assert "mypass" not in out["cmd"]

    def test_non_string_values_preserved(self):
        out = _redact_args({"port": 22, "count": 10, "flag": True})
        assert out["port"] == 22
        assert out["count"] == 10
        assert out["flag"] is True

    def test_nested_dict_redacted(self):
        out = _redact_args({"config": {"password": "nested", "host": "ok"}})
        assert out["config"]["password"] == "***"
        assert out["config"]["host"] == "ok"

    def test_list_of_strings_redacted(self):
        out = _redact_args({"urls": ["http://u:p@h1", "http://safe"]})
        assert "p@h1" not in out["urls"][0]

    def test_empty_args(self):
        assert _redact_args(None) == {}
        assert _redact_args({}) == {}

    def test_result_redaction(self):
        out = _redact_result({"password": "x", "data": "Authorization: Bearer sk-token-123"})
        assert out["password"] == "***"
        assert "sk-token-123" not in out["data"]

    def test_mask_secret_value_non_string(self):
        assert _mask_secret_value(42) == 42
        assert _mask_secret_value(None) is None

    def test_auth_tuple_both_secrets_masked_structure_preserved(self):
        """Regression: the auth=("u","p") regex used to corrupt the string
        (losing the closing paren) and leak the second secret.  The fix
        captures the closing ')' in group 3 and masks both secrets."""
        masked = _mask_secret_value('auth=("user","pass123")')
        assert "user" not in masked
        assert "pass123" not in masked
        assert masked == 'auth=("***","***")'
        # Single-quote variant
        masked_sq = _mask_secret_value("auth=('user','pass123')")
        assert "user" not in masked_sq
        assert "pass123" not in masked_sq
        assert masked_sq == "auth=('***','***')"


# --------------------------------------------------------------------------- #
# AuditStore — chain formation + verification
# --------------------------------------------------------------------------- #


class TestAuditChain:
    def test_first_record_has_genesis_prev_hash(self, store):
        rec = store.record(
            run_id="r1", session_id="s1", cycle=1, target_ip="10.0.0.1",
            tool="scan", action="execute",
        )
        assert rec.prev_hash == _GENESIS_HASH
        assert rec.this_hash != ""
        assert len(rec.this_hash) == 64  # sha256 hex

    def test_second_record_chains_to_first(self, store):
        rec1 = store.record(run_id="r1", session_id="s1", cycle=1, target_ip="a",
                            tool="scan", action="execute")
        rec2 = store.record(run_id="r1", session_id="s1", cycle=2, target_ip="b",
                            tool="crack", action="execute")
        assert rec2.prev_hash == rec1.this_hash

    def test_verify_empty_chain(self, store):
        valid, reason = store.verify_chain()
        assert valid is True
        assert "no audit records" in reason

    def test_verify_intact_chain(self, store):
        store.record(run_id="r1", session_id="s1", cycle=1, target_ip="a",
                     tool="scan", action="execute")
        store.record(run_id="r1", session_id="s1", cycle=2, target_ip="b",
                     tool="crack", action="execute")
        store.record(run_id="r1", session_id="s1", cycle=3, target_ip="c",
                     tool="deploy", action="execute")
        valid, reason = store.verify_chain()
        assert valid is True
        assert "3 records" in reason

    def test_verify_detects_tampered_record(self, store):
        store.record(run_id="r1", session_id="s1", cycle=1, target_ip="a",
                     tool="scan", action="execute", result={"hosts": ["1"]})
        store.record(run_id="r1", session_id="s1", cycle=2, target_ip="b",
                     tool="crack", action="execute")
        # Tamper with the first record directly in the DB.
        conn = sqlite3.connect(store.db_path)
        conn.execute("UPDATE audit_chain SET result_json = '{\"tampered\": true}' WHERE seq = 1")
        conn.commit()
        conn.close()
        valid, reason = store.verify_chain()
        assert valid is False
        assert "hash mismatch" in reason

    def test_verify_detects_broken_link(self, store):
        store.record(run_id="r1", session_id="s1", cycle=1, target_ip="a",
                     tool="scan", action="execute")
        store.record(run_id="r1", session_id="s1", cycle=2, target_ip="b",
                     tool="crack", action="execute")
        # Break the prev_hash link of the second record.  This also breaks
        # the hash (prev_hash is part of the hashed record), so verification
        # catches it as a hash mismatch or a prev_hash mismatch — both are
        # tamper detection.  We just assert the chain is not valid.
        conn = sqlite3.connect(store.db_path)
        conn.execute("UPDATE audit_chain SET prev_hash = 'deadbeef' WHERE seq = 2")
        conn.commit()
        conn.close()
        valid, reason = store.verify_chain()
        assert valid is False

    def test_verify_filtered_by_run_id(self, store):
        store.record(run_id="r1", session_id="s1", cycle=1, target_ip="a",
                     tool="scan", action="execute")
        store.record(run_id="r2", session_id="s1", cycle=1, target_ip="b",
                     tool="scan", action="execute")
        valid, reason = store.verify_chain(run_id="r1")
        assert valid is True
        assert "1 records" in reason

    def test_record_redacts_secrets(self, store):
        rec = store.record(
            run_id="r1", session_id="s1", cycle=1, target_ip="a",
            tool="crack_ssh", action="execute",
            arguments={"password": "mypass", "host": "10.0.0.1"},
            result={"password": "found_pass"},
        )
        assert "***" in rec.arguments_json
        assert "mypass" not in rec.arguments_json
        assert "***" in rec.result_json
        assert "found_pass" not in rec.result_json

    def test_chain_continues_across_store_instances(self, tmp_path):
        db = str(tmp_path / "test.db")
        s1 = AuditStore(db)
        rec1 = s1.record(run_id="r1", session_id="s1", cycle=1, target_ip="a",
                         tool="scan", action="execute")
        # New store instance on the same db — should continue the chain.
        s2 = AuditStore(db)
        rec2 = s2.record(run_id="r1", session_id="s1", cycle=2, target_ip="b",
                         tool="scan", action="execute")
        assert rec2.prev_hash == rec1.this_hash

    def test_concurrent_records_form_deterministic_chain(self, store):
        import threading
        hashes: list[str] = []
        lock = threading.Lock()

        def record_one(i):
            rec = store.record(
                run_id="r1", session_id="s1", cycle=i, target_ip=f"10.0.0.{i}",
                tool="scan", action="execute",
            )
            with lock:
                hashes.append(rec.this_hash)

        threads = [threading.Thread(target=record_one, args=(i,)) for i in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        # All 5 records should have unique hashes forming a valid chain.
        assert len(set(hashes)) == 5
        valid, reason = store.verify_chain()
        assert valid is True

    def test_recent_returns_records_newest_first(self, store):
        store.record(run_id="r1", session_id="s1", cycle=1, target_ip="10.0.0.1",
                     tool="scan", action="execute")
        store.record(run_id="r1", session_id="s1", cycle=2, target_ip="10.0.0.1",
                     tool="crack", action="execute")
        recs = store.recent(target_ip="10.0.0.1", limit=10)
        assert len(recs) == 2
        # Newest first (highest seq)
        assert recs[0]["cycle"] == 2
        assert recs[1]["cycle"] == 1

    def test_summary_reports_chain_validity(self, store):
        store.record(run_id="r1", session_id="s1", cycle=1, target_ip="a",
                     tool="scan", action="execute")
        s = store.summary()
        assert s["records"] == 1
        assert s["chain_valid"] is True

    def test_summary_detects_tamper(self, store):
        store.record(run_id="r1", session_id="s1", cycle=1, target_ip="a",
                     tool="scan", action="execute")
        conn = sqlite3.connect(store.db_path)
        conn.execute("UPDATE audit_chain SET tool = 'tampered' WHERE seq = 1")
        conn.commit()
        conn.close()
        s = store.summary()
        assert s["chain_valid"] is False

    def test_code_sha256_field(self, store):
        sha = script_sha256("echo hello")
        rec = store.record(
            run_id="r1", session_id="s1", cycle=1, target_ip="a",
            tool="deploy", action="execute",
            code_sha256=sha,
        )
        assert rec.code_sha256 == sha

    def test_exit_code_field(self, store):
        rec = store.record(
            run_id="r1", session_id="s1", cycle=1, target_ip="a",
            tool="scan", action="execute",
            exit_code=0,
        )
        assert rec.exit_code == 0

    def test_audit_record_compute_hash_excludes_this_hash(self):
        rec = AuditRecord(
            run_id="r1", session_id="s1", cycle=1, target_ip="a",
            tool="scan", action="execute",
        )
        h1 = rec.compute_hash()
        rec.this_hash = h1
        h2 = rec.compute_hash()
        # this_hash must not affect the hash computation.
        assert h1 == h2

    def test_audit_record_compute_hash_excludes_seq(self):
        rec = AuditRecord(
            run_id="r1", session_id="s1", cycle=1, target_ip="a",
            tool="scan", action="execute",
        )
        h1 = rec.compute_hash()
        rec.seq = 42
        h2 = rec.compute_hash()
        # seq must not affect the hash computation.
        assert h1 == h2


# --------------------------------------------------------------------------- #
# execute_tool integration — audit recording
# --------------------------------------------------------------------------- #


class TestExecuteToolAuditIntegration:
    """Regression tests for the audit wrapper in execute_tool."""

    def test_non_dict_result_still_audited(self, tmp_path):
        """Regression: a tool returning a non-dict (string, None, list) must
        not crash the audit wrapper.  The old code called result.get("error")
        unguarded — an AttributeError would silently skip the audit record."""
        from honeywatch.agent.tools import ToolContext, execute_tool, TOOL_REGISTRY

        ctx = ToolContext(db_path=str(tmp_path / "test.db"))
        # Monkeypatch a tool to return a bare string.
        original = TOOL_REGISTRY.get("get_status")
        TOOL_REGISTRY["get_status"]["func"] = lambda args, ctx: "not a dict"
        try:
            result = execute_tool("get_status", {}, ctx)
            assert result == "not a dict"
            # Audit record should still be written (with exit_code=0).
            records = ctx.audit_store.recent(limit=5)
            assert len(records) >= 1
            rec = records[0]
            assert rec["tool"] == "get_status"
            assert rec["exit_code"] == 0
        finally:
            if original:
                TOOL_REGISTRY["get_status"] = original

    def test_dict_with_error_records_exit_code_1(self, tmp_path):
        """A dict result with an 'error' key records exit_code=1."""
        from honeywatch.agent.tools import ToolContext, execute_tool, TOOL_REGISTRY

        ctx = ToolContext(db_path=str(tmp_path / "test.db"))
        original_func = TOOL_REGISTRY["get_status"]["func"]
        TOOL_REGISTRY["get_status"]["func"] = lambda args, ctx: {"error": "boom"}
        try:
            result = execute_tool("get_status", {}, ctx)
            assert result == {"error": "boom"}
            records = ctx.audit_store.recent(limit=5)
            assert len(records) >= 1
            rec = records[0]
            assert rec["exit_code"] == 1
        finally:
            TOOL_REGISTRY["get_status"]["func"] = original_func
"""Tests for the internal C2 CA (mTLS certificate authority).

These exercise real openssl (the same binary the production code shells out to)
to verify CA generation, worker cert signing, fingerprint pinning, and serial
extraction. Skipped when openssl is not on PATH so the suite still runs in
openssl-less CI.
"""

from __future__ import annotations

import os
import shutil
import subprocess

import pytest

from honeywatch.c2.ca import (
    CAError,
    ca_pin_from_cert,
    cert_fingerprint,
    cert_serial,
    generate_ca,
    sign_worker_cert,
)

_HAS_OPENSSL = shutil.which("openssl") is not None
pytestmark = pytest.mark.skipif(not _HAS_OPENSSL, reason="openssl not on PATH")


def _openssl_verify_ok(ca_cert: str, worker_cert: str) -> bool:
    """True when `openssl verify` accepts worker_cert as signed by ca_cert."""
    try:
        subprocess.run(
            ["openssl", "verify", "-CAfile", ca_cert, worker_cert],
            check=True, capture_output=True,
        )
        return True
    except subprocess.CalledProcessError:
        return False


def test_generate_ca_creates_ca_true_cert(tmp_path):
    ca_cert = tmp_path / "ca.crt"
    ca_key = tmp_path / "ca.key"
    generate_ca(str(ca_cert), str(ca_key), days=10)
    assert ca_cert.exists() and ca_key.exists()
    # The CA cert must assert CA:TRUE (openssl verifies it's a usable CA by
    # successfully signing a child -- covered by the signing test below -- and
    # the x509 text must contain the basicConstraints).
    out = subprocess.run(
        ["openssl", "x509", "-in", str(ca_cert), "-noout", "-text"],
        check=True, capture_output=True,
    ).stdout.decode("utf-8", "replace")
    assert "CA:TRUE" in out


def test_sign_worker_cert_chains_to_ca(tmp_path):
    ca_cert = tmp_path / "ca.crt"
    ca_key = tmp_path / "ca.key"
    generate_ca(str(ca_cert), str(ca_key), days=10)
    w_cert = tmp_path / "w.crt"
    w_key = tmp_path / "w.key"
    sign_worker_cert(str(ca_cert), str(ca_key), str(w_cert), str(w_key),
                     worker_id="worker-abc", days=10)
    assert w_cert.exists() and w_key.exists()
    assert _openssl_verify_ok(str(ca_cert), str(w_cert))
    # The worker cert must be clientAuth + CA:FALSE (cannot sign further certs).
    out = subprocess.run(
        ["openssl", "x509", "-in", str(w_cert), "-noout", "-text"],
        check=True, capture_output=True,
    ).stdout.decode("utf-8", "replace")
    assert "TLS Web Client Authentication" in out  # openssl's rendering of clientAuth
    assert "CA:FALSE" in out


def test_sign_worker_cert_sanitizes_worker_id(tmp_path):
    ca_cert = tmp_path / "ca.crt"
    ca_key = tmp_path / "ca.key"
    generate_ca(str(ca_cert), str(ca_key), days=10)
    w_cert = tmp_path / "w.crt"
    w_key = tmp_path / "w.key"
    # A worker_id with shell-unsafe chars must not break the CN/CSR.
    sign_worker_cert(str(ca_cert), str(ca_key), str(w_cert), str(w_key),
                     worker_id="evil; rm -rf /", days=10)
    out = subprocess.run(
        ["openssl", "x509", "-in", str(w_cert), "-noout", "-subject"],
        check=True, capture_output=True,
    ).stdout.decode("utf-8", "replace")
    assert "evilrm" in out.replace(" ", "")
    assert ";" not in out


def test_cert_fingerprint_stable_and_shaprefixed(tmp_path):
    ca_cert = tmp_path / "ca.crt"
    ca_key = tmp_path / "ca.key"
    generate_ca(str(ca_cert), str(ca_key), days=10)
    fp = cert_fingerprint(str(ca_cert))
    assert fp.startswith("sha256:")
    assert len(fp) == len("sha256:") + 64  # 32-byte SHA-256 hex
    # Stable across reads.
    assert cert_fingerprint(str(ca_cert)) == fp
    # Distinct certs have distinct fingerprints.
    ca2 = tmp_path / "ca2.crt"
    k2 = tmp_path / "ca2.key"
    generate_ca(str(ca2), str(k2), days=10)
    assert cert_fingerprint(str(ca2)) != fp


def test_ca_pin_from_cert_is_fingerprint(tmp_path):
    ca_cert = tmp_path / "ca.crt"
    ca_key = tmp_path / "ca.key"
    generate_ca(str(ca_cert), str(ca_key), days=10)
    assert ca_pin_from_cert(str(ca_cert)) == cert_fingerprint(str(ca_cert))


def test_cert_serial_is_int_and_distinct(tmp_path):
    ca_cert = tmp_path / "ca.crt"
    ca_key = tmp_path / "ca.key"
    generate_ca(str(ca_cert), str(ca_key), days=10)
    w1 = tmp_path / "w1.crt"; k1 = tmp_path / "w1.key"
    w2 = tmp_path / "w2.crt"; k2 = tmp_path / "w2.key"
    sign_worker_cert(str(ca_cert), str(ca_key), str(w1), str(k1), "w1", days=10)
    sign_worker_cert(str(ca_cert), str(ca_key), str(w2), str(k2), "w2", days=10)
    s1 = cert_serial(str(w1))
    s2 = cert_serial(str(w2))
    assert isinstance(s1, int) and isinstance(s2, int)
    assert s1 > 0 and s2 > 0
    assert s1 != s2  # distinct certs have distinct serials


def test_cert_fingerprint_missing_file_raises(tmp_path):
    with pytest.raises((FileNotFoundError, CAError)):
        cert_fingerprint(str(tmp_path / "nope.crt"))
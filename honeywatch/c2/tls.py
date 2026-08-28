"""TLS and nginx helper for the honeywatch C2 web plane.

Generates self-signed certificates for lab use and emits an nginx reverse-proxy
configuration that fronts the aiohttp controller with TLS and WebSocket support.
"""

from __future__ import annotations

import hmac
import os
import ssl
import subprocess
from pathlib import Path
from typing import Any

from honeywatch.c2.ca import CAError, ca_pin_from_cert


NGINX_TEMPLATE = """
# nginx reverse-proxy for honeywatch C2
# Place in /etc/nginx/sites-enabled/honeywatch and reload nginx.

upstream honeywatch_c2 {
    server 127.0.0.1:{{controller_port}};
}

server {
    listen {{nginx_port}} ssl;
    server_name {{server_name}};

    ssl_certificate     {{cert_path}};
    ssl_certificate_key {{key_path}};
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;

    location / {
        proxy_pass http://honeywatch_c2;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 86400;
    }
}
"""


def generate_self_signed(
    cert_path: str,
    key_path: str,
    hostname: str = "honeywatch.local",
    days: int = 365,
) -> None:
    """Create a self-signed cert/key pair using OpenSSL."""
    cert_path = os.path.abspath(cert_path)
    key_path = os.path.abspath(key_path)
    os.makedirs(os.path.dirname(cert_path) or ".", exist_ok=True)
    os.makedirs(os.path.dirname(key_path) or ".", exist_ok=True)
    try:
        subprocess.run(
            [
                "openssl",
                "req",
                "-x509",
                "-nodes",
                "-newkey",
                "rsa:2048",
                "-keyout",
                key_path,
                "-out",
                cert_path,
                "-days",
                str(days),
                "-subj",
                f"/CN={hostname}",
                "-addext",
                f"subjectAltName=DNS:{hostname},DNS:localhost,IP:127.0.0.1",
            ],
            check=True,
            capture_output=True,
        )
    except FileNotFoundError as exc:
        # openssl binary not on PATH -- raise a clear error instead of a bare
        # FileNotFoundError so the operator knows what to install.
        raise RuntimeError(
            "openssl not found on PATH; install openssl to generate a self-signed cert"
        ) from exc


def render_nginx_config(
    controller_port: int,
    cert_path: str,
    key_path: str,
    nginx_port: int = 443,
    server_name: str = "honeywatch.local",
) -> str:
    """Return an nginx site configuration string."""
    return (
        NGINX_TEMPLATE.replace("{{controller_port}}", str(controller_port))
        .replace("{{nginx_port}}", str(nginx_port))
        .replace("{{server_name}}", server_name)
        .replace("{{cert_path}}", cert_path)
        .replace("{{key_path}}", key_path)
    )


def write_nginx_config(
    path: str,
    controller_port: int,
    cert_path: str,
    key_path: str,
    nginx_port: int = 443,
    server_name: str = "honeywatch.local",
) -> None:
    """Write the rendered nginx config to ``path``."""
    text = render_nginx_config(controller_port, cert_path, key_path, nginx_port, server_name)
    Path(path).write_text(text, encoding="utf-8")


def ensure_self_signed_pair(base_dir: str = "certs", hostname: str = "honeywatch.local") -> tuple[str, str]:
    """Return paths to an existing or freshly-generated self-signed cert pair."""
    os.makedirs(base_dir, exist_ok=True)
    cert = os.path.join(base_dir, "honeywatch.crt")
    key = os.path.join(base_dir, "honeywatch.key")
    if not os.path.isfile(cert) or not os.path.isfile(key):
        generate_self_signed(cert, key, hostname)
    return cert, key


def build_ssl_context(cert_path: str | None, key_path: str | None) -> ssl.SSLContext | None:
    """Build an SSL context for the aiohttp controller.

    Returns ``None`` (-> controller serves plaintext) only when TLS paths were
    not requested at all. When a cert/key path *was* provided but the file is
    missing or unreadable, we raise rather than silently downgrading to HTTP --
    otherwise a typo'd path would expose the C2 dashboard over plaintext on a
    public bind with no warning.
    """
    if not cert_path or not key_path:
        return None
    if not os.path.isfile(cert_path) or not os.path.isfile(key_path):
        raise FileNotFoundError(
            f"TLS cert/key not found (cert={cert_path!r}, key={key_path!r}). "
            "Fix the paths, regenerate with --generate-certs, or run without "
            "--tls-cert/--tls-key for plaintext lab use."
        )
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.load_cert_chain(cert_path, key_path)
    return ctx


def build_client_ssl_context(
    ca_path: str | None,
    worker_cert: str | None = None,
    worker_key: str | None = None,
    ca_pin: str | None = None,
) -> ssl.SSLContext | None:
    """Build a client (worker) SSL context that pins the internal CA.

    Returns ``None`` when ``ca_path`` is falsy -- no mTLS, the worker talks
    plaintext HTTP and the existing lab behaviour is unchanged.

    When ``ca_path`` is set:
      * If ``ca_pin`` is provided, the CA file's SHA-256 fingerprint must match
        it (constant-time). This guards against CA-file substitution on the
        worker: a swapped CA file (e.g. an attacker's CA so they can MITM with
        a cert it signed) is rejected before it is ever trusted.
      * The context trusts ONLY this CA (``load_verify_locations``) with
        ``CERT_REQUIRED`` -- the controller cert must chain to our CA. No
        public CA can validate the controller, so a public-CA-issued impostor
        is rejected. This is CA pinning at the chain level.
      * ``check_hostname`` is disabled: the CA pin is the trust anchor, not
        the DNS name (controllers are often reached by IP, and the internal
        CA cert need not carry a SAN for every operator hostname).
      * If ``worker_cert``/``worker_key`` are provided, they are loaded as the
        client certificate chain (mutual TLS) so the controller can authenticate
        the worker.
    """
    if not ca_path:
        return None
    if not os.path.isfile(ca_path):
        raise FileNotFoundError(
            f"CA cert not found ({ca_path!r}). Fix --ca, or run without it "
            "for plaintext lab use."
        )
    if ca_pin is not None:
        actual = ca_pin_from_cert(ca_path)
        if not hmac.compare_digest(actual, ca_pin):
            raise CAError(
                f"CA pin mismatch: expected {ca_pin!r}, got {actual!r}. The "
                "CA file does not match the pinned fingerprint -- refusing to "
                "trust it (possible CA-file substitution)."
            )
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_verify_locations(ca_path)
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.check_hostname = False  # CA pin is the trust anchor, not the DNS name
    if worker_cert and worker_key:
        if not os.path.isfile(worker_cert) or not os.path.isfile(worker_key):
            raise FileNotFoundError(
                f"worker cert/key not found (cert={worker_cert!r}, key={worker_key!r})"
            )
        ctx.load_cert_chain(worker_cert, worker_key)
    return ctx


def build_mtls_server_ssl_context(
    cert_path: str | None,
    key_path: str | None,
    ca_path: str | None,
) -> ssl.SSLContext | None:
    """Build a controller server SSL context that requires worker client certs.

    Returns ``None`` when no server cert/key are configured (plaintext). When
    ``ca_path`` is set on top of a server cert, the context additionally requires
    every client to present a cert chaining to that CA (mutual TLS) -- so only
    workers holding a CA-signed cert can even complete the TLS handshake. The
    bearer token stays as a second factor at the application layer.
    """
    if not cert_path or not key_path:
        return None
    ctx = build_ssl_context(cert_path, key_path)  # raises on missing/typo'd path
    if ca_path:
        if not os.path.isfile(ca_path):
            raise FileNotFoundError(
                f"CA cert not found ({ca_path!r}). Fix --ca, or run without "
                "client-cert verification for server-TLS-only operation."
            )
        ctx.load_verify_locations(ca_path)
        ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx

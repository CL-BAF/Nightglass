"""TLS and nginx helper for the honeywatch C2 web plane.

Generates self-signed certificates for lab use and emits an nginx reverse-proxy
configuration that fronts the aiohttp controller with TLS and WebSocket support.
"""

from __future__ import annotations

import os
import ssl
import subprocess
from pathlib import Path
from typing import Any


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
    """Build an SSL context for the aiohttp controller."""
    if not cert_path or not key_path:
        return None
    if not os.path.isfile(cert_path) or not os.path.isfile(key_path):
        return None
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.load_cert_chain(cert_path, key_path)
    return ctx

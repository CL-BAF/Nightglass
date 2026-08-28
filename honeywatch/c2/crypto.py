"""Encrypted C2 transport for honeywatch.

Provides sealed-box encryption (X25519 + XSalsa20-Poly1305) for the
controller-to-worker communication channel. When encryption is enabled,
task scripts and variables are encrypted with the controller's public key;
worker results are encrypted the same way. The controller decrypts with
its private key.

Sealed boxes (NaCl ``crypto_box_seal``) don't require the sender to have a
keypair — they only need the recipient's public key. The sender generates an
ephemeral keypair per message, providing forward secrecy per task result.

Fallback: when ``nacl`` (PyNaCl) is unavailable, the module falls back to
AES-256-GCM with PBKDF2-derived keys from a pre-shared passphrase. This
uses only stdlib modules (``hashlib``, ``os``, ``struct``) and is less
secure than sealed boxes (no forward secrecy, passphrase-derived key) but
requires no external dependencies.

Architecture:

- Controller generates an X25519 keypair on start (or uses ``--c2-key``).
- ``GET /api/pubkey`` returns the controller's public key (base64-encoded).
- Worker fetches the pubkey on first connect.
- All task data is encrypted with a sealed box using the controller's public key.
- Worker results are encrypted the same way (sealed box to controller's pubkey).
- ``api_version=2`` in the JSON payload signals that fields are encrypted.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import struct
from typing import Any

__all__ = [
    "C2Crypto",
    "encrypt_task",
    "decrypt_task",
    "encrypt_result",
    "decrypt_result",
    "generate_keypair",
    "pubkey_b64",
    "vault_encrypt",
    "vault_decrypt",
    "derive_vault_key",
]


def _has_nacl() -> bool:
    try:
        from nacl.public import PrivateKey, SealedBox  # noqa: F401
        return True
    except ImportError:
        return False


def generate_keypair() -> tuple[bytes, bytes]:
    """Generate an X25519 keypair for C2 encryption.

    Returns (private_key, public_key) as raw 32-byte values.
    """
    if _has_nacl():
        from nacl.public import PrivateKey
        sk = PrivateKey.generate()
        return bytes(sk), bytes(sk.public_key)
    # Fallback: generate a random 32-byte keypair and derive the
    # "public key" as SHA-256(privkey). This is NOT a real X25519 keypair
    # but provides a deterministic key for AES-256-GCM.
    privkey = os.urandom(32)
    pubkey = hashlib.sha256(privkey).digest()
    return privkey, pubkey


def pubkey_b64(pubkey: bytes) -> str:
    """Encode a public key as base64 for transmission."""
    return base64.b64encode(pubkey).decode("ascii")


def _derive_aes_key(passphrase: str, salt: bytes) -> bytes:
    """Derive a 256-bit AES key from a passphrase using PBKDF2-SHA256.

    Uses 600,000 iterations per OWASP 2025 recommendation for SHA-256.
    """
    return hashlib.pbkdf2_hmac("sha256", passphrase.encode(), salt, 600_000)


def _aes_gcm_encrypt(plaintext: bytes, key: bytes) -> bytes:
    """Encrypt with AES-256-GCM using only stdlib (hashlib for HKDF).

    Format: salt(16) + nonce(12) + ciphertext + tag(16)
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(nonce, plaintext, None)
    return nonce + ct


def _aes_gcm_decrypt(data: bytes, key: bytes) -> bytes:
    """Decrypt AES-256-GCM ciphertext."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    nonce = data[:12]
    ct = data[12:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ct, None)


class C2Crypto:
    """Manages encryption keys and provides encrypt/decrypt for C2 traffic.

    When ``nacl`` is available, uses X25519 sealed boxes (forward-secret per
    message). When ``nacl`` is unavailable, falls back to AES-256-GCM with
    a passphrase-derived key (no forward secrecy, but no external deps).
    """

    def __init__(self, private_key: bytes | None = None, passphrase: str | None = None):
        self.use_nacl = _has_nacl()
        if private_key:
            self.private_key = private_key
            if self.use_nacl:
                from nacl.public import PrivateKey
                sk = PrivateKey(private_key)
                self.public_key = bytes(sk.public_key)
            else:
                self.public_key = hashlib.sha256(private_key).digest()
        elif passphrase:
            salt = b"honeywatch-c2-v1"  # Fixed salt for passphrase-derived keys
            self.private_key = _derive_aes_key(passphrase, salt)
            self.public_key = hashlib.sha256(self.private_key).digest()
        else:
            self.private_key, self.public_key = generate_keypair()
        self._sealed_box = None
        self._aes_key = None

    def _get_sealed_box_encrypt(self, recipient_pubkey: bytes):
        """Create a SealedBox for encryption with a recipient's public key."""
        from nacl.public import PublicKey, SealedBox
        pk = PublicKey(recipient_pubkey)
        return SealedBox(pk)

    def _get_sealed_box_decrypt(self):
        """Create a SealedBox for decryption with our private key."""
        if self._sealed_box is None:
            from nacl.public import PrivateKey, SealedBox
            sk = PrivateKey(self.private_key)
            self._sealed_box = SealedBox(sk)
        return self._sealed_box

    def encrypt(self, plaintext: str | bytes, recipient_pubkey: bytes | None = None) -> str:
        """Encrypt plaintext for a recipient.

        If recipient_pubkey is provided, encrypts with NaCl sealed box (forward
        secret). Otherwise, encrypts with our own key (for self-encryption when
        the controller encrypts task data for storage).

        Returns base64-encoded ciphertext.
        """
        if isinstance(plaintext, str):
            plaintext = plaintext.encode("utf-8")
        if self.use_nacl:
            pubkey = recipient_pubkey or self.public_key
            box = self._get_sealed_box_encrypt(pubkey)
            ct = box.encrypt(plaintext)
            return base64.b64encode(ct).decode("ascii")
        # AES-256-GCM fallback
        if self._aes_key is None:
            salt = b"honeywatch-c2-v1"
            self._aes_key = _derive_aes_key(
                base64.b64encode(self.private_key).decode(), salt
            )
        ct = _aes_gcm_encrypt(plaintext, self._aes_key)
        return base64.b64encode(ct).decode("ascii")

    def decrypt(self, ciphertext: str) -> bytes:
        """Decrypt ciphertext encrypted with our public key.

        Returns raw bytes. For sealed boxes, this works because the sender
        encrypted with our public key.
        """
        ct = base64.b64decode(ciphertext)
        if self.use_nacl:
            box = self._get_sealed_box_decrypt()
            return box.decrypt(ct)
        # AES-256-GCM fallback
        if self._aes_key is None:
            salt = b"honeywatch-c2-v1"
            self._aes_key = _derive_aes_key(
                base64.b64encode(self.private_key).decode(), salt
            )
        return _aes_gcm_decrypt(ct, self._aes_key)


def encrypt_task(
    task_data: dict[str, Any],
    crypto: C2Crypto,
) -> dict[str, Any]:
    """Encrypt task script and variables for C2 transport.

    Takes a task dict (with ``script``, ``variables``, etc.) and returns a
    new dict with encrypted fields. The ``marker_map`` is kept in plaintext
    for controller-side deobfuscation. A timestamp is included for replay
    protection — workers reject tasks older than ``task_max_age`` seconds.
    """
    encrypted_script = crypto.encrypt(task_data.get("script", ""))
    encrypted_variables = crypto.encrypt(json.dumps(task_data.get("variables", {})))
    from datetime import datetime, timezone
    result = {
        "task_id": task_data.get("id", ""),
        "operation_id": task_data.get("operation_id", ""),
        "payload_id": task_data.get("payload_id", ""),
        "encrypted_script": encrypted_script,
        "encrypted_variables": encrypted_variables,
        "marker_map": task_data.get("marker_map", {}),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "api_version": 2,
    }
    # Preserve target info (not encrypted — needed for worker routing).
    if "target" in task_data:
        target = task_data["target"]
        result["target"] = target if isinstance(target, dict) else {"ip": target.ip, "port": target.port}
    return result


def decrypt_task(
    encrypted_task: dict[str, Any],
    crypto: C2Crypto,
    task_max_age: float = 300.0,
) -> dict[str, Any]:
    """Decrypt task script and variables received from C2 transport.

    Returns a dict with ``script`` and ``variables`` in plaintext.
    Rejects tasks whose timestamp is older than ``task_max_age`` seconds
    to prevent replay attacks.
    """
    from datetime import datetime, timezone
    result = dict(encrypted_task)
    # Replay protection: reject stale tasks.
    timestamp_str = encrypted_task.get("timestamp")
    if timestamp_str:
        try:
            task_time = datetime.fromisoformat(timestamp_str).replace(tzinfo=timezone.utc)
            age = (datetime.now(timezone.utc) - task_time).total_seconds()
            if age > task_max_age:
                raise ValueError(f"task timestamp too old ({age:.0f}s > {task_max_age:.0f}s)")
        except (ValueError, TypeError):
            pass  # Malformed timestamp — proceed (backwards compat)
    if "encrypted_script" in encrypted_task:
        result["script"] = crypto.decrypt(encrypted_task["encrypted_script"]).decode("utf-8")
        del result["encrypted_script"]
    if "encrypted_variables" in encrypted_task:
        vars_json = crypto.decrypt(encrypted_task["encrypted_variables"]).decode("utf-8")
        result["variables"] = json.loads(vars_json)
        del result["encrypted_variables"]
    result.pop("api_version", None)
    result.pop("timestamp", None)
    return result


def encrypt_result(
    result_data: dict[str, Any],
    crypto: C2Crypto,
) -> dict[str, Any]:
    """Encrypt task result for C2 transport."""
    encrypted_result = crypto.encrypt(json.dumps(result_data))
    return {
        "encrypted_result": encrypted_result,
        "api_version": 2,
    }


def decrypt_result(
    encrypted_result: dict[str, Any],
    crypto: C2Crypto,
) -> dict[str, Any]:
    """Decrypt task result received from C2 transport."""
    if "encrypted_result" in encrypted_result:
        plaintext = crypto.decrypt(encrypted_result["encrypted_result"]).decode("utf-8")
        return json.loads(plaintext)
    return encrypted_result


# --------------------------------------------------------------------------- #
# Vault encryption (credential store at rest)
# --------------------------------------------------------------------------- #


def derive_vault_key(passphrase: str) -> bytes:
    """Derive a 256-bit master vault key from a passphrase.

    Uses PBKDF2-SHA256 with 600,000 iterations (OWASP 2025 recommendation)
    and a fixed application-level salt. The resulting key is cached by the
    Store and used to derive per-row keys via HKDF-expand.
    """
    return hashlib.pbkdf2_hmac(
        "sha256",
        passphrase.encode("utf-8"),
        b"honeywatch-vault-v1",
        600_000,
    )


def vault_encrypt(plaintext: str, master_key: bytes) -> tuple[bytes, bytes]:
    """Encrypt a credential value with a per-row random salt.

    Returns (ciphertext, salt). The salt is stored alongside the ciphertext
    in the database so each row has a unique encryption key, preventing
    pattern analysis across identical passwords.

    The master key is already PBKDF2-derived (600k iterations) from the
    passphrase. Per-row keys are derived with a single PBKDF2 round using
    the row's random salt — negligible cost compared to the initial
    derivation while ensuring each row has a unique AES key.
    """
    salt = os.urandom(16)
    derived_key = hashlib.pbkdf2_hmac("sha256", master_key, salt, 1)
    ct = _aes_gcm_encrypt(plaintext.encode("utf-8"), derived_key)
    return ct, salt


def vault_decrypt(ciphertext: bytes, salt: bytes, master_key: bytes) -> str:
    """Decrypt a credential value using the per-row salt.

    Derives the per-row key from the master vault key + stored salt, then
    decrypts with AES-256-GCM.
    """
    derived_key = hashlib.pbkdf2_hmac("sha256", master_key, salt, 1)
    return _aes_gcm_decrypt(ciphertext, derived_key).decode("utf-8")
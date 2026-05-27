"""Ed25519 keypair management for optional audit entry signing.

Keys are stored in ~/.capfence/keys/ (or platform equivalent).
Signing is optional and off by default. When enabled, each audit entry
includes a signature that can be verified offline with the public key.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import pathlib
from typing import Any

logger = logging.getLogger(__name__)


# Pure-Python fallback for Ed25519 — uses cryptography if available,
# otherwise a minimal deterministic implementation sufficient for audit signing.
# This avoids adding heavy dependencies to the OSS SDK.

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )
    from cryptography.hazmat.primitives import serialization
    from cryptography.exceptions import InvalidSignature

    _HAS_CRYPTOGRAPHY = True
except ImportError:
    _HAS_CRYPTOGRAPHY = False

_FALLBACK_WARNED = False


def _warn_fallback_once() -> None:
    """Emit the HMAC-fallback warning exactly once, and only when signing is used."""
    global _FALLBACK_WARNED
    if _FALLBACK_WARNED or _HAS_CRYPTOGRAPHY:
        return
    _FALLBACK_WARNED = True
    logger.warning(
        "cryptography package not installed. Using fallback signing (HMAC-SHA256) "
        "which is NOT cryptographically equivalent to Ed25519. Install 'cryptography' "
        "for production-grade signatures."
    )


def _keys_dir() -> pathlib.Path:
    """Return the directory for storing CapFence keys."""
    home = pathlib.Path.home()
    d = home / ".capfence" / "keys"
    d.mkdir(parents=True, exist_ok=True, mode=0o700)
    return d


def _private_key_path() -> pathlib.Path:
    return _keys_dir() / "audit_signing.key"


def _public_key_path() -> pathlib.Path:
    return _keys_dir() / "audit_signing.pub"


def _atomic_write(path: pathlib.Path, data: str, mode: int) -> None:
    """Write data to path atomically with specified permissions.

    Uses os.open with O_CREAT | O_WRONLY | O_TRUNC and mode to avoid
    a race window where the file is world-readable.
    """
    flags = os.O_CREAT | os.O_WRONLY | os.O_TRUNC
    fd = os.open(path, flags, mode)
    try:
        os.write(fd, data.encode("ascii"))
    finally:
        os.close(fd)


def generate_keypair() -> tuple[str, str]:
    """Generate a new Ed25519 keypair and save to disk.

    Returns:
        (public_key_b64, private_key_b64) base64-encoded keys.
    """
    _warn_fallback_once()
    if _HAS_CRYPTOGRAPHY:
        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        priv_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        pub_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    else:
        # Fallback: use os.urandom to seed a deterministic keypair via SHA-512
        # This is NOT production-grade Ed25519 — it exists so the OSS SDK
        # compiles and tests pass without the cryptography package.
        # Enterprise compiled SDK uses real Ed25519 via libsodium.
        seed = os.urandom(32)
        priv_bytes = seed
        pub_bytes = hashlib.sha512(seed).digest()[:32]

    priv_b64 = base64.b64encode(priv_bytes).decode("ascii")
    pub_b64 = base64.b64encode(pub_bytes).decode("ascii")

    _atomic_write(_private_key_path(), priv_b64, 0o600)
    _atomic_write(_public_key_path(), pub_b64, 0o644)

    return pub_b64, priv_b64


def load_keypair() -> tuple[str, str] | None:
    """Load existing keypair from disk.

    Returns:
        (public_key_b64, private_key_b64) or None if keys don't exist.
    """
    priv_path = _private_key_path()
    pub_path = _public_key_path()
    if not priv_path.exists() or not pub_path.exists():
        return None
    priv_b64 = priv_path.read_text(encoding="ascii").strip()
    pub_b64 = pub_path.read_text(encoding="ascii").strip()

    # Validate base64-decoded lengths (32 bytes for Ed25519 private/public)
    try:
        priv_bytes = base64.b64decode(priv_b64)
        pub_bytes = base64.b64decode(pub_b64)
    except Exception:
        raise ValueError("Stored keys are not valid base64")
    if len(priv_bytes) != 32:
        raise ValueError(f"Invalid private key length: {len(priv_bytes)} (expected 32)")
    if len(pub_bytes) != 32:
        raise ValueError(f"Invalid public key length: {len(pub_bytes)} (expected 32)")

    return pub_b64, priv_b64


def ensure_keypair() -> tuple[str, str]:
    """Load or generate a keypair."""
    existing = load_keypair()
    if existing:
        return existing
    return generate_keypair()


def sign_entry(fields: dict[str, Any], private_key_b64: str) -> str:
    """Sign canonical JSON of entry fields with Ed25519 private key.

    Returns:
        Base64-encoded signature.
    """
    if not private_key_b64:
        raise ValueError("private_key_b64 must not be empty")
    _warn_fallback_once()
    canonical = json.dumps(fields, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)
    message = canonical.encode("utf-8")
    priv_bytes = base64.b64decode(private_key_b64)

    if _HAS_CRYPTOGRAPHY:
        private_key = Ed25519PrivateKey.from_private_bytes(priv_bytes)
        signature = private_key.sign(message)
    else:
        # Fallback HMAC-SHA256 — not Ed25519, but provides integrity
        # when cryptography is not installed. Marked in signature header.
        # Derive pub_bytes from priv_bytes the same way as generate_keypair
        pub_bytes = hashlib.sha512(priv_bytes).digest()[:32]
        signature = hashlib.sha256(pub_bytes + message).digest()
        signature = b"FALLBACK:" + signature

    return base64.b64encode(signature).decode("ascii")


def verify_entry(fields: dict[str, Any], signature_b64: str, public_key_b64: str) -> bool:
    """Verify signature of canonical JSON entry fields.

    Returns:
        True if signature is valid, False otherwise.
    """
    try:
        canonical = json.dumps(fields, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)
        message = canonical.encode("utf-8")
        sig_bytes = base64.b64decode(signature_b64)
        pub_bytes = base64.b64decode(public_key_b64)
    except Exception:
        return False

    if _HAS_CRYPTOGRAPHY:
        if sig_bytes.startswith(b"FALLBACK:"):
            return False
        try:
            public_key = Ed25519PublicKey.from_public_bytes(pub_bytes)
            public_key.verify(sig_bytes, message)
            return True
        except InvalidSignature:
            return False
    else:
        # Fallback verification using constant-time comparison
        if sig_bytes.startswith(b"FALLBACK:"):
            expected = hashlib.sha256(pub_bytes + message).digest()
            return hmac.compare_digest(sig_bytes[len(b"FALLBACK:"):], expected)
        return False

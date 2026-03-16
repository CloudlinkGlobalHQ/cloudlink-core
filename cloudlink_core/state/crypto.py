"""
Credential encryption helpers.

Uses Fernet symmetric encryption (AES-128-CBC + HMAC-SHA256).

Key setup:
  1. Generate a key:  python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
  2. Set env var:     export CLOUDLINK_ENCRYPTION_KEY=<that key>

If CLOUDLINK_ENCRYPTION_KEY is not set the system runs in dev mode:
credentials are stored as plaintext with a warning logged. Never run
without the key in production.
"""
import logging
import os
from typing import Optional

logger = logging.getLogger(__name__)

_DEV_MODE_WARNED = False


def _get_key() -> Optional[bytes]:
    val = os.environ.get("CLOUDLINK_ENCRYPTION_KEY", "").strip()
    return val.encode() if val else None


def encrypt_credential(plaintext: str) -> str:
    """
    Encrypt a credential string. Returns a Fernet token (URL-safe base64).
    Falls back to plaintext in dev mode (no key set) with a warning.
    """
    global _DEV_MODE_WARNED
    key = _get_key()
    if not key:
        if not _DEV_MODE_WARNED:
            logger.warning(
                "CLOUDLINK_ENCRYPTION_KEY is not set. "
                "Credentials will be stored as plaintext. "
                "Set this variable before going to production."
            )
            _DEV_MODE_WARNED = True
        return plaintext

    from cryptography.fernet import Fernet
    return Fernet(key).encrypt(plaintext.encode()).decode()


def decrypt_credential(ciphertext: str) -> str:
    """
    Decrypt a Fernet token back to plaintext.
    Falls back to returning the value as-is in dev mode.
    """
    key = _get_key()
    if not key:
        return ciphertext

    from cryptography.fernet import Fernet, InvalidToken
    try:
        return Fernet(key).decrypt(ciphertext.encode()).decode()
    except InvalidToken:
        logger.error("Failed to decrypt credential — wrong key or corrupted data")
        raise


def mask_credential(plaintext: str) -> str:
    """Return a masked version safe to show in API responses."""
    if len(plaintext) <= 8:
        return "****"
    return plaintext[:4] + "****" + plaintext[-4:]

"""
SAT-SA AES-256-GCM File-Level Encryption.

Encryption Choice (D8 from design decisions):
  File-level AES-256-GCM encryption. NOT DuckDB native encryption.

  Rationale:
    DuckDB's native Community Edition does NOT support AES encryption.
    The enterprise extension has an unstable API and is not suitable for
    an air-gapped, single-binary deployment.

  Implementation:
    1. Input CSV/JSON data files are AES-256-GCM encrypted at rest.
    2. The engine decrypts the file to a temporary path before opening with DuckDB.
    3. The temp file is deleted on context manager exit (even if an exception occurs).
    4. The DuckDB .db file itself is NOT encrypted at the page level.
       The examiner's OS-level disk encryption (e.g., BitLocker) is expected for
       the DuckDB file. This is documented as a limitation in docs/security.md.

  Key Management:
    - Demo: Key loaded from a local file (demo.key). Key file MUST be stored
      separately from the data and must not be committed to version control.
    - Production stub: PKCS#11 interface (smartcard/HSM) documented in
      KeyProvider.load_from_pkcs11(). Implementation requires python-pkcs11.

  Limitations (documented per design requirement):
    - The decrypted temp file is plaintext while the engine process is running.
      Mitigation: temp file uses OS-level permissions (mode 0600); deleted on exit.
    - Key file loss = permanent data loss. No key escrow in this implementation.
    - GCM authentication tags verify ciphertext integrity before decryption.

References:
    - NIST SP 800-38D: GCM recommendation.
    - PKCS#11 v2.40: Cryptoki interface specification.
"""

from __future__ import annotations

import logging
import os
import tempfile
from abc import ABC, abstractmethod
from contextlib import contextmanager
from pathlib import Path
from typing import Generator

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

logger = logging.getLogger(__name__)

_NONCE_SIZE = 12   # GCM standard nonce size (bytes)
_KEY_SIZE = 32     # AES-256 key size (bytes)
_TAG_SIZE = 16     # GCM authentication tag (bytes)


# ─── Key Provider Interface ───────────────────────────────────────────────────

class KeyProvider(ABC):
    """Abstract interface for encryption key provisioning."""

    @abstractmethod
    def get_key(self) -> bytes:
        """Return the 32-byte (256-bit) AES key."""
        ...

    @classmethod
    def from_file(cls, key_path: Path | str) -> "FileKeyProvider":
        """Load key from a file (demo mode)."""
        return FileKeyProvider(Path(key_path))

    @classmethod
    def generate_demo_key(cls, key_path: Path | str) -> "FileKeyProvider":
        """Generate a new random key and save to file (for demo setup)."""
        key = os.urandom(_KEY_SIZE)
        path = Path(key_path)
        path.write_bytes(key)
        path.chmod(0o600)
        logger.info(f"Generated new demo key at {path}")
        return FileKeyProvider(path)

    @classmethod
    def load_from_pkcs11(
        cls,
        slot_id: int = 0,
        pin: str | None = None,
        key_label: str = "SAT-SA-KEY",
    ) -> "PKCS11KeyProvider":
        """
        STUB: Load key from a PKCS#11 hardware token (smartcard/HSM).

        In production, this method wraps python-pkcs11 to:
        1. Connect to the token at slot_id.
        2. Authenticate with PIN.
        3. Retrieve the AES key by label.
        4. Return a PKCS11KeyProvider that performs crypto operations on-device.

        Implementation requires: pip install python-pkcs11
        """
        return PKCS11KeyProvider(slot_id=slot_id, pin=pin, key_label=key_label)


class FileKeyProvider(KeyProvider):
    """
    Demo key provider: reads key from a local file.

    The key file must be 32 bytes (AES-256). Store separately from encrypted data.
    Do NOT commit the key file to version control.
    """

    def __init__(self, key_path: Path) -> None:
        self._key_path = key_path
        self._cached_key: bytes | None = None

    def get_key(self) -> bytes:
        if self._cached_key is None:
            if not self._key_path.exists():
                raise FileNotFoundError(
                    f"Key file not found: {self._key_path}. "
                    "Run: satsa ingest --generate-key to create one."
                )
            key = self._key_path.read_bytes()
            if len(key) != _KEY_SIZE:
                raise ValueError(
                    f"Invalid key size: {len(key)} bytes. Expected {_KEY_SIZE} bytes (AES-256)."
                )
            self._cached_key = key
        return self._cached_key


class PKCS11KeyProvider(KeyProvider):
    """
    STUB: PKCS#11 hardware token key provider.

    This is a documented interface stub. Production implementation requires
    the python-pkcs11 library and a configured PKCS#11 middleware.

    See docs/security.md §"Key Management" for deployment guidance.
    """

    def __init__(self, slot_id: int, pin: str | None, key_label: str) -> None:
        self._slot_id = slot_id
        self._pin = pin
        self._key_label = key_label

    def get_key(self) -> bytes:
        raise NotImplementedError(
            "PKCS#11 key provider is a documented stub. "
            "Install python-pkcs11 and implement token-specific key retrieval. "
            "See docs/security.md §PKCS11 for guidance."
        )


# ─── Encryption / Decryption ─────────────────────────────────────────────────

def encrypt_file(src_path: Path, dst_path: Path, key_provider: KeyProvider) -> None:
    """
    Encrypt ``src_path`` to ``dst_path`` using AES-256-GCM.

    Format of encrypted file:
        [12-byte nonce] [ciphertext + 16-byte GCM tag]

    The GCM authentication tag is appended by AESGCM automatically.
    On decryption, the tag is verified before any plaintext is returned.

    Args:
        src_path: Path to plaintext input file.
        dst_path: Path to write encrypted output.
        key_provider: Key provider instance.
    """
    key = key_provider.get_key()
    aesgcm = AESGCM(key)
    nonce = os.urandom(_NONCE_SIZE)

    plaintext = src_path.read_bytes()
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)  # No AAD

    with dst_path.open("wb") as f:
        f.write(nonce)
        f.write(ciphertext)

    logger.debug(f"Encrypted {src_path} → {dst_path} ({len(plaintext):,} bytes)")


def decrypt_to_bytes(enc_path: Path, key_provider: KeyProvider) -> bytes:
    """
    Decrypt an AES-256-GCM encrypted file and return plaintext bytes.

    Raises cryptography.exceptions.InvalidTag if the ciphertext has been tampered with.

    Args:
        enc_path: Path to encrypted file.
        key_provider: Key provider instance.

    Returns:
        Plaintext bytes.
    """
    key = key_provider.get_key()
    aesgcm = AESGCM(key)

    data = enc_path.read_bytes()
    if len(data) < _NONCE_SIZE + _TAG_SIZE:
        raise ValueError(f"Encrypted file too short: {enc_path} ({len(data)} bytes)")

    nonce = data[:_NONCE_SIZE]
    ciphertext = data[_NONCE_SIZE:]

    return aesgcm.decrypt(nonce, ciphertext, None)  # Raises InvalidTag if tampered


@contextmanager
def decrypted_temp_file(
    enc_path: Path,
    key_provider: KeyProvider,
    *,
    suffix: str = ".tmp",
) -> Generator[Path, None, None]:
    """
    Context manager: decrypt ``enc_path`` to a secure temporary file.

    The temp file is:
    - Written with mode 0600 (owner read/write only).
    - Deleted on exit, even if an exception occurs.

    Limitation: the temp file is plaintext while the process holds the context.
    Ensure the DuckDB connection is closed WITHIN this context manager.

    Usage:
        with decrypted_temp_file(enc_path, key_provider) as tmp:
            con = duckdb.connect(str(tmp))
            ...
            con.close()  # Must close before context exits

    Args:
        enc_path: Encrypted data file.
        key_provider: Key provider.
        suffix: Temp file suffix.

    Yields:
        Path to the decrypted temporary file.
    """
    plaintext = decrypt_to_bytes(enc_path, key_provider)

    # Create temp file in the same directory as the enc_path for security
    tmp_dir = enc_path.parent
    fd, tmp_path_str = tempfile.mkstemp(suffix=suffix, dir=tmp_dir)
    tmp_path = Path(tmp_path_str)

    try:
        with os.fdopen(fd, "wb") as f:
            f.write(plaintext)
        # Set restrictive permissions (best-effort; no-op on Windows)
        try:
            os.chmod(tmp_path, 0o600)
        except (AttributeError, OSError):
            pass

        logger.debug(f"Decrypted {enc_path} to temp file {tmp_path}")
        yield tmp_path
    finally:
        try:
            tmp_path.unlink(missing_ok=True)
            logger.debug(f"Deleted temp file {tmp_path}")
        except Exception as e:
            logger.error(f"Failed to delete temp file {tmp_path}: {e}")

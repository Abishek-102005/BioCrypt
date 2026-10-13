"""
BioCrypt — Cryptographic Core
AES-256-GCM encryption with scrypt key derivation.
"""
import os
import struct
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend


class DecryptionError(Exception):
    """Raised when decryption fails (wrong key, tampered data, bad format)."""


# ---------------------------------------------------------------------------
# Key derivation
# ---------------------------------------------------------------------------
SCRYPT_N = 2 ** 17   # CPU/memory cost (128 MiB)
SCRYPT_R = 8
SCRYPT_P = 1
SALT_LEN = 32
KEY_LEN  = 32        # 256 bits for AES-256


def derive_key(password: str, salt: bytes) -> bytes:
    """
    Derive a 256-bit key from *password* using scrypt.

    Parameters
    ----------
    password : str
        User-supplied plaintext password.
    salt : bytes
        Cryptographically random 32-byte salt.

    Returns
    -------
    bytes
        32-byte derived key.
    """
    kdf = Scrypt(
        salt=salt,
        length=KEY_LEN,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
        backend=default_backend(),
    )
    return kdf.derive(password.encode("utf-8"))


# ---------------------------------------------------------------------------
# AES-256-GCM helpers
# ---------------------------------------------------------------------------
NONCE_LEN = 12   # 96-bit nonce recommended for GCM


def _make_aad(version: int, kdf_id: int, algo_id: int) -> bytes:
    """Build the authenticated additional data (header bytes)."""
    return struct.pack("BBB", version, kdf_id, algo_id)


def encrypt_bytes(plaintext: bytes, password: str) -> bytes:
    """
    Encrypt *plaintext* with AES-256-GCM using a password-derived key.

    The returned blob is a complete BioCrypt ciphertext that includes all
    metadata needed for decryption.  Use crypto.file_format to pack it.

    Returns
    -------
    bytes
        Raw BioCrypt binary blob (packed by file_format.pack).
    """
    from crypto.file_format import FORMAT_VERSION, KDF_SCRYPT, ALGO_AES256GCM, pack

    salt  = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    key   = derive_key(password, salt)

    aad  = _make_aad(FORMAT_VERSION, KDF_SCRYPT, ALGO_AES256GCM)
    aesgcm = AESGCM(key)
    # AESGCM.encrypt appends the 16-byte tag after the ciphertext
    ct_with_tag = aesgcm.encrypt(nonce, plaintext, aad)

    return pack(
        version   = FORMAT_VERSION,
        kdf_id    = KDF_SCRYPT,
        algo_id   = ALGO_AES256GCM,
        salt      = salt,
        nonce     = nonce,
        ct_with_tag = ct_with_tag,
    )


def decrypt_bytes(blob: bytes, password: str) -> bytes:
    """
    Decrypt a BioCrypt blob produced by *encrypt_bytes*.

    Raises
    ------
    DecryptionError
        On wrong password, tampered data, bad format, or unsupported version.

    Returns
    -------
    bytes
        Original plaintext.
    """
    from crypto.file_format import unpack

    try:
        fields = unpack(blob)
    except ValueError as exc:
        raise DecryptionError(f"Invalid BioCrypt file format: {exc}") from exc

    try:
        key = derive_key(password, fields["salt"])
        aad = _make_aad(fields["version"], fields["kdf_id"], fields["algo_id"])
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(fields["nonce"], fields["ct_with_tag"], aad)
    except Exception as exc:
        # cryptography raises InvalidTag on tampered data / wrong key
        raise DecryptionError("Decryption failed — wrong password or corrupted file.") from exc

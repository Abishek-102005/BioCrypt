"""
BioCrypt — File Encryption / Decryption Service
"""
import os
import io
import re
import tempfile
from pathlib import Path
from werkzeug.utils import secure_filename

from crypto.encryption import encrypt_bytes, decrypt_bytes, DecryptionError


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
_BIOCRYPT_MAGIC = b"BIOCRYPT"
MAX_PLAINTEXT_SIZE = 50 * 1024 * 1024  # 50 MB


def _safe_filename(name: str) -> str:
    """Return a sanitised filename, raising ValueError if invalid."""
    name = secure_filename(name)
    if not name:
        raise ValueError("Invalid or empty filename.")
    return name


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def encrypt_file(file_bytes: bytes, original_name: str, password: str) -> tuple[bytes, str]:
    """
    Encrypt *file_bytes* and return ``(ciphertext_blob, output_filename)``.

    Parameters
    ----------
    file_bytes : bytes
        Raw file content to encrypt.
    original_name : str
        Original filename (used to derive the output name).
    password : str
        User-supplied password.

    Returns
    -------
    (bytes, str)
        The BioCrypt blob and the suggested download filename.

    Raises
    ------
    ValueError
        If the file is too large or the filename is invalid.
    """
    if len(file_bytes) > MAX_PLAINTEXT_SIZE:
        raise ValueError(
            f"File exceeds the {MAX_PLAINTEXT_SIZE // (1024*1024)} MB size limit."
        )

    safe_name = _safe_filename(original_name)
    blob = encrypt_bytes(file_bytes, password)
    out_name = safe_name + ".biocrypt"
    return blob, out_name


def decrypt_file(file_bytes: bytes, original_name: str, password: str) -> tuple[bytes, str]:
    """
    Decrypt a BioCrypt blob and return ``(plaintext_bytes, original_filename)``.

    Parameters
    ----------
    file_bytes : bytes
        Raw content of the `.biocrypt` file.
    original_name : str
        Name of the uploaded `.biocrypt` file.
    password : str
        User-supplied password.

    Returns
    -------
    (bytes, str)
        Decrypted data and the suggested download filename.

    Raises
    ------
    ValueError
        If the file is too large, not a BioCrypt file, or has an invalid name.
    DecryptionError
        If decryption or MAC verification fails.
    """
    if len(file_bytes) > MAX_PLAINTEXT_SIZE + 1024:
        raise ValueError("File is too large to decrypt.")

    safe_name = _safe_filename(original_name)

    # Quick sanity check before the expensive KDF
    if not file_bytes.startswith(_BIOCRYPT_MAGIC):
        raise ValueError("This does not appear to be a valid BioCrypt file.")

    plaintext = decrypt_bytes(file_bytes, password)

    # Strip the .biocrypt extension to restore the original name
    if safe_name.lower().endswith(".biocrypt"):
        out_name = safe_name[: -len(".biocrypt")]
    else:
        out_name = safe_name + ".decrypted"

    return plaintext, out_name

"""
BioCrypt — Folder Encryption / Decryption Service

Folders are packaged into a ZIP archive (in-memory) then encrypted as a single
BioCrypt blob.  On decryption the archive is extracted with path-traversal
protection.
"""
import io
import os
import zipfile
import re
from pathlib import Path, PurePosixPath

from crypto.encryption import encrypt_bytes, decrypt_bytes, DecryptionError

MAX_ARCHIVE_SIZE = 50 * 1024 * 1024  # 50 MB uncompressed


# ---------------------------------------------------------------------------
# Safe ZIP helpers
# ---------------------------------------------------------------------------

def _safe_extract_path(member_name: str, dest_dir: str) -> str:
    """
    Resolve the extraction path for a ZIP member, preventing path traversal.

    Raises
    ------
    ValueError
        If the resolved path escapes *dest_dir*.
    """
    dest = Path(dest_dir).resolve()
    target = (dest / member_name).resolve()
    try:
        target.relative_to(dest)
    except ValueError:
        raise ValueError(
            f"Unsafe ZIP path detected: '{member_name}' would escape the destination."
        )
    return str(target)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def zip_and_encrypt(files: list[tuple[str, bytes]], folder_name: str, password: str) -> tuple[bytes, str]:
    """
    Bundle *files* into a ZIP archive and encrypt it.

    Parameters
    ----------
    files : list of (str, bytes)
        List of (relative_path, file_content) pairs representing the folder.
    folder_name : str
        Name used as the top-level directory inside the ZIP.
    password : str
        User-supplied encryption password.

    Returns
    -------
    (bytes, str)
        BioCrypt blob of the encrypted ZIP and the suggested output filename.

    Raises
    ------
    ValueError
        If the total uncompressed size exceeds the limit.
    """
    buffer = io.BytesIO()
    total_size = 0

    with zipfile.ZipFile(buffer, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        for rel_path, data in files:
            # Clean relative path — no absolute paths or traversal
            clean = re.sub(r"[/\\]", "/", rel_path).lstrip("/")
            if ".." in clean.split("/"):
                raise ValueError(f"Unsafe path in folder: {rel_path!r}")
            arc_name = f"{folder_name}/{clean}"
            total_size += len(data)
            if total_size > MAX_ARCHIVE_SIZE:
                raise ValueError(
                    f"Total folder size exceeds {MAX_ARCHIVE_SIZE // (1024*1024)} MB limit."
                )
            zf.writestr(arc_name, data)

    zip_bytes = buffer.getvalue()
    blob = encrypt_bytes(zip_bytes, password)
    out_name = f"{folder_name}.biocrypt"
    return blob, out_name


def decrypt_and_list(blob: bytes, password: str) -> list[tuple[str, bytes]]:
    """
    Decrypt a BioCrypt blob and return the archived files as a list.

    Parameters
    ----------
    blob : bytes
        Raw BioCrypt file content.
    password : str
        User-supplied decryption password.

    Returns
    -------
    list of (str, bytes)
        Each element is (archive_member_name, file_content).

    Raises
    ------
    DecryptionError
        On wrong password or tampered data.
    ValueError
        If the decrypted bytes are not a valid ZIP archive.
    """
    zip_bytes = decrypt_bytes(blob, password)

    try:
        buffer = io.BytesIO(zip_bytes)
        out = []
        with zipfile.ZipFile(buffer, "r") as zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue
                # Validate member name before reading
                _safe_extract_path(info.filename, "/tmp")  # dummy dest for validation
                out.append((info.filename, zf.read(info.filename)))
        return out
    except zipfile.BadZipFile as exc:
        raise ValueError("Decrypted data is not a valid ZIP archive.") from exc


def decrypt_to_zip(blob: bytes, password: str) -> tuple[bytes, str]:
    """
    Decrypt a BioCrypt folder archive and return the raw ZIP bytes for download.

    Returns
    -------
    (bytes, str)
        Raw ZIP bytes and the suggested .zip filename.
    """
    from crypto.file_format import unpack
    import struct

    zip_bytes = decrypt_bytes(blob, password)

    # Validate it's a ZIP before returning
    try:
        zipfile.ZipFile(io.BytesIO(zip_bytes)).close()
    except zipfile.BadZipFile as exc:
        raise ValueError("Decrypted content is not a valid ZIP archive.") from exc

    return zip_bytes, "decrypted_folder.zip"

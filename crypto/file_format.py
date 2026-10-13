"""
BioCrypt — Binary File Format

Magic bytes : b'BIOCRYPT'  (8 bytes)
Version     : uint8        (1 byte)  — currently 1
KDF id      : uint8        (1 byte)  — 0x01 = scrypt
Algo id     : uint8        (1 byte)  — 0x01 = AES-256-GCM
Salt        : bytes        (32 bytes)
Nonce       : bytes        (12 bytes)
Ciphertext+Tag : bytes     (remainder — includes 16-byte GCM tag appended by cryptography)

Total header size (before ciphertext): 8+1+1+1+32+12 = 55 bytes
All header bytes are included as GCM authenticated additional data (AAD).
"""
import struct

# ---------------------------------------------------------------------------
# Format constants
# ---------------------------------------------------------------------------
MAGIC          = b"BIOCRYPT"   # 8 bytes
FORMAT_VERSION = 0x01
KDF_SCRYPT     = 0x01
ALGO_AES256GCM = 0x01

MAGIC_LEN   = 8
SALT_LEN    = 32
NONCE_LEN   = 12
TAG_LEN     = 16               # GCM authentication tag
MIN_CT_LEN  = TAG_LEN + 1     # at minimum: tag + 1 byte of ciphertext

# Fixed header size that is authenticated as AAD
HEADER_SIZE = MAGIC_LEN + 3 + SALT_LEN + NONCE_LEN   # = 55


# ---------------------------------------------------------------------------
# Pack / unpack helpers
# ---------------------------------------------------------------------------

def pack(
    version: int,
    kdf_id: int,
    algo_id: int,
    salt: bytes,
    nonce: bytes,
    ct_with_tag: bytes,
) -> bytes:
    """Serialise all fields into the BioCrypt binary format."""
    if len(salt) != SALT_LEN:
        raise ValueError(f"Salt must be {SALT_LEN} bytes, got {len(salt)}")
    if len(nonce) != NONCE_LEN:
        raise ValueError(f"Nonce must be {NONCE_LEN} bytes, got {len(nonce)}")
    if len(ct_with_tag) < MIN_CT_LEN:
        raise ValueError(f"Ciphertext+tag too short: {len(ct_with_tag)}")

    header = (
        MAGIC
        + struct.pack("BBB", version, kdf_id, algo_id)
        + salt
        + nonce
    )
    return header + ct_with_tag


def unpack(blob: bytes) -> dict:
    """
    Parse a BioCrypt binary blob.

    Returns a dict with keys:
        version, kdf_id, algo_id, salt, nonce, ct_with_tag

    Raises ValueError on structural errors.
    """
    if len(blob) < HEADER_SIZE + MIN_CT_LEN:
        raise ValueError("Data too short to be a valid BioCrypt file.")

    if blob[:MAGIC_LEN] != MAGIC:
        raise ValueError("Missing BioCrypt magic bytes — not a BioCrypt file.")

    offset = MAGIC_LEN
    version, kdf_id, algo_id = struct.unpack_from("BBB", blob, offset)
    offset += 3

    if version != FORMAT_VERSION:
        raise ValueError(f"Unsupported BioCrypt format version: {version}")

    salt  = blob[offset : offset + SALT_LEN]
    offset += SALT_LEN
    nonce = blob[offset : offset + NONCE_LEN]
    offset += NONCE_LEN
    ct_with_tag = blob[offset:]

    if len(ct_with_tag) < MIN_CT_LEN:
        raise ValueError("Ciphertext segment is too short.")

    return {
        "version"    : version,
        "kdf_id"     : kdf_id,
        "algo_id"    : algo_id,
        "salt"       : salt,
        "nonce"      : nonce,
        "ct_with_tag": ct_with_tag,
    }

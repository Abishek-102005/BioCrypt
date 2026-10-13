"""
BioCrypt — Automated Tests for Cryptography Layer
"""
import os
import sys
import pytest

# Make sure project root is on path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from crypto.encryption import encrypt_bytes, decrypt_bytes, DecryptionError
from crypto.file_format import pack, unpack, MAGIC


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def roundtrip(plaintext: bytes, password: str) -> bytes:
    blob = encrypt_bytes(plaintext, password)
    return decrypt_bytes(blob, password)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestEncryptDecryptRoundtrip:
    def test_small_file(self):
        data = b"Hello, BioCrypt! This is a small test."
        assert roundtrip(data, "P@ssw0rd_123") == data

    def test_empty_file(self):
        assert roundtrip(b"", "P@ssw0rd_123") == b""

    def test_binary_data(self):
        data = bytes(range(256)) * 100
        assert roundtrip(data, "binary_test!") == data

    def test_unicode_content(self):
        data = "BioCrypt 🔐 — Sécurité des fichiers".encode("utf-8")
        assert roundtrip(data, "unicode_pw") == data

    def test_large_file(self):
        data = os.urandom(10 * 1024 * 1024)  # 10 MB
        assert roundtrip(data, "large_file_pw!") == data

    def test_unique_nonces(self):
        """Two encryptions of the same data must produce different ciphertexts."""
        data = b"same data"
        blob1 = encrypt_bytes(data, "pw")
        blob2 = encrypt_bytes(data, "pw")
        assert blob1 != blob2   # different nonces

    def test_unique_salts(self):
        data = b"test"
        b1 = unpack(encrypt_bytes(data, "pw"))
        b2 = unpack(encrypt_bytes(data, "pw"))
        assert b1["salt"] != b2["salt"]


class TestWrongPassword:
    def test_wrong_password_raises(self):
        blob = encrypt_bytes(b"secret", "correct_password")
        with pytest.raises(DecryptionError):
            decrypt_bytes(blob, "wrong_password")

    def test_empty_password_mismatch(self):
        blob = encrypt_bytes(b"data", "real_password")
        with pytest.raises(DecryptionError):
            decrypt_bytes(blob, "")


class TestTampering:
    def test_flipped_bit_in_ciphertext(self):
        blob = bytearray(encrypt_bytes(b"important data", "pw"))
        blob[-5] ^= 0xFF  # flip bits near the end
        with pytest.raises(DecryptionError):
            decrypt_bytes(bytes(blob), "pw")

    def test_truncated_blob(self):
        blob = encrypt_bytes(b"data", "pw")
        with pytest.raises(DecryptionError):
            decrypt_bytes(blob[:30], "pw")

    def test_modified_salt(self):
        blob = bytearray(encrypt_bytes(b"data", "pw"))
        # Salt starts at byte 11 (8 magic + 3 ids)
        blob[11] ^= 0x01
        with pytest.raises(DecryptionError):
            decrypt_bytes(bytes(blob), "pw")

    def test_modified_nonce(self):
        blob = bytearray(encrypt_bytes(b"data", "pw"))
        # Nonce starts at byte 43 (8+3+32)
        blob[43] ^= 0xFF
        with pytest.raises(DecryptionError):
            decrypt_bytes(bytes(blob), "pw")


class TestFileFormat:
    def test_magic_bytes_present(self):
        blob = encrypt_bytes(b"test", "pw")
        assert blob[:8] == MAGIC

    def test_unpack_valid(self):
        blob = encrypt_bytes(b"test", "pw")
        fields = unpack(blob)
        assert "salt" in fields and "nonce" in fields and "ct_with_tag" in fields
        assert len(fields["salt"])  == 32
        assert len(fields["nonce"]) == 12

    def test_invalid_magic(self):
        with pytest.raises(ValueError, match="magic"):
            unpack(b"BADMAGIC" + b"\x01" * 100)

    def test_too_short(self):
        with pytest.raises(ValueError):
            unpack(b"BIOCRYPT\x01\x01\x01")

    def test_wrong_version(self):
        blob = bytearray(encrypt_bytes(b"test", "pw"))
        blob[8] = 0x99  # unsupported version
        with pytest.raises(ValueError, match="version"):
            unpack(bytes(blob))

    def test_not_a_biocrypt_file(self):
        with pytest.raises(DecryptionError):
            decrypt_bytes(b"This is not encrypted data at all!", "pw")


class TestPasswordAuth:
    def test_hash_and_verify(self):
        from auth.password_auth import hash_password, verify_password
        h = hash_password("Str0ng!Pass")
        assert verify_password("Str0ng!Pass", h)

    def test_wrong_password_fails(self):
        from auth.password_auth import hash_password, verify_password
        h = hash_password("correct")
        assert not verify_password("wrong", h)

    def test_hash_not_plaintext(self):
        from auth.password_auth import hash_password
        h = hash_password("mysecret")
        assert "mysecret" not in h


class TestBiometricStub:
    def test_unavailable(self):
        from auth.biometric_auth import is_available
        assert is_available() is False

    def test_reason_not_empty(self):
        from auth.biometric_auth import unavailable_reason
        assert len(unavailable_reason()) > 0

    def test_stubs_raise_not_implemented(self):
        from auth.biometric_auth import begin_registration
        with pytest.raises(NotImplementedError):
            begin_registration(1, "user")


class TestFolderService:
    def test_roundtrip_folder(self):
        from services.folder_service import zip_and_encrypt, decrypt_and_list
        files = [("doc.txt", b"Hello!"), ("sub/img.png", b"\x89PNG")]
        blob, name = zip_and_encrypt(files, "myfolder", "FolderPw1!")
        assert name.endswith(".biocrypt")
        restored = decrypt_and_list(blob, "FolderPw1!")
        content = {n: d for n, d in restored}
        assert content["myfolder/doc.txt"] == b"Hello!"
        assert content["myfolder/sub/img.png"] == b"\x89PNG"

    def test_wrong_password_folder(self):
        from services.folder_service import zip_and_encrypt, decrypt_and_list
        from crypto.encryption import DecryptionError
        files = [("f.txt", b"data")]
        blob, _ = zip_and_encrypt(files, "folder", "right_pw!")
        with pytest.raises(DecryptionError):
            decrypt_and_list(blob, "wrong_pw!")

    def test_unsafe_zip_path_rejected(self):
        from services.folder_service import zip_and_encrypt
        with pytest.raises(ValueError, match="[Uu]nsafe"):
            zip_and_encrypt([("../evil.sh", b"rm -rf /")], "bad", "pw")

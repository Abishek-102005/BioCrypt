"""
BioCrypt — File Service Tests
"""
import sys
import os
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services.file_service import encrypt_file, decrypt_file
from crypto.encryption import DecryptionError


class TestFileService:
    def test_encrypt_decrypt_roundtrip(self):
        data = b"Test file content 12345"
        blob, name = encrypt_file(data, "myfile.txt", "AnyPw!8#")
        assert name == "myfile.txt.biocrypt"
        plain, orig = decrypt_file(blob, name, "AnyPw!8#")
        assert plain == data
        assert orig == "myfile.txt"

    def test_wrong_password(self):
        blob, name = encrypt_file(b"data", "file.txt", "right_pw!")
        with pytest.raises(DecryptionError):
            decrypt_file(blob, name, "wrong_pw!")

    def test_decrypt_non_biocrypt_file(self):
        with pytest.raises(ValueError, match="[Bb]io[Cc]rypt"):
            decrypt_file(b"not encrypted content", "file.biocrypt", "pw")

    def test_empty_file(self):
        blob, _ = encrypt_file(b"", "empty.dat", "pw1234567")
        plain, _ = decrypt_file(blob, "empty.dat.biocrypt", "pw1234567")
        assert plain == b""

    def test_file_too_large(self):
        big = b"x" * (51 * 1024 * 1024)  # 51 MB > 50 MB limit
        with pytest.raises(ValueError, match="size limit"):
            encrypt_file(big, "huge.bin", "pw")

    def test_output_name_strips_biocrypt(self):
        blob, enc_name = encrypt_file(b"hello", "report.pdf", "pw")
        _, dec_name = decrypt_file(blob, enc_name, "pw")
        assert dec_name == "report.pdf"

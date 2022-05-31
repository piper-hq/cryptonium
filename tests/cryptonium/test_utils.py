import filecmp
import secrets
from pathlib import Path

import pytest
from cryptography.fernet import InvalidToken

from cryptonium import utils

TEST_MESSAGES = [
    "can we handle unicode? 👍",
    "This is a very secret message",
    "This is a very long message!" * 30,
]
DATA_PATH = Path(__file__).resolve().parent.joinpath("data/")


@pytest.mark.parametrize("plaintext", TEST_MESSAGES)
def test_symmetric_same_password_decrypts(plaintext):
    password = secrets.token_bytes(nbytes=32)
    crypto_1 = utils.SymmetricCrypto(password)
    crypto_2 = utils.SymmetricCrypto(password)
    ciphertext = crypto_1.encrypts(plaintext)
    assert crypto_2.decrypts(ciphertext) == plaintext


def test_symmetric_wrong_password_fails():
    crypto_1 = utils.SymmetricCrypto(b"password")
    crypto_2 = utils.SymmetricCrypto(b"another_password")
    ciphertext = crypto_1.encrypts("plaintext")
    assert pytest.raises(InvalidToken, crypto_2.decrypts, ciphertext)


def test_symmetric_encrypt_file():
    password = secrets.token_bytes(nbytes=32)
    crypto = utils.SymmetricCrypto(password)

    plaintext_path = DATA_PATH.joinpath("plaintext_file")
    ciphertext_path = DATA_PATH.joinpath("ciphertext_file")
    decrypted_path = DATA_PATH.joinpath("decrypted_file")

    # TODO: [drop py37] use missing_ok=True
    if ciphertext_path.exists():
        ciphertext_path.unlink()
    if decrypted_path.exists():
        decrypted_path.unlink()
    crypto.encrypt(plaintext_path, ciphertext_path)
    crypto.decrypt(ciphertext_path, decrypted_path)
    assert filecmp.cmp(plaintext_path, decrypted_path, shallow=False)
    ciphertext_path.unlink()
    decrypted_path.unlink()


def test_symmetric_encrypt_file_permissions():
    password = secrets.token_bytes(nbytes=32)
    crypto = utils.SymmetricCrypto(password)

    plaintext_path = DATA_PATH.joinpath("plaintext_file")
    missing_path = DATA_PATH.joinpath("missing_path")
    ciphertext_path = DATA_PATH.joinpath("ciphertext_file")
    decrypted_path = DATA_PATH.joinpath("decrypted_file")

    # TODO: [drop py37] use missing_ok=True
    if ciphertext_path.exists():
        ciphertext_path.unlink()
    if decrypted_path.exists():
        decrypted_path.unlink()
    if missing_path.exists():
        missing_path.unlink()
    assert pytest.raises(PermissionError, crypto.encrypt, missing_path, decrypted_path)

    crypto.encrypt(plaintext_path, ciphertext_path)
    assert pytest.raises(
        PermissionError, crypto.encrypt, plaintext_path, ciphertext_path
    )

    crypto.decrypt(ciphertext_path, decrypted_path)
    assert pytest.raises(
        PermissionError, crypto.decrypt, ciphertext_path, decrypted_path
    )
    ciphertext_path.unlink()
    decrypted_path.unlink()

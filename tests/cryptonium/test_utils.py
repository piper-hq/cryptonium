import secrets
from io import BytesIO
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
@pytest.mark.parametrize(
    "crypto_class", [utils.SaltedSymmetricCrypto, utils.SymmetricCrypto]
)
def test_symmetric_same_password_decrypts(crypto_class, plaintext):
    password = secrets.token_bytes(nbytes=32)
    crypto_1 = crypto_class(password)
    crypto_2 = crypto_class(password)
    ciphertext = crypto_1.encrypts(plaintext)
    assert crypto_2.decrypts(ciphertext) == plaintext


@pytest.mark.parametrize("plaintext", TEST_MESSAGES)
@pytest.mark.parametrize(
    "crypto_class", [utils.SaltedSymmetricCrypto, utils.SymmetricCrypto]
)
def test_symmetric_same_password_decrypt_bytes(crypto_class, plaintext):
    password = secrets.token_bytes(nbytes=32)
    crypto_1 = crypto_class(password)
    crypto_2 = crypto_class(password)
    ciphertext = crypto_1.encrypt_bytes(plaintext.encode())
    assert crypto_2.decrypt_bytes(ciphertext) == plaintext.encode()


@pytest.mark.parametrize(
    "crypto_class", [utils.SaltedSymmetricCrypto, utils.SymmetricCrypto]
)
def test_symmetric_wrong_password_fails(crypto_class):
    crypto_1 = crypto_class(b"password")
    crypto_2 = crypto_class(b"another_password")
    ciphertext = crypto_1.encrypts("plaintext")
    assert pytest.raises(InvalidToken, crypto_2.decrypts, ciphertext)


@pytest.mark.parametrize(
    "crypto_class", [utils.SaltedSymmetricCrypto, utils.SymmetricCrypto]
)
def test_symmetric_encrypt_file(crypto_class):
    password = secrets.token_bytes(nbytes=32)
    crypto = crypto_class(password)
    message = b"secret_message"

    ciphertext_path = DATA_PATH.joinpath("ciphertext_file")

    # TODO: [drop py37] use missing_ok=True
    if ciphertext_path.exists():
        ciphertext_path.unlink()
    with open(ciphertext_path, "wb") as target:
        crypto.encrypt(message, target)
    with open(ciphertext_path, "rb") as source:
        decrypted_message = crypto.decrypt(source)
    ciphertext_path.unlink()
    assert decrypted_message == message


@pytest.mark.parametrize(
    "crypto_class", [utils.SaltedSymmetricCrypto, utils.SymmetricCrypto]
)
def test_symmetric_encrypt_inmemory_file(crypto_class):
    password = secrets.token_bytes(nbytes=32)
    crypto = crypto_class(password)
    message = b"secret_message"

    ciphertext_io = BytesIO()

    crypto.encrypt(message, ciphertext_io)
    ciphertext_io.seek(0)
    decrypted_message = crypto.decrypt(ciphertext_io)

    assert decrypted_message == message

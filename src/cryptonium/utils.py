import base64
import os
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

LATEST_PROTOCOL = b"v1"


@dataclass
class KDFConfig:
    salt_length: int
    key_length: int
    iterations: int
    hash_function: hashes.HashAlgorithm
    backend: Any


class Crypto:
    @staticmethod
    def _check_permissions(source: Path, target: Path) -> None:
        source = source.absolute()
        if not os.access(source, os.R_OK):
            raise PermissionError(f"{source} is not readable")
        target = target.absolute()
        if not os.access(target.parent, os.W_OK, dir_fd=True):
            raise PermissionError(f"{target} is not writeable")
        if target.exists():
            raise PermissionError(f"{target} already exists")

    def _encrypt(self, plaintext: bytes) -> bytes:
        raise NotImplementedError(
            f"{self.__class__.__name__} must implement an encrypt method."
        )

    def _decrypt(self, ciphertext: bytes) -> bytes:
        raise NotImplementedError(
            f"{self.__class__.__name__} must implement a decrypt method."
        )

    def encrypts(self, plaintext: str) -> str:
        ciphertext = self._encrypt(plaintext.encode())
        return base64.b16encode(ciphertext).decode()

    def decrypts(self, ciphertext: str) -> str:
        decoded_ciphertext = base64.b16decode(ciphertext.encode())
        plaintext = self._decrypt(decoded_ciphertext)
        return plaintext.decode()

    def encrypt(self, plaintext_path: Path, ciphertext_path: Path) -> None:
        self._check_permissions(plaintext_path, ciphertext_path)
        with open(plaintext_path, "rb") as source:
            data = source.read()
        encrypted_data = self._encrypt(data)
        with open(ciphertext_path, "wb") as target:
            target.write(encrypted_data)

    def decrypt(self, ciphertext_path: Path, plaintext_path: Path) -> None:
        self._check_permissions(ciphertext_path, plaintext_path)
        with open(ciphertext_path, "rb") as source:
            encrypted_data = source.read()
        data = self._decrypt(encrypted_data)
        with open(plaintext_path, "wb") as target:
            target.write(data)


class SymmetricCrypto(Crypto):
    def __init__(self, password: bytes) -> None:
        self.password = password
        self.version = LATEST_PROTOCOL

    @staticmethod
    def _get_config(version: bytes) -> KDFConfig:
        if version == b"v1":
            return KDFConfig(
                salt_length=16,
                key_length=32,
                iterations=1_000_000,
                hash_function=hashes.SHA256(),
                backend=default_backend(),
            )

        raise ValueError("Unsupported protocol version")

    def _derive_key(self, salt: bytes, version: bytes = None) -> bytes:
        kdf_config = self._get_config(version or self.version)

        kdf = PBKDF2HMAC(
            algorithm=kdf_config.hash_function,
            length=kdf_config.key_length,
            salt=salt,
            iterations=kdf_config.iterations,
            backend=kdf_config.backend,
        )
        return base64.urlsafe_b64encode(kdf.derive(self.password))

    def _encrypt(self, plaintext: bytes) -> bytes:
        config = self._get_config(self.version)
        salt = secrets.token_bytes(nbytes=config.salt_length)
        key = self._derive_key(salt)
        fernet = Fernet(key)
        encrypted = fernet.encrypt(plaintext)
        return b"v1::" + salt + encrypted

    def _decrypt(self, ciphertext: bytes) -> bytes:
        version, ciphertext = ciphertext.split(b"::", 1)
        kdf_config = self._get_config(version)
        salt = ciphertext[: kdf_config.salt_length]
        encrypted_message = ciphertext[kdf_config.salt_length :]
        key = self._derive_key(salt, version=version)
        fernet = Fernet(key)
        return fernet.decrypt(encrypted_message)

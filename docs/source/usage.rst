=====
Usage
=====

``cryptonium`` offers an easy interface to encrypt/decrypt strings and files.

.. py:module:: utils

Currently there is only the utils module, containing a single class
symmetrically encrypt/decrypt the plaintext.

.. py:class:: SymmetricCrypto

    A symmetric crypto class, based on Fernet

    .. py:method:: encrypt_bytes(self, plaintext: bytes) -> bytes

       Encrypt bytes

    .. py:method:: decrypt_bytes(self, ciphertext: bytes) -> bytes

       Decrypt bytes, that were encrypted by this class

    .. py:method:: encrypts(self, plaintext: str) -> str

       Encrypt a string

    .. py:method:: decrypts(self, ciphertext: str) -> str

       Decrypt a string, that was encrypted by this class

    .. py:method:: encrypt(self, plaintext: bytes, ciphertext: BinaryIO) -> None

       Encrypt a file

    .. py:method:: decrypt(self, ciphertext: BinaryIO) -> bytes

       Decrypt a file

Worked example
--------------

The recommended way to use it in a django project is to add the following lines
near the top of the settings file:

.. code-block:: python

    from cryptonium import SymmetricCrypto

    password = b"<a_secure_password_as_bytes>"
    crypto = utils.SymmetricCrypto(password)

    # encrypt a string
    ciphertext = crypto.encrypts("secret message")

    # decrypt the ciphertext
    plaintext = crypto.decrypts(ciphertext)

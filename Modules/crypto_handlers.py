# pylint: disable=E0401
""" Built-in module """
import binascii
import logging
import sys
from socket import socket
# External modules #
from cryptography.exceptions import InvalidKey, InvalidTag
from cryptography.hazmat.primitives.ciphers import algorithms, Cipher
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
# Custom modules #
from Modules.utils import print_err


def aesccm_decrypt(aes_key: bytes, aes_nonce: bytes, fernet_key: bytes, sesh_pass: str,
                   connection: socket) -> bytes:
    """
    Decrypts the symmetrical fernet key used for encrypting and decrypting transfer data.

    :param aes_key:  The key for initializing the aesccm algo instance.
    :param aes_nonce:  The nonce associated with aesccm decryption.
    :param fernet_key:  The encrypted symmetrical fernet key to be decrypted.
    :param sesh_pass:  The session password used as the final piece in the decryption process.
    :param connection:  Remote socket connection for sending failed status on error.
    :return:  The decrypted symmetrical fernet key.
    """
    try:
        # Initialize the AESCCM algo instance #
        aesccm = AESCCM(aes_key)
        # Decrypt the encrypted symmetrical key with authenticated password #
        symm_key = aesccm.decrypt(aes_nonce, fernet_key, sesh_pass.encode())

    # If error occurs during the AESCCM algo instance initialization or fernet key decryption #
    except (InvalidKey, InvalidTag, ValueError) as decrypt_err:
        # Send operation failure status upon failure #
        connection.sendall(b'False')
        # Print error, log, and exit program #
        print_err('Error occurred decrypting the retrieved session symmetrical key')
        logging.error('Error occurred decrypting the retrieved session symmetrical key: %s\n\n',
                      decrypt_err)
        sys.exit(8)

    return symm_key


def aesccm_encrypt(aes_key: bytes, aes_nonce: bytes, fernet_key: bytes, sesh_pass: str,
                   connection: socket) -> bytes:
    """
    Encrypts the symmetrical fernet key used for encrypting and decrypting transfer data.

    :param aes_key:  The key for initializing the aesccm algo instance.
    :param aes_nonce:  The nonce associated with aesccm decryption.
    :param fernet_key:  The encrypted symmetrical fernet key to be decrypted.
    :param sesh_pass:  The session password used as the final piece in the decryption process.
    :param connection:  Remote socket connection for sending failed status on error.
    :return:  The decrypted symmetrical fernet key.
    """
    try:
        # Initialize the AESCCM algo instance #
        aesccm = AESCCM(aes_key)
        # Encrypt the symmetrical key with aessccm password encryption #
        crypt_key = aesccm.encrypt(aes_nonce, fernet_key, sesh_pass.encode())

    # If error occurs during symmetrical key encryption process #
    except (InvalidKey, InvalidTag, ValueError) as encrypt_err:
        # Send data indicating operation failed #
        connection.sendall(b'False')
        # Print error, log, and exit #
        print_err('Error occurred during symmetrical key encryption process')
        logging.error('Error occurred during symmetrical key encryption process: %s\n\n',
                      encrypt_err)
        sys.exit(10)

    return crypt_key


def chacha_decrypt(cha_algo: Cipher, data: bytes) -> bytes:
    """
    Utilizes the passed in ChaCha20 key to decrypt the passed in data in a error handled manner.

    :param cha_algo:  The ChaCha20 algorithm instance used for decryption.
    :param data:  The encrypted text data to be decrypted and returned.
    :return:  The decrypted text data in byte format.
    """
    try:
        # Set the algo instance to decryptor and decrypt #
        decryptor = cha_algo.decryptor()
        plain_data = decryptor.update(data)

    # If error occurs during ChaCha20 decryption process #
    except (binascii.Error, TypeError, ValueError) as decrypt_err:
        # Print error, log, and exit #
        print_err('Error occurring the decryption process of incoming data')
        logging.error('Error occurring the decryption process of incoming data: '
                      '%s\n\n', decrypt_err)
        sys.exit(13)

    return plain_data


def chacha_encrypt(cha_algo: Cipher, plain_data: bytes) -> bytes:
    """
    Utilizes the passed in ChaCha20 key to encrypt the passed in data in a error handled manner.

    :param cha_algo:  The ChaCha20 algo instance.
    :param plain_data:  The plain text data to be encrypted and returned.
    :return:  The encrypted plain text data that was passed in.
    """
    try:
        # Set the algo instance to encryptor and encrypt it #
        encryptor = cha_algo.encryptor()
        crypt_item = encryptor.update(plain_data)

    # If error occurs during fernet encryption process #
    except (binascii.Error, TypeError, ValueError) as encrypt_err:
        # Print error, log, and exit #
        print_err('Error occurred encrypting data chunk for transit')
        logging.error('Error occurred encrypting data chunk for transit: %s\n\n', encrypt_err)
        sys.exit(12)

    return crypt_item


def cha_init(key: bytes, nonce: bytes) -> Cipher:
    """
    Initializes the ChaCh20 algorithm object.

    :param key:  ChaCha20 key.
    :param nonce:  ChaCha20 nonce.
    :return:  Initialized ChaCha20 cipher instance.
    """
    # Initialize ChaCha20 encryption algo #
    algo = algorithms.ChaCha20(key, nonce)
    # Return the initialized ChaCha20 cipher object #
    return Cipher(algo, mode=None)

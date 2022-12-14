# pylint: disable=E0401
""" Built-in module """
import base64
import binascii
import logging
import socket
import sys
# External modules #
from cryptography.exceptions import InvalidKey, InvalidTag
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
# Custom modules #
from Modules.utils import print_err


def aesccm_decrypt(aes_key: bytes, aes_nonce: bytes, fernet_key: bytes, sesh_pass: str,
                   connection: socket.socket) -> bytes:
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
                   connection: socket.socket) -> bytes:
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
    except (InvalidTag, ValueError) as encrypt_err:
        # Send data indicating operation failed #
        connection.sendall(b'False')
        # Print error, log, and exit #
        print_err('Error occurred during symmetrical key encryption process')
        logging.error('Error occurred during symmetrical key encryption process: %s\n\n',
                      encrypt_err)
        sys.exit(10)

    return crypt_key


def fernet_decrypt(fernet_key: bytes, data: bytes) -> bytes:
    """
    Utilizes the passed in fernet key to decrypt the passed in data in a error handled manner.

    :param fernet_key:  The fernet symmetrical encryption key.
    :param data:  The encrypted text data to be decrypted and returned.
    :return:  The decrypted text data in byte format.
    """
    try:
        # Decrypt each item in parsed_inputs per iteration #
        base64_data = Fernet(fernet_key).decrypt(data)
        # Decode the decrypted data back to readable format #
        plain_data = base64.b64decode(base64_data)

    # If error occurs during fernet decryption process #
    except (binascii.Error, InvalidKey, InvalidToken, TypeError, ValueError) as decrypt_err:
        # Print error, log, and exit #
        print_err('Error occurring the fernet decryption process of incoming data')
        logging.error('Error occurring the fernet decryption process of incoming data: %s\n\n',
                      decrypt_err)
        sys.exit(13)

    return plain_data


def fernet_encrypt(fernet_key: bytes, plain_data: bytes) -> bytes:
    """
    Utilizes the passed in fernet key to encrypt the passed in data in a error handled manner.

    :param fernet_key:  The fernet symmetrical encryption key.
    :param plain_data:  The plain text data to be encrypted and returned.
    :return:  The encrypted plain text data that was passed in.
    """
    try:
        # Encode the data in base64 to prevent parsing errors during decryption #
        base64_data = base64.b64encode(plain_data)
        # Encrypt chunk before sending #
        crypt_item = Fernet(fernet_key).encrypt(base64_data)

    # If error occurs during fernet encryption process #
    except (binascii.Error, InvalidKey, InvalidToken, TypeError, ValueError) as encrypt_err:
        # Print error, log, and exit #
        print_err('Error occurred encrypting data chunk for transit')
        logging.error('Error occurred encrypting data chunk for transit: %s\n\n', encrypt_err)
        sys.exit(12)

    return crypt_item

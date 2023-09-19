# pylint: disable=E0401
""" Built-in module """
import logging
import sys
from socket import socket
# External modules #
from cryptography.exceptions import InvalidKey, InvalidTag, InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes, hmac
# Custom modules #
from Modules.utils import print_err


def authenticated_decrypt(aes_key: bytes, aes_nonce: bytes, crypt_symm: bytes, sesh_pass: str,
                          connection: socket) -> bytes:
    """
    Decrypts the symmetrical AESGCM key used for encrypting and decrypting transfer data.

    :param aes_key:  The key for initializing the AESGCM algo instance.
    :param aes_nonce:  The nonce associated with AESGCM decryption.
    :param crypt_symm:  The encrypted symmetrical fernet key to be decrypted.
    :param sesh_pass:  The session password used as the final piece in the decryption process.
    :param connection:  Remote socket connection for sending failed status on error.
    :return:  The decrypted symmetrical fernet key.
    """
    try:
        # Initialize the AESGCM algo instance #
        aesgcm = AESGCM(aes_key)
        # Decrypt the encrypted symmetrical key with authenticated password #
        symm_key = aesgcm.decrypt(aes_nonce, crypt_symm, sesh_pass.encode())

    # If error occurs during the AESGCM algo instance initialization or fernet key decryption #
    except (InvalidKey, InvalidTag, ValueError) as decrypt_err:
        # Send operation failure status upon failure #
        connection.sendall(b'False')
        # Print error, log, and exit program #
        print_err('Error occurred decrypting the retrieved session symmetrical key')
        logging.error('Error occurred decrypting the retrieved session symmetrical key: %s\n\n',
                      decrypt_err)
        sys.exit(8)

    return symm_key


def authenticated_encrypt(aes_key: bytes, aes_nonce: bytes, symm_key: bytes, sesh_pass: str,
                          connection: socket) -> bytes:
    """
    Encrypts the symmetrical AESGCM used for encrypting and decrypting transfer data.

    :param aes_key:  The key for initializing the AESGCM algo instance.
    :param aes_nonce:  The nonce associated with AESGCM decryption.
    :param symm_key:  The encrypted symmetrical fernet key to be decrypted.
    :param sesh_pass:  The session password used as the final piece in the decryption process.
    :param connection:  Remote socket connection for sending failed status on error.
    :return:  The decrypted symmetrical fernet key.
    """
    try:
        # Initialize the AESGCM algo instance #
        aesgcm = AESGCM(aes_key)
        # Encrypt the symmetrical key with AESGCM password encryption #
        crypt_key = aesgcm.encrypt(aes_nonce, symm_key, sesh_pass.encode())

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


def symm_decrypt(symm_key: bytes, symm_nonce: bytes, hmac_key: bytes, data: bytes) -> bytes:
    """
    Verifies the HMAC signature with associated data and decrypts encrypted data to plain text.

    :param symm_key:  The symmetrical AESGCM key.
    :param symm_nonce:  The symmetrical AESGCM nonce.
    :param hmac_key:  The HMAC signature key.
    :param data:  The data to verified and decrypted.
    :return:  The decrypted received data.
    """
    try:
        # Shave the 32 byte HMAC from the end of the data #
        signature = data[-32:]
        # Save the rest of the data in var #
        crypt_data = data[:-32]
        # Intialize the HMAC algo instance #
        hmac_algo = hmac.HMAC(hmac_key, hashes.SHA256())
        # Update instance with HMAC data to be verified #
        hmac_algo.update(crypt_data)
        # Verifty the data integrity #
        hmac_algo.verify(signature)

        # Initialize AESGCM algo instance #
        aesgcm = AESGCM(symm_key)
        # Decrypt the data with aesgcm symmetrical encryption #
        plain_data = aesgcm.decrypt(symm_nonce, crypt_data, None)

    # If error occurs during symmetrical process #
    except (IndexError, InvalidKey, InvalidTag, InvalidSignature, TypeError, UnsupportedAlgorithm,
            ValueError) as decrypt_err:
        # Print error, log, and exit #
        print_err('Error occurring the decryption process of incoming data')
        logging.error('Error occurring the decryption process of incoming data: %s\n\n',
                      decrypt_err)
        sys.exit(13)

    return plain_data


def symm_encrypt(symm_key: bytes, symm_nonce: bytes, hmac_key: bytes, plain_data: bytes) -> tuple:
    """
    Encrypts the plain text data to be sent with AESGCM and creates HMAC verification signature.

    :param symm_key:  The symmetrical AESGCM encryption key.
    :param symm_nonce:  The symmetrical AESGCM nonce.
    :param hmac_key:  The HMAC signature key.
    :param plain_data:  The plain data to be encrypted and signed.
    :return:  The encrypted data and HMAC signature to be sent.
    """
    try:
        # Initialize AESGCM algo instance #
        aesgcm = AESGCM(symm_key)
        # Encrypt the data to be sent #
        crypt_item = aesgcm.encrypt(symm_nonce, plain_data, None)

        # Initialize the HMAC algo instance #
        hmac_algo = hmac.HMAC(hmac_key, hashes.SHA256())
        # Update HMAC instance with data to be signed #
        hmac_algo.update(crypt_item)
        # Get HMAC signature from data #
        signature = hmac_algo.finalize()

    # If error occurs during symmetrical encryption process #
    except (InvalidKey, InvalidTag, InvalidSignature, TypeError, UnsupportedAlgorithm,
            ValueError) as encrypt_err:
        # Print error, log, and exit #
        print_err('Error occurred encrypting data chunk for transit')
        logging.error('Error occurred encrypting data chunk for transit: %s\n\n', encrypt_err)
        sys.exit(12)

    return crypt_item, signature

# pylint: disable=E0401
""" Built-in modules """
import logging
import os
import socket
import time
import sys
# External modules #
from argon2 import PasswordHasher
from argon2.exceptions import HashingError, InvalidHash, VerifyMismatchError
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
# Custom modules #
from Modules.crypto_handlers import authenticated_decrypt, authenticated_encrypt
from Modules.utils import pass_input, print_err, split_handler


def client_init(target_ip: str, port: int) -> tuple:
    """
    Function is called after test socket connection attempt is successful indicating a server is
    already established on the other end. After gathering session password from user, the final
    socket connection is re-setup and continually attempted on five second intervals until
    successful. Once connected, the input password is hashed and send to the remote system for
    authentication. If successfully authenticated, an encrypted symmetrical key is sent back and
    decrypted using the authenticated password to be returned to main.

    :param target_ip:  The target IP to connect to as string.
    :param port:  The TCP port which the network socket will be established.
    :return:  The established client network socket instance and the ChaCha20 algo instance.
    """
    # Get the session password from the user #
    session_pass = pass_input()

    # Set socket connection timeout #
    socket.setdefaulttimeout(None)
    # Initialize the TCP socket instance #
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    print(f'[+] Attempting to connect to {target_ip} on {port}')

    # While the connection attempt return code is not 0 (successful) #
    while True:
        # Attempt connection on remote port #
        res = sock.connect_ex((target_ip, port))
        # If the connection attempt was not successful #
        if res != 0:
            print('[*] Connection failed .. sleeping 5 seconds and retrying')
            # Sleep program for 5 seconds and re-iterate loop #
            time.sleep(5)
            continue

        break

    print(f'[!] Connection established to {target_ip}:{port}')

    # Initialize hash verifying instance #
    argon_instance = PasswordHasher()
    try:
        # Argon2 hash the users input password #
        hash_pass = argon_instance.hash(session_pass)

    # If error occurs during Argon2 hashing #
    except HashingError as hash_err:
        print_err('Error occurred hashing password to send for validation')
        logging.error('Error occurred hashing password to send for validation: %s\n\n', hash_err)
        sys.exit(6)

    # Send the hashed password to the server to be verified #
    sock.sendall(hash_pass.encode())

    # Wait till data is received back from the server #
    data = sock.recv(256)
    # If the returned data indicates authentication failure #
    if data == b'False':
        # Print error and exit #
        print_err('Input password failed to authenticate on remote host .. both ends will have to '
                  'restart the program to work properly')
        sys.exit(6)

    # Split the received bytes based on <$> divisor #
    keys = split_handler(data, sock)
    # Split keys in memory as bytes #
    auth_key = keys[0]
    auth__nonce = keys[1]
    crypt_key = keys[2]
    crypt_nonce = keys[3]
    crypt_hmac = keys[4]

    # Decrypt the session symmetrical key, nonce, and HMAC #
    symm_key = authenticated_decrypt(auth_key, auth__nonce, crypt_key, session_pass, sock)
    symm_nonce = authenticated_decrypt(auth_key, auth__nonce, crypt_nonce, session_pass, sock)
    hmac_key = authenticated_decrypt(auth_key, auth__nonce, crypt_hmac, session_pass, sock)

    # Send operation success status to server upon completion #
    sock.sendall(b'True')
    # Set socket to non-blocking #
    sock.setblocking(False)
    time.sleep(0.5)

    print('[!] Password verified and keys have been sent .. data transmission through the network '
          'is now permitted\n')

    return sock, symm_key, symm_nonce, hmac_key


def port_check(ip_addr: str, port: int) -> bool:
    """
    Creates TCP socket and checks to see if remote port on specified IP address is active.

    :param ip_addr:  The IP address of the remote host to connect to.
    :param port:  The port of the remote host to connect to.
    :return:  The True/False boolean value depending on operation success/failure.
    """
    # Set socket connection timeout #
    socket.setdefaulttimeout(1)
    # Create test TCP socket #
    test_conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Attempt connection on remote port with test socket #
    test_res = test_conn.connect_ex((ip_addr, port))
    # Terminate test socket #
    test_conn.close()

    # If connect operation was not successful #
    if not test_res == 0:
        return False

    # If connection operation was successful #
    return True


def server_init(port: int) -> tuple:
    """
    Function is called after test socket connection attempt is not successful indicating a server
    is current not present on the other end. After gathering the session password, the hostname is
    queried and used to get the IP address used to bind to the port. The server then waits for the
    incoming test connection, which when connected, null bytes are continually sent until an error
    is raised to the client side timing out. The raised error is ignored and execution is passed to
    wait for the final incoming connection. Once established, the server end waits for the clients
    hashed password to arrive and verifies it through hashing algorithm. If successful, a key set
    is generated and encrypted with the session password and sent back to the client. Finally, the
    server waits to receive a confirmation status message to ensure the key was received and
    decrypted.

    :param port:  The TCP port which the network socket will be established.
    :return:  The connected network socket client instance and ChaCha20 algo instance.
    """
    # Get the session password from the user #
    session_pass = pass_input()
    # Get the system hostname #
    hostname = socket.gethostname()

    # If the OS is Windows #
    if os.name == 'nt':
        # Use the hostname to get the IP Address #
        ip_addr = socket.gethostbyname(hostname)
    # If the OS is Linux #
    else:
        # Open network for Linux for now due
        # to gethostname() inconsistency #
        ip_addr = '0.0.0.0'

    # Set socket connection timeout #
    socket.setdefaulttimeout(None)
    # Initialize the TCP socket instance #
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Bind socket to server local IP and port #
    sock.bind((ip_addr, port))
    # Allow a single incoming socket connection #
    sock.listen(1)
    # Notify user host is acting as server #
    print(f'[+] No remote server present .. serving on ({hostname}||{ip_addr}):{port}')
    # Wait until test connection is received from client socket #
    test_sock, _ = sock.accept()

    try:
        # Once test connection is active, continually send null bytes
        # till an error is raised due to the connection closing #
        while True:
            test_sock.sendall(b'\x00')

    # When error is raised because client side is closed #
    except socket.error:
        pass

    # Wait to accept final connection #
    client_sock, address = sock.accept()

    print(f'[!] Connection established to {address[0]}:{port}')

    # Wait for salted hashed input to be sent #
    recv_hash = client_sock.recv(128)
    # Initialize hash verifying instance #
    argon2_instance = PasswordHasher()

    try:
        # Verify the received argon2 hash against the locally created hash to confirm session #
        argon2_instance.verify(recv_hash, session_pass)

    # If the received password and locally generated do not match #
    except (InvalidHash, VerifyMismatchError):
        # Send data indicating operation failed #
        client_sock.sendall(b'False')
        # Print error and exit #
        print_err('The received password hash does not match supplied password .. closing '
                  'connection')
        sys.exit(9)

    # Generate AESGCM authenticated components for encrypting symmetrical key #
    auth_key = AESGCM.generate_key(bit_length=256)
    auth_nonce = os.urandom(96 // 8)
    # Generate AESGCM components that will act as symmetrical key #
    symm_key = AESGCM.generate_key(bit_length=256)
    symm_nonce = os.urandom(96 // 8)
    # Generate HMAC signature for symmetrical data integrity #
    hmac_key = os.urandom(256//8)

    # Encrypt the session symmetrical key, nonce, and hmac for transit #
    crypt_key = authenticated_encrypt(auth_key, auth_nonce, symm_key, session_pass, sock)
    crypt_nonce = authenticated_encrypt(auth_key, auth_nonce, symm_nonce, session_pass, sock)
    crypt_hmac = authenticated_encrypt(auth_key, auth_nonce, hmac_key, session_pass, sock)

    # Parse the authenticated components and encrypted symmetrical
    # key, nonce, & HMAC for transit to client #
    key_bytes = b''.join([auth_key, b'<$>', auth_nonce, b'<$>', crypt_key, b'<$>', crypt_nonce,
                          b'<$>', crypt_hmac])
    # Send the parsed bytes with keys to client #
    client_sock.sendall(key_bytes)

    # Wait for response to ensure key was decrypted #
    data = client_sock.recv(8)
    # If received status indicates failure #
    if data == b'False':
        # Print error, log, and exit #
        print_err('Error occurred parsing and decrypting the send symmetrical key')
        logging.error('Error occurred parsing and decrypting the send symmetrical key\n')
        sys.exit(11)

    # Set the socket to non-blocking #
    client_sock.setblocking(False)

    print('[!] Password verified and keys have been sent .. data transmission through the network '
          'is now permitted\n')

    return client_sock, symm_key, symm_nonce, hmac_key

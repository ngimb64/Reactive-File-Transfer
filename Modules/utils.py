""" Built-in modules """
import errno
import logging
import os
import pathlib
import re
import socket
import sys
import time
import typing
from getpass import getpass
# External modules #
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from cryptography.exceptions import InvalidKey, InvalidTag
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers.aead import AESCCM


def chunk_bytes(bytes_string: bytes, length: int) -> typing.Generator:
    """
    Generator to split the bytes string passed in by the chunk length passed in it should be split
    into.

    :param bytes_string:  The bytes string to be split into chunks specified by the length.
    :param length:  How long each chunk of data should be.
    :return:  The byte parsing generator.
    """
    return (bytes_string[0+i:length+i] for i in range(0, len(bytes_string), length))


def client_init(target_ip: str, port: int) -> tuple:
    """
    Function is called after test socket connection attempt is successful indicating a server is
    already established on the other end. A final socket connection is re-setup and continually
    attempted on five second intervals until successful, set to non-blocking, and returned to the
    main thread.

    :param target_ip:  The target IP to connect to as string.
    :param port:  The TCP port which the network socket will be established.
    :return:  The established client network socket instance and symmetrical cryptographic key.
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

    print(f'[!] Connection established to {target_ip}:{port}\n')

    # Initialize hash verifying instance #
    argon_instance = PasswordHasher()
    # Argon2 hash the users input password #
    hash_pass = argon_instance.hash(session_pass)
    # Send the hashed password to the server to be verified #
    sock.sendall(hash_pass)

    # Wait till data is received back from the server #
    data = sock.recv(1024)
    # If the returned data indicates authentication failure #
    if data == b'False':
        # Print error and exit #
        print_err('Input password failed to authenticate on remote host .. both ends will have to '
                  'restart the program to work properly')
        sys.exit(6)

    # Split the three keys by divisor #
    keys = data.decode().split('<$>')
    # Split keys in memory as bytes #
    aesccm_key = keys[0].encode()
    nonce = keys[1].encode()
    fern_key = keys[2].encode()

    try:
        # Initialize the AESCCM algo instance #
        aesccm = AESCCM(aesccm_key)
        # Decrypt the encrypted symmetrical key with authenticated password #
        symm_key = aesccm.decrypt(nonce, fern_key, session_pass)

    # If error occurs during the AESCCM algo instance initialization or fernet key decryption #
    except (InvalidKey, InvalidTag, ValueError) as decrypt_err:
        # Send operation failure status upon failure #
        sock.sendall(b'False')
        # Print error, log, and exit program #
        print_err('Error occurred decrypting the retrieved session symmetrical key')
        logging.error('Error occurred decrypting the retrieved session symmetrical key: %s\n\n',
                      decrypt_err)
        sys.exit(7)

    # Send operation success status to server upon completion #
    sock.sendall(b'True')
    time.sleep(1)
    # Set socket to non-blocking #
    sock.setblocking(False)

    return sock, symm_key


def error_query(err_path: str, err_mode: str, err_obj):
    """
    Looks up the errno message to get description.

    :param err_path:  The path to file where the file operation occurred.
    :param err_mode:  The file mode during the error.
    :param err_obj:  The error message instance.
    :return:  Nothing
    """
    # If file does not exist #
    if err_obj.errno == errno.ENOENT:
        logging.error('%s does not exist\n\n', err_path)

    # If the file does not have read/write access #
    elif err_obj.errno == errno.EPERM:
        logging.error('%s does not have permissions for %s file mode\n\n', err_path, err_mode)

    # File IO error occurred #
    elif err_obj.errno == errno.EIO:
        logging.error('IO error occurred during %s mode on %s\n\n', err_mode, err_path)

    # If other unexpected file operation occurs #
    else:
        logging.error('Unexpected file operation occurred accessing %s: %s\n\n', err_path,
                      err_obj.errno)


def int_convert(str_int: str) -> int:
    """
    Convert the passed in size as string to int, handles errors accordingly.

    :param str_int:  The integer passed in string format.
    :return:  The converted integer in its original form.
    """
    try:
        # Convert file size to integer #
        raw_int = int(str_int)

    # If value can not be converted to int (not string) #
    except ValueError as val_err:
        logging.error('Error converting file size to integer %s\n\n', val_err)
        sys.exit(13)

    return raw_int


def parse_start_bytes(data_chunk: bytes, divider: bytes) -> tuple:
    """
    Takes the input data chunk containing file name and size to be transferred with divider in the
    middle.

    :param data_chunk:  Data chunk containing divider to split file name and size.
    :param divider:  The divider used to split the file name and size.
    :return:  The parsed file name and size as tuple grouping.
    """
    # Parse the file name and size from the initial string with <$> divider #
    name, size = data_chunk.split(divider)
    # Strip any extra path from file name #
    name = os.path.basename(name.decode())
    # Convert the file size to integer #
    size = int_convert(size.decode())

    return name, size


def pass_input() -> str:
    """
    Gathers user input for session password and second password input for verification.

    :return:  The validated session password.
    """
    while True:
        # Get the session password from the user #
        session_pass = getpass('[+] Enter reactive file transfer session password: ')
        session_pass2 = getpass('[+] Re-enter reactive file transfer session password to verify: ')

        # If the supplied password and verification password are not equal #
        if session_pass != session_pass2:
            print_err('Unable to use session password due to mismatch .. try again making sure '
                      'they are the same')
            continue

        break

    return session_pass


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


def print_err(msg: str):
    """
    Displays error via stderr.

    :param msg:  The error message to be displayed.
    :return:  Nothing.
    """
    print(f'\n* [ERROR] {msg} *\n', file=sys.stderr)


def secure_delete(path: pathlib.Path, passes=10):
    """
    Overwrite file data with random data number of specified passes and overwrite with random data.

    :param path:  Path to the file to be overwritten and deleted.
    :param passes:  Number of pass to perform random data overwrite.
    :return:  Nothing
    """
    # Get the file size in bytes #
    length = path.stat().st_size
    count, seconds = 0, 1

    while True:
        try:
            # Open file and overwrite the data for number of passes #
            with path.open('wb') as file:
                # Iterator number of passes to overwrite with
                # random data desired number of times #
                for _ in range(passes):
                    # Point file pointer to start of file #
                    file.seek(0)
                    # Write random data #
                    file.write(os.urandom(length))

            # Unlink (delete) file from file system #
            os.remove(path)
            break

        # If error occurs during file operation #
        except (IOError, OSError) as delete_err:
            # If attempts maxed #
            if count == 3:
                # Log error and break out of loop to attempt to delete file #
                logging.error('Three consecutive errors occurred file data scrub operation at %s:'
                              ' %s\n\n', str(path), delete_err)
                sys.exit(14)

            # Increase count, sleep, and increase sleep interval by 1 #
            count += 1
            time.sleep(seconds)
            seconds += 1
            continue


def server_init(port: int) -> tuple:
    """
    Function is called after test socket connection attempt is not successful indicating a server
    is current not present on the other end. The hostname is queried, then used to get the IP
    address; which is used to bind to the port set in the header of the file. The server then waits
    for the incoming test connection, which when connected, null bytes are continually sent until an
    error is raised to the client side timing out. The raised error is ignored and execution is
    passed to wait for the final incoming connection. Once established, the client socket is set to
    non-blocking and returned to the main thread.

    :param port:  The TCP port which the network socket will be established.
    :return:  The connected network socket client instance and symmetrical cryptographic key.
    """
    # Get the session password from the user #
    session_pass = pass_input()

    # If the OS is Windows #
    if os.name == 'nt':
        # Get the system hostname #
        hostname = socket.gethostname()
    # If the OS is Linux #
    else:
        # TODO: switch out with code that runs ifconfig and uses attempts to use the local ip in the
        #       same address class for port binding
        hostname = socket.gethostname()

    # Use the hostname to get the IP Address #
    ip_addr = socket.gethostbyname(hostname)

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
    argon_instance = PasswordHasher()

    try:
        # Verify the received argon2 hash against the locally created hash to confirm session #
        argon_instance.verify(recv_hash, session_pass)

    # If the received password and locally generated do not match #
    except VerifyMismatchError:
        # Send data indicating operation failed #
        client_sock.sendall(b'False')
        # Print error and exit #
        print_err('The received password hash does not match supplied password .. closing '
                  'connection')
        sys.exit(8)

    # Generate a symmetrical key for encrypting transit data #
    symm_key = Fernet.generate_key()
    # Generate aesccm components for encrypting symmetrical key to send to client #
    aesccm_key = AESCCM.generate_key(bit_length=256)
    nonce = os.urandom(13)

    try:
        # Initialize the AESCCM algo instance #
        aesccm = AESCCM(aesccm_key)
        # Encrypt the symmetrical key with aessccm password encryption #
        crypt_key = aesccm.encrypt(nonce, symm_key, session_pass)

    # If error occurs during symmetrical key encryption process #
    except (InvalidTag, ValueError) as encrypt_err:
        # Send data indicating operation failed #
        sock.sendall(b'False')
        # Print error, log, and exit #
        print_err('Error occurred during symmetrical key encryption process')
        logging.error('Error occurred during symmetrical key encryption process: %s\n\n',
                      encrypt_err)
        sys.exit(9)

    # Parse the encrypted symmetrical key and aessccm key & nonce for transit to client #
    key_bytes = f'{aesccm_key.decode()}<$>{nonce.decode()}<$>{crypt_key.decode()}'.encode()
    # Send the parsed bytes with keys to client #
    client_sock.sendall(key_bytes)

    # Wait for response to ensure key was decrypted #
    data = client_sock.recv(8)
    if data == b'False':
        # Print error, log, and exit #
        print_err('Error occurred parsing and decrypting the send symmetrical key')
        logging.error('Error occurred parsing and decrypting the send symmetrical key\n\n')
        sys.exit(10)

    # Set the socket to non-blocking #
    client_sock.setblocking(False)

    print('[!] Password verified and keys have been sent .. data transmission through the network '
          'is now permitted')

    return client_sock, symm_key


def validate_ip(ip_addr: str) -> str:
    """
    Checks the input target IP arg against regex validation.

    :param ip_addr:  The string IP address to be validated via regex.
    :return:  The validated IP address string, if error is not raised.
    """
    # If the input ip address fails to match regex validation #
    if not re.search(r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}', ip_addr):
        # Print error and exit #
        print_err('Improper IP format detected .. try again with proper IP address')
        sys.exit(3)

    return ip_addr


def validate_port(str_port: str) -> int:
    """
    Checks the input port arg against regex validation and max value.

    :param str_port:  The port to be validated as string.
    :return:  The validated port in raw integer format.
    """
    # Convert string number to integer #
    raw_int = int_convert(str_port)

    # If the port fails regex validation or is out of the IEEE specified non-privileged port range #
    if not re.search(r'[0-9]{4,5}', str_port) or raw_int < 1024 or raw_int > 65535:
        # Print error and exit #
        print_err('Improper port detected .. try again with a port in the range of 1000 to 65535')
        sys.exit(4)

    return raw_int

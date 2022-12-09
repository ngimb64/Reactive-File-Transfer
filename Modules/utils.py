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


def chunk_bytes(bytes_string: bytes, length: int) -> typing.Generator:
    """
    Generator to split the bytes string passed in by the chunk length passed in it should be split
    into.

    :param bytes_string:  The bytes string to be split into chunks specified by the length.
    :param length:  How long each chunk of data should be.
    :return:  The byte parsing generator.
    """
    return (bytes_string[0+i:length+i] for i in range(0, len(bytes_string), length))


def client_init(target_ip: str, port: int):
    """
    Function is called after test socket connection attempt is successful indicating a server is
    already established on the other end. A final socket connection is re-setup and continually
    attempted on five second intervals until successful, set to non-blocking, and returned to the
    main thread.

    :param target_ip:  The target IP to connect to as string.
    :param port:  The TCP port which the network socket will be established.
    :return:  The established client network socket instance.
    """
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
            print('\n[+] Connection failed .. sleeping 5 seconds and retrying')
            # Sleep program for 5 seconds and re-iterate loop #
            time.sleep(5)
            continue

        break

    print(f'\n[!] Connection established to {target_ip}:{port}')

    # Set socket to non-blocking #
    sock.setblocking(False)

    return sock


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
        sys.exit(5)

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
                logging.error('Three consecutive errors occurred during file secure_delete() %s:'
                              ' %s\n\n', str(path), delete_err)
                sys.exit(5)

            # Increase count, sleep, and increase sleep interval by 1 #
            count += 1
            time.sleep(seconds)
            seconds += 1
            continue


def server_init(port: int):
    """
    Function is called after test socket connection attempt is not successful indicating a server
    is current not present on the other end. The hostname is queried, then used to get the IP
    address; which is used to bind to the port set in the header of the file. The server then waits
    for the incoming test connection, which when connected, null bytes are continually sent until an
    error is raised to the client side timing out. The raised error is ignored and execution is
    passed to wait for the final incoming connection. Once established, the client socket is set to
    non-blocking and returned to the main thread.

    :param port:  The TCP port which the network socket will be established.
    :return:  The connected network socket client instance.
    """
    # Get the system hostname #
    hostname = socket.gethostname()

    # TODO: debug to figure what is going on when Linux side calls this function

    # If the OS is not Windows #
    if os.name != 'nt':
        hostname = f'{hostname}.local'

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
    # Set the socket to non-blocking #
    client_sock.setblocking(False)
    # Notify user of successful connection #
    print(f'\n[!] Connection established to {address[0]}:{port}')

    return client_sock


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

    # If the port fails regex validation or is greater than the max existing port #
    if not re.search(r'[0-9]{4,5}', str_port) or raw_int > 65535:
        # Print error and exit #
        print_err('Improper port detected .. try again with a port in the range of 1000 to 65535')
        sys.exit(4)

    return raw_int

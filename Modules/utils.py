""" Built-in modules """
import logging
import errno
import socket
import sys


def chunk_bytes(bytes_string: bytes, length: int) -> bytes:
    """
    Generator to split the bytes string passed in by the chunk length passed in it should be split
    into.

    :param bytes_string:  The bytes string to be split into chunks specified by the length.
    :param length:  How long each chunk of data should be.
    :return:  The byte parsing generator.
    """
    return (bytes_string[0+i:length+i] for i in range(0, len(bytes_string), length))


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
        print_err(f'{err_path} does not exist')
        logging.exception('%s does not exist\n\n', err_path)

    # If the file does not have read/write access #
    elif err_obj.errno == errno.EPERM:
        print_err(f'{err_path} does not have permissions for {err_mode} file mode,'
                  ' if file exists confirm it is closed')
        logging.exception('%s does not have permissions for %s file mode\n\n', err_path, err_mode)

    # File IO error occurred #
    elif err_obj.errno == errno.EIO:
        print_err(f'IO error occurred during {err_mode} mode on {err_path}')
        logging.exception('IO error occurred during %s mode on %s\n\n', err_mode, err_path)

    # If other unexpected file operation occurs #
    else:
        print_err(f'Unexpected file operation occurred accessing {err_path}: {err_obj.errno}')
        logging.exception('Unexpected file operation occurred accessing %s: %s\n\n',
                          err_path, err_obj.errno)


def port_check(ip: str, port: int) -> bool:
    """
    Creates TCP socket and checks to see if remote port on specified IP address is active.

    :param ip:  The IP address of the remote host to connect to.
    :param port:  The port of the remote host to connect to.
    :return:  The True/False boolean value depending on operation success/failure.
    """
    # Set socket connection timeout #
    socket.setdefaulttimeout(1)
    # Create test socket #
    test_conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Attempt connection on remote port with test socket #
    test_res = test_conn.connect_ex((ip, port))
    # Terminate test socket #
    test_conn.close()

    # If connect operation was not successful #
    if not test_res == 0:
        return False

    # If connection operation was successful #
    return True


def print_err(msg: str):
    """
    Prints error message through standard output.

    :param msg:  Error message to be displayed.
    :return:  Nothing
    """
    #  Print error via standard error #
    print(f'\n* [ERROR] {msg} *\n', file=sys.stderr)

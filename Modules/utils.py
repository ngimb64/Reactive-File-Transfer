""" Built-in modules """
import errno
import os
import socket
import time


def chunk_bytes(bytes_string: bytes, length: int):
    """
    Generator to split the bytes string passed in by the chunk length passed in it should be split
    into.

    :param bytes_string:  The bytes string to be split into chunks specified by the length.
    :param length:  How long each chunk of data should be.
    :return:  The byte parsing generator.
    """
    return (bytes_string[0+i:length+i] for i in range(0, len(bytes_string), length))


def error_query(err_path: str, err_mode: str, err_obj) -> str:
    """
    Looks up the errno message to get description.

    :param err_path:  The path to file where the file operation occurred.
    :param err_mode:  The file mode during the error.
    :param err_obj:  The error message instance.
    :return:  File related error message to be logged.
    """
    # If file does not exist #
    if err_obj.errno == errno.ENOENT:
        return f'{err_path} does not exist'

    # If the file does not have read/write access #
    elif err_obj.errno == errno.EPERM:
        return f'{err_path} does not have permissions for {err_mode} file mode'

    # File IO error occurred #
    elif err_obj.errno == errno.EIO:
        return f'IO error occurred during {err_mode} mode on {err_path}'

    # If other unexpected file operation occurs #
    else:
        return f'Unexpected file operation occurred accessing {err_path}: {err_obj.errno}'


def int_convert(str_int: str):
    """
    Convert the passed in size as string to int, handles errors accordingly.

    :param str_int:  The integer passed in string format.
    :return:  The converted integer in its original form or error message string on error.
    """
    try:
        # Convert file size to integer #
        raw_int = int(str_int)

    # If value can not be converted to int (not string) #
    except ValueError as val_err:
        return f'Error converting file size to integer in incoming thread {val_err}'

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
    socket.setdefaulttimeout(0.5)
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


def secure_delete(path, passes=10):
    """
    Overwrite file data with random data number of specified passes and overwrite with random data.

    :param path:  Path to the file to be overwritten and deleted.
    :param passes:  Number of pass to perform random data overwrite.
    :return:  None if on success, error message on failure.
    """
    # Get the file size in bytes #
    length = path.stat().st_size
    count = 0
    seconds = 1
    err_msg = None

    while True:
        # After three failed attempts, ignore and set error message to be returned #
        if count == 3:
            err_msg = 'Three failed attempts occurred attempting to overwrite random data to' \
                      f'{str(path)}'
            break

        try:
            # Open file and overwrite the data for number of passes #
            with path.open('wb') as file:
                for _ in range(passes):
                    # Point file pointer to start of file #
                    file.seek(0)
                    # Write random data #
                    file.write(os.urandom(length))

                break

        # If file error occurs #
        except (OSError, IOError):
            # Sleep for a second and reattempt data scrub #
            count += 1
            time.sleep(seconds)
            seconds += 1
            continue

    # Unlink (delete) file from file system #
    os.remove(path)
    return err_msg

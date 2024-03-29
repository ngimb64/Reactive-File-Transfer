# pylint: disable=E0401
""" Built-in modules """
import errno
import logging
import os
import re
import sys
from getpass import getpass
from socket import socket
from threading import Lock
# External modules #
from pyfiglet import Figlet, FigletError


# Global variables #
PARSE_MUTEX = Lock()
ERR_MUTEX = Lock()


def banner_display():
    """
    Renders and displays the programs pyfiglet banner.

    :return:  Nothing
    """
    try:
        # Initialize the pyfiglet instance and render it #
        banner = Figlet(font='slant', width=120)
        print(banner.renderText('Reactive File Transfer'))

    # If error occurs rendering the programs banner #
    except FigletError as banner_err:
        print_err('An error occurred rendering the RFT banner')
        logging.exception('An error occurred rendering the RFT banner %s\n\n', banner_err)
        sys.exit(5)


def error_query(err_path: str, err_mode: str, err_obj):
    """
    Looks up the errno message to get description.

    :param err_path:  The path to file where the file operation occurred.
    :param err_mode:  The file mode during the error.
    :param err_obj:  The error message instance.
    :return:  Nothing
    """
    # Set thread lock for exclusive access #
    with ERR_MUTEX:
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
        sys.exit(14)

    return raw_int


def parse_start_bytes(data_chunk: bytes, divider: bytes) -> tuple:
    """
    Takes the input data chunk containing file name and size to be transferred with divider in the
    middle.

    :param data_chunk:  Data chunk containing divider to split file name and size.
    :param divider:  The divider used to split the file name and size.
    :return:  The parsed file name and size as tuple grouping.
    """
    # Set thread lock for exclusive access #
    with PARSE_MUTEX:
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


def print_err(msg: str):
    """
    Displays error via stderr.

    :param msg:  The error message to be displayed.
    :return:  Nothing.
    """
    print(f'\n* [ERROR] {msg} *\n', file=sys.stderr)


def split_handler(in_data: bytes, connection: socket) -> list:
    """
    Takes the passed in data and splits it based on specified divisor in error handled procedure.

    :param in_data:  The data chunk to be split by divisor.
    :param connection:  Remote socket connection for sending failed status on error.
    :return:  Split data chunk as bytes list.
    """
    try:
        # Split the three keys by divisor #
        byte_list = in_data.split(b'<$>')

    # If the retrieved data lacks multiple values to split #
    except ValueError as val_err:
        # Send operation failure status upon failure #
        connection.sendall(b'False')
        # Print error, log, and exit #
        print_err('The retrieved key data lacks multiple values to split')
        logging.error('The retrieved key data lacks multiple values to split: %s\n\n', val_err)
        sys.exit(7)

    return byte_list


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

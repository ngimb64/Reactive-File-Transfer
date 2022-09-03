""" Built-in modules """
import logging
import errno
import sys


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


def print_err(msg: str):
    """
    Prints error message through standard output.

    :param msg:  Error message to be displayed.
    :return:  Nothing
    """
    #  Print error via standard error #
    print(f'\n* [ERROR] {msg} *\n', file=sys.stderr)

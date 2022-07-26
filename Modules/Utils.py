# Built-in modules #
import logging
import errno
import sys


"""
########################################################################################################################
Name:       ErrorQuery
Purpose:    Looks up the errno message to get description.
Parameters: Errno message.
Returns:    Nothing
########################################################################################################################
"""
def ErrorQuery(err_path: str, err_mode: str, err_obj):
    # If file does not exist #
    if err_obj.errno == errno.ENOENT:
        PrintErr(f'{err_path} does not exist')
        logging.exception(f'{err_path} does not exist\n\n')
        sys.exit(2)

    # If the file does not have read/write access #
    elif err_obj.errno == errno.EPERM:
        PrintErr(f'{err_path} does not have permissions for {err_mode} file mode, if file exists confirm it is closed')
        logging.exception(f'{err_path} does not have permissions for {err_mode} file mode\n\n')
        sys.exit(3)

    # File IO error occurred #
    elif err_obj.errno == errno.EIO:
        PrintErr(f'IO error occurred during {err_mode} mode on {err_path}')
        logging.exception(f'IO error occurred during {err_mode} mode on {err_path}\n\n')
        sys.exit(4)

    # If other unexpected file operation occurs #
    else:
        PrintErr(f'Unexpected file operation occurred accessing {err_path}: {err_obj.errno}')
        logging.exception(f'Unexpected file operation occurred accessing {err_path}: {err_obj.errno}\n\n')
        sys.exit(5)


"""
########################################################################################################################
Name:       PrintErr
Purpose:    Prints error message through standard output.
Parameters: Message to be displayed.
Returns:    None
########################################################################################################################
"""
def PrintErr(msg: str):
    #  Print error via standard error #
    print(f'\n* [ERROR] {msg} *\n', file=sys.stderr)

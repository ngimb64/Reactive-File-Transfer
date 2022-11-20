""" Built-in modules """
import logging
import os
from socket import socket
# External modules #
from tqdm import tqdm
# Custom modules #
from Modules.utils import error_query


# Global variables #
CLIENT_IP = '<Add_IP>'
CLIENT_PORT = 5001
BUFFER_SIZE = 4096
SEPARATOR = '<SEPARATOR>'


# File name for testing #
filename = 'test.txt'


def main():
    # Get the current working directory #
    cwd = os.getcwd()

    # If OS is Windows #
    if os.name == 'nt':
        path = f'{cwd}\\'
    # If OS is Linux #
    else:
        path = f'{cwd}/'

    # Initialize the logging facilities #
    logging.basicConfig(level=logging.DEBUG, filename=f'{path}portal_client.log')

    # get the file size
    filesize = os.path.getsize(filename)

    # Create socket object in context manager #
    with socket() as conn:
        # Connect to the client socket #
        conn.connect((CLIENT_IP, CLIENT_PORT))
        print(f'[!] Connected to {CLIENT_IP}:{CLIENT_PORT}')

        # send the filename and filesize
        conn.send(f'{filename}{SEPARATOR}{filesize}'.encode())

        # Setup progress-bar for file transfer #
        progress = tqdm(range(filesize), f'Sending {filename}', unit='B',
                        unit_scale=True, unit_divisor=1024)

        try:
            # Open the data to be sent in read bytes mode #
            with open(filename, 'rb') as send_file:
                while True:
                    # Read a chunk of binary data to send #
                    bytes_read = send_file.read(BUFFER_SIZE)
                    # If there is no more data to read #
                    if not bytes_read:
                        # Exit read loop #
                        break

                    # Ensure entire chunk of data is sent #
                    conn.sendall(bytes_read)
                    # Update the progress bar display #
                    progress.update(len(bytes_read))

        # If error occurs during file operation #
        except (IOError, OSError) as file_err:
            error_query(filename, 'rb', file_err)


if __name__ == '__main__':
    main()
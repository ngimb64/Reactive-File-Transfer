""" Built-in modules """
import logging
import os
import sys
from socket import socket
# External modules #
from tqdm import tqdm
# Custom modules #
from Modules.utils import error_query, print_err


# Global variables #
SERVER_IP = '0.0.0.0'
SERVER_PORT = 5001
BUFFER_SIZE = 4096
SEPARATOR = '<SEPARATOR>'


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
    logging.basicConfig(level=logging.DEBUG, filename=f'{path}portal_server.log')

    # Set return code #
    ret = 0

    try:
        # Create TCP socket object in context manager #
        with socket() as conn:
            while True:
                # Bind socket to server local IP and port #
                conn.bind((SERVER_IP, SERVER_PORT))
                # Allows socket connection #
                conn.listen(1)

                print(f'[+] Listening as {SERVER_IP}:{SERVER_PORT}')
                # Accept connection when available #
                client_socket, address = conn.accept()
                # Confirms connections is established #
                print(f'[!] {address} is connected.')

                # Set socket to client connection to receive data #
                received = client_socket.recv(BUFFER_SIZE).decode()
                # Split by separator to get file name and size #
                filename, filesize = received.split(SEPARATOR)
                # Strip any path from the filename #
                filename = os.path.basename(filename)
                try:
                    # Convert filesize to integer #
                    filesize = int(filesize)

                # If error occurs converting to integer #
                except ValueError as val_err:
                    print_err(f'Error converting file size to integer {val_err}')
                    sys.exit(2)

                # Setup progress-bar for file transfer #
                progress = tqdm(range(filesize), f'Receiving {filename}', unit='B',
                                unit_scale=True, unit_divisor=1024)

                # Open output file in write bytes mode #
                with open(filename, 'wb') as out_file:
                    while True:
                        # Read chunk of binary data to write to file #
                        bytes_read = client_socket.recv(BUFFER_SIZE)
                        # If there is no more data to write #
                        if not bytes_read:
                            # Exit write loop #
                            break

                        # Write read chunk of socket data to file #
                        out_file.write(bytes_read)
                        # Update the progress bar display #
                        progress.update(len(bytes_read))

    # If Ctrl + C is detected #
    except KeyboardInterrupt:
        print('Ctrl + C detected, exiting program ..')

    # If error occurs during file operation #
    except (OSError, IOError) as file_err:
        error_query(filename, 'wb', file_err)
        ret = 1

    finally:
        # close the client socket
        client_socket.close()
        sys.exit(ret)

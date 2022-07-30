# Built-in modules #
import os
import sys
from socket import socket

# External modules #
from tqdm import tqdm


# Pseudo-constants #
SERVER_IP = '0.0.0.0'
SERVER_PORT = 5001
BUFFER_SIZE = 4096
SEPARATOR = '<SEPARATOR>'


def main():
    # Set return code #
    ret = 0

    try:
        # Create TCP socket object in context manager #
        with socket() as conn:
            while True:
                # Bind socket to server local IP and port #
                conn.bind((SERVER_IP, SERVER_PORT))
                # Allows 5 simultaneous connections #
                conn.listen(5)

                print(f'[$] Listening as {SERVER_IP}:{SERVER_PORT}')
                # Accept connection when available #
                client_socket, address = conn.accept()
                # Confirms connections is established #
                print(f'[$] {address} is connected.')

                # Set socket to client connection to receive data #
                received = client_socket.recv(BUFFER_SIZE).decode()
                # Split input buffer by separator to return file name & size #
                filename, filesize = received.split(SEPARATOR)
                # Strip any path from the filename #
                filename = os.path.basename(filename)
                try:
                    # Convert filesize to integer #
                    filesize = int(filesize)

                # If error occurs converting to integer #
                except ValueError as val_err:
                    print(f'Error converting file size to integer {val_err}')

                # Setup progress-bar for file transfer #
                progress = tqdm(range(filesize), f'Receiving {filename}', unit='B', unit_scale=True, unit_divisor=1024)

                # Open output file in write bytes mode #
                with open(filename, 'wb') as f:
                    while True:
                        # read 1024 bytes from the socket (receive)
                        bytes_read = client_socket.recv(BUFFER_SIZE)
                        # If client is no longer sending data #
                        if not bytes_read:
                            # Exit loop & close session #
                            break

                        # write to the file the bytes we just received
                        f.write(bytes_read)
                        # update the progress bar
                        progress.update(len(bytes_read))

    # If Ctrl + C is detected #
    except KeyboardInterrupt:
        print('Ctrl + C detected, exiting program ..')

    # Id OS or file error occur #
    except (OSError, IOError) as err:
        print(f'Unexpected error occurred {err}')
        ret = 1

    finally:
        # close the client socket
        client_socket.close()
        sys.exit(ret)

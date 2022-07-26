# Built-in modules #
import os
from socket import socket

# External modules #
from tqdm import tqdm

SEPARATOR = '<SEPARATOR>'
BUFFER_SIZE = 4096

CLIENT_IP = '<add IP>'
# the port, let's use 5001
PORT = 5001
# the name of file we want to send, make sure it exists
filename = 'data.csv'


def main():
    # get the file size
    filesize = os.path.getsize(filename)

    # Create socket object in context manager #
    with socket() as conn:
        print(f'[+] Connecting to {CLIENT_IP}:{PORT}')
        conn.connect((CLIENT_IP, PORT))
        print('[+] Connected.')

        # send the filename and filesize
        conn.send(f'{filename}{SEPARATOR}{filesize}'.encode())

        # Setup progress-bar for file transfer #
        progress = tqdm(range(filesize), f'Sending {filename}', unit='B', unit_scale=True, unit_divisor=1024)

        # Open the data to be sent in read bytes mode #
        with open(filename, 'rb') as send_file:
            while True:
                # read the bytes from the file
                bytes_read = send_file.read(BUFFER_SIZE)
                if not bytes_read:
                    # file transmitting is done
                    break

                # we use sendall to assure transmission in
                # busy networks
                conn.sendall(bytes_read)
                # update the progress bar
                progress.update(len(bytes_read))


if __name__ == '__main__':
    main()
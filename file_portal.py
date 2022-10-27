""" Built-in modules """
import logging
import os
import queue
import select
import socket
import sys
import time
from threading import Thread
# External modules #
from tqdm import tqdm
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
# Custom modules #
from Modules.utils import chunk_bytes, error_query, port_check, print_err


# Global variables #
IP = '<Add_IP'
PORT = 5001
BUFFER_SIZE = 4096
BUFFER_DIV = '<$>'
SEND_QUEUE = queue.Queue()
READ_QUEUE = queue.Queue()


def auto_file_incoming():
    while True:
        # If the read queue is empty #
        if READ_QUEUE.empty():
            # Re-iterate loop to temporarily block operation #
            continue

        # Get the initial string with the file name and size #
        title_chunk = READ_QUEUE.get()
        # Parse the file name and size from the initial string with <$> divider #
        file_name, file_size = title_chunk.split(BUFFER_DIV)
        # Strip any extra path from file name #
        file_name = os.path.basename(file_name)

        # TODO: Add progress bars for incoming and outgoing files

        try:
            # Open the incoming file name in append bytes mode #
            with open(file_name, 'ab') as in_file:
                while True:
                    # If the read queue waiting for file data #
                    if READ_QUEUE.empty():
                        # Re-iterate loop to temporarily block operation #
                        continue

                    # Get the incoming data from the read queue #
                    incoming_data = READ_QUEUE.get()

                    # If the incoming data specifies end of file (EOF) #
                    if incoming_data == b'<END_FILE>':
                        # Exit the file write loop #
                        break

                    # Write the incoming data to the specified file name #
                    in_file.write(incoming_data)

        # If error occurs during file operation #
        except (IOError, OSError) as file_err:
            # Print the file error and log #
            error_query(file_name, 'ab', file_err)


class OutgoingFileDetector(FileSystemEventHandler):
    def on_modified(self, event):
        # Iterate through the files in the outgoing folder #
        for file in os.scandir(out_path):
            # Format file name and size with divider as start bytes #
            start_bytes = f'{file.name}{BUFFER_DIV}{os.path.getsize(file.name)}'.encode()
            # Send start bytes for setup and progress bar on remote system #
            SEND_QUEUE.put(start_bytes)

            # TODO: Add progress bars for incoming and outgoing files

            try:
                # Open file in bytes read mode to put in send queue #
                with open(file.name, 'rb') as send_file:
                    data = send_file.read()

            # If error occurs during file operation #
            except (IOError, OSError) as file_err:
                # Look up file error, print & log #
                error_query(file.name, 'rb', file_err)
                continue

            # If the file has more than one chunk of data to read #
            if len(data) > BUFFER_SIZE:
                # Iterate through read file data and split it into chunks 4096 bytes or fewer #
                for item in list(chunk_bytes(data, BUFFER_SIZE)):
                    SEND_QUEUE.put(item)
            # If the file data can be fit in one chunk #
            else:
                SEND_QUEUE.put(data)

            # Put EOF descriptor for remote system to know transfer is complete #
            end_bytes = b'<END_FILE>'
            SEND_QUEUE.put(end_bytes)


def auto_file_outgoing():
    # Initialize BackupHandler object #
    file_monitor = OutgoingFileDetector()
    # Initialize the observer object #
    observer = Observer()
    # Schedule the file monitoring object to run #
    observer.schedule(file_monitor, folders[1], recursive=True)
    # Start the file monitoring object #
    observer.start()

    # Run file system monitor until Ctrl+C #
    try:
        while True:
            time.sleep(15)

    # If Ctrl+C is detected #
    except KeyboardInterrupt:
        # Stop the file monitoring object #
        observer.stop()

    # Join the file monitoring child process to terminate #
    observer.join()


def client_init():
    # Set socket connection timeout #
    socket.setdefaulttimeout(1)
    # Initialize the TCP socket instance #
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Return code #
    res = 1

    print(f'[+] Attempting to connect to {IP} on {PORT} with 5 second sleep intervals')

    # While the connection attempt return code is not 0 (successful) #
    while res != 0:
        # Attempt connection on remote port #
        res = sock.connect_ex((IP, PORT))
        # If the connection attempt was not successful #
        if res != 0:
            # Sleep program for 5 seconds #
            time.sleep(5)

    print(f'[!] Connection established to {IP}:{PORT}')

    # Set socket to non-blocking #
    sock.setblocking(False)

    return sock


def server_init():
    # Get the system hostname #
    hostname = socket.gethostname()
    # Use the hostname to get the IP Address #
    ip = socket.gethostbyname(hostname)
    # Set socket connection timeout #
    socket.setdefaulttimeout(None)
    # Initialize the TCP socket instance #
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Bind socket to server local IP and port #
    sock.bind((ip, PORT))
    # Allow a single incoming socket connection #
    sock.listen(1)

    # Notify user host is acting as server #
    print(f'[+] No remote server present .. serving on ({hostname}||{ip}):{PORT}')

    # Wait until connection is received from client socket #
    client_sock, address = sock.accept()
    # Set the socket to non-blocking #
    client_sock.setblocking(False)

    # Notify user of successful connection #
    print(f'[!] Connection established to {address}:{PORT}')

    return client_sock


def main():
    # If the remote host is already listening for connections #
    if port_check(IP, PORT):
        # Act as the client side of connection #
        conn = client_init()
    # If no remote listeners are active #
    else:
        # Act as the server side of the connection #
        conn = server_init()

    # Initialize the automated file sender daemon thread instance #
    auto_file_reader = Thread(target=auto_file_outgoing, daemon=True, args=())
    # Initialize the automated file reader daemon thread instance #
    auto_file_writer = Thread(target=auto_file_incoming, daemon=True, args=())
    # Start the file reader outgoing data daemon thread #
    auto_file_reader.start()
    # Start the file writer incoming data daemon thread #
    auto_file_writer.start()

    print(f'\n[!] File system monitoring activated')

    # Pass socket instance to list to get inputs/outputs #
    inputs = [conn]
    outputs = [conn]

    try:
        while True:
            # Polls socket inputs, outputs, and errors. Returns socket file descriptor lists tuple #
            read_data, send_data, conn_errs = select.select(inputs, outputs, inputs, 0.5)

            # If the send queue has data to send #
            if not SEND_QUEUE.empty():
                # Iterate through
                for data in send_data:
                    # Get a chunk of data to send from queue #
                    chunk = SEND_QUEUE.get()

                    print(f'Data before send: {data}')

                    # Send the chunk of data through the TCP connection #
                    data = data.sendall(chunk)

                    print(f'Data after send: {data}')

                    # Remove chunk from outputs list #
                    outputs.remove(data)

            for data in read_data:
                data = data.recv(BUFFER_SIZE)

                print(f'Data received: {len(data)}\n\n{data}')

                READ_QUEUE.put(data)

                # data.close()

                # Remove the received data from inputs list #
                inputs.remove(data)
                break

            for data in conn_errs:
                # Log the exception #
                logging.exception(f'Error occurred during socket operation: %s\n\n', data)
                # Remove exception data in inputs in outputs list #
                inputs.remove(data)
                outputs.remove(data)
                break

    except KeyboardInterrupt:
        print('\nCtrl + C detected .. exiting program')


if __name__ == '__main__':
    # Get the current working directory #
    cwd = os.getcwd()
    folders = ('Incoming', 'Outgoing')

    # If OS is Windows #
    if os.name == 'nt':
        path = f'{cwd}\\'
        in_path = f'{path}\\{folders[0]}'
        out_path = f'{path}\\{folders[1]}'
    # If OS is Linux #
    else:
        path = f'{cwd}/'
        in_path = f'{path}/{folders[0]}'
        out_path = f'{path}/{folders[1]}'

    # Initialize the logging facilities #
    logging.basicConfig(level=logging.DEBUG, filename=f'{path}portal_client.log')
    # Create non-existing data transfer directories #
    [os.mkdir(folder) for folder in folders if not os.path.isdir(folder)]
    # Exit code #
    ret = 0

    try:
        main()

    # If unknown exception occurs #
    except Exception as err:
        # Print and log unknown exception #
        print_err(f'Unknown exception occurred: {err}')
        logging.exception(f'Unknown exception occurred: %s\n\n', err)
        ret = 1

    sys.exit(ret)

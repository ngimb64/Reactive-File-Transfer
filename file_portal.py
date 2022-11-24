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
from Modules.utils import chunk_bytes, error_query, int_convert, port_check


# Global variables #
IP = '<Add_IP>'
PORT = 5001
BUFFER_SIZE = 4096
BUFFER_DIV = b'<$>'
OUTPUT_QUEUE = queue.Queue()
ERROR_QUEUE = queue.Queue()
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
        file_name = os.path.basename(file_name.decode())
        # Convert the file size to integer #
        file_size = int_convert(file_size.decode())

        # If OS is Windows #
        if os.name == 'nt':
            file_path = f'{in_path}\\{file_name}'
        # If OS is Linux #
        else:
            file_path = f'{in_path}/{file_name}'

        # Setup progress-bar for file input #
        progress = tqdm(range(file_size), f'Receiving {file_name}', unit='B',
                        unit_scale=True, unit_divisor=BUFFER_SIZE)
        try:
            # Open the incoming file name in append bytes mode #
            with open(file_path, 'ab') as in_file:
                while True:
                    # If the read queue waiting for file data #
                    if READ_QUEUE.empty():
                        # Re-iterate loop to temporarily block operation #
                        continue

                    # Get the incoming data from the read queue #
                    incoming_data = READ_QUEUE.get()

                    # If the incoming data specifies end of file (EOF) #
                    if incoming_data == b'<END_FILE>\r\n':
                        # Exit the file write loop #
                        break

                    # Write the incoming data to the specified file name #
                    in_file.write(incoming_data)
                    # Update the progress bar with the number of bytes written to file #
                    progress.update(len(incoming_data))

        # If error occurs during file operation #
        except (IOError, OSError) as file_err:
            # Print the file error and log #
            error_query(file_path, 'ab', file_err)


class OutgoingFileDetector(FileSystemEventHandler):
    def on_modified(self, event):
        # Iterate through the files in the outgoing folder #
        for file in os.scandir(out_path):
            # If OS is Windows #
            if os.name == 'nt':
                file_path = f'{out_path}\\{file.name}'
            # If OS is Linux #
            else:
                file_path = f'{out_path}/{file.name}'

            # Get the size of the file #
            file_size = os.path.getsize(file_path)
            # Format file name and size with divider as start bytes #
            start_bytes = f'{file.name}{BUFFER_DIV}{file_size}'.encode()

            try:
                # Open file in bytes read mode to put in send queue #
                with open(file_path, 'rb') as send_file:
                    data = send_file.read()

            # If error occurs during file operation #
            except (IOError, OSError) as file_err:
                # Look up file error, print & log #
                error_query(file_path, 'rb', file_err)
                continue

            # Setup progress-bar for file output #
            progress = tqdm(range(file_size), f'Sending {file.name}', unit='B',
                            unit_scale=True, unit_divisor=BUFFER_SIZE)

            # Send start bytes for setup and progress bar on remote system #
            SEND_QUEUE.put(start_bytes)

            # If the file has more than one chunk of data to read #
            if len(data) > BUFFER_SIZE - 2:
                # Iterate through read file data and split it into chunks 4096 bytes or fewer #
                for chunk in list(chunk_bytes(data, BUFFER_SIZE - 2)):
                    # Put data in send queue and update progress bar #
                    SEND_QUEUE.put(chunk)
                    # Put data in send queue and update progress bar #
                    progress.update(len(chunk))
            # If the file data can be fit in one chunk #
            else:
                SEND_QUEUE.put(data)
                progress.update(len(data))

            # Put EOF descriptor for remote system to know transfer is complete #
            end_bytes = b'<END_FILE>'
            SEND_QUEUE.put(end_bytes)


def auto_file_outgoing():
    # Initialize BackupHandler object #
    file_monitor = OutgoingFileDetector()
    # Initialize the observer object #
    observer = Observer()
    # Schedule the file monitoring object to run #
    observer.schedule(file_monitor, out_path, recursive=True)
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


def display_output():
    while True:
        # If the output and error queues are empty #
        if OUTPUT_QUEUE.empty() and ERROR_QUEUE.empty():
            # Re-iterate to temporarily block operation #
            continue

        # If the output queue has data #
        if not OUTPUT_QUEUE.empty():
            # Get output message from output queue #
            output_msg = OUTPUT_QUEUE.get()
            # Display output via stdout #
            print(output_msg)

        # If the input queue has data #
        if not ERROR_QUEUE.empty():
            # Get error message from error queue #
            error_msg = ERROR_QUEUE.get()
            # Format error message #
            err_message = f'\n* [ERROR] {error_msg} *\n'
            # Display error message via stderr #
            print(err_message, file=sys.stderr)


def client_init():
    # Set socket connection timeout #
    socket.setdefaulttimeout(None)
    # Initialize the TCP socket instance #
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    print(f'[+] Attempting to connect to {IP} on {PORT}')

    # While the connection attempt return code is not 0 (successful) #
    while True:
        # Attempt connection on remote port #
        res = sock.connect_ex((IP, PORT))
        # If the connection attempt was not successful #
        if res != 0:
            print('\n[+] Connection failed .. sleeping 5 seconds and retrying')
            # Sleep program for 5 seconds and re-iterate loop #
            time.sleep(5)
            continue

        break

    print(f'\n[!] Connection established to {IP}:{PORT}')

    # Set socket to non-blocking #
    sock.setblocking(False)

    return sock


def server_init():
    # Get the system hostname #
    hostname = socket.gethostname()
    # Use the hostname to get the IP Address #
    ip = socket.gethostbyname(hostname)
    # Set socket connection timeout #
    socket.setdefaulttimeout(0.5)
    # Initialize the TCP socket instance #
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Bind socket to server local IP and port #
    sock.bind((ip, PORT))
    # Allow a single incoming socket connection #
    sock.listen(1)

    # TODO: only handling one connection, add code to reset connection for second final attempt

    # Notify user host is acting as server #
    print(f'[+] No remote server present .. serving on ({hostname}||{ip}):{PORT}')

    # Wait until connection is received from client socket #
    client_sock, address = sock.accept()
    # Set the socket to non-blocking #
    client_sock.setblocking(False)

    # Notify user of successful connection #
    print(f'\n[!] Connection established to {address}:{PORT}')

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

    # Initialize the output display thread #
    output_thread = Thread(target=display_output, daemon=True, args=())
    # Initialize the automated file sender daemon thread instance #
    auto_file_reader = Thread(target=auto_file_outgoing, daemon=True, args=())
    # Initialize the automated file reader daemon thread instance #
    auto_file_writer = Thread(target=auto_file_incoming, daemon=True, args=())
    # Start the program output daemon thread #
    output_thread.start()
    # Start the file reader outgoing data daemon thread #
    auto_file_reader.start()
    # Start the file writer incoming data daemon thread #
    auto_file_writer.start()

    OUTPUT_QUEUE.put(f'\n[!] File system monitoring activated')

    # Pass socket instance to list to get inputs/outputs #
    inputs = [conn]
    outputs = [conn]

    try:
        while True:
            # Polls socket inputs, outputs, and errors. Returns socket file descriptor lists tuple #
            read_data, send_data, conn_errs = select.select(inputs, outputs, inputs, 0.5)

            # If the send queue has data to send #
            if not SEND_QUEUE.empty():
                # Iterate through available send sockets #
                for sock in send_data:
                    # Get a chunk of data from send queue #
                    chunk = SEND_QUEUE.get()

                    OUTPUT_QUEUE.put(f'Data to be sent: {chunk.decode()}\n')

                    # Send the chunk of data through the TCP connection #
                    sock.sendall(chunk + b'\r\n')
                    # Remove chunk from outputs list #
                    outputs.remove(sock)

            # Iterate through available receive sockets #
            for sock in read_data:
                # Receive 4096 bytes of data from remote host #
                data = sock.recv(BUFFER_SIZE)

                # If the socket received data #
                if len(data) > 0:
                    OUTPUT_QUEUE.put(f'Data received: {data.decode()}\n')

                    # Put received data into read queue #
                    READ_QUEUE.put(data)

                    # Close the read socket #
                    sock.close()
                    # Remove socket from inputs list #
                    inputs.remove(sock)
                    break

            for sock in conn_errs:
                # Put message in error queue to be displayed stderr #
                ERROR_QUEUE.put(f'Error occurred during socket operation: {sock}')
                # Remove exception data in inputs in outputs list #
                inputs.remove(sock)
                outputs.remove(sock)
                break

    except KeyboardInterrupt:
        OUTPUT_QUEUE.put('\nCtrl + C detected .. exiting program')
        # Close the connection #
        conn.close()


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
        # ERROR_QUEUE.put(f'Unknown exception occurred: {err}')
        logging.exception('Unknown exception occurred: %s\n\n', err)
        ret = 1

    sys.exit(ret)

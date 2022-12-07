""" Built-in modules """
import logging
import os
import queue
import select
import socket
import sys
import time
from pathlib import Path
from threading import Thread
# External modules #
from tqdm import tqdm
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
# Custom modules #
from Modules.utils import chunk_bytes, error_query, parse_start_bytes, port_check, secure_delete


# Global variables #
TARGET_IP = '<Add_IP>'
PORT = 5001
BUFFER_SIZE = 4096
BUFFER_DIV = b'<$>'
OUTPUT_QUEUE = queue.Queue()
ERROR_QUEUE = queue.Queue()
SEND_QUEUE = queue.Queue()
READ_QUEUE = queue.Queue()


def auto_file_incoming():
    """
    Polls the read queue for incoming chunks of data and writes data to file name until delimiter
    is detected.

    :return:  Nothing, runs as background daemon thread until main thread exits.
    """
    while True:
        # If the read queue is empty #
        if READ_QUEUE.empty():
            # Re-iterate loop to temporarily block operation #
            continue

        # Get the initial string with the file name and size #
        title_chunk = READ_QUEUE.get()
        # Parse the file name and size from the received start bytes #
        file_name, file_size = parse_start_bytes(title_chunk, BUFFER_DIV)

        # If the file conversion function returns string indicating error #
        if isinstance(file_size, str):
            # Put the returned error in error queue for logging thread #
            ERROR_QUEUE.put(f'Error occurred converting string number "{file_size}" to integer')
            time.sleep(1)
            sys.exit(6)

        # Format the incoming file path #
        file_path = in_path / file_name

        try:
            # Open the incoming file name in append bytes mode #
            with file_path.open('ab') as in_file:
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
            # Lookup the file error and put in error queue for logging thread #
            err_msg = error_query(file_path, 'ab', file_err)
            ERROR_QUEUE.put(err_msg)


class OutgoingFileDetector(FileSystemEventHandler):
    """
    Watchdog file system monitoring class that continuously monitors the outgoing data directory to
    automatically read any modification (added files) data and feed into the send queue.
    """
    def on_modified(self, event):
        """
        Watchdog event is triggered per file system modification is designated outgoing folder.
        Data is read from the event file and feed into the send queue to be transferred through the
        network socket in chunks of data set by BUFFER_SIZE pseudo-constant.

        :param event:  File system event that occurred.
        :return:  Nothing
        """
        # Iterate through the files in the outgoing folder #
        for file in os.scandir(out_path):
            # Format the outgoing file path name #
            file_path = out_path / file.name
            # Get the size of the file #
            file_size = os.path.getsize(file_path)
            # Format file name and size with divider as start bytes #
            start_bytes = f'{file.name}{BUFFER_DIV.decode()}{file_size}'.encode()

            try:
                # Open file in bytes read mode to put in send queue #
                with file_path.open('rb') as send_file:
                    data = send_file.read()

            # If error occurs during file operation #
            except (IOError, OSError) as file_err:
                # Lookup the file error and put in error queue for logging thread #
                err_msg = error_query(file_path, 'rb', file_err)
                ERROR_QUEUE.put(err_msg)
                continue

            # Send start bytes for setup and progress bar on remote system #
            SEND_QUEUE.put(start_bytes)

            # If the file has more than one chunk of data to read #
            if len(data) > BUFFER_SIZE:
                # Iterate through read file data and split it into chunks 4096 bytes or fewer #
                for chunk in list(chunk_bytes(data, BUFFER_SIZE)):
                    # Put data in send queue and update progress bar #
                    SEND_QUEUE.put(chunk)
            # If the file data can be fit in one chunk #
            else:
                SEND_QUEUE.put(data)

            # Put EOF descriptor for remote system to know transfer is complete #
            end_bytes = b'<END_FILE>'
            SEND_QUEUE.put(end_bytes)

            # Delete the file from outgoing folder and overwrite
            # numerous passes of random data #
            ret = secure_delete(file_path)
            # If error message was returned from secure delete #
            if ret:
                # Put in the error queue to be logged #
                ERROR_QUEUE.put(ret)


def auto_file_outgoing():
    """
    Registers watchdog file system monitoring directory and continually monitors file system to
    trigger OutgoingFileDetector() watchdog event.

    :return:  Nothing, runs as background daemon thread until main thread exits.
    """
    # Initialize BackupHandler object #
    file_monitor = OutgoingFileDetector()
    # Initialize the observer object #
    observer = Observer()
    # Schedule the file monitoring object to run #
    observer.schedule(file_monitor, str(out_path.resolve()), recursive=True)
    # Start the file monitoring object #
    observer.start()

    # Run file system monitor until Ctrl+C #
    try:
        # Poll designed folder in file system for modifications (added files) #
        while True:
            time.sleep(5)

    # If Ctrl+C is detected #
    except KeyboardInterrupt:
        # Stop the file monitoring object #
        observer.stop()

    # Join the file monitoring child process to terminate #
    observer.join()


def logger():
    """
    Logging thread polls output and error queue to log info or error.

    :return:  Nothing, runs as background daemon thread until main thread exits.
    """
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
            logging.info(output_msg)

        # If the input queue has data #
        if not ERROR_QUEUE.empty():
            # Get error message from error queue #
            error_msg = ERROR_QUEUE.get()
            # Display error message via stderr #
            logging.error(error_msg)


def client_init():
    """
    Function is called after test socket connection attempt is successful indicating a server is
    already established on the other end. A final socket connection is re-setup and continually
    attempted on five second intervals until successful, set to non-blocking, and returned to the
    main thread.

    :return:  The established client network socket instance.
    """
    # Set socket connection timeout #
    socket.setdefaulttimeout(None)
    # Initialize the TCP socket instance #
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    print(f'[+] Attempting to connect to {TARGET_IP} on {PORT}')

    # While the connection attempt return code is not 0 (successful) #
    while True:
        # Attempt connection on remote port #
        res = sock.connect_ex((TARGET_IP, PORT))
        # If the connection attempt was not successful #
        if res != 0:
            print('\n[+] Connection failed .. sleeping 5 seconds and retrying')
            # Sleep program for 5 seconds and re-iterate loop #
            time.sleep(5)
            continue

        break

    print(f'\n[!] Connection established to {TARGET_IP}:{PORT}')

    # Set socket to non-blocking #
    sock.setblocking(False)

    return sock


def server_init():
    """
    Function is called after test socket connection attempt is not successful indicating a server
    is current not present on the other end. The hostname is queried, then used to get the IP
    address; which is used to bind to the port set in the header of the file. The server then waits
    for the incoming test connection, which when connected, null bytes are continually sent until an
    error is raised to the client side timing out. The raised error is ignored and execution is
    passed to wait for the final incoming connection. Once established, the client socket is set to
    non-blocking and returned to the main thread.

    :return:  The connected network socket client instance.
    """
    # Get the system hostname #
    hostname = socket.gethostname()

    # If the OS is not Windows #
    if os.name != 'nt':
        hostname = f'{hostname}.local'

    # Use the hostname to get the IP Address #
    ip_addr = socket.gethostbyname(hostname)
    # Set socket connection timeout #
    socket.setdefaulttimeout(None)
    # Initialize the TCP socket instance #
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Bind socket to server local IP and port #
    sock.bind((ip_addr, PORT))
    # Allow a single incoming socket connection #
    sock.listen(1)
    # Notify user host is acting as server #
    print(f'[+] No remote server present .. serving on ({hostname}||{ip_addr}):{PORT}')
    # Wait until test connection is received from client socket #
    test_sock, _ = sock.accept()

    try:
        # Once test connection is active, continually send null bytes
        # till an error is raised due to the connection closing #
        while True:
            test_sock.sendall(b'\x00')

    # When error is raised because client side is closed #
    except socket.error:
        pass

    # Wait to accept final connection #
    client_sock, address = sock.accept()
    # Set the socket to non-blocking #
    client_sock.setblocking(False)
    # Notify user of successful connection #
    print(f'\n[!] Connection established to {address[0]}:{PORT}')

    return client_sock


def main():
    """
    Runs test network check to see if remote system is already established as a server. Depending on
    the result, the system is established as client or server to avoid centralized server. After
    the network socket is established, background daemon threads are spawned to display program
    output, handle monitoring outing data directory, and handle writing incoming data. Finally, the
    main thread polls the network socket in a non-blocking manner; getting data from the send queue
    and sending it, and reading data from the socket and putting it in the read queue.

    :return:  Nothing
    """
    # If the remote host is already listening for connections #
    if port_check(TARGET_IP, PORT):
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

    # Pass socket instance to list to get inputs/outputs #
    inputs = [conn]
    outputs = [conn]
    # send_progress = None
    # recv_progress = None

    try:
        while True:
            # Polls socket inputs, outputs, and errors. Returns socket file descriptor lists tuple #
            read_data, send_data, conn_errs = select.select(inputs, outputs, inputs)

            # If the send queue has data to send #
            if not SEND_QUEUE.empty():
                # Iterate through available send sockets #
                for sock in send_data:
                    # Get a chunk of data from send queue #
                    chunk = SEND_QUEUE.get()

                    OUTPUT_QUEUE.put(f'Data to be sent: {chunk.decode()}\n')

                    # If chunk contain the file name and size #
                    if BUFFER_DIV in chunk:
                        # Parse the file name and size from the sent start bytes #
                        file_name, file_size = parse_start_bytes(chunk, BUFFER_DIV)

                        # If the file conversion function returns string indicating error #
                        if isinstance(file_size, str):
                            # Put the returned error in error queue for logging thread #
                            ERROR_QUEUE.put(file_size)
                            time.sleep(1)
                            sys.exit(2)

                        # # Setup progress-bar for file output #
                        # send_progress = tqdm(range(file_size), f'Sending {file_name}', unit='B',
                        #                 unit_scale=True, unit_divisor=BUFFER_SIZE)

                    # Send the chunk of data through the TCP connection #
                    sock.sendall(chunk)

                    # # If progress bar has not been initialized #
                    # if not send_progress:
                    #     # Put error code error queue to be logged #
                    #     ERROR_QUEUE.put('Send data progress bar not properly initialized')
                    #     time.sleep(1)
                    #     sys.exit(3)

                    # # Update the progress bar #
                    # send_progress.update(len(chunk))

                    # Remove chunk from outputs list #
                    outputs.remove(sock)
                    break

            # Iterate through available receive sockets #
            for sock in read_data:
                # Receive 4096 bytes of data from remote host #
                chunk = sock.recv(BUFFER_SIZE)

                # If the socket received data #
                if len(chunk) > 0:
                    OUTPUT_QUEUE.put(f'Data received: {chunk.decode()}\n')

                    # If chunk contain the file name and size #
                    if BUFFER_DIV in chunk:
                        # Parse the file name and size from the received start bytes #
                        file_name, file_size = parse_start_bytes(chunk, BUFFER_DIV)

                        # If the file conversion function returns string indicating error #
                        if isinstance(file_size, str):
                            # Put the returned error in error queue for logging thread #
                            ERROR_QUEUE.put(file_size)
                            time.sleep(1)
                            sys.exit(4)

                        # # Setup progress-bar for file input #
                        # recv_progress = tqdm(range(file_size), f'Receiving {file_name}', unit='B',
                        #                      unit_scale=True, unit_divisor=BUFFER_SIZE)

                    # Put received data into read queue #
                    READ_QUEUE.put(chunk)

                    # # If progress bar has not been initialized #
                    # if not recv_progress:
                    #     # Put error code error queue to be logged #
                    #     ERROR_QUEUE.put('Receive data progress bar not properly initialized')
                    #     time.sleep(1)
                    #     sys.exit(5)

                    # # Update the progress bar #
                    # recv_progress.update(len(chunk))

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

    # If Ctrl + C is detected #
    except KeyboardInterrupt:
        print('\n[!] Ctrl + C detected .. exiting program')

    # If an error is raised because the
    # other end of the connection closed #
    except OSError:
        print('\n[!] Connection was closed on the other end .. exiting program')

    # Close the connection #
    conn.close()


if __name__ == '__main__':
    # Get the current working directory #
    path = Path('.')
    # Group critical folders for operation #
    folders = ('Incoming', 'Outgoing')
    # Format log path and name #
    log_name = path / 'rft.log'
    # Format incoming/outgoing folder path and name #
    in_path = path / folders[0]
    out_path = path / folders[1]

    # Initialize the logging facilities #
    logging.basicConfig(level=logging.DEBUG, filename=str(log_name.resolve()))
    # Create non-existing data transfer directories #
    [Path(folder).mkdir(exist_ok=True) for folder in folders]
    # Initialize the output display thread #
    logger_thread = Thread(target=logger, daemon=True, args=())
    # Start the program output daemon thread #
    logger_thread.start()
    # Exit code #
    RET = 0

    try:
        main()

    # If unknown exception occurs #
    except Exception as err:
        # Log error and set error exit code #
        logging.exception('Unknown exception occurred: %s\n\n', err)
        RET = 1

    sys.exit(RET)

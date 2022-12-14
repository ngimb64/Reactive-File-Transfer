# pylint: disable=E0401,W0106
""" Built-in modules """
import base64
import logging
import os
import queue
import select
import sys
import time
from pathlib import Path
from threading import Thread, Lock
# External modules #
from rich.progress import Progress
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer
# Custom modules #
from Modules.crypto_handlers import chacha_decrypt, chacha_encrypt
from Modules.network_handlers import client_init, port_check, server_init
from Modules.utils import banner_display, base64_parse, error_query, parse_start_bytes, print_err, \
                          secure_delete, validate_ip, validate_port


# Global variables #
BUFFER_SIZE = 4096
BUFFER_DIV = b'<$>'
SEND_QUEUE = queue.Queue()
READ_QUEUE = queue.Queue()
PARSE_MUTEX = Lock()
ERR_MUTEX = Lock()


def auto_file_incoming():
    """
    Polls the read queue for incoming chunks of data and writes data to file name until delimiter
    is detected.

    :return:  Nothing, runs as background daemon thread until main thread exits.
    """
    while True:
        # Get the initial string with the file name and size #
        title_chunk = READ_QUEUE.get()

        # Obtain exclusive access to function with mutex lock #
        with PARSE_MUTEX:
            # Parse the file name and size from the received start bytes #
            file_name, _ = parse_start_bytes(title_chunk.encode(), BUFFER_DIV)

        # Format the incoming file path #
        file_path = in_path / file_name

        try:
            # Open the incoming file name in append bytes mode #
            with file_path.open('a') as in_file:
                while True:
                    # Get the incoming data from the read queue #
                    incoming_data = READ_QUEUE.get()

                    # If the incoming data specifies end of file (EOF) #
                    if incoming_data == '<EOF>':
                        # Exit the file write loop #
                        break

                    # Write the incoming data to the specified file name #
                    in_file.write(incoming_data)

        # If error occurs during file operation #
        except (IOError, OSError) as file_err:
            # Obtain exclusive access to function with mutex lock #
            with ERR_MUTEX:
                # Lookup the file error and log it #
                error_query(str(file_path.resolve), 'a', file_err)


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
            file_size = file_path.stat().st_size
            unread_data = file_size
            # Format file name and size with divider as start bytes #
            start_bytes = f'{file.name}{BUFFER_DIV.decode()}{file_size}'.encode()
            # Send start bytes for setup and progress bar on remote system #
            SEND_QUEUE.put(start_bytes)

            try:
                # Open file in bytes read mode to put in send queue #
                with file_path.open('rb') as send_file:
                    # While there is data left in the file to be read #
                    while unread_data > 0:
                        # If amount of unread data will fit in one chunk #
                        if unread_data <= BUFFER_SIZE - 5:
                            # Put last of the data in send queue #
                            data = send_file.read(unread_data)
                        # If amount of unread data exceeds size of data buffer #
                        else:
                            # Put max chunk in send queue #
                            data = send_file.read(BUFFER_SIZE - 5)

                        # Put read data chunk in send queue and subtract from read bytes #
                        SEND_QUEUE.put(data)
                        unread_data -= len(data)

            # If error occurs during file operation #
            except (IOError, OSError) as file_err:
                # Obtain exclusive access to function with mutex lock #
                with ERR_MUTEX:
                    # Lookup the file error and log it #
                    error_query(str(file_path.resolve()), 'rb', file_err)
                    continue

            # Put EOF descriptor for remote system to know transfer is complete #
            SEND_QUEUE.put(b'<EOF>')
            # Delete the file from outgoing folder and overwrite
            # numerous passes of random data #
            secure_delete(file_path)


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
            time.sleep(15)

    # If Ctrl+C is detected #
    except KeyboardInterrupt:
        # Stop the file monitoring object #
        observer.stop()

    # Join the file monitoring child process to terminate #
    observer.join()


def main():
    """
    Runs test network check to see if remote system is already established as a server. Depending on
    the result, the system is established as client or server to avoid centralized server. After
    the network socket is established, background daemon threads are spawned to display program
    output, handle monitoring outing data directory, and handle writing incoming data. Finally, the
    main thread polls the network socket in a non-blocking manner. It gets data from the send queue,
    encrypts, and sends it. As well as, reading data from the socket, decrypting it, and putting it
     in the read queue to be written on the remote system's disk.

    :return:  Nothing
    """
    # If there are less than three arguments passed into program #
    if len(sys.argv) < 3:
        # Print usage error and exit #
        print_err('Improper number of args passed into program .. Usage is: (python (Windows) ||'
                  'python3 (Linux)) reactive_file_transfer.py <ip address> <port>')
        sys.exit(2)

    # Run the input parameters through validation functions #
    target_ip_arg = validate_ip(sys.argv[1])
    port_arg = validate_port(sys.argv[2])

    # Display the programs banner #
    banner_display()

    try:
        # If the remote host is already listening for connections #
        if port_check(target_ip_arg, port_arg):
            # Act as the client side of connection #
            conn, symm_algo = client_init(target_ip_arg, port_arg)
        # If no remote listeners are active #
        else:
            # Act as the server side of the connection #
            conn, symm_algo = server_init(port_arg)

    except KeyboardInterrupt:
        print('\n[!] Ctrl + C detected .. exiting program')
        sys.exit(0)

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

    try:
        # Initialize the rich progress bar instance #
        with Progress() as progress:
            while True:
                # Polls socket inputs, outputs, and errors. Returns socket file descriptor tuple #
                read_data, send_data, conn_errs = select.select(inputs, outputs, inputs)

                # If the send queue has data to send #
                if not SEND_QUEUE.empty():
                    # Iterate through available send sockets #
                    for sock in send_data:
                        # Get a chunk of data from send queue #
                        chunk = SEND_QUEUE.get()

                        # If chunk contain the file name and size #
                        if BUFFER_DIV in chunk:
                            # Obtain exclusive access to function with mutex lock #
                            with PARSE_MUTEX:
                                # Parse the file name and size from the sent start bytes #
                                file_name, file_size = parse_start_bytes(chunk, BUFFER_DIV)

                            # Setup progress-bar for file output #
                            send_progress = progress.add_task(f'[green]Sending  {file_name} ..',
                                                              total=(file_size + len(chunk)))

                        logging.info('Send data length before encryption: %s\n', len(chunk))

                        # Encrypt and encode the data chunk to be sent #
                        crypt_chunk = chacha_encrypt(symm_algo, chunk)
                        encoded_chunk = base64.urlsafe_b64encode(crypt_chunk)

                        logging.info('Send data length after encryption: %s\n', len(crypt_chunk))

                        # Send the chunk of data through the TCP connection #
                        sock.sendall(encoded_chunk + b'<EOL>')
                        # Update the progress bar #
                        progress.update(send_progress, advance=len(chunk))

                # Iterate through available receive sockets #
                for sock in read_data:
                    # Receive 4096 bytes of data from remote host #
                    chunk = sock.recv(BUFFER_SIZE)

                    # If the socket received data #
                    if len(chunk) > 0:
                        logging.info('Initial recv chunk of data: %s\n', chunk)

                        # Split up any combined chunks of data as list #
                        parsed_inputs = chunk.split(b'<EOL>')
                        # Filters out any empty strings in list #
                        parsed_inputs = b' '.join(parsed_inputs).split()

                        # Iterate through parsed read bytes as string list #
                        for item in parsed_inputs:
                            logging.info('Recv data length before decryption: %s\n', len(item))
                            logging.info('Recv data before decryption: %s\n', item)

                            # Trim any base64 padding from received data #
                            item = base64_parse(item)
                            # Decode the base64 item #
                            decoded_crypt = base64.urlsafe_b64decode(item +
                                                                     (b'=' * (4 - len(item) % 4)))
                            # Decrypt each item in parsed_inputs per iteration #
                            plain_item = chacha_decrypt(symm_algo, decoded_crypt)

                            logging.info('Recv data length after decryption: %s\n', len(plain_item))
                            logging.info('Recv data after decryption: %s\n', plain_item)

                            # If chunk contain the file name and size #
                            if BUFFER_DIV in plain_item:
                                # Obtain exclusive access to function with mutex lock #
                                with PARSE_MUTEX:
                                    # Parse the file name and size from the received start bytes #
                                    file_name, file_size = parse_start_bytes(plain_item, BUFFER_DIV)

                                # Setup progress-bar for file input #
                                recv_progress = progress.add_task(f'[red]Receiving  {file_name} ..',
                                                                  total=file_size)

                            # Put received data into read queue #
                            READ_QUEUE.put(plain_item.decode())
                            # Update the progress bar #
                            progress.update(recv_progress, advance=len(item))

                for sock in conn_errs:
                    print_err('Error occurred during socket operation')
                    # Put message in error queue to be displayed stderr #
                    logging.error('Error occurred during socket operation: %s\n', sock)
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
    logging.basicConfig(filename=str(log_name.resolve()), level=logging.DEBUG,
                        format='%(asctime)s line%(lineno)d::%(funcName)s[%(levelname)s]>>'
                        ' %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
    # Create non-existing data transfer directories #
    [Path(folder).mkdir(exist_ok=True) for folder in folders]
    # Exit code #
    RET = 0

    try:
        main()

    # If unknown exception occurs #
    except Exception as err:
        # Log error and set error exit code #
        logging.exception('Unknown exception occurred: %s\n', err)
        RET = 1

    sys.exit(RET)

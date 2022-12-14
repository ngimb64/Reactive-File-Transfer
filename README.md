# Reactive File Transfer (RFT)

[//]: # (![alt text]&#40;https://github.com/ngimb64/Reactive-File-Transfer/blob/main/ReactiveFileTransfer.gif?raw=true&#41;)

[//]: # (![alt text]&#40;https://github.com/ngimb64/Reactive-File-Transfer/blob/main/ReactiveFileTransfer.png?raw=true&#41;)

&#9745;&#65039; Bandit verified<br>
&#9745;&#65039; Synk verified<br>
&#9745;&#65039; Pylint verified 9.87/10

## Prereqs 
This program runs on Windows and Linux, written in Python version 3.10.6

## Purpose
Reactive file transfer establishes an automated multi-directional encrypted file transfer service with password protection.
By utilizing active file system monitoring, the program features designated directories that are synced across remote systems.
When a file system modification is activated due to moving data in the designated Outgoing directory, it automatically transfers to the remote systems Incoming directory.
RFT features a combination of symmetrical encryption with HMAC integrity check that is protected with AESCCM authenticated encryption during transmission.

## Installation
- Run the setup.py script to build a virtual environment and install all external packages in the created venv.

> Examples:<br> 
>       &emsp;&emsp;- Windows:  `python setup.py venv`<br>
>       &emsp;&emsp;- Linux:  `python3 setup.py venv`

- Once virtual env is built traverse to the (Scripts-Windows or bin-Linux) directory in the environment folder just created.
- For Windows, in the venv\Scripts directory, execute `activate` or `activate.bat` script to activate the virtual environment.
- For Linux, in the venv/bin directory, execute `source activate` to activate the virtual environment.
- If for some reason issues are experienced with the setup script, the alternative is to manually create an environment, activate it, then run pip install -r packages.txt in project root.

## How To Use
- Ensure the prereqs are met (most later versions of 3 should work) and the installation steps have been followed
- Run the program as instructed below and enter session password when prompted

> Examples:<br>
>       &emsp;&emsp;- Windows: `python reactive_file_transfer.py <remote_ip> <remote_port>`<br>
>       &emsp;&emsp;- Linux: `python3 reactive_file_transfer.py <remote_ip> <remote_port>`

- Once the network connection is established and authenticated, the program should be ready to transfer files
- Simply drag or move data into the Outgoing folder for the remote host to receive it in their Incoming folder and vice versa

## Function Layout
-- reactive_file_transfer.py --
> auto_file_incoming &nbsp;-&nbsp; Polls the read queue for incoming chunks of data and writes data to file name until delimiter is detected.

> OutgoingFileDetector &nbsp;-&nbsp; Watchdog event is triggered per file system modification is designated outgoing folder.
>                                    Data is read from the event file and feed into the send queue to be transferred through the network socket in chunks of data set by BUFFER_SIZE pseudo-constant.<br><br>
> on_modified &nbsp;-&nbsp; Watchdog event is triggered per file system modification is designated outgoing folder.
>                           Data is read from the event file and feed into the send queue to be transferred through the network socket in chunks of data set by BUFFER_SIZE pseudo-constant.

> auto_file_outgoing &nbsp;-&nbsp; Registers watchdog file system monitoring directory and continually monitors file system to trigger OutgoingFileDetector() watchdog event.

> main &nbsp;-&nbsp; Runs test network check to see if remote system is already established as a server.
>                    Depending on the result, the system is established as client or server to avoid centralized server.
>                    After the network socket is established, background daemon threads are spawned to display program output, handle monitoring outing data directory, and handle writing incoming data. 
>                    Finally, the main thread polls the network socket in a non-blocking manner; getting data from the send queue and sending it, and reading data from the socket and putting it in the read queue.

-- crypto_handlers.py --
> aesccm_decrypt &nbsp;-&nbsp; Decrypts the symmetrical fernet key used for encrypting and decrypting transfer data.

> aesccm_encrypt &nbsp;-&nbsp; Encrypts the symmetrical fernet key used for encrypting and decrypting transfer data.

> fernet_decrypt &nbsp;-&nbsp; Utilizes the passed in fernet key to decrypt the passed in data in a error handled manner.

> fernet_encrypt &nbsp;-&nbsp; Utilizes the passed in fernet key to encrypt the passed in data in a error handled manner.

-- network_handlers.py --
> client_init &nbsp;-&nbsp; Function is called after test socket connection attempt is successful indicating a server is already established on the other end.
>                           After gathering session password from user, the final socket connection is re-setup and continually attempted on five second intervals until successful. 
>                           Once connected, the input password is hashed and send to the remote system for authentication. 
>                           If successfully authenticated, an encrypted symmetrical key is sent back and decrypted using the authenticated password to be returned to main.

> port_check &nbsp;-&nbsp; Creates TCP socket and checks to see if remote port on specified IP address is active.

> server_init &nbsp;-&nbsp; Function is called after test socket connection attempt is not successful indicating a server is current not present on the other end. 
>                           After gathering the session password, the hostname is queried and used to get the IP address used to bind to the port. 
>                           The server then waits for the incoming test connection, which when connected, null bytes are continually sent until an error is raised to the client side timing out. 
>                           The raised error is ignored and execution is passed to wait for the final incoming connection. 
>                           Once established, the server end waits for the clients hashed password to arrive and verifies it through hashing algorithm. 
>                           If successful, a key set is generated and encrypted with the session password and sent back to the client. 
>                           Finally, the server waits to receive a confirmation status message to ensure the key was received and decrypted.

-- utils.py --
> banner_display &nbsp;-&nbsp; Renders and displays the programs pyfiglet banner.

> cha_init &nbsp;-&nbsp; Initializes the ChaCh20 algorithm object. 

> error_query &nbsp;-&nbsp; Looks up the errno message to get description.

> int_convert &nbsp;-&nbsp; Convert the passed in size as string to int, handles errors accordingly.

> parse_start_bytes &nbsp;-&nbsp; Takes the input data chunk containing file name and size to be transferred with divider in the middle.

> pass_input &nbsp;-&nbsp; Gathers user input for session password and second password input for verification.

> print_err &nbsp;-&nbsp; Displays error via stderr.

> secure_delete &nbsp;-&nbsp; Overwrite file data with random data number of specified passes and overwrite with random data.

> split_handler &nbsp;-&nbsp; Takes the passed in data and splits it based on specified divisor in error handled procedure.

> validate_ip &nbsp;-&nbsp; Checks the input target IP arg against regex validation.

> validate_port &nbsp;-&nbsp; Checks the input port arg against regex validation and max value.

## Exit Codes
-- reactive_file_transfer.py --
> 0 - Successful operation (__main__)<br>
> 1 - Unknown exception occurred (__main__)<br>
> 2 - Improper number of args were passed in on execution (main)<br> 

-- crypto_handlers.py --
> 8 - Error occurred during AESCCM algorithm initialization or session key decryption (aesccm_decrypt)<br>
> 10 - Error occurred encrypting sessions symmetrical cryptographic key (aesccm_encrypt)<br>
> 12 - Error occurred encrypting data chunk to be sent to remote host (fernet_encrypt)<br>
> 13 - Error occurred decrypting data chunk received by remote host (fernet_decrypt)<br>

-- network_handlers.py --
> 6 - Password authentication failed on remote server host (client_init)<br>
> 9 - Received client hash does not match established session password (server_init)<br>
> 11 - If error occurred on the client side parsing and decrypting session symmetrical key (server_init)<br>

-- utils.py --
> 3 - Error occurred validating input IP address arg (validate_ip)<br>
> 4 - Error occurred validating input port numer arg (validate_port)<br>
> 5 - Error occurred rendering pyfiglet program banner (banner_display)<br>
> 7 - The retrieved key data lacks multiple values to split (split_handler)<br>
> 14 - Error occurred converting string number to integer (int_convert)<br>
> 15 - If three consecutive errors occur overwriting and deleting file data (secure_delete)<br>
from socketserver import BaseRequestHandler
from Servers import TCPServer

from cmd import Cmd
from os import path, urandom, mkdir, rmdir, remove, rename, scandir
from hashlib import pbkdf2_hmac
from string import digits, whitespace, punctuation
from platform import platform
from socket import socket, AF_INET, SOCK_STREAM, timeout
from datetime import datetime, timedelta
from threading import Thread
from itertools import count
from json import load, dump

import logging

logging.basicConfig(level=logging.INFO)
sep = r'/'

# FTP Protocol described in RFC-959
# https://tools.ietf.org/html/rfc959


class ActiveConnection(Thread):
    def __init__(self, arg, binary):
        Thread.__init__(self, target=self.connect)

        addr_info = arg.split(',', 5)
        self.ip = '.'.join(addr_info[:4])
        self.port = (int(addr_info[4]) << 8) | int(addr_info[5])
        self.binary = binary

        self.sock = socket(AF_INET, SOCK_STREAM)
        self.fd_write = self.sock.makefile('wb' if binary else 'w')
        self.fd_read = self.sock.makefile('rb' if self.binary else 'r')

    def connect(self):
        self.sock.connect((self.ip, self.port))

    def send(self, data):
        self.fd_write.write(data)

    def send_blank(self):
        self.fd_write.write(b'' if self.binary else '')

    def send_crlf(self):
        self.fd_write.write(b'\r\n' if self.binary else '\r\n')

    def close(self):
        self.sock.close()

    def update(self, binary):
        self.fd_write = self.sock.makefile('wb' if binary else 'w')
        self.fd_read = self.sock.makefile('rb' if self.binary else 'r')

    def read(self, fileloc, skip):
        with open(fileloc, 'rb' if self.binary else 'r') as file:
            self.fd_write.write(file.read())

    def write(self, fileloc, skip):
        with open(fileloc, 'wb' if self.binary else 'w') as file:
            file.write(self.fd_read.read())

    def append(self, fileloc, skip):
        with open(fileloc, 'ab' if self.binary else 'a') as file:
            file.write(self.fd_read.read())


class PassiveConnection(Thread):
    def __init__(self, ip, binary, port=0, ):
        Thread.__init__(self, target=self.connect)
        self.sock = socket(AF_INET, SOCK_STREAM)
        self.sock.bind((ip, port))
        self.binary = binary

        self.sock.listen(1)

    def connect(self):

        sock, _ = self.sock.accept()
        self.sock.close()
        self.sock = sock
        self.fd_write = sock.makefile('wb' if self.binary else 'w')
        self.fd_read = sock.makefile('rb' if self.binary else 'r')

    def get_str(self):
        ip, port = self.sock.getsockname()
        p1 = (port & 0xff00) >> 8
        p2 = port & 0x00ff
        return f'{ip.replace(".", ",")},{p1},{p2}'

    def send(self, data):
        self.fd_write.write(data)

    def send_blank(self):
        self.fd_write.write(b'' if self.binary else '')

    def send_crlf(self):
        self.fd_write.write(b'\r\n' if self.binary else '\r\n')

    def close(self):
        self.sock.close()

    def update(self, binary):
        self.binary = binary

    def read(self, fileloc, skip):
        with open(fileloc, 'rb' if self.binary else 'r') as file:
            self.send(file.read()[skip:])

    def write(self, fileloc, skip):
        with open(fileloc, 'wb' if self.binary else 'w') as file:
            file.write(self.fd_read.read())

    def append(self, fileloc, skip):
        with open(fileloc, 'ab' if self.binary else 'a') as file:
            file.write(self.fd_read.read())


class FTPCommandHandler(BaseRequestHandler, Cmd):
    def setup(self):
        self.server.active = self.server.active + 1

        self.request.settimeout(60*5)
        sock_read = self.request.makefile('r')
        self.sock_write = self.request.makefile('w')

        Cmd.__init__(self, stdin=sock_read)
        self.use_rawinput = False
        self.prompt = ''

        self.logging = logging.getLogger('(Not signed in)')
        self.logging.propagate = False

        fh = logging.FileHandler(f'{self.server.root}{path.sep}logs{path.sep}{self.client_address[0]}.log')
        fh.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
        self.logging.addHandler(fh)

        self.logging.info('CONNECTED')

        self.username = ''
        self.home = ''
        self.selected = sep
        self.binary = False
        self.history = []
        self.connection = None
        self.skip = 0
        self.rename = ''

    def finish(self):
        # Let server know that this instance if finishing.
        self.server.active = self.server.active - 1
        # Detach handlers from the logging instance.
        # Prevents issue where if same IP connects, multiple
        # Entries will be logged for single command.
        for handler in self.logging.handlers:
            self.logging.removeHandler(handler)

    def handle(self):
        try:
            # FTP initial READY message to client
            self.send('220 Service ready.')
            # Loop through the sequence of getting commands
            # Until we quit or have an error.
            self.cmdloop()
        except timeout:
            # If client doesn't send a command before the timeout
            # Close connection.
            self.logging.info('Client timed out. Closing connectino.')
            self.request.close()
        except (ConnectionAbortedError, ConnectionResetError):
            # If the connection to client is lost
            # IE: Network outage
            self.logging.info('closed connection forcefully.')
        except Exception as e:
            # If an unexpected error happens, log it.
            self.logging.exception(e)

    def precmd(self, line):
        if self.server.shutingdown:
            # Check to see if server shutting down
            return 'QUIT'

        # Every command given logged.
        self.logging.info(f'REQUEST - {line}')

        # Allow for non-case sensitive commands.
        return line.lower()

    def postcmd(self, stop, line):
        if stop:
            # If client quiting.
            # Otherwise, will retain username in
            # Logs between sessions. (Not wanted)
            self.logging.name = '(Not signed in)'

        return stop

    def check_home(self, dir):
        # Measure to make sure that command isn't
        # Trying to break out of the user's file system.
        # Makes sure that the users root directory is a common
        # path to the requested location.

        return path.commonpath(
                    (
                            # Find common path between requested path and
                            # Home directory
                            path.abspath(self.home),
                            path.abspath(dir)
                    )
                                ) == path.abspath(self.home)

    def exists(self, fileloc):
        # Measure to check that the given file path actually exists under the home directory.

        return path.exists(f'{self.home.rstrip(sep)}{sep}{self.selected.rstrip(sep)}{sep}{fileloc}')

    def true_fileloc(self, fileloc=''):
        # Measure to make sure that when reading, writing, listing files, the
        # Actual location is under the home directory.
        return f'{self.home.rstrip(sep)}{sep}{self.selected.rstrip(sep)}{sep}{fileloc}'

    def format_entry(self, entry):
        # Format os.path.DirEntry instances for LIST command.

        # Get stats of file.
        stats = entry.stat()

        # Identify if file(-) or directory(d)
        type = '-' if entry.is_file() else 'd'

        # Generic reading, writing information. To Be Expanded later.
        access = f'rw-r--r-- 1 {self.username}' if entry.is_file() else f'rwxr-xr-x 1 {self.username}'

        # Size of file / directory.
        size = f'{stats.st_size}'.rjust(13, ' ')

        if datetime.now()-timedelta(days=30*6) > datetime.fromtimestamp(stats.st_mtime):
            # If last modification was more than 6 months ago
            # Set format to month, day, year format
            modification = datetime.fromtimestamp(stats.st_mtime).strftime('%b %d %Y')
        else:
            # If last modification was less than 6 months ago
            # Set format to month, day, hour, minute format
            modification = datetime.fromtimestamp(stats.st_mtime).strftime('%b %d %H:%M')

        return f'{type}{access}{size} {modification} {entry.name}'

    def send(self, data):
        self.logging.info(f'RESPONSE - {data}')
        with self.request.makefile('wb' if self.binary else 'w') as sock:
            sock.write(f'{data}\r\n'.encode() if self.binary else f'{data}\r\n')

    def default(self, line):
        # If client tries to give an unexpected command.
        self.send('500 Syntax error, command unrecognized.')

    def do_EOF(self, arg):
        # If we recieve an EOF from the file descriptor.
        self.logging.info('closed connection forcefully.')
        return True

    def do_noop(self, arg):
        # No OP command.
        # Does nothing but send an OK response.
        self.send('200 Command okay.')

    def do_user(self, username):
        if len(username) == 0 or ' ' in username or username[0] in whitespace+punctuation+digits:
            # Check for invalid characters in username
            self.send('501 Failed to log in: Bad characters in username.')
            return

        # Check to see if a private user is trying to login
        if self.server.check_username(username):
            self.username = username
            if self.server.req_pass:
                # If a password is required to log in, ask for password
                self.send('331 User name okay, need password.')
                return
            # If a password isn't required to log in, allow to proceed'

            # Set home directory
            self.home = self.server.login(username, '')
            # Set name for logging to the username.
            self.logging.name = self.username
            self.send('230 User logged in, proceed.')
        else:
            self.send('530 User name not okay.')

    def do_pass(self, password):
        if self.server.req_pass:

            if set(password) & set(whitespace):
                # Check for invalid characters in username
                self.send('501  failed to log in: Bad password characters.')
                return

            if self.username == '':
                # Must use USER command before PASS command
                self.send('503 Bad sequence of commands.')
                return

            # Try to get a directory for a username / password combination.
            directory = self.server.login(self.username, password)
            if directory:
                # If the directory is a non-empty string
                # Log in succeeded.
                # Set username for logging
                self.logging.name = self.username
                # Set home directory
                self.home = directory
                self.send('230 User logged in, proceed.')
            else:
                self.send('530 Password not okay.')
                return True

        else:
            # If a password isn't needed, let client know.
            self.send('202 Command not implemented, password not required.')

    def do_acct(self, arg):
        # Could be used to allow an authorized user to use multiple accounts (IE: Sub accounts)
        self.send('202 Command not implemented, Server does not support ACCT command.')

    def do_cwd(self, arg):
        if self.home == '':
            # If we aren't signed in yet.
            self.send('530 Not logged in.')
            return

        # Change Working Directory.
        if arg == '':
            # CWD must have arguments
            self.send('501 Syntax error in parameters or arguments.')
            return

        if arg == '..':
            # Prevent breaking out of local filesystem.
            # Also allows us to go back one step in history.
            return self.do_cdup('')

        # Identify path as a child of the home directory
        new_dir = self.true_fileloc(arg)

        if path.exists(new_dir) and path.isdir(new_dir):
            # First make sure the path exists and is a directory.
            if self.check_home(new_dir):
                # Add current location to history to go back to.
                self.history.append(self.selected)
                # Set new current location.
                self.selected = f'{self.selected.strip(sep)}{arg.strip(sep)}{sep}'
                self.send(f'250 New Working Directory is: {self.selected}.')
                return

        # If either file not found or outside home directory.
        self.send(f'550 {arg}: No such file or directory found.')

    def do_xcwd(self, arg):
        # Some clients treat XCWD as CWD
        return self.do_cwd(arg)

    def do_cdup(self, arg):
        if self.home == '':
            # Need to be signed in.
            self.send('530 Need to sign in.')
            return

        if arg:
            # CDUP can not have arguments
            self.send('501 Syntax error in parameters or arguments.')
            return
        if self.history:
            self.selected = self.history.pop(-1)
            self.send('250 Okay.')
        else:
            self.send('550 Unable to go further back.')

    def do_xcup(self, arg):
        # Some clients treat XCUP the same as CDUP
        return self.do_cdup(arg)

    def do_smnt(self, arg):
        # Used to mount different filesystems.
        self.send('202 Command not implemented, Server does not support SMNT command.')

    def do_rein(self, arg):
        # Reset all parameters to defaults.
        self.logging.name = '(Not signed in)'
        self.logging.info(f'{self.username} Logged out.')
        self.username = ''
        self.home = ''
        self.selected = sep
        self.binary = False
        self.history = []
        self.connection = None
        self.skip = 0
        self.rename = ''
        self.send('220 Service ready.')

    def do_quit(self, arg):
        if arg:
            # QUIT command can not accept any arguments
            self.send('500 Syntax error, command unrecognized.')
            return

        if self.server.shutingdown:
            # In the case of the server shutting down, notify client
            self.logging.info('closed connection.')
            self.send('421 Service not available, closing control connection.')
            return True

        self.logging.info('closed connection.')
        self.send('221 Service closing control connection.')
        return True

    def do_port(self, arg):
        if self.home == '':
            # Must be signed in to use PORT
            self.send('530 Need to sign in.')
            return

        if arg.count(',') != 5:
            # PORT must have an argument in format H1,H2,H3,H4,p1,p2
            self.send('501 Syntax error in parameters or arguments.')
            return

        # Create an active connection to the address defined in the arg
        self.connection = ActiveConnection(arg, binary=self.binary)
        self.send('200 Ready to connect.')
        return

    def do_pasv(self, arg):
        if self.home == '':
            # Must be signed in to use PASV
            self.send('530 Need to sign in.')
            return

        if arg:
            # PASV can not have arguments
            self.send('501 Syntax error in parameters or arguments.')

        # Create a passive connection object
        self.connection = PassiveConnection(self.server.to_ip, binary=self.binary)

        self.send(f'227 Entering passive mode ({self.connection.get_str()}).')

    def do_type(self, arg):
        if arg == '':
            # Check to make sure parameters were provided
            self.send('501 Syntax error in parameters or arguments.')
            return


        if self.selected == '':
            # Check to see if we're logged in.
            self.send('530 Not logged in.')
            return

        if arg == 'a' or arg == 'a n':
            # If ASCII or ASCII Non-print
            self.binary = False
            self.send('200 Binary flag set to OFF')
        elif arg == 'i' or arg == 'l 8':
            # If Image or Bytes
            self.binary = True
            self.send('200 Binary flag set to ON')
        else:
            self.send('504 Command not implemented for that parameter.')
            return

        if self.connection:
            self.connection.update(self.binary)

    def do_stru(self, arg):
        if arg == 'f':
            self.send('200 FILE structure selected.')
            return
        self.send('504 Command not implemented for that parameter.')

    def do_mode(self, arg):
        if arg == 's':
            self.send('200 STREAM mode selected.')
            return
        self.send('504 Command not implemented for that parameter.')

    def do_retr(self, arg):

        self.send('150 Ready to transmit.')

        self.connection.start()
        self.connection.join(timeout=30)

        file = self.true_fileloc(arg)

        if path.isdir(file):
            self.send('451 Requested action aborted. Can not download directory like a file.')
            return

        if not path.exists(file):
            self.send('451 Requested action aborted. Can not find file.')
            return

        self.connection.read(file, self.skip)
        self.connection.close()
        self.connection = None
        self.skip = 0

        self.send('226 Done transmitting.')

    def do_stor(self, arg):
        self.send('150 Ready to recieve.')

        self.connection.start()
        self.connection.join(timeout=30)

        file = self.true_fileloc(arg)

        try:
            self.connection.write(file, self.skip)
        except Exception as e:
            self.logging.error(e)
            self.send('451 Requested action aborted. Local error in processing.')
            return
        self.connection.close()
        self.connection = None
        self.skip = 0

        self.send('226 Done recieving.')

    def do_stou(self, file):
        self.send(b'150 Ready to recieve.')

        self.connection.start()
        self.connection.join(timeout=30)

        if not file:
            file = 'new_file'

        if self.exists(file):
            head, tail = path.splitext(file)
            for i in count(1, 1):
                test = f'{head}({i}){tail}'
                if not self.exists(test):
                    file = test
                    break
        try:
            self.connection.write(self.true_fileloc(file), self.skip)
        except Exception as e:
            self.logging.error(e)
            self.send('451 Requested action aborted. Local error in processing.')
            return

        self.connection.close()
        self.connection = None
        self.skip = 0

        self.send(f'226 Saved as {file}.')

    def do_appe(self, arg):

        self.send('150 Ready to recieve.')

        self.connection.start()
        self.connection.join(timeout=30)

        file = self.true_fileloc(arg)

        try:
            self.connection.append(file, self.skip)
        except Exception as e:
            self.logging.error(e)
            self.send('451 Requested action aborted. Local error in processing.')
            return
        self.connection.close()
        self.connection = None
        self.skip = 0

        self.send('226 Done recieving.')

    def do_allo(self, arg):
        self.send('202 Command not implemented, superfluous at this site.')

    def do_rest(self, arg):
        if arg.isalnum():
            self.skip = int(arg)
            self.send(f'350 set new skip value ({arg}).')

    def do_rnfr(self, arg):
        file = self.true_fileloc(arg)
        if path.exists(file) and self.check_home(file):
            self.send('350 file exists and is ready to be renamed.')
            self.rename = file

    def do_rnto(self, arg):
        if self.rename:
            file = self.true_fileloc(arg)
            if self.check_home(file):
                rename(self.rename, file)
                self.rename = ''
                self.send('250 file renamed successfully.')

    def do_abor(self, arg):
        # Used to abort transfer of file(s)
        self.send('202 Command not implemented, Server does not support ABOR command.')

    def do_dele(self, arg):
        if self.exists(arg):
            try:
                remove(self.true_fileloc(arg))
                self.send('250 File removed.')
                return

            except Exception as e:
                self.logging.error(e)

        self.send('450 Requested file action not taken.')

    def do_rmd(self, arg):

        file = self.true_fileloc(arg)
        self.send(f'257 Ready to remove directory: "{arg}"')

        try:
            rmdir(file)
            self.send('250 Directory removed.')

        except Exception as e:
            self.logging.error(e)
            self.send('550 Could not delete directory.')

    def do_xrmd(self, arg):
        return self.do_rmd(arg)

    def do_mkd(self, arg):

        self.send(f'257 Ready to make directory: "{self.selected}{sep}{arg}"')

        try:
            mkdir(self.true_fileloc(arg))
            self.send(f'250 "{arg}" Directory created.')
        except Exception as e:
            self.logging.error(e)
            self.send('550 Could not create directory.')

    def do_xmkd(self, arg):
        return self.do_mkd(arg)

    def do_pwd(self, arg):
        if self.home == '':
            self.send('530 Need to sign in.')
            return

        if arg:
            # PWD can not accept arguments
            self.send('501 Syntax error in parameters or arguments.')
        elif self.selected:
            # Send directory to client
            self.send(f'257 "{self.selected}"')
        elif self.username == '':
            self.send('550 Requested action not taken.')

    def do_xpwd(self, arg):
        # Some FTP clients assume FTP always has 4-character commands
        return self.do_pwd(arg)

    def do_list(self, arg):
        if self.home == '':
            self.send('530 Need to sign in.')
            return

        self.send('150 Processing...')



        try:
            self.connection.start()
            self.connection.join(timeout=30)
        except ConnectionError:
            self.send('425 No TCP connection established on data connection')
            return
        except Exception as e:
            self.logging.error(e)
            self.send('426 Error on TCP connection. Try again.')
            return

        dir = list(sorted(scandir(self.true_fileloc()), key=sort_dir_entry))
        if dir:
            self.logging.info(dir)
            for entry in dir:
                data = self.format_entry(entry)
                self.logging.info(data.strip())
                self.connection.send(data.encode() if self.binary else data)
                self.connection.send_crlf()

            self.send('226 Directory successfully transmitted')

        else:
            self.connection.send_blank()

            self.send('226 No files found in directory')

        self.connection.close()
        self.connection = None
        return

    def do_nlst(self, arg):
        if self.home == '':
            self.send('530 Need to sign in.')
            return

        self.send('150 Processing...')

        try:
            self.connection.start()
            self.connection.join(timeout=30)
        except ConnectionError:
            self.send('425 No TCP connection established on data connectionn')
            return
        except Exception as e:
            self.logging.error(e)
            self.send('426 Error on TCP connection. Try again.')
            return

        dir = list(sorted(scandir(self.true_fileloc()), key=sort_dir_entry))
        if dir:
            self.logging.info(dir)
            for entry in dir:

                data = f'{self.selected}{entry.name}\r\n'
                self.logging.info(data.strip())
                self.connection.send(data.encode() if self.binary else data)

            self.send('226 Directory successfully transmitted')

        else:
            self.connection.send_blank()
            self.send('226 No files found in directory')

        self.connection.close()
        self.connection = None

    def do_site(self, arg):
        # Used to provide services
        # specific to his system that are essential to file transfer
        # but not sufficiently universal to be included as commands in
        # the protocol.
        self.send('202 Command not implemented, Server does not support SITE command.')

    def do_syst(self, arg):
        if arg:
            # SYST can not have arguments
            self.send('501 Syntax error in parameters or arguments.')
            return
        # Return info about server operating system EG: Windows-10
        self.send(f'215 {platform(terse=True)}')

    def do_stat(self, arg):
        # During file transfer: Status of file transfer
        # Otherwise: Same as LIST function, but through command connection.
        self.send('202 Command not implemented, Server does not support STAT command.')

    def do_size(self, arg):
        new_path = self.true_fileloc(arg)

        if self.home:
            if path.exists(new_path):
                if self.check_home(new_path):
                    size = path.getsize(new_path)
                    self.logging.info(f'Size of {arg}: {size}')
                    self.send(f'213 {size}')
                    return
            self.send('550 Unable to find file.')
            return
        self.send('530 Need to sign in.')


class FTPCommandServer(TCPServer):
    def __init__(self, ip: str, public=False, req_pass=True, root_dir: str = path.curdir):
        TCPServer.__init__(self, ip, 21, FTPCommandHandler)
        self.ip = ip  # Server IP address.
        self.active = 0  # Active number of clients communicating.

        self.shutingdown = False  # Flag for if server needs to shutdown.
        self.public = public  # Flag for if the server is public. (IE: Allow anonymous log ins)
        self.req_pass = req_pass  # Flag for if the server requires a password to sign in.

        self.root = root_dir  # Root directory where files are stored for the server and clients.
        if not path.exists(f'{root_dir}{sep}users'):
            mkdir(f'{root_dir}{sep}users')  # Directory where all user directories will be saved to.
        if not path.exists(f'{root_dir}{sep}logs'):
            mkdir(f'{root_dir}{sep}logs')  # Directory where all logs will be saved to.
        if not path.exists(f'{root_dir}{sep}userdata'):
            # Directory where user data (IE usernames and passwords) will be stored
            mkdir(f'{root_dir}{sep}userdata')

        # Dictionary containing all user data
        # Gets loaded with saved data from disk if any.
        self.userdata = dict()
        self.load()

        # Logger for the server. Stores things like what users sign in with.
        self.logging = logging.getLogger('FTP Server')
        # Logger will save to disk.
        fh = logging.FileHandler(f'{self.root}{path.sep}logs{path.sep}server.log')
        fh.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
        self.logging.addHandler(fh)


        if public:
            # If this is a public server, create an anonymous account with no password info.
            public_dir = fr'{self.root}{sep}users{sep}public'
            self.userdata['anonymous'] = (None, None, public_dir)
            if not path.exists(public_dir):
                # Creates the directory for the anonymous user.
                mkdir(public_dir)

    def hash(self, password, salt):
        # Used by add_user method to hash password securely for storing.
        return pbkdf2_hmac('sha256', password, salt, 100_000).hex()

    def add_user(self, username, password):
        # Add a user to the server.
        if username in self.userdata:
            # Prevent the creating of multiple users with the same username.
            # Prevents accidental overwriting of pre-existing usernames.
            return

        salt = urandom(64)  # Salt for hashing password.
        home_dir = fr'{self.root}{sep}users{sep}{username}'  # Home directory of the user.

        if not path.exists(home_dir):
            # if the directory for the doesn't exist yet, create it.
            mkdir(home_dir)
        # Add new user to the userdata dictionary.
        self.userdata[username] = (self.hash(password.encode(), salt), int.from_bytes(salt, 'big'), home_dir)

    def check_username(self, username):
        # Allows FTPCommandHandler to check if the username is able to be used.
        # Basically a function to make slightly better
        return username in self.userdata

    def login(self, username, password):
        # Try to log in a user with their password.
        if self.public and username == 'anonymous':
            # If the server is public and the public account is trying to sign in.
            # We don't really care what password they sign in with for this account,
            # other than for logging purposes.
            self.logging.info(f'anonymous logged in with "{password}"')
            return self.userdata[username][2]

        if username in self.userdata:
            # Only continue if we know the username is in the dictionary.

            # Get the stored data.
            hashed_pass, salt, directory = self.userdata[username]

            if self.req_pass:
                # If we require a password, which we always should.
                # Hash the given password and check the hash to what was stored.
                if hashed_pass == self.hash(password.encode(), salt.to_bytes(64, 'big')):
                    # If the hash matches, return the home directory for the user.
                    self.logging.info(f'{username} logged in with "{password}"')
                    return directory
            else:
                # If we don't require a password, just pass along the directory.
                self.logging.info(f'{username} logged in with "{password}" (Not required).')
                return directory

            return

    def shutdown(self):
        # We are trying to shut down the server.
        # If any clients try to issue a command, inform them
        # And close the connection.
        self.shutingdown = True
        TCPServer.shutdown(self)
        while self.active:
            pass

    def save(self):
        # Save userdata to disk in JSON format.
        with open(f'{self.root}{path.sep}userdata{path.sep}userdata.dat', 'w') as file:
            dump(self.userdata, file)

    def load(self):
        # Load userdata from disk in JSON format.
        file = f'{self.root}{path.sep}userdata{path.sep}userdata.dat'
        if path.exists(file):
            with open(f'{self.root}{path.sep}userdata{path.sep}userdata.dat', 'r') as file:
                self.userdata.update(load(file))


def sort_dir_entry(entry):
    # Key for sorted to sort DirEntry objects
    if entry.is_file():
        # This ensures that directories always get transmitted first and file second.
        return f'1{entry.name}'
    return f'0{entry.name}'

if __name__ == '__main__':
    server = FTPCommandServer('127.0.0.1')
    server.add_user('tester', 'test')
    server.start()



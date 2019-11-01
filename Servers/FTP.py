from socketserver import BaseRequestHandler
from Servers import TCPServer

from cmd import Cmd
from os import path, urandom, sep, mkdir, scandir
from hashlib import pbkdf2_hmac
from string import digits, whitespace, punctuation
from platform import platform
from socket import socket, AF_INET, SOCK_STREAM
from datetime import datetime, timedelta

import logging

logging.basicConfig(format='%(levelname)s:  %(message)s', level=logging.INFO)

# Daytime Protocol described in RFC-959
# https://tools.ietf.org/html/rfc959

class FTPCommandHandler(BaseRequestHandler, Cmd):
    def setup(self):
        self.server.active = self.server.active+1


        sock_read = self.request.makefile('r')

        Cmd.__init__(self, stdin=sock_read)
        self.use_rawinput = False
        self.prompt = ''

        logging.info(f'{self.client_address[0]} CONNECTED')

        self.username = ''
        self.home = ''
        self.selected = ''
        self.binary = False
        self.history = []
        self.connection = None

    def finish(self):
        self.server.active = self.server.active - 1

    def handle(self):
        try:
            self.request.send(b'220 Service ready.\r\n')
            self.cmdloop()
        except ConnectionAbortedError as e:
            logging.info(f'{self.client_address[0]} closed connection forcefully.')
        except Exception as e:
            logging.exception(e)

    def precmd(self, line):
        if self.server.shuttingdown:
            # Check to see if server shutting down
            return 'QUIT'
        elif self.username == '' and not line.lower().startswith('user'):
            self.request.send(b'530 Need to sign in.')
        elif self.home == '' and not line.lower().startswith('pass'):
            self.request.send(b'530 Need to sign in.')

        logging.info(f'{self.client_address[0]}: {line}')

        return line.lower()

    def check_home(self, dir):
        return path.commonpath(
                    (
                            # Safeguard against people trying to break out of their home folder
                            path.abspath(self.home),
                            path.abspath(dir)
                    )
                                ) == path.abspath(self.home)

    def format_entry(self, entry):
        stats = entry.stat

        type = '-' if entry.is_file() else 'd'
        access = 'rw-r--r-- 1 owner group' if entry.is_file() else 'rwxr-xr-x 1 owner grou'
        size = f'{stats.st_size}'.rjust(13, ' ')

        if datetime.now()-timedelta(days=30*6) > stats.st_mtime:
            modification = datetime(second=stats.st_mtime).strftime('%b %d %Y')
        else:
            modification = datetime(second=stats.st_mtime).strftime('%b %d %H:%M')

        return f'{type}{access}{size}{modification}{entry.name}'

    def default(self, line):
        logging.info(f'Unrecognized command.')
        self.request.send(b'500 Syntax error, command unrecognized.\r\n')

    def do_EOF(self, arg):
        logging.info(f'{self.client_address[0]} closed connection forcefully.')
        return True

    def do_noop(self, arg):
        self.request.send(b'200 Command okay.\r\n')

    def do_user(self, username):
        if ' ' in username or username[0] in whitespace+punctuation+digits:
            # Check for invalid characters in username
            logging.info(f'Failed to log in: Bad characters in username.')
            self.request.send(b'501 Syntax error in USER argument.\r\n')
            return

        # Check to see if a private user is trying to login
        if self.server.check_username(username):
            self.username = username
            if self.server.req_pass:
                # If a password is required to log in, ask for password
                logging.info(f'{self.username} failed to log in: Need password.')
                self.request.send(b'331 User name okay, need password.\r\n')
                return
            # If a password isn't required to log in, allow to proceed'
            self.home = self.server.login(username, '')
            self.selected = self.selected
            logging.info(f'{self.username} logged in.')
            self.request.send(b'230 User logged in, proceed.\r\n')
        else:
            logging.info(f'Failed to log in: Bad username.')
            self.request.send(b'530 User name not okay.\r\n')

    def do_pass(self, password):
        if self.server.req_pass:

            if set(password) & set(whitespace):
                # Check for invalid characters in username
                logging.info(f'{self.username} failed to log in: Bad password characters.')
                self.request.send(b'501 Syntax error in PASS argument\r\n')
                return

            if self.username == '':
                logging.info(f'Failed to log in: Bad sequence of commands.')
                self.request.send(b'503 Bad sequence of commands.\r\n')
                return

            directory = self.server.login(self.username, password)
            if directory:
                logging.info(f'{self.username} logged in.')
                self.home = directory
                self.selected = directory
                self.request.send(b'230 User logged in, proceed.\r\n')
            else:
                logging.info(f'{self.username} failed to log in: Bad password.')
                self.request.send(b'530 Password not okay.\r\n')
                return True

        else:
            self.request.send(b'202 Command not implemented, password not required.\r\n')

    def do_acct(self, arg):
        # Could be used to allow an authorized user to use multiple accounts (IE: Sub accounts)
        self.request.send(b'202 Command not implemented, Server does not support ACCT command.\r\n')

    def do_cwd(self, arg):
        if arg == '':
            # CDUP can not have arguments
            self.request.send(b'501 Syntax error in parameters or arguments.\r\n')
            return

        new_dir = f'{self.selected}{path.sep}{arg}'

        if path.exists(new_dir) and path.isdir(new_dir):
            if self.check_home(new_dir):
                self.history.append(self.selected)
                self.selected = new_dir
                self.request.send(b'250 Okay.\r\n')
                return

        self.request.send(f'550 {new_dir}: No such file or directory found.\r\n'.encode())

    def do_xcwd(self, arg):
        # Some clients treat XCWD as CWD
        return self.do_cwd(arg)

    def do_cdup(self, arg):
        if arg:
            # CDUP can not have arguments
            self.request.send(b'501 Syntax error in parameters or arguments.\r\n')
            return
        if self.history:
            self.selected = self.history.pop(-1)
            self.request.send(b'250 Okay.\r\n')
        else:
            self.request.send(b'550 Unable to go further back.\r\n')

    def do_xcup(self, arg):
        # Some clients treat XCUP the same as CDUP
        return self.do_cdup(arg)

    def do_smnt(self, arg):
        pass

    def do_rein(self, arg):
        logging.info(f'{self.username} Logged out.')
        self.username = ''
        self.selected = ''
        self.request.send(b'220 Service ready.\r\n')

    def do_quit(self, arg):
        if arg:
            # QUIT command can not accept any arguments
            self.request.send(b'500 Syntax error, command unrecognized.\r\n')
            return

        if self.server.shuttingdown:
            # In the case of the server shutting down, notify client on next command
            logging.info(f'{self.client_address[0]} closed connection.')
            self.request.send(b'421 Service not available, closing control connection.\r\n')
            return True

        logging.info(f'{self.client_address[0]} closed connection.')
        self.request.send(b'221 Service closing control connection.\r\n')
        return True

    def do_port(self, arg):
        if arg == '' or arg.count(',') != 5:
            # CDUP can not have arguments
            self.request.send(b'501 Syntax error in parameters or arguments.\r\n')
            return

        addr_info = arg.split(',', 5)
        ip = '.'.join(addr_info[:4])
        port = (int(addr_info[4]) << 8) | int(addr_info[5])

        self.connection = (socket(AF_INET, SOCK_STREAM), (ip, port))
        self.request.send(b'200 Ready to connect.\r\n')
        return

    def do_pasv(self, arg):
        pass

    def do_type(self, arg):
        if arg == '':
            # Check to make sure parameters were provided
            self.request.send(b'501 Syntax error in parameters or arguments.\r\n')
            return


        if self.selected == '':
            # Check to see if we're logged in.
            self.request.send(b'530 Not logged in.\r\n')
            return

        if arg == 'a' or arg == 'a n':
            # If ASCII or ASCII Non-print
            self.binary = False
            self.request.send(b'200 Binary flag set to OFF\r\n')
        elif arg == 'i' or arg == 'l 8':
            # If Image or Bytes
            self.binary = True
            self.request.send(b'200 Binary flag set to ON\r\n')
        else:
            self.request.send(b'504 Command not implemented for that parameter.\r\n')

    def do_stru(self, arg):
        if arg == 'f':
            self.request.send(b'200 FILE structure selected.\r\n')
            return
        self.request.send(b'504 Command not implemented for that parameter.\r\n')

    def do_mode(self, arg):
        if arg == 's':
            self.request.send(b'200 STREAM mode selected.\r\n')
            return
        self.request.send(b'504 Command not implemented for that parameter.\r\n')

    def do_retr(self, arg):
        pass

    def do_stor(self, arg):
        pass

    def do_stou(self, arg):
        pass

    def do_appe(self, arg):
        pass

    def do_allo(self, arg):
        pass

    def do_rest(self, arg):
        pass

    def do_rnfr(self, arg):
        pass

    def do_rnto(self, arg):
        pass

    def do_abor(self, arg):
        pass

    def do_dele(self, arg):
        pass

    def do_rmd(self, arg):
        pass

    def do_mkd(self, arg):
        pass

    def do_pwd(self, arg):
        if arg:
            # PWD can not accept arguments
            self.request.send(b'501 Syntax error in parameters or arguments.\r\n')
        elif self.selected:
            # Send directory to client
            self.request.send(f'257 "{self.selected}"\r\n'.encode())
        elif self.username == '':
            self.request.send(b'550 Requested action not taken.\r\n')

    def do_xpwd(self, arg):
        # Some FTP clients assume FTP always has 4-character commands
        return self.do_pwd(arg)

    def do_list(self, arg):
        self.request.send(b'150 Processing...\r\n')

        try:
            self.connection[0].connect(self.connection[1])
        except ConnectionError as e:
            logging.info(e)
            self.request.send(b'425 No TCP connection established on data connection\r\n')
            return
        except Exception as e:
            logging.error(e)
            self.request.send(b'426 Error on TCP connection. Try again.\r\n')
            return

        dir = list(sorted(scandir(self.selected)))
        if dir:
            logging.info(dir)
            for entry in scandir(self.selected):
                data = self.format_entry(entry)
                logging.info(f'Sending {self.client_address[0]}: {data.strip()}')
                self.connection[0].send(data.encode())

            logging.info('Directory successfully transmitted')
            self.request.send(b'226 Directory successfully transmitted\r\n')

        else:
            self.connection[0].send(b'\r\n')
            logging.info(f'Sending {self.client_address[0]}: NO FILES IN DIRECTORY')
            self.request.send(b'226 No files found in directory\r\n')

        self.connection[0].close()
        self.connection = None
        return

    def do_nlst(self, arg):

        self.request.send(b'150 Processing...\r\n')

        try:
            self.connection[0].connect(self.connection[1])
        except ConnectionError as e:
            logging.info(e)
            self.request.send(b'425 No TCP connection established on data connection\r\n')
            return
        except Exception as e:
            logging.error(e)
            self.request.send(b'426 Error on TCP connection. Try again.\r\n')
            return

        dir = list(sorted(scandir(self.selected)))
        if dir:
            logging.info(dir)
            for entry in scandir(self.selected):
                data = f'{entry.path}\r\n'
                logging.info(f'Sending {self.client_address[0]}: {data.strip()}')
                self.connection[0].send(data.encode())

            logging.info('Directory successfully transmitted')
            self.request.send(b'226 Directory successfully transmitted\r\n')

        else:
            self.connection[0].send(b'\r\n')
            logging.info(f'Sending {self.client_address[0]}: NO FILES IN DIRECTORY')
            self.request.send(b'226 No files found in directory\r\n')

        self.connection[0].close()
        self.connection = None
        self.request.send(b'150 Processing...\r\n')

        try:
            self.connection[0].connect(self.connection[1])
        except ConnectionError as e:
            logging.info(e)
            self.request.send(b'425 No TCP connection established on data connection\r\n')
            return
        except Exception as e:
            logging.error(e)
            self.request.send(b'426 Error on TCP connection. Try again.\r\n')
            return

        dir = list(sorted(scandir(self.selected)))
        if dir:
            logging.info(dir)
            for entry in scandir(self.selected):
                data = f'{entry.path}\r\n'
                logging.info(f'Sending {self.client_address[0]}: {data.strip()}')
                self.connection[0].send(data.encode())

            logging.info('Directory successfully transmitted')
            self.request.send(b'226 Directory successfully transmitted\r\n')

        else:
            self.connection[0].send(b'\r\n')
            logging.info(f'Sending {self.client_address[0]}: NO FILES IN DIRECTORY')
            self.request.send(b'226 No files found in directory\r\n')

        self.connection[0].close()
        self.connection = None
        return



    def do_site(self, arg):
        pass

    def do_syst(self, arg):
        if arg:
            # SYST can not have arguments
            self.request.send(b'501 Syntax error in parameters or arguments.\r\n')
            return
        # Return info about server operating system EG: Windows-10
        self.request.send(f'215 {platform(terse=True)}\r\n'.encode())

    def do_stat(self, arg):
        pass

    def do_size(self, arg):
        if self.home:
            if path.exists(arg):
                if self.check_home(arg):
                    size = path.getsize(arg)
                    logging.info(f'Size of {arg}: {size}')
                    self.request.send(f'213 {size}\r\n'.encode())
                    return
            self.request.send(b'550 Unable to find file.')
            return
        self.request.send(b'530 Need to sign in.')


class FTPCommandServer(TCPServer):
    def __init__(self, ip: str, public=False, req_pass=True, root_dir: str = path.curdir):
        TCPServer.__init__(self, ip, 21, FTPCommandHandler)
        self.ip = ip
        self.active = 0
        self.shuttingdown = False

        self.public = public
        self.req_pass = req_pass

        self.root = root_dir
        self.userdata = dict()

        if public:
            self.userdata['anonymous'] = (None, None, fr'{sep}public')

        pass
    def hash(self, password, salt):
        return pbkdf2_hmac('sha256', password, salt, 100_000).hex()

    def add_user(self, username, password):
        if username in self.userdata:
            return

        salt = urandom(64)
        home_dir = fr'{self.root}{sep}{username}'

        if not path.exists(home_dir):
            mkdir(home_dir)
        self.userdata[username] = (self.hash(password.encode(), salt), salt, home_dir)

    def check_username(self, username):
        return username in self.userdata

    def login(self, username, password):
        if self.public and username == 'anonymous':
            logging.info(f'anonymous logged in with {password}')
            return self.userdata[username][2]

        if username in self.userdata:
            hashed_pass, salt, directory = self.userdata[username]

            if self.req_pass:
                if hashed_pass == self.hash(password.encode(), salt):
                    logging.info(f'{username} logged in')
                    return directory
            else:
                return directory

            return

    def shutdown(self):
        self.shuttingdown = True
        TCPServer.shutdown(self)
        while self.active:
            pass


if __name__ == '__main__':
    server = FTPCommandServer('127.0.0.1')
    server.add_user('tester', 'test')
    server.start()



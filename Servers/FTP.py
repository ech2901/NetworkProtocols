from socketserver import BaseRequestHandler
from Servers import TCPServer

from cmd import Cmd
from os import path, urandom, sep
from hashlib import pbkdf2_hmac
from string import digits, whitespace, punctuation

import logging

logging.basicConfig(format='%(levelname)s:  %(message)s', level=logging.INFO)

# Daytime Protocol described in RFC-959
# https://tools.ietf.org/html/rfc959

class FTPCommandHandler(BaseRequestHandler, Cmd):
    def setup(self):
        self.server.active = self.server.active+1


        sock_read = self.request.makefile('r')
        sock_write = self.request.makefile('w')

        Cmd.__init__(self, stdin=sock_read)
        self.use_rawinput = False
        self.prompt = f'{self.server.ip}:  '

        logging.info(f'{self.client_address[0]} CONNECTED')

        self.username = ''
        self.directory = ''

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
        return line.lower()

    def default(self, line):
        self.server.send(b'500 Syntax error, command unrecognized.')

    def do_EOF(self, arg):
        logging.info(f'{self.client_address[0]} closed connection forcefully.')
        return True

    def do_noop(self, arg):
        self.request.send(b'200 Command okay.\r\n')

    def do_user(self, username):
        if ' ' in username or username[0] in whitespace+punctuation+digits:
            # Check for invalid characters in username
            self.request.send(b'501 Syntax error in USER argument')
            return

        # Check to see if a private user is trying to login
        if self.server.check_username(username):
            self.username = username
            if self.server.req_pass:
                # If a password is required to log in, ask for password
                self.request.send(b'331 User name okay, need password.\r\n')
                return
            # If a password isn't required to log in, allow to proceed'
            self.request.send(b'230 User logged in, proceed.\r\n')
        else:
            self.request.send(b'530 User name not okay.\r\n')

    def do_pass(self, password):
        if self.server.req_pass:

            if set(password) & set(whitespace):
                # Check for invalid characters in username
                self.request.send(b'501 Syntax error in PASS argument\r\n')
                return

            if self.username == '':
                self.request.send(b'503 Bad sequence of commands.')

            directory = self.server.login(self.username, password)
            if directory:
                self.directory = directory
                self.request.send(b'230 User logged in, proceed.\r\n')
            else:
                self.request.send(b'530 Password not okay.\r\n')
                return True

        else:
            self.request.send(b'202 Command not implemented, password not required.\r\n')

    def do_acct(self, arg):
        # Could be used to allow an authorized user to use multiple accounts (IE: Sub accounts)
        self.request.send(b'202 Command not implemented, Server does not support ACCT command.\r\n')

    def do_cwd(self, arg):
        pass

    def do_cdup(self, arg):
        pass

    def do_smnt(self, arg):
        pass

    def do_rein(self, arg):
        self.username = ''
        self.directory = ''
        self.request.send(b'220 Service ready.')

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
        pass

    def do_pasv(self, arg):
        pass

    def do_type(self, arg):
        pass

    def do_stru(self, arg):
        pass

    def do_mode(self, arg):
        pass

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
        pass

    def do_list(self, arg):
        pass

    def do_nlst(self, arg):
        pass

    def do_site(self, arg):
        pass

    def do_syst(self, arg):
        pass

    def do_stat(self, arg):
        pass




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
            self.userdata['anonymous'] = (None, None, fr'{self.root}{sep}public')

    def hash(self, password, salt):
        return pbkdf2_hmac('sha256', password, salt, 100_000).hex()

    def add_user(self, username, password):
        if username in self.userdata:
            return

        salt = urandom(64)
        self.userdata[username] = (self.hash(password.encode(), salt), salt, fr'{self.root}{sep}{username}')

    def check_username(self, username):
        return username in self.userdata

    def login(self, username, password):
        if self.public and username == 'anonymous':
            logging.info(f'anonymous logged in with {password}')
            return self.userdata[username][2]

        if username in self.userdata:
            hashed_pass, salt, directory = self.userdata[username]

            if hashed_pass == self.hash(password.encode(), salt):
                logging.info(f'{username} logged in')
                return directory
            return

    def shutdown(self):
        self.shuttingdown = True
        TCPServer.shutdown(self)
        while self.active:
            pass





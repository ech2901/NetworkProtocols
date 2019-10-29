from socketserver import BaseRequestHandler
from Servers import TCPServer

from cmd import Cmd

import logging

logging.basicConfig(format='%(levelname)s:  %(message)s', level=logging.INFO)

# Daytime Protocol described in RFC-959
# https://tools.ietf.org/html/rfc959

class FTPCommandHandler(BaseRequestHandler, Cmd):
    def setup(self):

        sock_read = self.request.makefile('r')
        sock_write = self.request.makefile('w')

        Cmd.__init__(self, stdin=sock_read, stdout=sock_write)
        self.use_rawinput = False
        self.prompt = f'{self.server.ip}:  '

    def handle(self):
        try:
            self.cmdloop(intro='FTP Server')
        except ConnectionAbortedError as e:
            logging.info(f'{self.client_address[0]} closed connection forcefully.')
        except Exception as e:
            logging.exception(e)

    def precmd(self, line):
        return line.lower()

    def do_EOF(self, arg):
        logging.info(f'{self.client_address[0]} closed connection forcefully.')
        return True

    def do_noop(self, arg):
        self.request.send(b'200 Command okay.\r\n')

    def do_user(self, arg):
        pass

    def do_pass(self, arg):
        pass

    def do_acct(self, arg):
        pass

    def do_cwd(self, arg):
        pass

    def do_cdup(self, arg):
        pass

    def do_smnt(self, arg):
        pass

    def do_rein(self, arg):
        pass

    def do_quit(self, arg):
        logging.info(f'{self.client_address[0]} closed connection.')
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
    def __init__(self, ip):
        TCPServer.__init__(self, ip, 21, FTPCommandHandler)
        self.ip = ip


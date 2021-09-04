from cmd import Cmd
from socketserver import BaseRequestHandler

from BaseServers import BaseTCPServer


class SMTPHandler(BaseRequestHandler, Cmd):
    def setup(self):
        self.request.settimeout(60 * 5)
        sock_read = self.request.makefile('r')
        self.sock_write = self.request.makefile('w')

        Cmd.__init__(self, stdin=sock_read)
        self.use_rawinput = False
        self.prompt = ''

    def send(self, data):
        with self.request.makefile('wb') as sock:
            sock.write(f'{data}\r\n'.encode())

    def default(self, line):
        print(f'Invalid entry: {line}')
        self.send('502 Command not implemented')


class SMTPServer(BaseTCPServer):
    def __init__(self, ip: str, port: int = 25):
        BaseTCPServer.__init__(self, ip, port, SMTPHandler)


if __name__ == '__main__':
    server = SMTPServer('', 465)
    server.run()

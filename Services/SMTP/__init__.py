from cmd import Cmd
from select import select
from socket import timeout, gethostname
from socketserver import BaseRequestHandler

from BaseServers import BaseTCPServer


class SMTPHandler(BaseRequestHandler, Cmd):

    def finish(self):
        print("Connection closing.")

    def setup(self):
        self.request.settimeout(60 * 5)
        sock_read = self.request.makefile('r')
        self.sock_write = self.request.makefile('w')

        Cmd.__init__(self, stdin=sock_read)
        self.use_rawinput = False
        self.prompt = ''

    def handle(self):
        print("Connetion made.")
        try:
            # FTP initial READY message to client
            self.send('220 Service ready.')
            # Loop through the sequence of getting commands
            # Until we quit or have an error.
            self.cmdloop()
        except timeout:
            # If client doesn't send a command before the timeout
            # Close connection.
            print('Client timed out. Closing connectino.')
            self.request.close()
        except (ConnectionAbortedError, ConnectionResetError):
            # If the connection to client is lost
            # IE: Network outage
            print('closed connection forcefully.')
        except Exception as e:
            # If an unexpected error happens, log it.
            print(e)

    def precmd(self, line):
        print(line)
        # Allow for non-case sensitive commands.
        return line.lower()

    def send(self, data):
        with self.request.makefile('wb') as sock:
            sock.write(f'{data}\r\n'.encode())

    def default(self, line):
        self.send('502 Command not implemented')

    def do_helo(self, client):
        self.send(f'250-{self.server.domain}')
        self.send('250-AUTH PLAIN')
        self.send('250-SIZE 30000000')
        self.send('250-8BITMIME')
        self.send('250 OK')

    def do_ehlo(self, client):
        self.send(f'250-{self.server.domain}')
        self.send('250-AUTH PLAIN')
        self.send('250-SIZE 30000000')
        self.send('250-8BITMIME')
        self.send('250 OK')

    def do_quit(self, line):
        self.send(f'221 {self.server.domain} Service closing transmissin channel')
        return True

    def do_mail(self, sender):
        print(sender)
        self.send('250 ok')
        read, _, _ = select([self.request, ], [], [], 10)
        recpt_list = [self.request.recv(1024).decode().strip()]
        self.send('250 ok')
        while True:
            data = self.request.recv(1024).decode().strip()
            if data.startswith('rcpt'):
                recpt_list.append(data)
                self.send('250 ok')
            else:
                self.send('354 Start mail input; end with <CRLF>.<CRLF>')
                msg = ''
                while not msg.endswith('\r\n.\r\n'):
                    msg = msg + self.request.recv(4).decode()
                break
        print(recpt_list)
        print(msg[:-5])
        self.send('250 ok')
        print('___message recieved___')







class SMTPServer(BaseTCPServer):
    def __init__(self, ip: str, port: int = 25, domain=None):
        BaseTCPServer.__init__(self, ip, port, SMTPHandler)
        if domain:
            self.domain = domain
        else:
            self.domain = f'{gethostname()}'

if __name__ == '__main__':
    server = SMTPServer('', 465)
    server.run()

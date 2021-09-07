from cmd import Cmd
from select import select
from socket import timeout, gethostname
from socketserver import BaseRequestHandler

from BaseServers import BaseTCPServer
from Services.SMTP.Auth import Auth


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
        # Still allows for case sensitive arguments.
        command, args = line.split(' ', 1)

        if command.lower() in self.server.extensions:
            return f'extension {command.lower()} {args}'

        return ' '.join([command.lower(), args])

    def send(self, data):
        with self.request.makefile('wb') as sock:
            sock.write(f'{data}\r\n'.encode())

    def recv(self, bytecount=1024, strip=True, decode=True):
        data = self.request.recv(bytecount)
        if decode:
            data = data.decode()
        if strip:
            return data.strip()
        return data

    def default(self, line):
        self.send(f'502 {line} Command not implemented')

    def do_extension(self, line):
        extension, args = line.split(' ', 1)
        self.server.extensions[extension](self, args)

    def do_helo(self, client):
        self.send(f'250 {self.server.domain}')

    def do_ehlo(self, client):
        self.send(f'250-{self.server.domain}')
        for extension in self.server.extensions.values():
            self.send(f'250-{str(extension)}')
        self.send('250 OK')

    def do_quit(self, line):
        self.send(f'221 {self.server.domain} Service closing transmissin channel')
        return True

    def do_mail(self, sender):
        print(sender)
        self.send('250 ok')
        read, _, _ = select([self.request, ], [], [], 10)
        recpt_list = [self.recv()]
        self.send('250 ok')
        while True:
            data = self.recv()
            if data.startswith('rcpt'):
                recpt_list.append(data)
                self.send('250 ok')
            else:
                self.send('354 Start mail input; end with <CRLF>.<CRLF>')
                msg = ''
                while not msg.endswith('\r\n.\r\n'):
                    msg = msg + self.recv(strip=False)
                break
        print(recpt_list)
        print(msg[:-5])
        self.send('250 ok')
        print('___message recieved___')


class SMTPServer(BaseTCPServer):
    def __init__(self, ip: str, port: int = 25, domain=None, *extensions):
        BaseTCPServer.__init__(self, ip, port, SMTPHandler)

        if type(domain) == str:
            self.domain = domain
        elif domain is None:
            self.domain = f'{gethostname()}'
        else:
            self.domain = f'{gethostname()}'
            extensions = extensions + (domain,)
        self.extensions = dict([(ext.__class__.__name__.lower(), ext) for ext in extensions])


if __name__ == '__main__':
    server = SMTPServer('', 465, Auth(plain=True))
    server.run()
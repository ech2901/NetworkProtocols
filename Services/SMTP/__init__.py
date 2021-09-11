from cmd import Cmd
from datetime import datetime
from email.message import EmailMessage
from socket import timeout, gethostname
from socketserver import BaseRequestHandler

from BaseServers import BaseTCPServer
from Services.SMTP.Extensions import Auth, Size, StartTLS
from Services.SMTP.Mailbox import MailboxSystem


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

        self.clear_state()

        if 'size' in self.server.extensions:
            self.size = self.server.extensions['size'].size
            # Maximum size, which will be advertized to clients
            # Messages bigger than this will be rejected
        else:
            self.size = 2_000_000
            # Max size of 2mb by default
            # Messages bigger than this will be rejected.

    def clear_state(self):
        self.message = EmailMessage()
        self.content = ''

    def handle(self):
        print("Connetion made.")
        try:
            # FTP initial READY message to client
            self.send(f'220 {self.server.domain} Service ready.')
            # Loop through the sequence of getting commands
            # Until we quit or have an error.
            self.cmdloop()
        except timeout:
            # If client doesn't send a command before the timeout
            # Close connection.
            self.send(f'221 {self.server.domain} Service closing transmission control. Timed out.')
            print('Client timed out. Closing connection.')
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

        command, *args = line.split(' ', 1)

        new_line = ' '.join([command.lower(), *args])

        if command.lower() in self.server.extensions:
            return f'extension {new_line}'

        return new_line

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
        extension, *args = line.split(' ', -1)
        self.server.extensions[extension](self, *args)

    def do_helo(self, client):
        self.clear_state()
        self.send(f'250 {self.server.domain}')

    def do_ehlo(self, client):
        # send response for each extension available.
        self.clear_state()
        self.send(f'250-{self.server.domain}')
        for extension in self.server.extensions.values():
            self.send(f'250-{str(extension)}')
        self.send('250 OK')

    def do_quit(self, line):
        self.clear_state()
        self.send(f'221 {self.server.domain} Service closing transmissin channel')
        return True

    def do_mail(self, sender):
        self.clear_state()
        self.message['From'] = sender
        self.send('250 Sender recieved.')

    def do_rcpt(self, recipient):
        if self.message['To'] is None:
            self.message['To'] = list()
        self.message['To'].append(recipient)
        self.send('250 Recipient recieved.')

    def do_data(self, data):
        self.send('354 Start mail input; end with <CRLF>.<CRLF>')
        while True:
            self.content = self.content + self.recv(1024)
            if self.content.endswith('\r\n.\r\n'):
                break

        self.message.set_content(self.content)
        self.message['Date'] = datetime.now().strftime('%a, %d %b %Y %H:%M:%S %z')

        self.server.mailbox.get(self.message['From'].split('@')[0]).get_folder('outbox').add(self.message)
        self.clear_state()

        self.send('250 Content recieved.')

    def do_rset(self):
        self.message = EmailMessage()
        self.content = ''
        self.send('250 buffers cleared.')

    def do_vrfy(self, user):
        self.send('252 Cannot VRFY user, but will accept message and attempt delivery.')

    def do_expn(self, mailing_list):
        self.send('550 Access denied.')

    def do_help(self, line):
        self.send('250-Commands:')
        for method, func in self.__dict__.items():
            if method.startswith('do_'):
                self.send(f'250-{func.__doc__}')
        self.send('250 All Done')

    def do_noop(self, line):
        self.send('250 ok.')



class SMTPServer(BaseTCPServer):
    def __init__(self, ip: str, port: int = 25, domain=None, *extensions, **kwargs):
        BaseTCPServer.__init__(self, ip, port, SMTPHandler)
        self.mailbox = kwargs.get('maibox', MailboxSystem())

        if type(domain) == str:
            self.domain = domain
        elif domain is None:
            self.domain = f'{gethostname()}'
        else:
            self.domain = f'{gethostname()}'
            extensions = extensions + (domain,)

        self.extensions = dict()
        for ext in extensions:
            self.extensions[ext.__class__.__name__.lower()] = ext
            self.RequestHandlerClass = ext.wrap(self.RequestHandlerClass)




if __name__ == '__main__':
    server = SMTPServer('', 465, Size(4))
    server.run()

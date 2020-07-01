from socket import socket, AF_INET, SOCK_STREAM
from threading import Thread


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

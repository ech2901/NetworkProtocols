from socket import socket, AF_INET, SOCK_DGRAM


class EchoClient(socket):
    def __init__(self, ip):
        socket.__init__(self, AF_INET, SOCK_DGRAM)
        self.dest = (ip, 7)

    def set_dest(self, ip):
        self.dest = (ip, 7)

    def message(self, data: bytes):
        self.sendto(data, self.dest)
        return self.recvfrom(1024)

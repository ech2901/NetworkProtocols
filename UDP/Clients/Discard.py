from socket import socket, AF_INET, SOCK_DGRAM


class DiscardClient(socket):
    def __init__(self, ip):
        socket.__init__(self, AF_INET, SOCK_DGRAM)
        self.dest = (ip, 9)

    def set_dest(self, ip):
        self.dest = (ip, 9)

    def message(self, data: bytes):
        self.sendto(data, self.dest)

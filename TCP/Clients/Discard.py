from socket import socket, AF_INET, SOCK_STREAM


class EchoClient(socket):
    def __init__(self, ip):
        socket.__init__(self, AF_INET, SOCK_STREAM)
        socket.connect(self, (ip, 9))

    def message(self, data: bytes):
        self.send(data)

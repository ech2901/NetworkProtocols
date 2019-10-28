from socket import socket, AF_INET, SOCK_STREAM


# This is a class because you might want to send multiple messages to the server
class EchoClient(socket):
    def __init__(self, ip: str):
        socket.__init__(self, AF_INET, SOCK_STREAM)
        socket.connect(self, (ip, 7))

    def message(self, data: bytes):
        """
        Send data to server to be echo-ed back

        :param data: bytes
        :return: bytes
        """
        self.send(data)
        return self.recv(1024)





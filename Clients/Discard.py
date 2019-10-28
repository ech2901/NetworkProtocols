from socket import socket, AF_INET, SOCK_STREAM, SOCK_DGRAM


# This is a class because you might want to send multiple messages to the server
class TCPDiscard(socket):
    def __init__(self, ip: str):
        socket.__init__(self, AF_INET, SOCK_STREAM)
        socket.connect(self, (ip, 9))

    def message(self, data: bytes):
        """
        Send data to server to be discarded

        :param data:
        :return: None
        """
        self.send(data)


def UDPDiscard(ip: str, message: bytes):
    """
    Send data to the discard server
    Expect no returned information

    :param ip: str
    :param message: bytes
    :return: None
    """
    with socket(AF_INET, SOCK_DGRAM) as sock:
        sock.sendto(message, (ip, 9))

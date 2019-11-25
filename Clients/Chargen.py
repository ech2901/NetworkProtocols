from socket import socket, AF_INET, SOCK_STREAM, SOCK_DGRAM


# This is a class because you might want to send multiple messages to the server
class TCPChargen(socket):
    def __init__(self, ip: str):
        socket.__init__(self, AF_INET, SOCK_STREAM)
        socket.connect(self, (ip, 19))

    def loop(self):
        """
        Print to console stream of characters from server.
        Close socket to stop

        :return:
        """

        while True:
            data = self.recv(1024)
            yield data


def UDPChargen(ip: str):
    """
    Send data to echo server
    Expect sent data to be returned from server

    :param ip: to_str
    :param message: bytes
    :return: bytes
    """
    with socket(AF_INET, SOCK_DGRAM) as sock:
        sock.sendto(b'', (ip, 19))
        data = sock.recvfrom(1024)
    return data[0]

from socket import socket, AF_INET, SOCK_STREAM, SOCK_DGRAM


# This is a class because you might want to send multiple messages to the server
class TCPEcho(socket):
    def __init__(self, ip: str):
        socket.__init__(self, AF_INET, SOCK_STREAM)
        socket.connect(self, (ip, 7))

    def __call__(self, data: bytes):
        """
        Send data to server to be echo-ed back

        :param data: bytes
        :return: bytes
        """
        self.send(data)
        return self.recv(1024)


def UDPEcho(ip: str, message: bytes):
    """
    Send data to echo server
    Expect sent data to be returned from server

    :param ip: str
    :param message: bytes
    :return: bytes
    """
    with socket(AF_INET, SOCK_DGRAM) as sock:
        sock.sendto(message, (ip, 7))
        data = sock.recvfrom(1024)
    return data

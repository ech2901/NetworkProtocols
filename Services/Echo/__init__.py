import logging
from socket import socket, AF_INET, SOCK_STREAM, SOCK_DGRAM
from socketserver import BaseRequestHandler

from BaseServers import BaseTCPServer, BaseUDPServer


# Echo Protocol described in RFC-862
# https://tools.ietf.org/html/rfc862

# This is a class because you might want to send multiple messages to the server
class TCPClient(socket):
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


def UDPClient(ip: str, message: bytes):
    """
    Send data to echo server
    Expect sent data to be returned from server

    :param ip: to_str
    :param message: bytes
    :return: bytes
    """
    with socket(AF_INET, SOCK_DGRAM) as sock:
        sock.sendto(message, (ip, 7))
        data = sock.recvfrom(1024)
    return data[0]


logging.basicConfig(format='%(levelname)s:  %(message)s', level=logging.INFO)


class TCPHandler(BaseRequestHandler):
    def handle(self):
        logging.info(f'{self.client_address[0]} CONNECTED')
        while True:
            # Recieve data from client
            data = self.request.recv(1024)
            if data:
                # If logging level set to info print it to output
                # Send same data recieved from client back to client
                logging.info(f'{self.client_address[0]}: {data}')
                self.request.send(data)
            else:
                break
        logging.info(f'{self.client_address[0]} DISCONNECTED')


class UDPHandler(BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        # Echo sent data back to client
        logging.info(f'{self.client_address[0]}: {data}')
        sock.sendto(data, self.client_address)


class TCPServer(BaseTCPServer):
    def __init__(self, ip):
        BaseTCPServer.__init__(self, ip, 7, TCPHandler)


class UDPServer(BaseUDPServer):
    def __init__(self, ip):
        BaseUDPServer.__init__(self, ip, 7, UDPHandler)

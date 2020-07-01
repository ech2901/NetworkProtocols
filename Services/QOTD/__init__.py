import logging
from socket import socket, AF_INET, SOCK_STREAM, SOCK_DGRAM
from socketserver import BaseRequestHandler

from BaseServers import BaseTCPServer, BaseUDPServer


# This doesn't really need to be a class because the server should disconnect after sending data
def TCPClient(ip: str):
    """
    Provided an IP address, retrieve QOTD from a server

    :param ip: to_str
    :return: bytes
    """
    with socket(AF_INET, SOCK_STREAM) as sock:
        sock.connect((ip, 17))
        data = sock.recv(1024)
    return data


# This doesn't really need to be a class because the server should disconnect after sending data
def UDPClient(ip: str):
    """
    Provided an IP address, retrieve QOTD from a server

    :param ip: to_str
    :return: bytes
    """
    with socket(AF_INET, SOCK_DGRAM) as sock:
        sock.sendto(b'', (ip, 17))
        data = sock.recvfrom(1024)
    return data[0]


logging.basicConfig(format='%(levelname)s:  %(message)s', level=logging.INFO)


# Daytime Protocol described in RFC-865
# https://tools.ietf.org/html/rfc865


class TCPHandler(BaseRequestHandler):
    def handle(self):
        logging.info(f'{self.client_address[0]} CONNECTED')

        # Send Quote of the Day to client
        self.request.send(self.server.message)
        logging.info(f'SERVER to {self.client_address[0]}: {self.server.message}')

        logging.info(f'{self.client_address[0]} DISCONNECTED')


class UDPHandler(BaseRequestHandler):
    def handle(self):
        logging.info(f'{self.client_address[0]} CONNECTED')

        # Aquire socket to send data through
        _, sock = self.request

        # Send Quote of the Day to client
        sock.sendto(self.server.message, self.client_address)
        logging.info(f'SERVER to {self.client_address[0]}: {self.server.message}')

        logging.info(f'{self.client_address[0]} DISCONNECTED')


class TCPServer(BaseTCPServer):
    def __init__(self, ip, message: bytes = b''):
        BaseTCPServer.__init__(self, ip, 17, TCPHandler)
        # Message to send to clients
        self.message = message

    def set_message(self, message: bytes):
        self.message = message


class UDPServer(BaseUDPServer):
    def __init__(self, ip, message: bytes = b''):
        BaseUDPServer.__init__(self, ip, 17, UDPHandler)
        # Message to send to clients
        self.message = message

    def set_message(self, message: bytes):
        self.message = message

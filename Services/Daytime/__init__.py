import logging
from datetime import datetime
from socket import socket, AF_INET, SOCK_STREAM, SOCK_DGRAM
from socketserver import BaseRequestHandler

from BaseServers import BaseTCPServer, BaseUDPServer


# This doesn't really need to be a class because the server should disconnect after sending data
def TCPClient(ip: str):
    """
    Provided an IP address, retrieve daytime info from a server

    :param ip: to_str
    :return: bytes
    """
    with socket(AF_INET, SOCK_STREAM) as sock:
        sock.connect((ip, 13))
        data = sock.recv(1024)
    return data


# This doesn't really need to be a class because the server should disconnect after sending data
def UDPClient(ip: str):
    """
    Provided an IP address, retrieve daytime info from a server

    :param ip: to_str
    :return: bytes
    """
    with socket(AF_INET, SOCK_DGRAM) as sock:
        sock.sendto(b'', (ip, 13))
        data = sock.recvfrom(1024)
    return data[0]


logging.basicConfig(format='%(levelname)s:  %(message)s', level=logging.INFO)


# Daytime Protocol described in RFC-867
# https://tools.ietf.org/html/rfc867

class TCPHandler(BaseRequestHandler):
    def handle(self):
        logging.info(f'{self.client_address[0]} CONNECTED')

        # Get the current daytime with timezone information
        # Timezone name provided from OS
        data = datetime.now().astimezone().strftime(self.server.format).encode()

        # Send daytime info to client
        self.request.send(data)
        logging.info(f'SERVER to {self.client_address[0]}: {data}')

        logging.info(f'{self.client_address[0]} DISCONNECTED')


class UDPHandler(BaseRequestHandler):
    def handle(self):
        logging.info(f'{self.client_address[0]} CONNECTED')

        # Aquire socket to send data through
        _, sock = self.request

        # Get the current daytime with timezone information
        # Timezone name provided from OS
        data = datetime.now().astimezone().strftime(self.server.format).encode()

        # Send daytime info to client
        sock.sendto(data, self.client_address)
        logging.info(f'SERVER to {self.client_address[0]}: {data}')

        logging.info(f'{self.client_address[0]} DISCONNECTED')


class TCPServer(BaseTCPServer):
    def __init__(self, ip, format='%d %b %y %H:%M:%S %Z'):
        BaseTCPServer.__init__(self, ip, 13, TCPHandler)
        # String format for server to respond with
        self.format = format


class UDPServer(BaseUDPServer):
    def __init__(self, ip, format='%d %b %y %H:%M:%S %Z'):
        BaseUDPServer.__init__(self, ip, 13, UDPHandler)
        # String format for server to respond with
        self.format = format

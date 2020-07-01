import logging
from socket import socket, AF_INET, SOCK_STREAM, SOCK_DGRAM
from socketserver import BaseRequestHandler

from BaseServers import BaseTCPServer, BaseUDPServer


# Discard Protocol described in RFC-863
# https://tools.ietf.org/html/rfc863

# This is a class because you might want to send multiple messages to the server
class TCPClient(socket):
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


def UDPClient(ip: str, message: bytes):
    """
    Send data to the discard server
    Expect no returned information

    :param ip: to_str
    :param message: bytes
    :return: None
    """
    with socket(AF_INET, SOCK_DGRAM) as sock:
        sock.sendto(message, (ip, 9))


logging.basicConfig(format='%(levelname)s:  %(message)s', level=logging.INFO)


class TCPHandler(BaseRequestHandler):
    def handle(self):
        logging.info(f'{self.client_address[0]} CONNECTED')
        while True:
            # Recieve data from client
            data = self.request.recv(1024)
            if data:
                # If logging level set to info print it to output
                # Otherwise, do nothing with the data and discard it
                logging.info(f'{self.client_address[0]}: {data}')
            else:
                break
        logging.info(f'{self.client_address[0]} DISCONNECTED')


class UDPHandler(BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        # Discard sent data
        logging.info(f'{self.client_address[0]}: {data}')


class TCPServer(BaseTCPServer):
    def __init__(self, ip):
        BaseTCPServer.__init__(self, ip, 9, TCPHandler)


class UDPServer(BaseUDPServer):
    def __init__(self, ip):
        BaseUDPServer.__init__(self, ip, 9, UDPHandler)

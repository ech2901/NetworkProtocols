from socketserver import BaseRequestHandler
from Servers import TCPServer, UDPServer
from os.path import exists

import logging

logging.basicConfig(format='%(levelname)s:  %(message)s', level=logging.INFO)


class TCPQOTDHandler(BaseRequestHandler):
    def handle(self):
        logging.info(f'{self.client_address[0]} CONNECTED')


        # Send Quote of the Day to client
        self.request.send(self.server.message)
        logging.info(f'SERVER to {self.client_address[0]}: {self.server.message}')

        logging.info(f'{self.client_address[0]} DISCONNECTED')


class UDPQOTDHandler(BaseRequestHandler):
    def handle(self):
        logging.info(f'{self.client_address[0]} CONNECTED')

        # Aquire socket to send data through
        _, sock = self.request

        # Send Quote of the Day to client
        sock.sendto(self.server.message, self.client_address)
        logging.info(f'SERVER to {self.client_address[0]}: {self.server.message}')

        logging.info(f'{self.client_address[0]} DISCONNECTED')


class TCPQOTDServer(TCPServer):
    def __init__(self, ip, message: bytes = b''):
        TCPServer.__init__(self, ip, 17, TCPQOTDHandler)
        # String format for server to respond with
        self.message = message

    def set_message(self, message: bytes):
        self.message = message


class UDPQOTDServer(UDPServer):
    def __init__(self, ip, message: bytes = b''):
        UDPServer.__init__(self, ip, 17, UDPQOTDHandler)
        # String format for server to respond with
        self.message = message

    def set_message(self, message: bytes):
        self.message = message


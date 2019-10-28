from socketserver import BaseRequestHandler
from Servers import TCPServer, UDPServer
from datetime import datetime

import logging

logging.basicConfig(format='%(levelname)s:  %(message)s', level=logging.INFO)

# Daytime Protocol described in RFC-867
# https://tools.ietf.org/html/rfc867

class TCPDaytimeHandler(BaseRequestHandler):
    def handle(self):
        logging.info(f'{self.client_address[0]} CONNECTED')

        # Get the current daytime with timezone information
        # Timezone name provided from OS
        data = datetime.now().astimezone().strftime(self.server.format).encode()

        # Send daytime info to client
        self.request.send(data)
        logging.info(f'SERVER to {self.client_address[0]}: {data}')

        logging.info(f'{self.client_address[0]} DISCONNECTED')


class UDPDaytimeHandler(BaseRequestHandler):
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


class TCPDaytimeServer(TCPServer):
    def __init__(self, ip, format='%d %b %y %H:%M:%S %Z'):
        TCPServer.__init__(self, ip, 13, TCPDaytimeHandler)
        # String format for server to respond with
        self.format = format


class UDPDaytimeServer(UDPServer):
    def __init__(self, ip, format='%d %b %y %H:%M:%S %Z'):
        UDPServer.__init__(self, ip, 13, UDPDaytimeHandler)
        # String format for server to respond with
        self.format = format


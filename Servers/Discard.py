from socketserver import BaseRequestHandler
from Servers import TCPServer, UDPServer

import logging

logging.basicConfig(format='%(levelname)s:  %(message)s', level=logging.INFO)


class TCPDiscardHandler(BaseRequestHandler):
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


class UDPDiscardHandler(BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        # Discard sent data
        logging.info(f'{self.client_address[0]}: {data}')


class UDPDiscardServer(UDPServer):
    def __init__(self, ip):
        UDPServer.__init__(self, ip, 9, TCPDiscardHandler)


class TCPDiscardServer(TCPServer):
    def __init__(self, ip):
        TCPServer.__init__(self, ip, 9, UDPDiscardHandler)

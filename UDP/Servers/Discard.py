from socketserver import BaseRequestHandler
from UDP.Servers import BaseThreadedServer

import logging

logging.basicConfig(format='%(levelname)s:  %(message)s', level=logging.INFO)


class DiscardHandler(BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        # Discard sent data
        logging.info(f'{self.client_address[0]}: {data}')

class UDPDiscardServer(BaseThreadedServer):
    def __init__(self, ip):
        BaseThreadedServer.__init__(self, ip, 9, DiscardHandler)

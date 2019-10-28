from socketserver import BaseRequestHandler
from TCP.Servers import BaseThreadedServer

import logging

logging.basicConfig(format='%(levelname)s:  %(message)s', level=logging.INFO)


class DiscardHandler(BaseRequestHandler):
    def handle(self):
        logging.info(f'{self.client_address[0]} CONNECTED')
        while True:
            data = self.request.recv(1024)
            if data:
                logging.info(f'{self.client_address[0]}: {data}')
            else:
                break
        logging.info(f'{self.client_address[0]} DISCONNECTED')

class TCPDiscardServer(BaseThreadedServer):
    def __init__(self, ip):
        BaseThreadedServer.__init__(self, ip, 9, DiscardHandler)
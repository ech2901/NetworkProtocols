from socketserver import BaseRequestHandler
from UDP.Servers import BaseThreadedServer

import logging

logging.basicConfig(format='%(levelname)s:  %(message)s', level=logging.INFO)


class EchoHandler(BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        # Echo sent data back to client
        logging.info(f'{self.client_address[0]}: {data}')
        sock.sendto(data, self.client_address)

class UDPEchoServer(BaseThreadedServer):
    def __init__(self, ip):
        BaseThreadedServer.__init__(self, ip, 7, EchoHandler)

from socketserver import BaseRequestHandler
from UDP.Servers import BaseThreadedServer
from datetime import datetime

import logging

logging.basicConfig(format='%(levelname)s:  %(message)s', level=logging.INFO)


class DaytimeHandler(BaseRequestHandler):
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

class UDPDaytimeServer(BaseThreadedServer):
    def __init__(self, ip, format='%d %b %y %H:%M:%S %Z'):
        BaseThreadedServer.__init__(self, ip, 13, DaytimeHandler)
        # String format for server to respond with
        self.format = format




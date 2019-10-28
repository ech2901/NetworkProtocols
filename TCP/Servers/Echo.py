from socketserver import BaseRequestHandler
from TCP.Servers import BaseThreadedServer

import logging

logging.basicConfig(format='%(levelname)s:  %(message)s', level=logging.INFO)


class EchoHandler(BaseRequestHandler):
    def handle(self):
        logging.info(f'{self.client_address[0]} CONNECTED')
        while True:
            # Recieve data from client
            data = self.request.recv(1024)
            if data:
                # If logging level set to info print it to output
                # Send same data recieved from client back to client
                logging.info(f'{self.client_address[0]}: {data}')
                self.request.send(data)
            else:
                break
        logging.info(f'{self.client_address[0]} DISCONNECTED')

class TCPEchoServer(BaseThreadedServer):
    def __init__(self, ip):
        BaseThreadedServer.__init__(self, ip, 7, EchoHandler)





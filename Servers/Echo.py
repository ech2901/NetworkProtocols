from socketserver import BaseRequestHandler
from Servers import TCPServer, UDPServer

import logging

logging.basicConfig(format='%(levelname)s:  %(message)s', level=logging.INFO)

# Echo Protocol described in RFC-862
# https://tools.ietf.org/html/rfc862


class TCPEchoHandler(BaseRequestHandler):
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


class UDPEchoHandler(BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        # Echo sent data back to client
        logging.info(f'{self.client_address[0]}: {data}')
        sock.sendto(data, self.client_address)


class UDPEchoServer(UDPServer):
    def __init__(self, ip):
        UDPServer.__init__(self, ip, 7, UDPEchoHandler)


class TCPEchoServer(TCPServer):
    def __init__(self, ip):
        TCPServer.__init__(self, ip, 7, TCPEchoHandler)

from socketserver import BaseRequestHandler
from Servers import TCPServer, UDPServer

from string import printable
from random import randrange, randint

import logging

logging.basicConfig(format='%(levelname)s:  %(message)s', level=logging.INFO)

# Echo Protocol described in RFC-864
# https://tools.ietf.org/html/rfc864


class TCPChargenHandler(BaseRequestHandler):
    def handle(self):
        logging.info(f'{self.client_address[0]} CONNECTED')

        offset = 0

        while True:
            try:
                data = self.server.data[offset % self.server.size:(offset + self.server.width) % self.server.size].encode()
                offset = offset + 1

                # If logging level set to info print it to output
                # Send some data to client
                logging.info(f'{self.client_address[0]}: {data}')
                self.request.send(data+b'\r\n')

            except ConnectionResetError as e:
                break
            except Exception as e:
                logging.exception(e)
                break

        logging.info(f'{self.client_address[0]} DISCONNECTED')


class UDPChargenHandler(BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        # Echo sent data back to client

        size = randrange(0, 512)
        data = ''
        while len(data) < size:
            data = data + self.server.data

        data = data[:size].encode()

        logging.info(f'{self.client_address[0]}: {data}')
        sock.sendto(data+b'\r\n', self.client_address)


class UDPChargenServer(UDPServer):
    def __init__(self, ip, data: str = printable, width: int = 72):
        UDPServer.__init__(self, ip, 19, UDPChargenHandler)
        self.data = data
        self.size = len(data)
        self.width = width


class TCPChargenServer(TCPServer):
    def __init__(self, ip, data: str = printable, width: int = 72):
        TCPServer.__init__(self, ip, 19, TCPChargenHandler)
        self.data = data
        self.size = len(data)
        self.width = width

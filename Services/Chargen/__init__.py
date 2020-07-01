import logging
from random import randrange
from socket import socket, AF_INET, SOCK_STREAM, SOCK_DGRAM
from socketserver import BaseRequestHandler
from string import printable

from BaseServers import BaseTCPServer, BaseUDPServer


# Echo Protocol described in RFC-864
# https://tools.ietf.org/html/rfc864


# This is a class because you might want to send multiple messages to the server
class TCPClient(socket):
    def __init__(self, ip: str):
        socket.__init__(self, AF_INET, SOCK_STREAM)
        socket.connect(self, (ip, 19))

    def loop(self):
        """
        Print to console stream of characters from server.
        Close socket to stop

        :return:
        """

        while True:
            data = self.recv(1024)
            yield data


def UDPClient(ip: str):
    """
    Send data to echo server
    Expect sent data to be returned from server

    :param ip: to_str
    :param message: bytes
    :return: bytes
    """
    with socket(AF_INET, SOCK_DGRAM) as sock:
        sock.sendto(b'', (ip, 19))
        data = sock.recvfrom(1024)
    return data[0]


logging.basicConfig(format='%(levelname)s:  %(message)s', level=logging.INFO)


class TCPHandler(BaseRequestHandler):
    def handle(self):
        logging.info(f'{self.client_address[0]} CONNECTED')

        offset = 0

        while True:
            try:
                data = self.server.data[
                       offset % self.server.get_size:(offset + self.server.width) % self.server.get_size].encode()
                offset = offset + 1

                # If logging level set to info print it to output
                # Send some data to client
                logging.info(f'{self.client_address[0]}: {data}')
                self.request.send(data + b'\r\n')

            except ConnectionResetError as e:
                break
            except Exception as e:
                logging.exception(e)
                break

        logging.info(f'{self.client_address[0]} DISCONNECTED')


class UDPHandler(BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        # Echo sent data back to client

        size = randrange(0, 512)
        data = ''
        while len(data) < size:
            data = data + self.server.data

        data = data[:size].encode()

        logging.info(f'{self.client_address[0]}: {data}')
        sock.sendto(data + b'\r\n', self.client_address)


class TCPServer(BaseTCPServer):
    def __init__(self, ip, data: str = printable, width: int = 72):
        BaseTCPServer.__init__(self, ip, 19, TCPHandler)
        self.data = data
        self.size = len(data)
        self.width = width


class UDPServer(BaseUDPServer):
    def __init__(self, ip, data: str = printable, width: int = 72):
        BaseUDPServer.__init__(self, ip, 19, UDPHandler)
        self.data = data
        self.size = len(data)
        self.width = width

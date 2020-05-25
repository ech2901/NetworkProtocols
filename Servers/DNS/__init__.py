import ssl
from socket import socket, AF_INET, SOCK_DGRAM, timeout
from socketserver import BaseRequestHandler
from struct import pack, unpack

from Servers import UDPServer, TCPServer
from .Classes import Packet, Type, Class, ResourceRecord
from .Storage import BaseStorage


class BaseDNSHandler(BaseRequestHandler):

    def lookup(self, query):
        packet = Packet(self.packet.identification,
                        0, self.packet.opcode, rd=self.packet.rd,
                        questions=[query])

        sock = socket(AF_INET, SOCK_DGRAM)
        sock.settimeout(self.server.timeout)

        for server in self.server.servers:
            sock.sendto(packet.to_bytes(), (server, 53))

            try:
                data, addr = sock.recvfrom(65536)
            except timeout:
                continue

            resp_packet = Packet.from_bytes(data)
            if resp_packet.identification == packet.identification and resp_packet.answer_rrs:
                if self.server.verbose:
                    print(f'{query.name} -> {len(resp_packet.answer_rrs)} found.')
                self.to_cache.append((query, resp_packet.answer_rrs))
                self.packet.answer_rrs.extend(resp_packet.answer_rrs)
                return

        raise FileNotFoundError

    def get_packet(self):
        pass

    def send_packet(self):
        pass

    def setup(self):
        self.get_packet()
        self.to_cache = list()
        if self.server.verbose:
            print(f'{self.client_address[0]} connected.')

    def handle(self):
        self.packet.qr = 1
        for query in self.packet.questions:
            if self.server.verbose:
                print(f'{self.client_address[0]} requested {query.name}.')

            records = self.server.storage[query]
            if records:
                if self.server.verbose:
                    print(f'Records found for {query.name}')
                self.packet.answer_rrs.extend(records)
            else:
                try:
                    self.lookup(query)
                except FileNotFoundError:
                    if self.server.verbose:
                        print(f'No record found for {query.name}')
                except Exception as e:
                    if self.server.verbose:
                        print(f'Exception while looking up {query.name}')
                        print(e.with_traceback(e.__traceback__))
                    return

    def finish(self):
        self.send_packet()
        for query, records in self.to_cache:
            self.server.storage.add_cache(query, records)


class TCPDNSHandler(BaseDNSHandler):

    def get_packet(self):
        size = unpack('! H', self.request.recv(2))[0]
        self.packet = Packet.from_bytes(self.request.recv(size))

    def send_packet(self):
        data = self.packet.to_bytes()
        self.request.send(pack('! H', len(data)))
        self.request.send(data)


class SSLDNSHandler(TCPDNSHandler):

    def get_packet(self):
        self.request = self.server.context.wrap_socket(self.request, server_side=True)
        self.request.do_handshake()

        size = unpack('! H', self.request.recv(2))[0]
        self.packet = Packet.from_bytes(self.request.recv(size))


class UDPDNSHandler(BaseDNSHandler):

    def get_packet(self):
        self.packet = Packet.from_bytes(self.request[0])

    def send_packet(self):
        self.request[1].sendto(self.packet.to_bytes(), self.client_address)


class BaseDNSServer(object):
    def __init__(self, storage: BaseStorage, *servers, verbose=False):
        self.timeout = 4
        self.verbose = verbose

        self.servers = servers

        self.storage = storage




class UDPDNSServer(UDPServer, BaseDNSServer):
    def __init__(self, *servers, verbose=False):
        UDPServer.__init__(self, '', 53, UDPDNSHandler)
        BaseDNSServer.__init__(self, *servers, verbose=verbose)


class TCPDNSServer(TCPServer, BaseDNSServer):
    def __init__(self, *servers, verbose=False, enable_ssl=False):
        if enable_ssl:
            self.context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH, )
            TCPServer.__init__(self, '', 853, SSLDNSHandler)
        else:
            TCPServer.__init__(self, '', 53, TCPDNSHandler)

        BaseDNSServer.__init__(self, *servers, verbose=verbose)

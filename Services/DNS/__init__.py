import ssl
from os import urandom
from socket import socket, AF_INET, SOCK_STREAM, SOCK_DGRAM, timeout
from socketserver import BaseRequestHandler
from struct import pack, unpack

from BaseServers import BaseUDPServer, BaseTCPServer
from .Classes import Packet, Query, Type, Class, Packet, ResourceRecord
from .Storage import BaseStorage


def UDPClient(url, *servers, **kwargs):
    request = Query(url.encode(), kwargs.get('type', Type.A), kwargs.get('class', Class.IN))
    packet = Packet(kwargs.get('id', int.from_bytes(urandom(2), 'big')),
                    0, kwargs.get('opcode', 0), rd=kwargs.get('rd', True),
                    questions=[request])

    sock = socket(AF_INET, SOCK_DGRAM)
    sock.settimeout(kwargs.get('timeout', 1))

    for server in servers:
        sock.sendto(packet.to_bytes(), (server, 53))

        try:
            data, addr = sock.recvfrom(65536)
        except timeout:
            continue

        resp_packet = Packet.from_bytes(data)
        if resp_packet.identification == packet.identification:
            return resp_packet


def TCPClient(url, *servers, **kwargs):
    request = Query(url.encode(), kwargs.get('type', Type.A), kwargs.get('class', Class.IN))
    packet = Packet(kwargs.get('id', int.from_bytes(urandom(2), 'big')),
                    0, kwargs.get('opcode', 0), rd=kwargs.get('rd', True),
                    questions=[request])

    for server in servers:
        try:
            with socket(AF_INET, SOCK_STREAM) as sock:
                sock.connect((server, 53))
                sock.settimeout(kwargs.get('timeout', 1))

                send_data = packet.to_bytes()

                sock.send(pack('! H', len(send_data)) + send_data)

                size = unpack('! H', sock.recv(2))[0]
                data = sock.recv(size)

                resp_packet = Packet.from_bytes(data)
                if resp_packet.identification == packet.identification:
                    return resp_packet
        except timeout:
            continue


def SSLClient(url, *servers, **kwargs):
    request = Query(url.encode(), kwargs.get('type', Type.A), kwargs.get('class', Class.IN))
    packet = Packet(kwargs.get('id', int.from_bytes(urandom(2), 'big')),
                    0, kwargs.get('opcode', 0), rd=kwargs.get('rd', True),
                    questions=[request])

    context = ssl.create_default_context()

    for server in servers:
        try:
            with socket(AF_INET, SOCK_STREAM) as sock:
                sock.connect((server, 853))
                sock.settimeout(kwargs.get('timeout', 1))
                with context.wrap_socket(sock, server_hostname=server) as s_sock:
                    s_sock.do_handshake()

                    send_data = packet.to_bytes()

                    s_sock.send(pack('! H', len(send_data)) + send_data)

                    size = unpack('! H', s_sock.recv(2))[0]
                    data = s_sock.recv(size)

                    resp_packet = Packet.from_bytes(data)
                    if resp_packet.identification == packet.identification:
                        return resp_packet
        except timeout:
            continue


class BaseHandler(BaseRequestHandler):

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


class TCPHandler(BaseHandler):

    def get_packet(self):
        size = unpack('! H', self.request.recv(2))[0]
        self.packet = Packet.from_bytes(self.request.recv(size))

    def send_packet(self):
        data = self.packet.to_bytes()
        self.request.send(pack('! H', len(data)))
        self.request.send(data)


class SSLHandler(TCPHandler):

    def get_packet(self):
        self.request = self.server.context.wrap_socket(self.request, server_side=True)
        self.request.do_handshake()

        size = unpack('! H', self.request.recv(2))[0]
        self.packet = Packet.from_bytes(self.request.recv(size))


class UDPHandler(BaseHandler):

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


class TCPServer(BaseTCPServer, BaseDNSServer):
    def __init__(self, *servers, verbose=False, enable_ssl=False):
        if enable_ssl:
            self.context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH, )
            BaseTCPServer.__init__(self, '', 853, SSLHandler)
        else:
            BaseTCPServer.__init__(self, '', 53, TCPHandler)

        BaseDNSServer.__init__(self, *servers, verbose=verbose)


class UDPServer(BaseUDPServer, BaseDNSServer):
    def __init__(self, *servers, verbose=False):
        BaseUDPServer.__init__(self, '', 53, UDPHandler)
        BaseDNSServer.__init__(self, *servers, verbose=verbose)

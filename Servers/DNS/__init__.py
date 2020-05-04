from datetime import datetime, timedelta
from os import urandom
from socket import socket, AF_INET, SOCK_DGRAM, timeout
from socketserver import BaseRequestHandler

from Servers import UDPServer
from Servers.DNS.Classes import Packet


class UDPDNSHandler(BaseRequestHandler):

    def lookup(self, request):
        packet = Packet(int.from_bytes(urandom(2), 'big'),
                        0, self.packet.opcode, rd=self.packet.rd,
                        questions=[request])

        sock = socket(AF_INET, SOCK_DGRAM)
        sock.settimeout(self.server.timeout)

        for server in self.server.servers:
            sock.sendto(packet.to_bytes(), (server, 53))

            try:
                data, addr = sock.recvfrom(65536)
            except timeout:
                continue

            resp_packet = Packet.from_bytes(data)
            if resp_packet.identification == packet.identification:
                self.to_cache.extend(resp_packet.answer_rrs)
                self.packet.additional_rrs.extend(resp_packet.answer_rrs)

        raise FileNotFoundError

    def setup(self):
        self.packet = Packet.from_bytes(self.request[0])
        self.to_cache = list()
        print(f'{self.client_address[0]} connected.')

    def handle(self):
        for query in self.packet.questions:
            print(f'{self.client_address[0]} requested {query.name.decode()}.')
            try:
                record = self.server.records[query.name][query._type][query._class]
                print(f'{query.name.decode()} -> {record}')
                self.packet.authority_rrs.extend(record)
            except KeyError:
                try:
                    record, expiration = self.server.cache[query.name][query._type][query._class]
                    if datetime.now() >= expiration:
                        raise KeyError
                    print(f'{query.name.decode()} -> {record}')
                    self.packet.additional_rrs.extend(record)
                except KeyError:
                    try:
                        self.lookup(query)
                    except FileNotFoundError:
                        print(f'No record found for {query.name.decode()}')
                    except Exception as e:
                        print(f'Exception while looking up {query.name.decode()}')
                        print(e)
                        return

        self.packet.qr = 1
        self.request[1].sendto(self.packet.to_bytes(), self.client_address)

    def finish(self):
        for record in self.to_cache:
            expiration = datetime.now() + timedelta(seconds=record.ttl)
            self.server.cache[record.name][record._type][record._class] = (record, expiration)

class UDPDNSServer(UDPServer):
    def __init__(self, timeout=4, *servers):
        UDPServer.__init__(self, '', 53, UDPDNSHandler)

        self.timeout = timeout

        self.servers = servers
        self.records = dict()
        self.cache = dict()



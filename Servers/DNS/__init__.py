from os import urandom
from socket import socket, AF_INET, SOCK_DGRAM, timeout
from socketserver import BaseRequestHandler

from Servers import UDPServer
from Servers.DNS.Classes import Packet


class UDPDNSHandler(BaseRequestHandler):

    def setup(self):
        self.packet = Packet.from_bytes(self.request[0])

    def handle(self):
        records = list()
        auth_rr = list()
        add_rr = list()
        for query in self.packet.questions:
            try:
                auth_rr.append(self.server.records[query.name][query._type][query._class])
            except KeyError:
                try:
                    add_rr.append(self.server.cache[query.name][query._type][query._class])
                except KeyError:
                    try:
                        if self.packet.opcode == 0:
                            add_rr.append(self.server.lookup(query))
                        elif self.packet.opcode == 1:
                            add_rr.append(self.server.ilookup(query))
                    except FileNotFoundError:
                        pass

        records.extend(auth_rr)
        records.extend(add_rr)

        packet = Packet(self.packet.identification, 1, self.packet.opcode, False,
                        False, self.packet.rd, False, True, False, 0,
                        self.packet.questions, records, auth_rr, add_rr)

        self.request[1].sendto(packet.to_bytes(), self.client_address)


class UDPDNSServer(UDPServer):
    def __init__(self, ip, *servers):
        UDPServer.__init__(self, ip, 53, UDPDNSHandler)
        self.servers = servers
        self.records = dict()
        self.cache = dict()

    def lookup(self, request):
        packet = Packet(int.from_bytes(urandom(2), 'big'),
                        0, 0, rd=True,
                        questions=[request])

        sock = socket(AF_INET, SOCK_DGRAM)
        sock.settimeout(1)

        for server in self.servers:
            sock.sendto(packet.to_bytes(), (server, 53))

            try:
                data, addr = sock.recvfrom(65536)
            except timeout:
                continue

            resp_packet = Packet.from_bytes(data)
            if resp_packet.identification == packet.identification:
                return resp_packet.answer_rrs[0]

        raise FileNotFoundError

from datetime import datetime, timedelta
from socket import socket, AF_INET, SOCK_DGRAM, timeout
from socketserver import BaseRequestHandler

from Servers import UDPServer
from Servers.DNS.Classes import Packet, Type, Class, ResourceRecord


class UDPDNSHandler(BaseRequestHandler):

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
                    print(f'{query.name.decode()} -> {len(resp_packet.answer_rrs)} found.')
                self.to_cache.append((query, resp_packet.answer_rrs))
                self.packet.answer_rrs.extend(resp_packet.answer_rrs)
                return

        raise FileNotFoundError

    def is_blocked(self, query):
        if query.name in self.server.blacklist_hostnames:
            return True
        else:
            *_, host, root = query.name.split(b'.', -1)
            return b'.'.join([host, root]) in self.server.blacklist_domains


    def setup(self):
        self.packet = Packet.from_bytes(self.request[0])
        self.to_cache = list()
        if self.server.verbose:
            print(f'{self.client_address[0]} connected.')

    def handle(self):
        for query in self.packet.questions:
            if self.server.verbose:
                print(f'{self.client_address[0]} requested {query.name.decode()}.')

            if self.is_blocked(query):
                if self.server.verbose:
                    print(f'{query.name.decode()} is blocked.')
                self.packet.answer_rrs.append(ResourceRecord(query.name, *self.server.dummy_record))
                continue

            try:
                records = self.server.records[(query.name, query._type, query._class)]
                if self.server.verbose:
                    print(f'{query.name.decode()} -> {len(records)} authoritive found.')
                self.packet.answer_rrs.extend(records)
            except KeyError:
                try:
                    records, expiration = self.server.cache[(query.name, query._type, query._class)]
                    if datetime.now() >= expiration:
                        raise KeyError
                    if self.server.verbose:
                        print(f'{query.name.decode()} -> {len(records)} previously cached.')
                    self.packet.answer_rrs.extend(records)
                except KeyError:
                    try:
                        self.lookup(query)
                    except FileNotFoundError:
                        if self.server.verbose:
                            print(f'No record found for {query.name.decode()}')
                    except Exception as e:
                        if self.server.verbose:
                            print(f'Exception while looking up {query.name.decode()}')
                            print(e.with_traceback(e.__traceback__))
                        return

        self.packet.qr = 1
        self.request[1].sendto(self.packet.to_bytes(), self.client_address)

    def finish(self):
        for query, records in self.to_cache:
            expiration = datetime.now() + timedelta(seconds=min(records, key=lambda x: x.ttl).ttl)
            self.server.cache[(query.name, query._type, query._class)] = (records, expiration)


class UDPDNSServer(UDPServer):
    def __init__(self, *servers, verbose=False):
        UDPServer.__init__(self, '', 53, UDPDNSHandler)

        self.timeout = 4
        self.verbose = verbose

        self.servers = servers
        self.records = dict()
        self.cache = dict()

        self.blacklist_domains = list()
        self.blacklist_hostnames = list()
        packed_rdata = Type.A.factory('0.0.0.0').packed
        # Dummy record for blocks addresses.
        self.dummy_record = (Type.A, Class.IN, (1 << 32) - 1, len(packed_rdata), packed_rdata)

    def add_record(self, name: str, _type: Type, _class: Class, ttl: int, rdata: str):
        packed_rdata = _type.factory(rdata).packed
        record = ResourceRecord(name.encode(), _type, _class, ttl, len(packed_rdata), packed_rdata)
        key = (record.name, record._type, record._class)
        if key in self.records:
            self.records[key].append(record)
            return
        self.records[key] = list()
        self.records[key].append(record)

    def block_domain(self, domain: str):
        *_, host, root = domain.split('.', -1)
        self.blacklist_domains.append(f'{host}.{root}'.encode())

    def block_hostname(self, hostname: str):
        self.blacklist_hostnames.append(hostname.encode())

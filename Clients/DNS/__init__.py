from os import urandom
from socket import socket, AF_INET, SOCK_DGRAM, timeout

from Clients.DNS.Classes import Query, Types, Packet


def lookup(url, *servers, **kwargs):
    request = Query(url.encode(), kwargs.get('type', Types.A), kwargs.get('class', Classes.IN))
    packet = Packet(kwargs.get('id', int.from_bytes(urandom(2), 'big')),
                    0, kwargs.get('opcode', 0), rd=kwargs.get('rd', True),
                    questions=[request])

    sock = socket(AF_INET, SOCK_DGRAM)
    sock.bind(('', 0))
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


def ilookup(ip, *servers, **kwargs):
    ip = '.'.join(reversed(ip.split('.'))) + '.in-addr.arpa'

    kwargs['type'] = Types.PTR
    return lookup(ip, *servers, **kwargs)

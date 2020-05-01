import ssl
from os import urandom
from socket import socket, AF_INET, SOCK_STREAM, SOCK_DGRAM, timeout
from struct import pack, unpack

from Clients.DNS.Classes import Query, Type, Class, Packet


def lookup(url, *servers, **kwargs):
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


def ilookup(ip, *servers, **kwargs):
    ip = '.'.join(reversed(ip.split('.'))) + '.in-addr.arpa'

    kwargs['type'] = Type.PTR
    return lookup(ip, *servers, **kwargs)


def lookup_tcp(url, *servers, **kwargs):
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


def ilookup_tcp(ip, *servers, **kwargs):
    ip = '.'.join(reversed(ip.split('.'))) + '.in-addr.arpa'

    kwargs['type'] = Type.PTR
    return lookup_tcp(ip, *servers, **kwargs)


def lookup_ssl(url, *servers, **kwargs):
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


def ilookup_ssl(ip, *servers, **kwargs):
    ip = '.'.join(reversed(ip.split('.'))) + '.in-addr.arpa'

    kwargs['type'] = Type.PTR
    return lookup_ssl(ip, *servers, **kwargs)

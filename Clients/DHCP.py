from uuid import getnode
from dataclasses import dataclass
from enum import Enum
from os import urandom
from struct import pack, unpack

from socket import socket, AF_INET, SOCK_DGRAM, SOL_SOCKET, SO_BROADCAST, IPPROTO_IP
from ipaddress import ip_address

@dataclass
class Option(object):
    code: int
    size: int
    data: bytes

    def to_bytes(self):
        return pack(f'! 2B {self.size}s', self.code, self.size, self.data)

    @classmethod
    def from_bytes(cls, data):
        code = data[0]
        size = data[1]
        op_data = data[2:2+size]

        if len(data) > 2+size:
            return cls(code, size, op_data), data[2+size:]
        return cls(code, size, op_data), b''

    def int(self):
        return int.from_bytes(self.data, 'big')

    def list_int(self):
        return list(self.data)

    def str(self):
        return self.data.decode()

    def ip(self):
        return ip_address(self.data)

    def multi_ip(self):
        return [ip_address(self.data[i:i+4]) for i in range(0, self.size, 4)]

class Format(Enum):
    MASK = (1, 'Subnet Mask', Option.ip)
    ROUTER = (3, 'Router(s)', Option.multi_ip)
    TIME = (4, 'Time Server(s)', Option.multi_ip)
    NAME = (5, 'Name Server(s)', Option.multi_ip)
    DNS = (6, 'DNS Server(s)', Option.multi_ip)
    LOG = (7, 'Log Server(s)', Option.multi_ip)
    COOKIE = (8, 'Cookie Server(s)', Option.multi_ip)
    LPR = (9, 'Time Server(s)', Option.multi_ip)
    IMPRESS = (10, 'Time Server(s)', Option.multi_ip)
    RLS = (11, 'Resource Location Server(s)', Option.multi_ip)
    HOST = (12, 'Host Name', Option.str)
    BSIZE = (13, 'Boot File Size', Option.int)
    MERIT = (14, 'Merit Dump File', Option.str)
    DOMAIN = (15, 'Domain Name', Option.str)
    SWAP = (16, 'Swap Server', Option.ip)
    ROOT = (17, 'Root Path', Option.str)
    EXT = (18, 'Extensions path', Option.str)
    BROAD = (28, 'Broadcast Address', Option.ip)
    REQ = (50, 'Requested IP Address', Option.ip)
    IPLT = (51, 'IP Address Lease Time', Option.int)
    TYPE = (53, 'DHCP Message Type', Option.int)
    SEID = (54, 'Server Identifier', Option.int)
    RLST = (55, 'Parameter Request List', Option.list_int)
    MESS = (56, 'Message', Option.str)
    MSZE = (57, 'Maximum DHCP Message Size', Option.int)
    RENEW = (58, 'Renewal (T1) Time Value', Option.int)
    REBIND = (59, 'Rebinding (T2) Time Value', Option.int)
    VENDOR = (60, 'Vendor Class Identifier', Option.str)
    CLIENT = (61, 'Client Identifier', Option.str)
    END = (255, 'End', Option.int)

    def __format__(self, option):
        return self.value[1], self.value[2](option)

    @classmethod
    def format(cls, option):
        for form in cls:
            if form.value[0] == option.code:
                return form.__format__(option)

        return f'UNDEFINED CODE: {option.code}', option.data


class Packet(object):
    def __init__(self, **kwargs):
        self.data = kwargs

    def setopt(self, key, value):
        self.data[key] = value

    @classmethod
    def from_bytes(cls, data):
        keys = ('op', 'htype', 'hlen', 'hops', 'xid', 'secs', 'flags', 'ciaddr', 'yiaddr', 'siaddr', 'giaddr', 'cookie')
        values = unpack('! 4B I 2H 4I 6s 10x 64x 128x L', data[:240])

        data_out = dict()
        for key, value in zip(keys, values):
            data_out[key] = value

        if len(data) > 240:
            data_out['options'] = data[240:]


        return cls(**data_out)

    def to_bytes(self):
        return pack(
                    '! 4B 4s 2H 4I 6s 10x 64x 128x L',
                    self.data.get('op', 1),
                    self.data.get('htype', 1),
                    self.data.get('hlen', 6),
                    self.data.get('hops', 0),
                    self.data.get('xid', urandom(4)),
                    self.data.get('secs', 0),
                    self.data.get('flags', 1 << 15),
                    self.data.get('ciaddr', 0),
                    self.data.get('yiaddr', 0),
                    self.data.get('siaddr', 0),
                    self.data.get('giaddr', 0),
                    self.data.get('chaddr', getnode().to_bytes(6, 'big')),
                    self.data.get('cookie', 0x63825363),
                    ) + self.data.get('options', b'')

    @property
    def mac(self):
        mac = self.data.get('chaddr', getnode().to_bytes(6, 'big'))
        out = ':'.join([hex(i)[2:].upper() for i in mac])
        return out

    @property
    def client_ip(self):
        return ip_address(self.data.get('ciaddr', 0)).exploded

    @property
    def given_ip(self):
        return ip_address(self.data.get('yiaddr', 0)).exploded

    @property
    def server_ip(self):
        return ip_address(self.data.get('siaddr', 0)).exploded

    @property
    def gateway_ip(self):
        return ip_address(self.data.get('giaddr', 0)).exploded

    @property
    def options(self):
        out = list()
        data = self.data.get('options', b'')

        while data:
            option, data = Option.from_bytes(data)
            out.append(Format.format(option))
            if option.code == 0xff:
                break

        return out

    def __len__(self):
        return len(self.to_bytes())


SERVER_IP = '255.255.255.255'  # DHCP Default server ip
SERVER_PORT = 67  # DHCP Default server port


CLIENT_IP = '0.0.0.0'  # DHCP Default client ip
CLIENT_PORT = 68  # DHCP Default client port

RELAY = False


def discover(sock, packet=Packet(), options=b''):
    packet.setopt('options', options)

    sock.sendto(packet.to_bytes(), (SERVER_IP, SERVER_PORT))
    offer_data = sock.recvfrom(20448)[0]
    offer = Packet.from_bytes(offer_data)

    return offer

def request(sock, packet, options=b''):
    packet.setopt('options', options)
    sock.sendto(packet.to_bytes(), (SERVER_IP, SERVER_PORT))

    ack_data = sock.recvfrom(2048)[0]

    ack = Packet.from_bytes(ack_data)

    return ack

def dhcp_client(packet=Packet(), options=b''):
    sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP)
    sock.setsockopt(SOL_SOCKET, SO_BROADCAST, 1)
    sock.bind((CLIENT_IP, CLIENT_PORT))


    offer = discover(sock, packet, options)

    req_packet = Packet(siaddr=offer.data['siaddr'])
    request_options = (
        Option(53, 1, (3).to_bytes(1, 'big')),
        Option(50, 4, offer.data['yiaddr'].to_bytes(4, 'big')),
        Option(54, 4, offer.data['siaddr'].to_bytes(4, 'big'))
    )

    option_data = options
    for option in request_options:
        option_data = option_data + option.to_bytes()

    ack = request(sock, req_packet, option_data)

    return offer, ack



if RELAY:
    test_ip = ip_address('192.168.0.101')

    sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP)
    sock.setsockopt(SOL_SOCKET, SO_BROADCAST, 1)

    test_packet = Packet(hops=1, giaddr=test_ip._ip, chaddr=(0xB827EBC4D973).to_bytes(6, 'big'))
    sock.bind((test_ip.compressed, CLIENT_PORT))
    test_packet.setopt('options', (0x350101370401030f06ff).to_bytes(10, 'big'))

    sock.sendto(test_packet.to_bytes(), (SERVER_IP, SERVER_PORT))

    recv_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP)
    recv_sock.bind((test_ip.compressed, SERVER_PORT))

    offer_data = recv_sock.recvfrom(2048)[0]


    offer = Packet.from_bytes(offer_data)

    request = Packet(siaddr=offer.data['siaddr'])

    request.setopt('hops', 1)
    request.setopt('giaddr', test_ip._ip)
    request.setopt('chaddr', (getnode()+10).to_bytes(6, 'big'))

    options = (
                Option(53, 1, (3).to_bytes(1, 'big')),
                Option(50, 4, offer.data['yiaddr'].to_bytes(4, 'big')),
                Option(54, 4, offer.data['siaddr'].to_bytes(4, 'big'))
                )

    option_data = b''
    for option in options:
        option_data = option_data+option.to_bytes()

    request.setopt('options', option_data)
    sock.sendto(request.to_bytes(), (SERVER_IP, SERVER_PORT))

    ack_data = recv_sock.recvfrom(2048)[0]

    ack = Packet.from_bytes(ack_data)

else:
    # 0x350101370401030f06ff
    offer, ack = dhcp_client()
    pass







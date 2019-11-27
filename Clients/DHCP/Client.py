from uuid import getnode
from os import urandom
from struct import pack, unpack

from socket import socket, AF_INET, SOCK_DGRAM, SOL_SOCKET, SO_BROADCAST, IPPROTO_IP
from ipaddress import ip_address

from Clients.DHCP.Options import OptionCodes

SERVER_IP = '255.255.255.255'  # DHCP Default server ip
SERVER_PORT = 67  # DHCP Default server port

CLIENT_IP = '0.0.0.0'  # DHCP Default client ip
CLIENT_PORT = 68  # DHCP Default client port


class Packet(object):
    def __init__(self, **kwargs):
        self.data = dict()
        self.data.update(kwargs)

    def setopt(self, key, value):
        self.data[key] = value

    @classmethod
    def from_bytes(cls, data):
        keys = (
            'op', 'htype', 'hlen', 'hops', 'xid', 'secs', 'flags',
            'ciaddr', 'yiaddr', 'siaddr', 'giaddr', 'chaddr', 'cookie'
        )
        values = unpack('! 4B I 2H 4I 6s 10x 64x 128x L', data[:240])

        data_out = dict()
        for key, value in zip(keys, values):
            data_out[key] = value

        if len(data) > 240:
            data_out['options'] = data[240:]


        return cls(**data_out)

    def to_bytes(self):
        return pack(
                    '! 4B I 2H 4I 6s 10x 64x 128x L',
                    self.data.get('op', 1),
                    self.data.get('htype', 1),
                    self.data.get('hlen', 6),
                    self.data.get('hops', 0),
                    self.data.get('xid', 0),
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
    def xid(self):
        return self.data.get('xid', 0)

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
            option, data = OptionCodes.from_bytes(data)
            out.append(option)

        return out

    def __len__(self):
        return len(self.to_bytes())

    def __str__(self):
        out = str(self.data)[1:-1].replace(', ', '\n')
        for option in self.options:
            out = f'{out}\n\n{option}'

        return out


def discover(sock, packet=Packet()):

    sock.sendto(packet.to_bytes(), (SERVER_IP, SERVER_PORT))
    offer_data = sock.recvfrom(2048)[0]
    offer = Packet.from_bytes(offer_data)

    return offer


def request(sock, packet):
    sock.sendto(packet.to_bytes(), (SERVER_IP, SERVER_PORT))

    ack_data = sock.recvfrom(2048)[0]

    ack = Packet.from_bytes(ack_data)

    return ack


def dhcp_client(packet=Packet(), *options_list):
    sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP)
    sock.setsockopt(SOL_SOCKET, SO_BROADCAST, 1)
    sock.bind((CLIENT_IP, CLIENT_PORT))

    options = b''
    for option in options_list:
        options = options+option.bytes

    offer = discover(sock, packet, options)

    req_packet = Packet(siaddr=offer.data['siaddr'])

    request_options = (
        OptionCodes.DHCP_MESSAGE_TYPE(3),
        OptionCodes.REQUESTED_IP(offer.given_ip),
        OptionCodes.SERVER_ID(offer.server_ip)
    )

    option_data = options
    for option in request_options:
        option_data = option_data + option.bytes

    ack = request(sock, req_packet, option_data)

    return packet, offer, req_packet, ack

data = list()
sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP)
sock.setsockopt(SOL_SOCKET, SO_BROADCAST, 1)
sock.bind((CLIENT_IP, CLIENT_PORT))


packet1 = Packet(options=b'5\x01\x01=\x07\x01X\xcbR\x0e\x86\xcf9\x02\x05\xdc<\x0fandroid-dhcp-107\n\x01\x03\x06\x0f\x1a\x1c3:;+\xff')
data.append(packet1)

offer = discover(sock, packet1)
data.append(offer)

packet2 = Packet(options=b'5\x01\x03=\x07\x01X\xcbR\x0e\x86\xcf2\x04\xc0\xa8\x00\x9f6\x04\xc0\xa8\x00\x019\x02\x05\xdc<\x0fandroid-dhcp-107\n\x01\x03\x06\x0f\x1a\x1c3:;+\xff')
data.append(packet2)

ack = request(sock, packet2)
data.append(ack)






for p in data:
    print(f'{"".rjust(20, "-")}\n{p}\n{"".rjust(20, "-")}\n')
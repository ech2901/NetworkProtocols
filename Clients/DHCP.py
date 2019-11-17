from uuid import getnode
from dataclasses import dataclass
from enum import Enum
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
            out.append(option)
            if option.code == 0xff:
                break

        return out

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



SERVER_IP = '255.255.255.255'  # DHCP Default server ip
SERVER_PORT = 67  # DHCP Default server port


CLIENT_IP = '0.0.0.0'  # DHCP Default client ip
CLIENT_PORT = 68  # DHCP Default client port


test_packet = Packet(chaddr=(getnode()).to_bytes(6, 'big'))
test_packet.setopt('options', (0x350101370401030f06ff).to_bytes(10, 'big'))


sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP)
sock.setsockopt(SOL_SOCKET, SO_BROADCAST, 1)
sock.bind((CLIENT_IP, CLIENT_PORT))

sock.sendto(test_packet.to_bytes(), (SERVER_IP, SERVER_PORT))

data = sock.recvfrom(2048)[0]

recv = Packet.from_bytes(data)





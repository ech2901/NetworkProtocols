from uuid import getnode
from dataclasses import dataclass
from enum import Enum
from os import urandom
from struct import pack, unpack

from socket import socket, AF_INET, SOCK_DGRAM, SOL_SOCKET, SO_BROADCAST, IPPROTO_IP
from ipaddress import ip_address

SERVER_IP = '255.255.255.255'  # DHCP Default server to_ip
SERVER_PORT = 67  # DHCP Default server port


CLIENT_IP = '0.0.0.0'  # DHCP Default client to_ip
CLIENT_PORT = 68  # DHCP Default client port

RELAY = False



class IP_Formatter(object):
    @staticmethod
    def to_bytes(data):
        if type(data) == list:
            out = []
            for addr in data:
                out.append(ip_address(addr).packed)
            return b''.join(out)
        return ip_address(data).packed

    @staticmethod
    def from_bytes(data):
        if len(data) > 4:
            out = []
            for index in range(0, len(data), 4):
                out.append(ip_address(data[index:index+4]).compressed)
            return out
        return ip_address(data).compressed


class Int_Formatter(object):
    @staticmethod
    def to_bytes(data):
        size = data.bit_length()//8
        if data % 8:
            size = size+1

        return data.to_bytes(size, 'big')
    @staticmethod
    def from_bytes(data):
        return int.from_bytes(data, 'big')


class List_Formatter(object):
    @staticmethod
    def to_bytes(data):
        return b''.join([val.to_bytes(1, 'big') for val in data])

    @staticmethod
    def from_bytes(data):
        return list(data)


class Str_Formatter(object):
    @staticmethod
    def to_bytes(data):
        return data.encode()

    @staticmethod
    def from_bytes(data):
        return data.decode(errors='ignore')



class Bool_Formatter(object):
    @staticmethod
    def to_bytes(data):
        if data:
            return b'\xff'
        return b'\x00'

    @staticmethod
    def from_bytes(data):
        return bool(int.from_bytes(data, 'big'))


class Filter_Formatter(object):
    @staticmethod
    def to_bytes(data):
        out = []
        for dest, mask in data:
            out.append(ip_address(dest).packed + ip_address(mask).packed)

        return b''.join(out)

    @staticmethod
    def from_bytes(data):
        out = []
        for index in range(0, len(data), 8):
            dest, mask = ip_address(data[index:index+4]), ip_address(data[index+4:index+8])
            out.append((dest.compressed, mask.compressed))
        return out


@dataclass(repr=False)
class Option(object):
    code: int
    size: int
    name: str = 'Unknown Code'
    formatter: object = Int_Formatter
    data: bytes = b''

    def set(self, data):
        self.data = self.formatter.to_bytes(data)

    def get(self):
        return self.formatter.from_bytes(self.data)


    @property
    def bytes(self):
        return self.code.to_bytes(1, 'big')+self.size.to_bytes(1, 'big')+self.data

    def __str__(self):
        return f'Name: {self.name}\nCode: {self.code}\nData: {self.get()}'

    def __repr__(self):
        return f'Option(name={self.name}, code={self.code}, data={self.get()})'


class OptionCodes(Enum):
    PAD = (0, 'Pad Byte', List_Formatter)
    SUBNET = (1, 'Subnet Mask', IP_Formatter)
    TIME_OFFSET = (2, 'Time Offset', Int_Formatter)
    ROUTER = (3, 'Router', IP_Formatter)
    TIME_SERVER = (4, 'Time Server(s)', IP_Formatter)
    NAME_SERVER = (5, 'Name Server(s)', IP_Formatter)
    DNS_SERVER = (6, 'DNS Server(s)', IP_Formatter)
    LOG_SERVER = (7, 'Log Server(s)', IP_Formatter)
    COOKIE_SERVER = (8, 'Cookie Server(s)', IP_Formatter)
    IMPRESS_SERVER = (10, 'Impress Server(s)', IP_Formatter)
    RESOURCE_LOCATION_SERVER = (11, 'Resource Location Server(s)', IP_Formatter)
    HOST_NAME = (12, 'Host Name', Str_Formatter)
    BOOT_FILE_SIZE = (13, 'Boot File Size', Int_Formatter)
    MERIT_DUMP_FILE = (14, 'Merit Dump File', Str_Formatter)
    DOMAIN_NAME = (15, 'Domain Name', Str_Formatter)
    SWAP_SERVER = (16, 'Swap Server', IP_Formatter)
    ROOT_PATH = (17, 'Root Path', Str_Formatter)
    EXTENSIONS_PATH = (18, 'Extensions Path', Str_Formatter)
    IP_FORWARDING = (19, 'IP Forwarding enable/disable', Bool_Formatter)
    NON_LOCAL_ROUTING = (20, 'Non-Local Source Routing enable/disable', Bool_Formatter)
    POLICY_FILTER = (21, 'Policy Filter', Filter_Formatter)
    MAX_REASEMBLY_SIZE = (22, 'Max Datagram Reassembly Size', Int_Formatter)
    IP_TTL = (23, 'Default IP Time-to-live', Int_Formatter)
    MTU_AGING_TIMEOUT = (24, 'Path MTU Aging Timeout', Int_Formatter)
    MTU_PLATEU_TABLE = (25, 'Path MTU Plateau Table', List_Formatter)
    INTERFACE_MTU = (26, 'Interface MTU', List_Formatter)
    SUBNETS_LOCAL = (27, 'All Subnets Local', Bool_Formatter)
    BROADCAST_ADDRESS = (28, 'Broadcast Address', IP_Formatter)
    PERFORM_MASK_DISCO = (29, 'Perform Mask Discovery', Bool_Formatter)
    MASK_SUPPLIER = (30, 'Mask Supplier', Bool_Formatter)
    ROUTER_DISCO = (31, 'Perform Router Discovery', Bool_Formatter)
    ROUTER_SOLICITATION_ADDRESS = (32, 'Router Solicitation Address', IP_Formatter)
    STATIC_ROUTE = (33, 'Static Route', POLICY_FILTER)
    TRAILER_ENCAPSULATION_OPTION = (34, 'Trailer Encapsulation Option', Bool_Formatter)
    ARP_CACHE_TIMEOUT = (35, 'Arp Cache Timeout', Int_Formatter)
    ETHERNET_ENCAPSULATION = (36, 'Ethernet Encapsulation', Bool_Formatter)
    TCP_TTL = (37, 'TCP Default Time-to-live', Int_Formatter)
    TCP_KEEPALIVE_INTERVAL = (38, 'TCP Keepalive Interval', Int_Formatter)
    TCP_KEEPALIVE_GARBAGE = (39, 'TCP Keepalive Garbage', Int_Formatter)
    NETWORK_INFO_DOMAIN = (40, 'Network Info Service Domain', Str_Formatter)
    NETWORK_INFO_SERVERS = (41, 'Network Information Server(s)', IP_Formatter)
    NTP_SERVERS = (42, 'Network Time Protocol Server(s)', IP_Formatter)
    VENDOR_INFO = (43, 'Vendor-specific Information', Str_Formatter)
    NETBIOS_NAME_SERVER = (44, 'NetBIOS over TCP/IP Name Server', IP_Formatter)
    NETBIOS_DISTRIBUTION_SERVER = (45, 'NetBIOS over TCP/IP Datagram Distributin Server', IP_Formatter)
    NETBIOS_NODE_TYPE = (46, 'NetBIOS over TCP/IP Node Type', Int_Formatter)
    NETBIOS_SCOPE = (47, 'NetBIOS over TCP/IP Scope', List_Formatter)
    X_WINDOW_FONT_SERVER = (48, 'X Window System Font Server', IP_Formatter)
    X_WINDOW_DISPLAY_MANAGER = (49, 'X Window System Display Manager', IP_Formatter)
    REQUESTED_IP = (50, 'Requested IP Address', IP_Formatter)
    IP_LEASE_TIME = (51, 'IP Address Lease Time', Int_Formatter)
    OPTION_OVERLOAD = (52, 'Option Overload', Bool_Formatter)
    DHCP_MESSAGE_TYPE = (53, 'DHCP Message Type', Int_Formatter)
    SERVER_ID = (54, 'Server ID', IP_Formatter)
    PARAMETER_REQ_LIST = (55, 'Parameter Request List', List_Formatter)
    MESSAGE = (56, 'Message', Str_Formatter)
    MAX_DHCP_MESSAGE_SIZE = (57, 'Max DHCP Message Size', Int_Formatter)
    RENEWAL_T1_VAL = (58, 'Renewal (T1) Time Valuue', Int_Formatter)
    RENEWAL_T2_VAL = (59, 'Renewal (T2)) Time Value', Int_Formatter)
    VENDOR_ID = (60, 'Vendor Class ID', List_Formatter)
    CLIENT_ID = (61, 'Client ID', List_Formatter)
    NETWORK_INFO_PLUS_DOMAIN = (64, 'Network Information Service+ Domain', Str_Formatter)
    NETOWRK_INFO_PLUS_SERVERS = (65, 'Network Information Service+ Server(s)', IP_Formatter)
    TFTP_SERVER_NAME = (66, 'TFTP Server Name', IP_Formatter)
    BOOTFILE_NAME = (67, 'Bootfile Name', Str_Formatter)
    MOBILE_IP_AGENT = (68, 'Mobile IP Home Agent', IP_Formatter)
    SMTP_SERVERS = (69, 'SMTP Server(s)', IP_Formatter)
    POP_SERVERS = (70, 'POP Server(s)', IP_Formatter)
    NNTP_SERVERS = (71, 'NNTP Server(s)', IP_Formatter)
    WWW_SERVERS = (72, 'Default WWW Server(s)', IP_Formatter)
    FINGER_SERVERS = (73, 'Default Finger Protocol Server(s)', IP_Formatter)
    IRC_SERVERS = (74, 'IRC Server(s)', IP_Formatter)
    STREETTALK_SERVERS = (75, 'StreetTalk Server(s)', IP_Formatter)
    STREETTALK_DIRECTORY_SERVER = (76, 'StreetTalk Directory Assistance Server(s)', IP_Formatter)
    RELAY_AGENT_INFO = (82, 'Relay Agent Info', List_Formatter)
    NDS_SERVERS = (85, 'Novel Directory Service Server(s)', IP_Formatter)
    NDS_TREE_NAME = (86, 'Novel Directory Service Tree Name', Str_Formatter)
    NDS_CONTEXT = (87, 'Novel Directory Service Context', List_Formatter)
    TZ_POSIX = (100, 'Time Zone, POSIX Style', Str_Formatter)
    TZ_TZ_DATABASE = (101, 'Time Zone, tz Database Style', Str_Formatter)
    DOMIAN_SEARCH = (119, 'Domain Search', Str_Formatter)
    CLASSLESS_STATIC_ROUTE = (121, 'Classless Static Route', List_Formatter)
    END = (255, 'End Byte', List_Formatter)

    @classmethod
    def get(cls, code, size, data):
        for op in cls:
            if code == op.value[0]:
                code, name, formatter = op.value
                return Option(code, size, name, formatter, data)
        return Option(code, size, data=data)

    @classmethod
    def from_bytes(cls, raw_data):
        code = raw_data[0]
        size = raw_data[1]
        data = raw_data[2:2+size]

        option = cls.get(code, size, data)

        if len(data):
            return option, raw_data[2+size:]
        return option, b''

    def __call__(self, size, data):
        code, name, formatter = self.value
        return Option(code, size, name, formatter, formatter.to_bytes(data))


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
            option, data = OptionCodes.from_bytes(data)
            out.append(option)

        return out

    def __len__(self):
        return len(self.to_bytes())


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
        OptionCodes.DHCP_MESSAGE_TYPE(1, 3),
        OptionCodes.REQUESTED_IP(4, offer.given_ip),
        OptionCodes.SERVER_ID(4, offer.server_ip)
    )

    option_data = options
    for option in request_options:
        option_data = option_data + option.bytes

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

    option = OptionCodes.PARAMETER_REQ_LIST(8, [2, 4, 5, 7, 8, 9, 12, 15])

    offer, ack = dhcp_client(Packet(), option)
    pass







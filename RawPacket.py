from socket import htons, IPPROTO_TCP
from os import urandom
from struct import pack, unpack
from ipaddress import ip_address


def build_ethernet(destination: bytes, source: bytes, payload: bytes, **kwargs):
    """
    Build  raw ethernet frames for sending.
    :param destination: bytes: MAC address sending to.
    :param source: bytes: MAC address sending from
    :param payload: bytes
    :keyword type: int: Packet Type (optional)
    :keyword tag: int: 802.11 tag (optional)
    :return: bytes
    """
    if 'tag' in kwargs:
        header = pack('! 6s 6s L H', destination, source, kwargs.get('tag'), kwargs.get('type', 0x0800))
    else:
        header = pack('! 6s 6s H', destination, source, kwargs.get('type', 0x0800))

    return header + payload


def disassemble_ethernet(packet):
    """
    Disassemble a ethernet packet for inspection.
    Can be used to build a packet later.

    :param packet: bytes: Ethernet packet to disassemble
    :return: dict
    """
    out = dict()

    ethe_tag_test = int.from_bytes(packet[12:14], 'big')
    if(ethe_tag_test == 0x8100 or ethe_tag_test == 0x88a8):
        keys = ('destination', 'source', 'tag', 'type')
        values = unpack('! 6s 6s L H', packet[:18])
        out['payload'] = packet[18:]
    else:
        keys = ('destination', 'source', 'type')
        values = unpack('! 6s 6s H', packet[:14])
        out['payload'] = packet[14:]

    for key, value in zip(keys, values):
        out[key] = value

    return out


def build_ipv4(source: str, destination: str, payload: bytes, **kwargs):
    """
    Build header for IPv4 packet.
    :param source: bytes: Source IP address
    :param destination: bytes: Destinatin IP address
    :param payload: bytes
    :keyword version: int: 4 bit field specifying version. (optional: default is 4)
    :keyword ihl: int: 4 bit field specifying header size. (optional unless adding IP Options: default is 5)
    :keyword id: int: 4 byte field specifying packet ID. (optional: default is random)
    :keyword flags: int: flags for IP header. (optional: default is 000)
    :keyword offset: int: Packet offset for fragmented packets. (optional: default is 0)
    :keyword ttl: int: Time to live for packet. (optional: default is 255)
    :keyword protocol: int: Protocol used (tcp-6, udp-17, etc). (optional: default is 6)

    :return: bytes
    """
    version = kwargs.get('version', 4)  # 4 bit field; should omit as this identifies packet as ipv4
    ihl = kwargs.get('ihl', 5)  # 4 bit field; size in bytes
    dscp = kwargs.get('dscp', 0)  # 6 bit field
    ecn = kwargs.get('ecn', 0)    # 2 bit field
    length = kwargs.get('length', 0)  # 32 bit field; should omit as kernel will compute
    id = kwargs.get('id', int.from_bytes(urandom(2), 'big'))  # 32 bit field
    flags = kwargs.get('flags', 0)  # 3 bit field
    offset = kwargs.get('offset', 0)  # 29 bit field
    ttl = kwargs.get('ttl', 255)  # 8 bit field
    protocol = kwargs.get('protocol', IPPROTO_TCP)  # 8 bit field
    checksum = kwargs.get('cheksum', 0)  # 32 bit field; should omit as kernel will compute

    ihl_ver = (version << 4) | ihl
    dscp_ecn = (dscp << 2) | ecn
    flag_offset = (flags << 13) | offset

    header = pack('! 2B 3H 2B H 4s 4s',
                  ihl_ver, dscp_ecn, length, id,
                  flag_offset, ttl, protocol,
                  checksum, ip_address(source).packed, ip_address(destination).packed)

    return header + kwargs.get('options', b'') + payload


def disassemble_ipv4(packet: bytes):
    """
    Disassemble a IPv4 packet for inspection.
    Can be used to build a packet later.

    :param packet: bytes: IPv4 packet to disassemble
    :return: dict
    """
    out = dict()

    ihl_ver = packet[0]
    out['version'] = ihl_ver >> 4  # IP Version. Should always be 4 for this disassembly
    out['ihl'] = ihl_ver & 0x0f  # length of header in 4 byte words

    out['options'] = packet[20:out['ihl']*4]  # If header has options capture them

    out['payload'] = packet[out['ihl']*4:]  # Get the payload of the IP packet

    keys = ('dscp_ecn', 'length', 'id', 'flags_offset', 'ttl', 'protocol',
            'checksum', 'source', 'destination')
    values = unpack('! B 3H 2B H 4s 4s', packet[1:20])

    for key, value in zip(keys, values):
        if(key == 'dscp_ecn'):
            out['dscp'] = value >> 2
            out['ecn'] = value & 0x03
        elif(key == 'flags_offset'):
            out['flags'] = value >> 13
            out['offset'] = value & (0xffff >> 3)
        elif(key in ('source', 'destination')):
            out[key] = ip_address(value)
        else:
            out[key] = value

    return out


def build_tcp(source: int, destination: int, payload: bytes, **kwargs):
    """
    Build header for TCP packet
    :param source: int: Source port number
    :param destination: int: Destination port number
    :param payload: bytes
    :return: bytes
    """
    seq = kwargs.get('seq', 0)
    ack_seq = kwargs.get('ack_seq', 0)
    data_offset = kwargs.get('offset', 5)

    # TCP Flags
    ns = kwargs.get('ns', False)
    cwr = kwargs.get('cwr', False)
    ece = kwargs.get('ece', False)
    urg = kwargs.get('urg', False)
    ack = kwargs.get('ack', False)
    psh = kwargs.get('psh', False)
    rst = kwargs.get('rst', False)
    syn = kwargs.get('syn', True)
    fin = kwargs.get('fin', False)

    window = htons(kwargs.get('window', 5840))
    checksum = kwargs.get('checksum', 0)
    urg_pointer = kwargs.get('urg_pointer', 0)

    offset_ns = (data_offset << 4) | ns

    flags = 0
    for val in (cwr, ece, urg, ack, psh, rst, syn, fin):
        flags = (flags << 1) | val

    header = pack('! 2H 2L 2B 3H', source, destination, seq, ack_seq, offset_ns, flags, window, checksum, urg_pointer)

    return header + kwargs.get('options', b'') + payload


def disassemble_tcp(packet: bytes):
    """
    Disassemble a TCP packet for inspection.
    Can be used to build a packet later.

    :param packet: bytes: TCP packet to disassemble
    :return: dict
    """
    out = dict()

    keys = ('source', 'destinatin', 'seq', 'ack_seq', 'offset_ns', 'flags', 'window', 'checksum', 'urg_pointer')
    values = unpack('! 2H 2L 2B 3H', packet[:20])

    for key, value in zip(keys, values):
        if(key == 'offset_ns'):
            out['offset'] = value >> 4
            out['ns'] = bool(value & 0x01)
        elif(key == 'flags'):
            for flag in ('fin', 'syn', 'rst', 'psh', 'ack', 'urg', 'ece', 'cwr'):
                out[flag] = bool(value & 0x01)
                value = value >> 1
        else:
            out[key] = value

    out['options'] = packet[20:out['offset']*4]
    out['payload'] = packet[out['offset']*4:]

    return out


def build_udp(source: int, destination: int, payload: bytes, **kwargs):
    """
    Build header for UDP packet
    :param source: int: Source port number
    :param destination: int: Destination port number
    :param payload: bytes
    :return:
    """
    header = pack('! 4H', source, destination, kwargs.get('length', 0), kwargs.get('checksum', 0))

    return header + payload


def disassemble_udp(packet: bytes):
    """
    Disassemble a UDP packet for inspection.
    Can be used to build a packet later.

    :param packet: bytes: UDP packet to disassemble
    :return: dict
    """
    out = dict()

    keys = ('source', 'destination', 'length', 'checksum')
    values = unpack('! 4H', packet[:8])

    for key, value in zip(keys, values):
        out[key] = value

    out['payload'] = packet[8:]

    return out

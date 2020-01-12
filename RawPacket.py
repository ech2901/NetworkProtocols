from socket import socket, AF_PACKET, SOCK_RAW, htons, IPPROTO_TCP
from os import urandom
from struct import pack, unpack

def raw_socket(interface: str = 'eth0'):
    sock = socket(AF_PACKET, SOCK_RAW, htons(3))
    sock.bind((interface, 0))

def send_raw(destination: bytes, source: bytes, type: bytes, payload: bytes, interface: str = 'eth0'):
    assert(len(destination) == len(source) == 6)  # Source/Destination must be 6 bytes
    assert(len(type) == 2)  # Ethernet type must be 2 bytes


    sock = raw_socket(interface)
    sock.send(destination + source + type + payload)



def build_ipv4(source: bytes, destination: bytes, payload: bytes, **kwargs):
    version = kwargs.get('versin', 4)  # 4 bit field; should omit as this identifies packet as ipv4
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
    options = kwargs.get('options', b'')

    ihl_ver = (version << 4) | ihl
    dscp_ecn = (dscp << 2) | ecn
    flag_offset = (flags << 13) | offset

    header = pack('! 2B 3H 2B H 4s 4s',
                  ihl_ver, dscp_ecn, length, id,
                  flag_offset, ttl, protocol,
                  checksum, source, destination)

    return header + options + payload

def disassemble_ipv4(packet):
    out = dict()

    ihl_ver = packet[0]
    out['version'] = ihl_ver >> 4  # IP Version. Should always be 4 for this disassembly
    out['ihl'] = ihl_ver & 0xff  # length of header in 4 byte words

    if(out['ihl'] > 5):
        out['options'] = packet[20:out['ihl']*4]  # If header has options capture them
    else:
        out['options'] = b''

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
        else:
            out[key] = value

    return out





def build_tcp(source: int, destination: int, payload: bytes, **kwargs):
    seq = kwargs.get('seq', 0)
    ack_seq = kwargs.get('ack', 0)
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
    checksum = 0
    urg_pointer = 0

    offset_ns = (data_offset << 4) | ns

    flags = 0
    for val in (cwr, ece, urg, ack, psh, rst, syn, fin):
        flags = (flags << 1) | val

    header = pack('! 2H 2L 2B 3H', source, destination, seq, ack_seq, offset_ns, flags, window, checksum, urg_pointer)

    return header + payload

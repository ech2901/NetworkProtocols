from socket import htons, IPPROTO_TCP
from os import urandom
from struct import pack, unpack
from ipaddress import ip_address


class BasePacket(object):

    format = ''

    def __init__(self):
        self.data = dict()

    def build(self):
        pass

    @classmethod
    def disassemble(cls, packet: bytes):
        pass

    def calc_checksum(self, *, data=b''):
        pass

    def set(self, **kwargs):
        self.data.update(kwargs)

    def __len__(self):
        pass


def build_ethernet(destination: bytes, source: bytes, payload, **kwargs):
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


class IPv4(BasePacket):

    format = '! 2B 3H 2B H 4s 4s'

    def __init__(self, source: str, destination: str, payload: BasePacket, **kwargs):
        BasePacket.__init__(self)

        self.data['source'] = source
        self.data['destination'] = destination
        self.data['version'] = kwargs.get('version', 4)
        self.data['ihl'] = kwargs.get('ihl', 5)
        self.data['dscp'] = kwargs.get('dscp', 0)
        self.data['ecn'] = kwargs.get('ecn', 0)
        self.data['length'] = kwargs.get('length', (self.data['ihl'] * 4) + len(payload))
        self.data['id'] = kwargs.get('id', 0)
        self.data['flags'] = kwargs.get('flags', 0)
        self.data['offset'] = kwargs.get('offset', 0)
        self.data['ttl'] = kwargs.get('ttl', 255)
        self.data['protocol'] = kwargs.get('protocol', IPPROTO_TCP)
        self.data['checksum'] = kwargs.get('cheksum', 0)
        self.data['options'] = kwargs.get('options', b'')

        self.data['payload'] = payload


        def build(self):
            ihl_ver = (self.data['version'] << 4) | self.data['ihl']
            dscp_ecn = (self.data['dscp'] << 2) | self.data['ecn']
            flag_offset = (self.data['flags'] << 13) | self.data['offset']

            header = pack(self.format,
                          ihl_ver, dscp_ecn, self.data['length'], self.data['id'],
                          flag_offset, self.data['ttl'], self.data['protocol'],
                          self.data['checksum'], ip_address(self.data['source']).packed,
                          ip_address(self.data['destination']).packed)

            return header + self.data['options'] + self.data['payload']

    @classmethod
    def disassemble(cls, packet: bytes):
        out = dict()

        ihl_ver = packet[0]
        out['version'] = ihl_ver >> 4  # IP Version. Should always be 4 for this disassembly
        out['ihl'] = ihl_ver & 0x0f  # length of header in 4 byte words

        out['options'] = packet[20:out['ihl'] * 4]  # If header has options capture them

        out['payload'] = packet[out['ihl'] * 4:]  # Get the payload of the IP packet

        keys = ('dscp_ecn', 'length', 'id', 'flags_offset', 'ttl', 'protocol',
                'checksum', 'source', 'destination')
        values = unpack(cls.format, packet[1:20])

        for key, value in zip(keys, values):
            if (key == 'dscp_ecn'):
                out['dscp'] = value >> 2
                out['ecn'] = value & 0x03
            elif (key == 'flags_offset'):
                out['flags'] = value >> 13
                out['offset'] = value & (0xffff >> 3)
            elif (key in ('source', 'destination')):
                out[key] = ip_address(value)
            else:
                out[key] = value

        return cls(**out)

    def calc_checksum(self, *, data=b''):
        pseudo_header = ip_address(self.data['source']).packed + ip_address(self.data['destination']).packed
        pseudo_header = pseudo_header + pack('! 2B H', 0, self.data['protocol'], len(self.data['payload']))
        self.data['payload'].calc_checksum(data=pseudo_header)

        calc_bytes = self.build()[:self.data['ihl'] * 4]

        if (len(calc_bytes) % 2 != 0):
            # Make sure there is an even number of bytes
            calc_bytes = calc_bytes + b'\x00'

        values = unpack(f'! {len(calc_bytes) // 2}H', calc_bytes)
        sum_total = sum(values)

        while(sum_total > 0xffff):
            # If sum is bigger than 2 bytes, add the overflow to the sum
            sum_total = sum_total + (sum_total >> 16)

        # Calculate the compliment of the sum to get the checksum.
        compliment = -sum_total % 0xffff

        if compliment:
            self.data['checksum'] = compliment
            return
        # If the checksum is calculated to be zero, set to 0xFFFF
        self.data['checksum'] = 0xffff

    def __len__(self):
        return self.data['length']



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


class UDP(BasePacket):

    format = '! 4H'

    def __init__(self, source: int, destination: int, payload: bytes, **kwargs):
        BasePacket.__init__(self)
        self.data['source'] = source
        self.data['destination'] = destination
        self.data['length'] = kwargs.get('length', 8 + len(payload))
        self.data['checksum'] = kwargs.get('checksum', 0)
        self.data['payload'] = payload

    def build(self):
        header = pack(self.format, self.data['source'], self.data['destination'],
                      self.data['length'], self.data['checksum'])

        return header + self.data['payload']

    @classmethod
    def disassemble(cls, packet: bytes):
        """
        Disassemble a UDP packet for inspection.

        :param packet: bytes: UDP packet to disassemble
        :return: dict
        """

        out = dict()

        keys = ('source', 'destination', 'length', 'checksum')
        values = unpack(cls.format, packet[:8])

        for key, value in zip(keys, values):
            out[key] = value

        out['payload'] = packet[8:]

        return cls(**out)

    def calc_checksum(self, *, data=b''):
        # source, destination, and length are already 2 bytes each
        sum_total = self.data['source'] + self.data['destination'] + self.data['length']

        # Bytes of data we need to calculate for
        calc_bytes = data + self.data['payload']

        if(len(calc_bytes) % 2 != 0):
            # Make sure there is an even number of bytes
            calc_bytes = calc_bytes + b'\x00'

        # unpack all the bytes into 2 byte integers
        values = unpack(f'! {len(calc_bytes) // 2}H', calc_bytes)
        sum_total = sum_total + sum(values)

        while(sum_total > 0xffff):
            # If sum is bigger than 2 bytes, add the overflow to the sum
            sum_total = sum_total + (sum_total >> 16)

        # Calculate the compliment of the sum to get the checksum.
        compliment = -sum_total % 0xffff

        if compliment:
            self.data['checksum'] = compliment
            return
        # If the checksum is calculated to be zero, set to 0xFFFF
        self.data['checksum'] = 0xffff

    def __len__(self):
        return self.data['length']


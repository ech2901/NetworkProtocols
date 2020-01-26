from dataclasses import dataclass, field
from ipaddress import IPv4Address, IPv6Address
from struct import pack, unpack
from typing import Dict


# --------------------------------------------------
# Helper Class(es)
#
#
# --------------------------------------------------

class MAC_Address(object):
    def __init__(self, address):
        if (type(address) == int):
            self.packed = address.to_bytes(6, 'big')
            self.address = ':'.join([hex(i)[2:].rjust(2, '0') for i in self.packed])
            self._address = address
        elif (type(address) == bytes):
            self.packed = address
            self.address = ':'.join([hex(i)[2:].rjust(2, '0') for i in self.packed])
            self._address = int.from_bytes(address, 'big')
        elif (type(address) == str):
            self.packed = pack('! 6B', *[int(i, 16) for i in address.split(':')])
            self.address = address
            self._address = int.from_bytes(self.packed, 'big')
        elif (type(address) == MAC_Address):
            self.packed = address.packed
            self.address = address.address
            self._address = address._address
        else:
            raise TypeError(
                f'Argument <address> must be of type bytes, int, or str but type {type(address)} was provided.')

    def __repr__(self):
        return f"MAC_Address('{self.address}')"

    def __str__(self):
        return self.address

    def __eq__(self, other):
        if (type(other) == MAC_Address):
            return self._address == other._address
        else:
            return self == MAC_Address(other)

    def __hash__(self):
        return hash(self._address)


# --------------------------------------------------
# Base Class(es)
#
#
# --------------------------------------------------
class BasePacket(object):

    format: str = field(default='', init=False, repr=False)  # Used to pack / unpack data in subclasses
    # Used when an identifying value is needed for a derived class
    # IE: Ethernet frames need to know the ethertype of the payload
    identifier: int = field(default=-1, init=False, repr=False)

    classes: Dict = field(default=dict(), init=False, repr=False)

    def __init_subclass__(cls, **kwargs):

        if (cls.identifier.default >= 0):
            super().__init_subclass__(**kwargs)
            cls.classes.default[cls.identifier.default] = cls

    def build(self):
        pass

    @classmethod
    def disassemble(cls, packet: bytes):
        pass

    def calc_checksum(self, *, data=b''):
        pass

    def _calc_compliment_(self, data):
        out = 0

        if (len(data) % 2 != 0):
            # Make sure there is an even number of bytes
            data = data + b'\x00'

        # unpack all the bytes into 2 byte integers
        values = unpack(f'! {len(data) // 2}H', data)
        # Sum values together
        out = out + sum(values)

        while(out > 0xffff):
            # If sum is bigger than 2 bytes, add the overflow to the sum
            out = (out & 0xffff) + (out >> 16)

        # Calculate the compliment of the sum to get the checksum.
        compliment = -out % 0xffff

        if compliment:
            return compliment

        # If the checksum is calculated to be zero, set to 0xFFFF
        return 0xffff

    def __len__(self):
        pass

    def swap(self):
        pass

# --------------------------------------------------
# Link Layer
#
#
# --------------------------------------------------
@dataclass(init=False)
class Ethernet(BasePacket):
    destination: MAC_Address
    source: MAC_Address
    tag: bytes
    type: int
    payload: BasePacket

    def __init__(self, destination: MAC_Address, source: MAC_Address, payload: BasePacket, **kwargs):
        BasePacket.__init__(self)

        self.destination = destination
        self.source = source
        self.tag = kwargs.get('tag', None)
        self.type = kwargs.get('type', payload.identifier)
        self.payload = payload

    def build(self):
        if (self.tag):
            header = pack('! 6s 6s L H', self.destination, self.source,
                          self.tag, self.type)
        else:
            header = pack('! 6s 6s H', self.destination.packed, self.source.packed, self.type)

        return header + self.payload.build()

    @classmethod
    def disassemble(cls, packet: bytes):
        """
        Disassemble a ethernet packet for inspection.
        Can be used to build a packet later.

        :param packet: bytes: Ethernet packet to disassemble
        :return: dict
        """
        out = dict()

        ethe_tag_test = int.from_bytes(packet[12:14], 'big')
        if (ethe_tag_test == 0x8100 or ethe_tag_test == 0x88a8):
            keys = ('destination', 'source', 'tag', 'type')
            values = unpack('! 6s 6s L H', packet[:18])
            out['payload'] = cls.classes.default[values[-1]].disassemble(packet[18:])
        else:
            keys = ('destination', 'source', 'type')
            values = unpack('! 6s 6s H', packet[:14])
            out['payload'] = cls.classes.default[values[-1]].disassemble(packet[14:])

        for key, value in zip(keys, values):
            if (key in ('source', 'destination')):
                out[key] = MAC_Address(value)
            else:
                out[key] = value

        return cls(**out)

    def swap(self):
        self.destination, self.source = self.source, self.destination
        self.payload.swap()

    def calc_checksum(self, *, data=b''):
        self.payload.calc_checksum()

    def __len__(self):
        if (self.tag):
            return 18 + len(self.payload)
        return 14 + len(self.payload)

# --------------------------------------------------
# Internet Layer
#
#
# --------------------------------------------------


@dataclass(init=False)
class IPv4(BasePacket):
    format: str = field(default='! 2B 3H 2B H 4s 4s', init=False, repr=False)
    identifier: int = field(default=0x0800, init=False, repr=False)

    source: IPv4Address
    destination: IPv4Address
    version: int = field(default=4, init=False)
    ihl: int
    dscp: int
    ecn: int
    length: int
    id: int
    flags: int
    offset: int
    ttl: int
    protocol: int
    checksum: int
    options: bytes

    payload: BasePacket

    def __init__(self, source: IPv4Address, destination: IPv4Address, payload: BasePacket, **kwargs):
        BasePacket.__init__(self)

        self.source = source
        self.destination = destination
        # version would go here if it wasn't static
        self.ihl = kwargs.get('ihl', 5)
        self.dscp = kwargs.get('dscp', 0)
        self.ecn = kwargs.get('ecn', 0)
        self.length = kwargs.get('length', (self.ihl * 4) + len(payload))
        self.id = kwargs.get('id', 0)
        self.flags = kwargs.get('flags', 0)
        self.offset = kwargs.get('offset', 0)
        self.ttl = kwargs.get('ttl', 255)
        self.protocol = kwargs.get('protocol', payload.identifier)
        self.checksum = kwargs.get('checksum', 0)
        self.options = kwargs.get('options', b'')

        self.payload = payload

    def build(self):
        ihl_ver = (self.version << 4) | self.ihl
        dscp_ecn = (self.dscp << 2) | self.ecn
        flag_offset = (self.flags << 13) | self.offset

        header = pack(self.format,
                      ihl_ver, dscp_ecn, self.length, self.id,
                      flag_offset, self.ttl, self.protocol,
                      self.checksum, self.source.packed,
                      self.destination.packed)

        return header + self.options + self.payload.build()

    @classmethod
    def disassemble(cls, packet: bytes):
        out = dict()

        keys = ('ver_ihl', 'dscp_ecn', 'length', 'id', 'flags_offset', 'ttl', 'protocol',
                'checksum', 'source', 'destination')
        values = unpack(cls.format, packet[:20])

        for key, value in zip(keys, values):
            if (key == 'ver_ihl'):
                out['ihl'] = value & 0x0f
            elif (key == 'dscp_ecn'):
                out['dscp'] = value >> 2
                out['ecn'] = value & 0x03
            elif (key == 'flags_offset'):
                out['flags'] = value >> 13
                out['offset'] = value & (0xffff >> 3)
            elif (key in ('source', 'destination')):
                out[key] = IPv4Address(value)
            else:
                out[key] = value

        out['options'] = packet[20:out['ihl'] * 4]  # If header has options capture them

        # Get the payload of the IP packet
        out['payload'] = cls.classes.default[out['protocol']].disassemble(packet[out['ihl'] * 4:])

        return cls(**out)

    def calc_checksum(self, *, data=b''):
        pseudo_header = self.source.packed + self.destination.packed
        pseudo_header = pseudo_header + pack('! 2B H', 0, self.protocol, len(self.payload))
        self.payload.calc_checksum(data=pseudo_header)

        calc_bytes = self.build()[:self.ihl * 4]

        self.checksum = self._calc_compliment_(calc_bytes)

    def __len__(self):
        return self.length

    def swap(self):
        self.destination, self.source = self.source, self.destination
        self.payload.swap()


@dataclass(init=False)
class IPv6(BasePacket):
    format: str = field(default='! L H 2B 16s 16s', init=False, repr=False)
    identifier: int = field(default=0x86DD, init=False, repr=False)

    source: IPv6Address
    destination: IPv6Address
    version: int = field(default=6, init=False)
    ds: int
    ecn: int
    label: int
    length: int  # Length of payload
    next_header: int
    limit: int
    payload: BasePacket

    def __init__(self, source: IPv6Address, destination: IPv6Address, payload: BasePacket, **kwargs):
        self.source = source
        self.destination = destination
        # version would go here if it wasn't static
        self.ds = kwargs.get('ds', 0)
        self.ecn = kwargs.get('ecn', 0)
        self.label = kwargs.get('label', 0)
        self.length = kwargs.get('length', len(payload))
        self.next_header = kwargs.get('next_header', payload.identifier)
        self.limit = kwargs.get('limit', 255)

        self.payload = payload

    def build(self):
        ver_class_label = (self.version << 28) + (self.ds << 22)
        ver_class_label = ver_class_label + (self.ecn << 20) + self.label

        header = pack(self.format, ver_class_label, self.length,
                      self.next_header, self.limit, self.source, self.destination
                      )

        return header + self.payload.build()

    @classmethod
    def disassemble(cls, packet: bytes):
        out = dict()

        keys = ('ver_class_label', 'length', 'next_header', 'limit', 'source', 'destination')
        values = unpack(cls.format, packet[:40])

        for key, value in zip(keys, values):
            if (key == 'ver_class_label'):
                out['ds'] = (value >> 22) & 0x3f
                out['ecn'] = (value >> 20) & 0x03
                out['label'] = value & 0xf_ffff
            elif (key in ('source', 'destination')):
                out[key] = IPv6Address(value)
            else:
                out[key] = value

        out['payload'] = BasePacket.classes.default[out['next_header']].disassemble(packet[40:out['length']])

        return cls(**out)

    def calc_checksum(self, *, data=b''):
        psuedo_header = self.source.packed + self.destination.packed
        psuedo_header = psuedo_header + pack('! 2L', len(self.payload), self.next_header)

        self.payload.calc_checksum(data=psuedo_header)

    def __len__(self):
        return 40 + self.length

    def swap(self):
        self.destination, self.source = self.source, self.destination
        self.payload.swap()



# --------------------------------------------------
# Transport Layer
#
#
# --------------------------------------------------
@dataclass(init=False)
class TCP(BasePacket):
    format: str = field(default='! 2H 2L 2B 3H', init=False, repr=False)
    identifier: int = field(default=0x0006, init=False, repr=False)

    source: int
    destination: int
    seq: int
    ack_seq: int
    data_offset: int

    ns: bool
    cwr: bool
    ece: bool
    urg: bool
    ack: bool
    psh: bool
    rst: bool
    syn: bool
    fin: bool

    window: int
    checksum: int
    urg_pointer: int

    options: bytes

    payload: bytes

    def __init__(self, source: int, destination: int, payload: bytes, **kwargs):
        BasePacket.__init__(self)
        self.source = source
        self.destination = destination
        self.seq = kwargs.get('seq', 0)
        self.ack_seq = kwargs.get('ack_seq', 0)
        self.data_offset = kwargs.get('offset', 5)

        # TCP Flags
        self.ns = kwargs.get('ns', False)
        self.cwr = kwargs.get('cwr', False)
        self.ece = kwargs.get('ece', False)
        self.urg = kwargs.get('urg', False)
        self.ack = kwargs.get('ack', False)
        self.psh = kwargs.get('psh', False)
        self.rst = kwargs.get('rst', False)
        self.syn = kwargs.get('syn', True)
        self.fin = kwargs.get('fin', False)

        self.window = kwargs.get('window', 5840)
        self.checksum = kwargs.get('checksum', 0)
        self.urg_pointer = kwargs.get('urg_pointer', 0)

        self.options = kwargs.get('options', b'')

        self.payload = payload

    def build(self):
        offset_ns = (self.data_offset << 4) | self.ns

        flags = 0
        for key in ('cwr', 'ece', 'urg', 'ack', 'psh', 'rst', 'syn', 'fin'):
            flags = (flags << 1) | getattr(self, key)

        header = pack(self.format, self.source, self.destination, self.seq,
                      self.ack_seq, offset_ns, flags,
                      self.window, self.checksum, self.urg_pointer
                      )

        return header + self.options + self.payload

    @classmethod
    def disassemble(cls, packet: bytes):
        out = dict()

        keys = ('source', 'destination', 'seq', 'ack_seq', 'offset_ns', 'flags', 'window', 'checksum', 'urg_pointer')
        values = unpack(cls.format, packet[:20])

        for key, value in zip(keys, values):
            if (key == 'offset_ns'):
                out['offset'] = value >> 4
                out['ns'] = bool(value & 0x01)
            elif (key == 'flags'):
                for flag in ('fin', 'syn', 'rst', 'psh', 'ack', 'urg', 'ece', 'cwr'):
                    out[flag] = bool(value & 0x01)
                    value = value >> 1
            else:
                out[key] = value

        out['options'] = packet[20:out['offset'] * 4]
        out['payload'] = packet[out['offset'] * 4:]

        return cls(**out)

    def calc_checksum(self, *, data=b''):
        self.checksum = self._calc_compliment_(data + self.build())

    def __len__(self):
        return (self.data_offset * 4) + len(self.payload)

    def swap(self):
        self.destination, self.source = self.source, self.destination


@dataclass(init=False)
class UDP(BasePacket):
    format: str = field(default='! 4H', init=False, repr=False)
    identifier: int = field(default=0x0011, init=False, repr=False)

    source: int
    destination: int
    length: int
    checksum: int
    payload: bytes


    def __init__(self, source: int, destination: int, payload: bytes, **kwargs):
        BasePacket.__init__(self)
        self.source = source
        self.destination = destination
        self.length = kwargs.get('length', 8 + len(payload))
        self.checksum = kwargs.get('checksum', 0)
        self.payload = payload

    def build(self):
        header = pack(self.format, self.source, self.destination,
                      self.length, self.checksum)

        return header + self.payload

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
        self.checksum = self._calc_compliment_(data + self.build())

    def __len__(self):
        return self.length

    def swap(self):
        self.destination, self.source = self.source, self.destination

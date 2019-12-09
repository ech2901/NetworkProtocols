from struct import pack, unpack
from dataclasses import dataclass
from ipaddress import ip_address
from enum import IntFlag

class TCPFlag(IntFlag):
    NS = 1
    CWR = 2
    ECE = 4
    URG = 8
    ACK = 16
    PSH = 32
    RST = 64
    SYN = 128
    FIN = 256



@dataclass
class EthPacket(object):
    _destination: bytes = bytes(6)
    _source: bytes = bytes(6)
    tag: int = None
    _ethertype: bytes = b'\x08\x00'
    crc: int = 0
    payload: bytes = b''


    @classmethod
    def from_bytes(cls, data, *, q_tag=False):

        if q_tag:
            payload = data[18:-4]
            keys = ('_destination', '_source', 'tag', '_ethertype')
            values = unpack(f'! 6s 6s I 2s {len(payload)}x', data[:-4])
        else:
            payload = data[14:-4]

            keys = ('_destination', '_source', '_ethertype')
            values = unpack(f'! 6s 6s 2s {len(payload)}x', data[:-4])

        crc = unpack('< I', data[-4:])[0]

        return cls(payload=payload, crc=crc, **dict(zip(keys, values)))

    def to_bytes(self):
        if self.tag is None:
            data = pack('! 6s 6s I', self._destination, self._source, self.ethertype)
        else:
            data = pack('! 6s 6s I H', self._destination, self._source, self.ethertype, self.tag)

        return data + self.payload

    @property
    def destination(self):
        return ':'.join(hex(i)[2:] for i in self._destination)

    @property
    def source(self):
        return ':'.join(hex(i)[2:] for i in self._source)

    @property
    def ethertype(self):
        return int.from_bytes(self._ethertype, 'big')

@dataclass
class IP4Packet(object):
    version: int = 4
    _ihl: int = 5
    dscp: int = 0
    ecn: int = 0
    length: int = 20
    identification: int = 0
    _flags: int = 0
    offset: int = 0
    ttl: int = 60
    protocol: int = 1
    checksum: int = 0
    _source: bytes = bytes(4)
    _destination: bytes = bytes(4)
    options: bytes = None
    payload: bytes = b''

    @classmethod
    def from_bytes(cls, data):
        version = data[0] >> 4
        if version != 4:
            raise TypeError('Packet is not an IPv4 packet.')

        ihl = data[0] & 0x0F
        dscp = data[1] >> 2
        ecn = data[1] & 0x03
        flags = data[7] >> 5
        offset = ((data[7] << 8) + data[8]) & 0x1FFF
        length, identification, ttl, protocol, checksum, source, destination = unpack('! 2x 2H 2x 2B H 4s 4s',data[:20])
        options = data[20:ihl*4]

        return cls(version, ihl, dscp, ecn, length, identification, flags, offset,
                   ttl, protocol, checksum, source, destination, options, data[ihl*4:])

    def to_bytes(self):
        vers_ihl = (self.version << 4) | self._ihl
        dscp_ecn = (self.dscp << 2) | self.ecn
        flags_offset = (self._flags << 5) | self.offset


        if self.options:
            return pack('! 2B 3H 2B H 4s 4s', vers_ihl, dscp_ecn, self.length,
                        self.identification,flags_offset, self.ttl, self.protocol,
                        self.checksum, self._source, self._destination) + self.options + self.payload

        return pack('! 2B 3H 2B H 4s 4s', vers_ihl, dscp_ecn, self.length,
                    self.identification,flags_offset, self.ttl, self.protocol,
                    self.checksum, self._source, self._destination) + self.payload



    @property
    def ihl(self):
        '''
        :return: number of octets in the header.
        '''
        return self._ihl*4

    @property
    def source(self):
        '''
        :return: source IP address sending packet.
        '''
        return str(ip_address(self._source))

    @property
    def destination(self):
        '''
        :return: destination IP address packet is being sent to.
        '''
        return str(ip_address(self._destination))

    @property
    def flags(self):
        out = dict()
        out['RESERVED'] = bool(self._flags & 0b100)
        out["Don't Fragment"] = bool(self._flags & 0b010)
        out['More Fragments'] = bool(self._flags & 0b001)
        return out

@dataclass
class TCPPacket(object):
    source: int
    destination: int
    sequence: int = 0
    ack: int = 0
    offset: int = 5
    _flags: int = 0
    size: int = 0
    checksuum: int = 0
    urgent: int = 0
    options: bytes = None
    payload: bytes = b''

    @classmethod
    def from_bytes(cls, data):
        source, dest, seq, ack, size, checksum, urg = unpack('! 2H 2I 2x 3H', data[:20])
        offset = data[13] >> 4
        flags = ((data[13] & 0x01) << 8) + data[14]
        options = data[20:offset*4]
        payload = data[offset*4:]


        return cls(source, dest, seq, ack, offset, flags, size, checksum, urg, options, payload)

    def to_bytes(self):
        offset_flags = (self.offset << 12) | self._flags

        if self.options:
            return pack('! 2H 2I 4H', self.source, self.destination, self.sequence,
                        self.ack, offset_flags) + self.options + self.payload

        return pack('! 2H 2I I 4H', self.source, self.destination, self.sequence,
                    self.ack, offset_flags) + self.payload





tcp = TCPPacket(30000, 8080, 0, 0, )
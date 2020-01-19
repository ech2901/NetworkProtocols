from ipaddress import ip_address
from socket import htons
from struct import pack, unpack


# --------------------------------------------------
# Base Class(es)
#
#
# --------------------------------------------------

class BasePacket(object):

    format = ''  # Used to pack / unpack data in subclasses
    # Used when an identifying value is needed for a derived class
    # IE: Ethernet frames need to know the ethertype of the payload
    identifier = -1

    classes = dict()

    def __init__(self, **kwargs):
        # Initialize data storage for packet
        for key, value in kwargs.items():
            setattr(self, key, value)

    def __init_subclass__(cls, **kwargs):
        if(cls.identifier >= 0):
            super().__init_subclass__(**kwargs)
            cls.classes[cls.identifier] = cls

    def build(self):
        pass

    @classmethod
    def disassemble(cls, packet: bytes, packet_type=None):
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

    def update(self, **kwargs):
        self.data.update(kwargs)

    def __len__(self):
        pass

# --------------------------------------------------
# Link Layer
#
#
# --------------------------------------------------

class Ethernet(BasePacket):

    format = '! 6s 6s H'  # Format for Ethernet header

    def __init__(self, destination: bytes, source: bytes, payload: BasePacket, **kwargs):
        BasePacket.__init__(self)
        self.data['destination'] = destination
        self.data['source'] = source
        self.data['tag'] = kwargs.get('tag', None)
        self.data['type'] = kwargs.get('type', payload.identifier)
        self.data['payload'] = payload

    def build(self):
        if(self.data['tag']):
            header = pack('! 6s 6s L H', self.data['destination'], self.data['source'],
                                        self.data['tag'], self.data['type'])
        else:
            header = pack(self.format, self.data['destination'], self.data['source'], self.data['type'])

        return header + self.data['payload'].build()

    @classmethod
    def disassemble(cls, packet: bytes, packet_type=BasePacket):
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
            out['payload'] = cls.classes[values[-1]].disassemble(packet[18:])
        else:
            keys = ('destination', 'source', 'type')
            values = unpack('! 6s 6s H', packet[:14])
            out['payload'] = cls.classes[values[-1]].disassemble(packet[14:])

        for key, value in zip(keys, values):
            out[key] = value

        return cls(**out)

    def calc_checksum(self, *, data=b''):
        self.data['payload'].calc_checksum()

    def __len__(self):
        return len(self.build())

# --------------------------------------------------
# Internet Layer
#
#
# --------------------------------------------------
class IPv4(BasePacket):

    format = '! B 3H 2B H 4s 4s'
    identifier = 0x0800

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
        self.data['protocol'] = kwargs.get('protocol', payload.identifier)
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

            return header + self.data['options'] + self.data['payload'].build()

    @classmethod
    def disassemble(cls, packet: bytes, packet_type=BasePacket):
        out = dict()

        ihl_ver = packet[0]
        out['version'] = ihl_ver >> 4  # IP Version. Should always be 4 for this disassembly
        out['ihl'] = ihl_ver & 0x0f  # length of header in 4 byte words

        out['options'] = packet[20:out['ihl'] * 4]  # If header has options capture them

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

        # Get the payload of the IP packet
        out['payload'] = cls.classes[out['protocol']].disassemble(packet[out['ihl'] * 4:])

        return cls(**out)

    def calc_checksum(self, *, data=b''):
        pseudo_header = ip_address(self.data['source']).packed + ip_address(self.data['destination']).packed
        pseudo_header = pseudo_header + pack('! 2B H', 0, self.data['protocol'], len(self.data['payload']))
        self.data['payload'].calc_checksum(data=pseudo_header)

        calc_bytes = self.build()[:self.data['ihl'] * 4]

        self.data['checksum'] = self._calc_compliment_(calc_bytes)

    def __len__(self):
        return self.data['length']


# --------------------------------------------------
# Transport Layer
#
#
# --------------------------------------------------

class TCP(BasePacket):

    format = '! 2H 2L 2B 3H'
    identifier = 6

    def __init__(self, source: int, destination: int, payload: bytes, **kwargs):
        BasePacket.__init__(self)

        self.data['source'] = source
        self.data['destinaiton'] = destination
        self.data['seq'] = kwargs.get('seq', 0)
        self.data['ack_seq'] = kwargs.get('ack_seq', 0)
        self.data['data_offset'] = kwargs.get('offset', 5)

        # TCP Flags
        self.data['ns'] = kwargs.get('ns', False)
        self.data['cwr'] = kwargs.get('cwr', False)
        self.data['ece'] = kwargs.get('ece', False)
        self.data['urg'] = kwargs.get('urg', False)
        self.data['ack'] = kwargs.get('ack', False)
        self.data['psh'] = kwargs.get('psh', False)
        self.data['rst'] = kwargs.get('rst', False)
        self.data['syn'] = kwargs.get('syn', True)
        self.data['fin'] = kwargs.get('fin', False)

        self.data['window'] = htons(kwargs.get('window', 5840))
        self.data['checksum'] = kwargs.get('checksum', 0)
        self.data['urg_pointer'] = kwargs.get('urg_pointer', 0)

        self.data['options'] = kwargs.get('options', b'')

        self.data['payload'] = payload

    def build(self):
        offset_ns = (self.data['data_offset'] << 4) | self.data['ns']

        flags = 0
        for key in ('cwr', 'ece', 'urg', 'ack', 'psh', 'rst', 'syn', 'fin'):
            flags = (flags << 1) | self.data[key]

        header = pack(self.format, self.data['source'], self.data['destination'], self.data['seq'],
                        self.data['ack_seq'], offset_ns, flags,
                        self.data['window'], self.data['checksum'], self.data['urg_pointer']
                      )

        return header + self.data['options'] + self.data['payload']

    @classmethod
    def disassemble(cls, packet: bytes, packet_type=None):
        out = dict()

        keys = ('source', 'destination', 'seq', 'ack_seq', 'offset_ns', 'flags', 'window', 'checksum', 'urg_pointer')
        values = unpack('! 2H 2L 2B 3H', packet[:20])

        for key, value in zip(keys, values):
            if (key == 'offset_ns'):
                out['offset'] = value >> 4
                out['ns'] = bool(value & 0x01)
            elif (key == 'flags'):
                for flag in ('fin', 'syn', 'rst', 'psh', 'ack', 'urg', 'ece', 'cwr'):
                    out[flag] = bool(value & 0x01)
                    value = value >> 1
            elif (key in ('source', 'destination')):
                out[key] = ip_address(value)
            else:
                out[key] = value

        out['options'] = packet[20:out['offset'] * 4]
        out['payload'] = packet[out['offset'] * 4:]

        return cls(**out)

    def calc_checksum(self, *, data=b''):
        self.data['checksum'] = self._calc_compliment_(data + self.build())

    def __len__(self):
        return (self.data['data_offset'] * 4) + len(self.data['payload'])


class UDP(BasePacket):

    format = '! 4H'
    identifier = 17

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
    def disassemble(cls, packet: bytes, packet_type=None):
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
        self.data['checksum'] = self._calc_compliment_(data + self.build())

    def __len__(self):
        return self.data['length']


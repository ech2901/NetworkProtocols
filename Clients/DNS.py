from dataclasses import dataclass, field
from enum import Enum
from ipaddress import ip_address
from os import urandom
from socket import socket, AF_INET, SOCK_DGRAM, timeout
from struct import pack, unpack


def unpack_name(data, offset_copy=None, *, return_unused=False):
    name_data = list(data)
    size = name_data.pop(0)
    name = list()
    while size:
        if size == 0xc0:
            offset = name_data.pop(0)

            referenced_name = unpack_name(offset_copy[offset:], offset_copy)
            name.extend(list(referenced_name))
            break

        name.extend(name_data[:size])
        name_data = name_data[size:]

        size = name_data.pop(0)
        if size:
            name.append(b'.'[0])

    if return_unused:
        return bytes(name), bytes(name_data)
    return bytes(name)


def pack_name(data):
    if data:
        name_data = data.split(b'.')
        name = b''
        for segment in name_data:
            size = len(segment)
            name = name + pack(f'! B {size}s', size, segment)

        return name + b'\x00'
    return b'\x00'


class Types(Enum):
    A = (1, 'IPv4 Address', ip_address)
    NS = (2, 'Authoritative Name Server')
    MD = (3, 'Mail Destinatin (Obsolete)')
    MF = (4, 'Mail Forwarder (Obsolete)')
    CNAME = (5, 'Canonical name')
    SOA = (6, 'Start of Authority')
    MB = (7, 'Mailbox Domain Name')
    MG = (8, 'Mail Group Member')
    MR = (9, 'Mail Rename Doamin Name')
    NULL = (10, 'Null Resource Record')
    WKS = (11, 'Well Known Service')
    PTR = (12, 'Domain Name Pointer', unpack_name)
    HINFO = (13, 'IPv4 Address')
    MINFO = (14, 'IPv4 Address')
    MX = (15, 'IPv4 Address')
    TXT = (16, 'IPv4 Address')
    RP = (17, 'IPv4 Address')
    AFSDB = (18, 'IPv4 Address')
    X25 = (19, 'IPv4 Address')
    ISDN = (20, 'IPv4 Address')
    RT = (21, 'IPv4 Address')
    NSAP = (22, 'IPv4 Address')
    NSAP_PTR = (23, 'IPv4 Address')
    SIG = (24, 'IPv4 Address')
    KEY = (25, 'IPv4 Address')
    PX = (26, 'IPv4 Address')
    GPOS = (27, 'IPv4 Address')
    AAAA = (28, 'IPv4 Address', ip_address)
    LOC = (29, 'IPv4 Address')
    NXT = (30, 'IPv4 Address')
    EID = (31, 'IPv4 Address')
    NIMLOC = (32, 'IPv4 Address')
    NB = (32, 'IPv4 Address')
    SRV = (33, 'IPv4 Address')
    NBSTAT = (33, 'IPv4 Address')
    ATMA = (34, 'IPv4 Address')
    NAPTR = (35, 'IPv4 Address')
    KX = (36, 'IPv4 Address')
    CERT = (37, 'IPv4 Address')
    A6 = (38, 'IPv4 Address')
    DNAME = (39, 'IPv4 Address')
    SINK = (40, 'IPv4 Address')
    OPT = (41, 'IPv4 Address')
    APL = (42, 'IPv4 Address')
    DS = (43, 'IPv4 Address')
    SSHFP = (44, 'IPv4 Address')
    IPSECKEY = (45, 'IPv4 Address')
    RRSIG = (46, 'IPv4 Address')
    NSEC = (47, 'IPv4 Address')
    DNSKEY = (48, 'IPv4 Address')
    DHCID = (49, 'IPv4 Address')
    NSEC3 = (50, 'IPv4 Address')
    NSEC3PARAM = (51, 'IPv4 Address')
    TLSA = (52, 'IPv4 Address')
    HIP = (55, 'IPv4 Address')
    NINFO = (56, 'IPv4 Address')
    RKEY = (57, 'IPv4 Address')
    TALINK = (58, 'IPv4 Address')
    CHILD_DS = (59, 'IPv4 Address')
    SPF = (99, 'IPv4 Address')
    UINFO = (100, 'IPv4 Address')
    UID = (101, 'IPv4 Address')
    GID = (102, 'IPv4 Address')
    UNSPEC = (103, 'IPv4 Address')
    TKEY = (249, 'IPv4 Address')
    TSIG = (250, 'IPv4 Address')
    IXFT = (251, 'IPv4 Address')
    AXFR = (252, 'IPv4 Address')
    MAILB = (253, 'IPv4 Address')
    MAILA = (254, 'IPv4 Address')
    ALL = (255, 'IPv4 Address')
    URI = (256, 'IPv4 Address')
    CAA = (257, 'IPv4 Address')
    DNSSEC_TA = (32768, 'IPv4 Address')
    DNSSEC_LV = (32769, 'IPv4 Address')

    def __new__(cls, _type, description='', factory=bytes):
        obj = object.__new__(cls)
        obj._value_ = _type
        obj.description = description
        obj.factory = factory
        return obj

    def __repr__(self):
        return f'{self._name_}(type={self._value_}, description={self.description})'

    def __str__(self):
        return repr(self)

    @classmethod
    def from_bytes(cls, data):
        _type = unpack('! H', data)[0]
        return cls(_type)

    def to_bytes(self):
        return pack('! H', self._value_)


class Classes(Enum):
    IN = (1, 'Internet')
    CH = (3, 'Chaos')
    HS = (4, 'Hesoid')
    NONE = (254, 'None')
    ANY = (255, 'Any')

    def __new__(cls, _class, description):
        obj = object.__new__(cls)
        obj._value_ = _class
        obj.description = description
        return obj

    def __repr__(self):
        return f'{self._name_}(class={self._value_}, description={self.description})'

    def __str__(self):
        return repr(self)

    @classmethod
    def from_bytes(cls, data):
        _class = unpack('! H', data)[0]
        return cls(_class)

    def to_bytes(self):
        return pack('! H', self._value_)


@dataclass
class Packet(object):
    identification: int
    qr: int
    opcode: int = 0
    aa: bool = False
    tc: bool = False
    rd: bool = True
    ra: bool = False
    z: bool = field(default=False, init=False)
    ad: bool = False
    cd: bool = True
    rcode: int = 0
    total_questions: int = field(init=False)
    total_answer_rrs: int = field(init=False)
    total_authority_rrs: int = field(init=False)
    total_additional_rrs: int = field(init=False)
    questions: list = field(default_factory=list)
    answer_rrs: list = field(default_factory=list)
    authority_rrs: list = field(default_factory=list)
    additional_rrs: list = field(default_factory=list)

    def __post_init__(self):
        self.total_questions = len(self.questions)
        self.total_answer_rrs = len(self.answer_rrs)
        self.total_authority_rrs = len(self.authority_rrs)
        self.total_additional_rrs = len(self.additional_rrs)

    @classmethod
    def from_bytes(cls, data):
        offset_copy = data

        identification, flags, tq, ta, tau, tad = unpack('! 6H', data[:12])

        qr = flags >> 15
        opcode = (flags & 0b111100000000000) >> 11
        aa = bool(flags & 0b10000000000)
        tc = bool(flags & 0b1000000000)
        rd = bool(flags & 0b100000000)
        ra = bool(flags & 0b10000000)
        # z = bool(flags &0b1000000) Not needed, but good to see the placement
        ad = bool(flags & 0b100000)
        cd = bool(flags & 0b10000)
        rcode = flags & 0b1111

        questions = list()
        answers = list()
        authorities = list()
        additionals = list()

        data = data[12:]

        for _ in range(tq):
            question, data = Query.from_bytes(data, offset_copy)
            questions.append(question)

        for _ in range(ta):
            answer, data = ResourceRecord.from_bytes(data, offset_copy)
            answers.append(answer)

        for _ in range(tau):
            auth_answer, data = ResourceRecord.from_bytes(data, offset_copy)
            authorities.append(auth_answer)

        for _ in range(tad):
            add_answer, data = ResourceRecord.from_bytes(data, offset_copy)
            additionals.append(add_answer)

        return cls(identification, qr, opcode, aa, tc, rd, ra, ad, cd,
                   rcode, questions, answers, authorities, additionals)

    def to_bytes(self):
        flags = (self.qr << 15) + (self.opcode << 11) + (self.aa << 10) + (self.tc << 9)
        flags = flags + (self.rd << 8) + (self.ra << 7) + (self.ad << 5) + (self.cd << 4)
        flags = flags + self.rcode

        data = pack('! 6H', self.identification, flags, self.total_questions,
                    self.total_answer_rrs, self.total_authority_rrs, self.total_additional_rrs)

        for question in self.questions:
            data = data + question.to_bytes()

        for answer in self.answer_rrs:
            data = data + answer.to_bytes()

        for authority in self.authority_rrs:
            data = data + authority.to_bytes()

        for additional in self.additional_rrs:
            data = data + additional.to_bytes()

        return data

    def __str__(self):
        out = 'DNS'.center(64, '-')
        out = f'{out}\nIdentification: {self.identification}\nQuery/Response: {"Response" if self.qr else "Query"}'
        out = f'{out}\nOp Code: {self.opcode}\nAuthoritative Answer: {self.aa}\nTruncated: {self.tc}'
        out = f'{out}\nRecursion Desired: {self.rd}\nRecursion Available: {self.ra}\nAuthenticated Data: {self.ad}'
        out = f'{out}\nChecking Disabled: {self.cd}\nReturn Code: {self.rcode}\nTotal Questions: {self.total_questions}'
        out = f'{out}\nTotal Answer Resource Records: {self.total_answer_rrs}'
        out = f'{out}\nTotal Authority Resource Records: {self.total_authority_rrs}'
        out = f'{out}\nTotal Additional Resource Records: {self.total_additional_rrs}'

        for question in self.questions:
            out = f'{out}\n{str(question)}'

        for answer in self.answer_rrs:
            out = f'{out}\n{str(answer)}'

        for answer in self.authority_rrs:
            out = f'{out}\n{str(answer)}'

        for answer in self.additional_rrs:
            out = f'{out}\n{str(answer)}'

        return out


@dataclass(repr=False)
class Query(object):
    name: bytes
    _type: Types
    _class: Classes

    @classmethod
    def from_bytes(cls, data, offset_copy=None):
        name, data = unpack_name(data, offset_copy, return_unused=True)

        _type, _class = unpack('! 2H', data[:4])

        return cls(name, Types(_type), Classes(_class)), data[4:]

    def to_bytes(self):
        name = pack_name(self.name)

        return name + self._type.to_bytes() + self._class.to_bytes()

    def __repr__(self):
        return f'{self.__class__.__name__}(name={self.name}, type={self._type.description}, class={self._class.description})'

    def __str__(self):
        out = 'Query'.center(64, '-')
        out = f'{out}\nName: {self.name.decode()}\nType: {self._type.description}\nClass: {self._class.description}'
        return out

@dataclass(repr=False)
class ResourceRecord(object):
    name: bytes
    _type: Types
    _class: Classes
    ttl: int
    rdata_length: int
    rdata: bytes

    @classmethod
    def from_bytes(cls, data, offset_copy=None):
        name, data = unpack_name(data, offset_copy, return_unused=True)

        _type, _class, ttl, length = unpack('! 2H L H', data[:10])

        rdata = data[10:10 + length]

        return cls(name, Types(_type), Classes(_class), ttl, length, rdata), data[10 + length:]

    def to_bytes(self):
        name = pack_name(self.name)
        data = name + self._type.to_bytes() + self._class.to_bytes() + pack('! L H', self.ttl, self.rdata_length)

        return data + self.rdata

    def __repr__(self):
        out = f'{self.__class__.__name__}(name={self.name}, type={self._type.description}'
        out = out + f', class={self._class.description}, ttl={self.ttl}, rdata={self._type.factory(self.rdata)})'
        return out

    def __str__(self):
        out = 'Record'.center(64, '-')
        out = f'{out}\nName: {self.name.decode()}\nType: {self._type.description}\nClass: {self._class.description}'
        out = f'{out}\nTTL: {self.ttl}\nRecord Data: {self._type.factory(self.rdata).decode()}'
        return out

def lookup(url, *servers, **kwargs):
    request = Query(url.encode(), kwargs.get('type', Types.A), kwargs.get('class', Classes.IN))
    packet = Packet(kwargs.get('id', int.from_bytes(urandom(2), 'big')),
                    0, kwargs.get('opcode', 0), rd=kwargs.get('rd', True),
                    questions=[request])

    sock = socket(AF_INET, SOCK_DGRAM)
    sock.bind(('', 0))
    sock.settimeout(kwargs.get('timeout', 1))

    for server in servers:
        sock.sendto(packet.to_bytes(), (server, 53))

        try:
            data, addr = sock.recvfrom(65536)
        except timeout:
            continue

        resp_packet = Packet.from_bytes(data)
        if resp_packet.identification == packet.identification:
            return resp_packet


def ilookup(ip, *servers, **kwargs):
    ip = '.'.join(reversed(ip.split('.'))) + '.in-addr.arpa'

    kwargs['type'] = Types.PTR
    return lookup(ip, *servers, **kwargs)

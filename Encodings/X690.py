from dataclasses import dataclass, field
from enum import IntFlag
from math import log
from typing import Any, Dict

from .TwosComplement import *


def _get_int_bytes_(data: int):
    return round((data.bit_length() / 8) + 0.4)

class BaseFormatter(object):
    classes: Dict = dict()

    def __init__(self, data: bytes):
        self.size = len(data)
        self._raw_data_ = data

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        cls.classes[cls.tag.default] = cls

    @staticmethod
    def get(tag, formatter_id: int):
        return BaseFormatter.classes.get(tag, BaseFormatter)(formatter_id)

    def __bytes__(self):
        return self._raw_data_

    @classmethod
    def encode(cls, data):
        pass


class IdentityClass(IntFlag):
    Universal = 0b00
    Application = 0b01
    ContextSpecific = 0b10
    Private = 0b11


class IdentityPC(IntFlag):
    Primitive = 0b0
    Constructed = 0b1


class IdentityTag(IntFlag):
    EOC = 0
    Boolean = 1
    Integer = 2
    BitString = 3
    OctetString = 4
    Null = 5
    ObjectIdentifier = 6
    ObjectDescriptor = 7
    External = 8
    Real = 9
    Enumerated = 10
    EmbeddedPDV = 11
    UTF8String = 12
    RelativeOID = 13
    Time = 14
    # Reserved = 15
    Sequence = 16
    Set = 17
    NumericString = 18
    PrintableString = 19
    T61String = 20
    VideotexString = 21
    IA5String = 22
    UTCTime = 23
    GeneralizedTime = 24
    GraphicString = 25
    VisibleString = 26
    GeneralString = 27
    UniversalString = 28
    CharacterString = 29
    BMPString = 30
    Date = 31
    TimeOfDay = 32
    Duration = 34
    OIDIRI = 35
    RelativeOIDIRI = 36


@dataclass
class Identity(object):
    id_class: IdentityClass
    id_pc: IdentityPC
    id_tag: IdentityTag

    @classmethod
    def decode(cls, data):
        octet = data.pop(0)
        id_class = IdentityClass(octet >> 6)
        id_pc = IdentityPC((octet >> 5) & 1)
        id_tag = octet & 31

        if id_tag == 31:
            id_tag = 0
            while True:
                octet = data.pop(0)
                id_tag = id_tag + (octet & 127)
                if id_tag & 128:
                    break

        return cls(id_class, id_pc, IdentityTag(id_tag)), data


@dataclass
class BER(object):
    ber_id: Identity
    ber_length: int
    ber_content: Any

    @classmethod
    def decode(cls, data):
        list_data = list(data)
        ber_id, list_data = Identity.decode(list_data)
        ber_length = list_data.pop(0)

        if ber_length & 128:
            byte_count = ber_length & 127
            ber_length = 0
            for i in range(byte_count):
                ber_length = ber_length + list_data.pop(0)

        ber_content = bytes(list_data[:ber_length])
        list_data = list_data[ber_length:]

        if list_data:
            return cls(ber_id, ber_length, BaseFormatter.get(ber_id.id_tag, ber_content)), bytes(list_data)
        return cls(ber_id, ber_length, BaseFormatter.get(ber_id.id_tag, ber_content))


@dataclass(init=False)
class EOC(BaseFormatter):
    data: bool
    tag: IdentityTag = field(default=IdentityTag.EOC, repr=False)

    def __init__(self, data):
        super().__init__(data)
        self.data = bytes()


@dataclass(init=False)
class Boolean(BaseFormatter):
    data: bool
    tag: IdentityTag = field(default=IdentityTag.Boolean, repr=False)

    def __init__(self, data):
        super().__init__(data)
        self.data = bool.from_bytes(data, 'big')

    @classmethod
    def encode(cls, data: bool):
        if data:
            return cls('\xff')
        else:
            return cls(b'\x00')


@dataclass(init=False)
class Integer(BaseFormatter):
    data: int
    tag: IdentityTag = field(default=IdentityTag.Integer, repr=False)

    def __init__(self, data: bytes):
        super().__init__(data)

        self.data = from_complement(int.from_bytes(data, 'big'), 8 * len(data))

    @classmethod
    def encode(cls, data: int):
        byte_count = _get_int_bytes_(data)
        out = to_complement(data, 8 * byte_count)

        return cls(out.to_bytes(byte_count, 'big'))


@dataclass(init=False)
class Enumerated(BaseFormatter):
    data: int
    tag: IdentityTag = field(default=IdentityTag.Enumerated, repr=False)

    def __init__(self, data: bytes):
        super().__init__(data)
        self.data = int.from_bytes(data, 'big')

    @classmethod
    def encode(cls, data: int):
        byte_count = round((data.bit_length() / 8) + 0.4)
        return cls(data.to_bytes(byte_count, 'big'))


@dataclass(init=False)
class Real(BaseFormatter):
    data: int
    tag: IdentityTag = field(default=IdentityTag.Real, repr=False)

    def __init__(self, data: bytes):
        super().__init__(data)
        octets = list(data)
        value = (octets[0] >> 6)
        if value == 3:
            # x.690 does not implement this currently.
            pass
        elif value == 2:
            self._standard_format_(octets)
        elif value == 1:
            self._special_format_(octets)
        else:
            self._iso_format_(octets)

    def _standard_format_(self, octets: list):
        encoding_format = octets.pop(0)
        sign_bin = (encoding_format >> 6) & 0b01
        base_bin = (encoding_format >> 4) & 0b11
        factor = (encoding_format >> 2) & 0b11
        format_bin = encoding_format & 0b11

        sign = -1 if sign_bin else 1

        if base_bin != 3:
            base = pow(2, 1 + base_bin)
        else:
            # X.690 reserves this for future editions.
            pass

        octets = bytes(octets)

        if format_bin == 0:
            exponent = from_complement(octets[0], 8)
            octets = octets[1:]

        elif format_bin == 1:
            temp_exp = int.from_bytes(octets[0:2], 'big')
            exponent = from_complement(temp_exp, 16)
            octets = octets[2:]

        elif format_bin == 2:
            temp_exp = int.from_bytes(octets[0:3], 'big')
            exponent = from_complement(temp_exp, 24)
            octets = octets[3:]

        else:
            exp_byte_count = octets[0]
            temp_exp = int.from_bytes(octets[1:exp_byte_count + 2], 'big')
            exponent = from_complement(temp_exp, 8 * exp_byte_count)
            octets = octets[exp_byte_count + 2:]

        number = int.from_bytes(octets, 'big')

        m = sign * number * pow(2, factor)
        self.data = m * pow(base, exponent)

    def _iso_format_(self, octets: list):
        # TODO Implement ISO 6093 NR1 form for case 0b01
        # TODO Implement ISO 6093 NR2 form for case 0b10
        # TODO Implement ISO 6093 NR3 form for case 0b11
        # TODO Buy ISO 6093 standard so this can be implemented
        pass

    def _special_format_(self, octets: list):
        value = octets[0] & 0b11

        if value == 3:
            self.data = float('-0')
        elif value == 2:
            self.data = float('nan')
        elif value == 1:
            self.data = float('-inf')
        else:
            self.data = float('inf')

    @classmethod
    def encode(cls, data: float, base10=False):
        data = float(data)

        if data == float('-0'):
            return cls(b'\x43')
        elif data == float('nan'):
            return cls(b'\x42')
        elif data == float('-inf'):
            return cls(b'\x41')
        elif data == float('inf'):
            return cls(b'\x40')
        elif base10:
            # Need to purchase ISO 6093 to do this part
            pass
        else:
            m, e = float(data).as_integer_ratio()
            e = -int(log(e, 2))
            if e == 0:
                while m % 2 == 0:
                    e = e + 1
                    m = m // 2

            if m < 0:
                m = -m
                sign = 1
            else:
                sign = 0

            byte_count = (e.bit_length() + 7) // 8
            if e % 4 == 0:
                e = to_complement(e / 4, byte_count * 8)
                base = 2
            elif e % 3 == 0:
                e = to_complement(e / 3, byte_count * 8)
                base = 1
            else:
                e = to_complement(e, byte_count * 8)
                base = 0

            if m % 8 == 0:
                m = m / 8
                f = 3
            elif m % 4 == 0:
                m = m / 4
                f = 2
            elif m % 2 == 0:
                m = m / 2
                f = 1
            else:
                f = 0

            if byte_count == 1:
                e_bytes = e.to_bytes(1, 'big')
                e_bits = 00
            elif byte_count == 2:
                e_bytes = e.to_bytes(2, 'big')
                e_bits = 1
            elif byte_count == 3:
                e_bytes = e.to_bytes(3, 'big')
                e_bits = 2
            else:
                e_bytes = byte_count.to_bytes(1, 'big') + e.to_bytes(byte_count, 'big')
                e_bits = 3

            octet = bytes([128 | sign << 6 | base << 4 | f << 2 | e_bits])

            m_bytes = (m.bit_length() + 7) // 8
            return cls(octet + e_bytes + m.to_bytes(m_bytes, 'big'))

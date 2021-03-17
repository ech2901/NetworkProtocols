from dataclasses import dataclass, field
from enum import IntFlag
from math import log
from typing import Dict, SupportsBytes, List, AnyStr

from Encodings.TwosComplement import *


def _get_int_bytes_(data: int):
    return round((data.bit_length() / 8) + 0.4)


def decode_bytes(data: bytes):
    list_data = list(data)
    encoding_id, list_data = Identity.decode(list_data)
    encoding_length = list_data.pop(0)

    if encoding_length == 128:
        # Indefinate form being used.
        # Should only be used for BitString, OctetString, and String types.
        encoding_indef, data = decode_bytes(bytes(list_data))
        encoding_content = encoding_indef.ber_content
        while True:
            encoding_indef, data = decode_bytes(data)
            if encoding_indef.ber_id.id_tag == IdentityTag.EOC:
                break
            encoding_content = encoding_content + encoding_indef.ber_content

        return encoding_id, 0, encoding_content, data

    elif encoding_length & 128:
        # Long form of length being used.
        byte_count = encoding_length & 127
        encoding_length = 0
        for i in range(byte_count):
            encoding_length = encoding_length + list_data.pop(0)

    encoding_content = bytes(list_data[:encoding_length])
    list_data = list_data[encoding_length:]

    if list_data:
        return encoding_id, encoding_length, BaseFormatter.get(encoding_id.id_tag, encoding_content), bytes(list_data)
    return encoding_id, encoding_length, BaseFormatter.get(encoding_id.id_tag, encoding_content), None


class BaseFormatter(object):
    classes: Dict = dict()

    def __init__(self, data: bytes):
        self.size = len(data)
        self._raw_data_ = data

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        cls.classes[cls.tag.default] = cls

    @staticmethod
    def get(tag, data: bytes):
        return BaseFormatter.classes.get(tag, BaseFormatter)(data)

    def __bytes__(self):
        return self._raw_data_

    @classmethod
    def encode(cls, data):
        pass

    def decode(self):
        # TODO: handle long and indeterminant length

        size_id = len(self._raw_data_)

        if size_id >= 128:
            pass
        else:
            return bytes(self.tag) + size_id.to_bytes(1, 'big') + self._raw_data_


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
    # https://www.obj-sys.com/asn1tutorial/node13.html
    # 'ObjectDescriptor is used with the OBJECT IDENTIFIER type and takes values that are human-readable strings
    # delimited by quotes. The type has seldom been implemented, and will not be discussed further.'
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

    def __bytes__(self):
        return self.value.to_bytes(1, 'big')


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


@dataclass(init=False)
class EOC(BaseFormatter):
    data: None = None
    tag: IdentityTag = field(default=IdentityTag.EOC, repr=False)


@dataclass(init=False)
class Boolean(BaseFormatter):
    data: bool
    tag: IdentityTag = field(default=IdentityTag.Boolean, repr=False)

    def __init__(self, data, value=None):
        super().__init__(data)
        if value:
            self.data = data
        else:
            self.data = bool.from_bytes(data, 'big')

    @classmethod
    def encode(cls, data: bool):
        if data:
            return cls(b'\xff', data)
        else:
            return cls(b'\x00', data)


@dataclass(init=False)
class Integer(BaseFormatter):
    data: int
    tag: IdentityTag = field(default=IdentityTag.Integer, repr=False)

    def __init__(self, data: bytes, value=None):
        super().__init__(data)
        if value:
            self.data = value
        else:
            self.data = from_complement(int.from_bytes(data, 'big'), 8 * len(data))

    @classmethod
    def encode(cls, data: int):
        byte_count = _get_int_bytes_(data)
        out = to_complement(data, 8 * byte_count)

        return cls(out.to_bytes(byte_count, 'big'), data)


@dataclass(init=False)
class Enumerated(BaseFormatter):
    data: int
    tag: IdentityTag = field(default=IdentityTag.Enumerated, repr=False)

    def __init__(self, data: bytes, value=None):
        super().__init__(data)
        if value:
            self.data = value
        else:
            self.data = int.from_bytes(data, 'big')

    @classmethod
    def encode(cls, data: int):
        byte_count = round((data.bit_length() / 8) + 0.4)
        return cls(data.to_bytes(byte_count, 'big'), data)


@dataclass(init=False)
class Real(BaseFormatter):
    data: int
    tag: IdentityTag = field(default=IdentityTag.Real, repr=False)

    def __init__(self, data: bytes, value=None):
        super().__init__(data)
        if value:
            self.data = value
        else:
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

        if base_bin == 0:
            base = 2
        elif base_bin == 1:
            base = 8
        elif base_bin == 2:
            base = 16
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
            return cls(b'\x43', data)
        elif data == float('nan'):
            return cls(b'\x42', data)
        elif data == float('-inf'):
            return cls(b'\x41', data)
        elif data == float('inf'):
            return cls(b'\x40', data)
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
            return cls(octet + e_bytes + m.to_bytes(m_bytes, 'big'), data)


@dataclass(init=False)
class BitString(BaseFormatter):
    data: int
    tag: IdentityTag = field(default=IdentityTag.BitString, repr=False)

    def __init__(self, data: bytes, value=None):
        super().__init__(data)
        if value:
            self.data = value
        else:
            unused = data[0]
            self.data = int.from_bytes(data[1:], 'big') >> unused
        self._bitcount_ = (len(data[1:]) * 8) - unused

    def __add__(self, other):
        # For when indefinate form being used and want an easy way of converting.
        data = (self.data << other._bitcount_) + other.data
        return BitString.encode(data, self._bitcount_ + other._bitcount_)

    @classmethod
    def encode(cls, data: int, size: int = None):
        if size:
            # If we want a specific size to use that may have leading 0's
            # EG: 0x0000004f would normally be encoded as b'\x00\x4f' otherwise.
            byte_count = (size + 7) // 8
        else:
            byte_count = _get_int_bytes_(data)

        padding = 8 - (data.bit_length() % 8)
        return cls(padding.to_bytes(1, 'big') + (data << padding).to_bytes(byte_count, 'big'), data)


@dataclass(init=False)
class OctetString(BaseFormatter):
    data: bytes
    tag: IdentityTag = field(default=IdentityTag.OctetString, repr=False)

    def __init__(self, data: bytes, value=None):
        # value never gets used. Only implemented as an argument
        # to maintain structure similarities to other classes.
        super().__init__(data)
        self.data = self.data

    def __add__(self, other):
        return OctetString(self.data + other.data)

    @classmethod
    def encode(cls, data: SupportsBytes):
        return cls(bytes(data))


@dataclass(init=False)
class Null(BaseFormatter):
    data: None
    tag: IdentityTag = field(default=IdentityTag.Null, repr=False)

    def __init__(self, data: None = None):
        # value and data never gets used. Only implemented as an argument
        # to maintain structure similarities to other classes.
        super().__init__(b'')
        self.data = None

    @classmethod
    def encode(cls, data: None = None):
        return cls(None)


@dataclass(init=False)
class Sequence(BaseFormatter):
    data: List
    tag: IdentityTag = field(default=IdentityTag.Sequence, repr=False)

    def __init__(self, data: bytes, value=None):
        super().__init__(data)
        if value:
            self.data = value
        else:
            self.data = list()
            while data:
                _, _, encoding, data = decode_bytes(data)
                self.data.append(encoding.ber_content)

    @classmethod
    def encode(cls, *args):
        data = b''
        for arg in args:
            data = data + arg.decode()
        return cls(data, list(args))


@dataclass(init=False)
class Set(BaseFormatter):
    data: List
    tag: IdentityTag = field(default=IdentityTag.Set, repr=False)

    def __init__(self, data: bytes, value=None):
        super().__init__(data)
        if value:
            self.data = value
        else:
            self.data = list()
            while data:
                _, _, encoding, data = decode_bytes(data)
                self.data.append(encoding.ber_content)

    @classmethod
    def encode(cls, *args):
        data = b''
        for arg in args:
            data = data + arg.decode()
        return cls(data, list(args))


@dataclass(init=False)
class ObjectIdentifier(BaseFormatter):
    data: List
    tag: IdentityTag = field(default=IdentityTag.ObjectIdentifier, repr=False)

    def __init__(self, data: bytes, value=None):
        super().__init__(data)
        if value:
            self.data = value
        else:
            self.data = list()
            data = list(data)
            while data:
                value = data.pop(0)
                if value & 128:
                    temp_val = (value & 127)
                    while value & 128:
                        temp_val = temp_val << 7
                        value = data.pop(0)
                        temp_val = temp_val | (value & 127)
                    value = temp_val

                self.data.append(value)

    @classmethod
    def encode(cls, OID, *args):
        def transform(val: int):
            # Turn integer into format compatible with OID
            # bit 7 marks end of number with a 0
            # bits 6-0 are used to denote an actual number base 128
            # IE: 0xFF becomes 0x817f due to leading bit moving to second byte
            data = list()
            data.append(val & 127)
            val = val >> 7
            while val:
                data.insert(0, 128 | (val & 127))
                val = val >> 7
            return bytes(data)

        if type(OID) == str:
            nums = list(map(int, OID.split('.')))
        else:
            nums = [OID, ]
            nums.extend(args)

        data = b''
        for num in nums:
            data = data + transform(num)

        return cls(data, nums)


@dataclass(init=False)
class ObjectDescriptor(BaseFormatter):
    data: AnyStr
    tag: IdentityTag = field(default=IdentityTag.ObjectDescriptor, repr=False)

    def __init__(self, data: bytes, value=None):
        super().__init__(data)
        if value:
            self.data = value
        else:
            self.data = data.decode()

    @classmethod
    def encode(cls, data: AnyStr):

        if data.startswith("'") and data.endswith("'"):
            return cls(data.encode(), data)
        elif data.startswith('"') and data.endswith('"'):
            return cls(data.encode(), data)
        else:
            return cls(f'"{data}"'.encode(), data)

from dataclasses import dataclass, field
from enum import IntFlag
from typing import Any, Dict


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

        if data == b'\x00':
            self.data = 0
        else:
            # Get two's compliment.

            compliment = 1 << (len(data) * 8)
            raw_data = int.from_bytes(data, 'big')
            self.data = compliment - raw_data

            mask_check = compliment >> 1
            if mask_check & self.data:
                self.data = (self.data ^ mask_check) - mask_check

    @classmethod
    def encode(cls, data: int):
        if data == 0:
            return cls(b'\x00')
        # The smallest bit_length for a non-zero number is 1 bit.
        # Because 1/8 = 0.125, adding 0.4 to that will force it to round up with the round builtin.
        # Also because 7/8 = 0.875, adding 0.4 won't allow the value to round up more than needed.
        # 0.4 was chosen because the round builtin rounds to 0 when given a value <= 0.5.
        # EG: round(0.5) => 0
        # EG: round(0.50000000000000001) => 0
        # EG: round(0.5000000000000001) => 1
        # EG: round(1.5) => 2

        byte_count = round((data.bit_length() / 8) + 0.4)
        if data < 0:
            out = -data
        else:

            compliment = 1 << 8 * byte_count
            out = compliment - data

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
        self.data = int.from_bytes(data, 'big')

    @classmethod
    def encode(cls, data: int):
        byte_count = round((data.bit_length() / 8) + 0.4)
        return cls(data.to_bytes(byte_count, 'big'))

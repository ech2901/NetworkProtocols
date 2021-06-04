from enum import IntFlag
from typing import Dict

from Encodings.ASN1 import Context
from Encodings.ASN1.EncodingClasses import Sequence, OctetString, Set, ContextSpecificFormatter, decode_bytes
from .Classes import AttributeDescription, AssertionValue
from .Enums import FilterChoice


class BaseChoice(object):
    classes: Dict = dict()

    def __init_subclass__(cls, **kwargs):
        cls.classes[cls.tag] = cls

    @classmethod
    def get(cls, tag: int, data: bytes):
        return cls.classes[tag](data)

    def __repr__(self):
        return f'{self.tag.name}({repr(self.choice)})'


class Filter(Context):
    def __init__(self, tag: IntFlag, data: bytes):
        self.tag = FilterChoice(tag)
        self.data = BaseChoice.get(tag, data)

    def __repr__(self):
        return repr(self.data)


class AND(BaseChoice):
    tag: FilterChoice = FilterChoice.AND

    def __init__(self, data: bytes):
        self.choice = Set(data)
        for index, filter in enumerate(self.choice.data):
            self.choice.data[index] = filter.apply(Filter)


class OR(AND):
    tag: FilterChoice = FilterChoice.OR


class Not(BaseChoice):
    tag: FilterChoice = FilterChoice.NOT

    def __init__(self, data):
        id, _, data, _ = decode_bytes(data)
        self.choice = ContextSpecificFormatter(id, data).apply(Filter)


class EqualityMatch(BaseChoice):
    tag: FilterChoice = FilterChoice.Equality_Match

    def __init__(self, data: bytes):
        self.choice = Sequence(data)
        self.desc, self.val = self.choice.data

    def __repr__(self):
        return f'{self.tag.name}({self.desc}={self.val})'


class Substrings(BaseChoice):
    tag = FilterChoice = FilterChoice.Substrings

    def __init__(self, data: bytes):
        self.choice = Sequence(data)
        self.type = AttributeDescription.subclass(self.choice.data[0])
        self.substrings = self.choice.data[1]
        for index, substring in self.substrings.data:
            self.substrings.data[index] = AssertionValue.subclass(self.substrings.data[index])
        # TODO make it so that initial(limit=1), any(limit=MAX), and final(limit=1) happens. Seperate as needed
        # in reference to above: https://datatracker.ietf.org/doc/html/rfc4511#page-21


class GreaterOrEqual(EqualityMatch):
    tag: FilterChoice = FilterChoice.Greater_Or_Equal

    def __repr__(self):
        return f'{self.tag.name}({self.desc}>={self.val})'


class LessOrEqual(EqualityMatch):
    tag: FilterChoice = FilterChoice.Less_Or_Equal

    def __repr__(self):
        return f'{self.tag.name}({self.desc}<={self.val})'


class Present(BaseChoice):
    tag: FilterChoice = FilterChoice.Present

    def __init__(self, data: bytes):
        self.choice = OctetString(data)


class ApproxMatch(EqualityMatch):
    tag: FilterChoice = FilterChoice.Approx_Match

    def __repr__(self):
        return f'{self.tag.name}({self.desc}~{self.val})'


class ExtensibleMatch(BaseChoice):
    tag: FilterChoice = FilterChoice.Extensible_Match
    # TODO implement from https://datatracker.ietf.org/doc/html/rfc4511#page-21

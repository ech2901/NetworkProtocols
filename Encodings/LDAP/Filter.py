from enum import IntFlag
from typing import Dict

from Encodings.ASN1 import Context
from Encodings.ASN1.EncodingClasses import Sequence, OctetString
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


class EqualityMatch(BaseChoice):
    tag: FilterChoice = FilterChoice.Equality_Match

    def __init__(self, data: bytes):
        self.choice = Sequence(data)
        self.desc, self.val = self.choice.data

    def __repr__(self):
        return f'{self.tag.name}({self.desc}={self.val})'


class Substrings(BaseChoice):
    tag = FilterChoice = FilterChoice.Substrings


class GreaterOrEqual(EqualityMatch):
    tag: FilterChoice = FilterChoice.Greater_Or_Equal


class LessOrEqual(EqualityMatch):
    tag: FilterChoice = FilterChoice.Less_Or_Equal


class Present(BaseChoice):
    tag: FilterChoice = FilterChoice.Present

    def __init__(self, data: bytes):
        self.choice = OctetString(data)


class ApproxMatch(EqualityMatch):
    tag: FilterChoice = FilterChoice.Approx_Match


class ExtensibleMatch(BaseChoice):
    tag: FilterChoice = FilterChoice.Extensible_Match

from dataclasses import dataclass
from enum import IntFlag


class TagClass(IntFlag):
    universal = 0b00
    application = 0b01
    context_specific = 0b10
    private = 0b11


class TagSyntax(IntFlag):
    pass


class UniversalSyntax(TagSyntax):
    Boolean = 0b1
    Integer = 0b10
    OctetString = 0b100
    Null = 0b101
    Enumerated = 0b1010
    Sequence = 0b110000
    Set = 0b110001


class ApplicationSyntax(TagSyntax):
    pass


@dataclass
class Tag(object):
    _class: TagClass
    constructed: bool
    syntax: TagSyntax

    @classmethod
    def unpack(cls, data):
        _class = data >> 6
        constructed = bool((data >> 5) & 1)
        syntax = TagSyntax(data & 0b11111)
        return cls(_class, constructed, syntax)

    def pack(self):
        out = self._class << 6
        out = out | (self.constructed << 5)
        out = out | self.syntax
        return bytes([out])

from Encodings.ASN1.EncodingClasses import Sequence

from .Classes import LDAPOID


class Control(Sequence):
    def __init__(self, data: bytes, value: list = None):
        super().__init__(data, value)
        self.controlType = LDAPOID.subclass(self.data[0])
        self.criticality = self.data[1]
        if self.data[2]:
            self.controlValue = self.data[3]
        else:
            self.controlValue = None


class Controls(Sequence):
    def __init__(self, data: bytes, value: list = None):
        super().__init__(data, value)
        for index, control in enumerate(self.data):
            self.data[index] = Control.subclass(control)

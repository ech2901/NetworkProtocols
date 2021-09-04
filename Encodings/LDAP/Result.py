from Encodings.ASN1.EncodingClasses import Sequence
from .Classes import LDAPDN, LDAPString, Referral
from .Enums import ResultCode


class LDAPResult(Sequence):
    def __init__(self, data: bytes, value: list = None):
        super().__init__(data, value)
        self.resultCode = ResultCode(self.data[0].data)
        self.matchedDN = LDAPDN.subclass(self.data[1])
        self.diagnosticMessage = LDAPString.subclass(self.data[2])
        if self.data[3]:
            self.referral = Referral.subclass(self.data[3])
        else:
            self.referral = None

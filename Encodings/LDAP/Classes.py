from Encodings.ASN1.EncodingClasses import OctetString, Sequence, Set, Integer


# Define classes used for identification as part of the LDAP specification RFC 4511
# Right now, no real functionality other than custom __repl__ implemented in BaseFormatter
# https://datatracker.ietf.org/doc/html/rfc4511

class LDAPString(OctetString):
    pass


class LDAPOID(OctetString):
    pass


class LDAPDN(OctetString):
    pass


class RelativeLDAPDN(OctetString):
    pass


class AttributeDescription(OctetString):
    pass


class AttributeValue(OctetString):
    pass


class AssertionValue(OctetString):
    pass


class MatchingRuleID(OctetString):
    pass


class URI(OctetString):
    pass


class AttributeValueAssertion(Sequence):
    def __init__(self, data: bytes, value: list = None):
        super().__init__(data, value)

        assert (len(self.data) == 2, f'Must contain exactly 2 values. Recieved {len(self.data)}.')

        self.attributeDesc = AttributeDescription.subclass(self.data[0])
        self.assertionValue = AssertionValue.subclass(self.data[1])
        self.data = [self.attributeDesc, self.assertionValue]


class PartialAttribute(Sequence):
    def __init__(self, data: bytes, value: list = None):
        super().__init__(data, value)

        assert (len(self.data) == 2, f'Must contain exactly 2 values. Recieved {len(self.data)}.')

        self.attributeDesc = AttributeDescription.subclass(self.data[0])

        self.attributeValues = self.data[1]
        assert (type(self.attributeValues) == Set,
                f'Attribute Values must be a Set. Recieved {type(self.attributeValues)}')

        for index, attributeValue in enumerate(self.attributeValues.data):
            self.attributeValues[index] = AttributeValue.subclass(attributeValue)


class Attribute(PartialAttribute):
    pass


class MessageID(Integer):
    pass


class Referral(Sequence):
    def __init__(self, data: bytes, value: list = None):
        super().__init__(data, value)

        for index, uri in enumerate(self.data):
            self.data[index] = URI.subclass(uri)


class AttributeSelection(Sequence):
    def __init__(self, data: bytes, value: list = None):
        super().__init__(data, value)

        for index, ldap_string in enumerate(self.data):
            self.data[index] = LDAPString.subclass(ldap_string)

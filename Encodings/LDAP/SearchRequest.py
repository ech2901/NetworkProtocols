from collections import namedtuple

from Encodings.ASN1 import ApplicationFormatter, decode_bytes
from .Classes import LDAPDN, AttributeSelection
from .Enums import LDAPTags, Scopes, DerefAliases
from .Filter import Filter

search_request = namedtuple("SearchRequest", ['baseObject', 'scope', 'derefAliases', 'sizeLimit',
                                              'timeLimit', 'typesOnly', 'filter', 'attributes'])


class SearchRequest(ApplicationFormatter):
    tag = LDAPTags.Search_Request
    data: search_request

    def __init__(self, data: bytes, value=None):
        super().__init__(data)
        if value:
            self.data = value
        else:
            search_data = list()
            while data:
                _, _, encoding, data = decode_bytes(data)

                search_data.append(encoding)

            search_data[0] = LDAPDN.subclass(search_data[0])
            search_data[1] = Scopes(search_data[1].data)
            search_data[2] = DerefAliases(search_data[2].data)
            search_data[-2] = search_data[-2].apply(Filter)
            search_data[-1] = AttributeSelection.subclass(search_data[-1])

            self.data = search_request(*search_data)

    @classmethod
    def encode(cls, *args):
        data = b''
        for arg in args:
            data = data + arg.decode()
        return cls(data, search_request(*args))

    def __repr__(self):
        return repr(self.data)

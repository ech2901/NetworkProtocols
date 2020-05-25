from datetime import datetime, timedelta

from .Classes import Query, ResourceRecord, Type, Class


class BaseStorage(object):
    def __init__(self):
        packed_rdata = Type.A.factory('0.0.0.0').packed
        self.dummy_record = (Type.A, Class.IN, (1 << 32) - 1, len(packed_rdata), packed_rdata)

    def is_blocked(self, query: Query):
        pass

    def get(self, query: Query):
        pass

    def add_record(self, record: ResourceRecord):
        pass

    def add_cache(self, query: Query, records: list):
        pass

    def __contains__(self, query: Query):
        pass

    def __getitem__(self, query: Query):
        if self.is_blocked(query):
            return [ResourceRecord(query.name, *self.dummy_record)]
        if query in self:
            return self.get(query)
        return None


class DictStorage(BaseStorage):
    def __init__(self):
        BaseStorage.__init__(self)

        self.records = dict()
        self.cache = dict()
        self.blocked_domains = dict()
        self.blocked_hostnames = dict()

    def is_blocked(self, query: Query):
        if query.name in self.blocked_hostnames:
            return True
        else:
            *subdomains, root = query.name.split(b'.', -1)
            if root in self.blocked_domains:
                return True
            for subdomain in reversed(subdomains):
                root = b'.'.join([subdomain, root])
                if root in self.blocked_domains:
                    return True
        return False

    def get(self, query: Query):
        key = (query.name, query._type, query._class)
        try:
            return [self.records[key]]
        except KeyError:
            try:
                cached_records, expiration = self.cache[key]
                if datetime.now() < expiration:
                    return cached_records

            except KeyError:
                return None

    def add_record(self, record: ResourceRecord):
        self.records[(record.name, record._type, record._class)] = record

    def add_cache(self, query: Query, records: list):
        expiration = datetime.now() + timedelta(seconds=min(records, key=lambda x: x.ttl).ttl)
        self.cache[(query.name, query._type, query._class)] = (records, expiration)

    def __contains__(self, query: Query):
        test = (query.name, query._type, query._class)
        return (test in self.records) or (test in self.cache)

from datetime import datetime, timedelta
from json import load, dump

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
        self.blocked_domains = list()
        self.blocked_hostnames = list()

    def load(self, file: str):
        try:
            with open(file, 'r') as file:
                data = load(file)
        except FileNotFoundError:
            return

        self.blocked_hostnames.extend(data['blocked_hostnames'])
        self.blocked_domains.extend(data['blocked_domains'])

        for name in data['records']:
            _type = Type(data['records'][name]['type'])
            _class = Class(data['records'][name]['class'])
            ttl = data['records'][name]['ttl']
            rdata_length = data['records'][name]['data_length']
            rdata = int.to_bytes(rdata_length, data['records'][name]['data'])
            self.add_record(ResourceRecord(name, _type, _class, ttl, rdata_length, rdata))

    def save(self, file: str):
        out = dict()
        out['records'] = dict()
        for record in self.records.values():
            out['records'][record.name] = {'type': record._type._value, 'class': record._class._value,
                                           'ttl': record.ttl,
                                           'data_length': record.rdata_length,
                                           'data': int.from_bytes(record.rdata, 'big')}

        out['blocked_domains'] = self.blocked_domains
        out['blocked_hostnames'] = self.blocked_hostnames
        with open(file, 'w') as file:
            dump(out, file)

    def is_blocked(self, query: Query):
        if query.name in self.blocked_hostnames:
            return True
        else:
            *subdomains, root = query.name.split('.', -1)
            if root in self.blocked_domains:
                return True
            for subdomain in reversed(subdomains):
                root = '.'.join([subdomain, root])
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

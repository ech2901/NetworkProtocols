from dataclasses import dataclass
from ipaddress import ip_network, ip_address
from sched import scheduler
from threading import Thread

from RawPacket import MAC_Address


@dataclass(init=False)
class Record(object):
    name: str
    mac: MAC_Address
    ip: ip_address
    options: list

    def __init__(self, name, mac, ip, *options):
        self.name = name
        self.mac = MAC_Address(mac)
        self.ip = ip_address(ip)

        # These options will take priority
        self.options = options

    def __hash__(self):
        return hash(repr(self))

    def dump(self):
        out = dict()
        out['name'] = self.name
        out['mac'] = str(self.mac)
        out['ip'] = str(self.ip)
        return out

    @classmethod
    def load(cls, data):
        return cls(data['name'], data['mac'], data['ip'])


class GarbageCollector(Thread):
    def __init__(self):
        super().__init__()
        self.schedule = scheduler()
        self.keep_alive = True

    def run(self):
        while self.keep_alive:
            self.schedule.run()

    def insert(self, delay, action, *args):
        self.schedule.enter(delay, 1, action, args)

    def shutdown(self):
        self.keep_alive = False
        for event in self.schedule.queue:
            self.schedule.cancel(event)


class Pool(object):
    def __init__(self, network='192.168.0.0', mask='255.255.255.0'):
        self._network = ip_network(fr'{network}/{mask}')
        self.hosts = list(self._network.hosts())

        # IP/MAC reservations
        self.reservations = dict()

        # White/Blacklist handling
        self.listing = list()
        self.list_mode = 'b'

    def reserve(self, record: Record):

        try:
            self.hosts.remove(record.ip)
            self.reservations[record.mac] = record
        except ValueError:
            if record.mac in self.reservations:
                pass
            elif record.ip == self.broadcast:
                pass
            else:
                print(f'IP {record.ip} not in network {self._network}')

    def unreserve(self, mac: MAC_Address):
        self.reservations.pop(mac, None)

    def is_reserved(self, mac: MAC_Address):
        return mac in self.reservations

    def add_listing(self, mac: MAC_Address):
        if mac not in self.listing:
            self.listing.append(mac)

    def remove_listing(self, mac: MAC_Address):
        if mac in self.listing:
            self.listing.remove(mac)

    def toggle_listing_mode(self):
        if self.list_mode == 'w':
            self.list_mode = 'b'
            return
        self.list_mode = 'w'

    def get_ip(self, clientid: str, mac: MAC_Address, ip: ip_address):

        if mac in self.listing:
            if self.list_mode == 'b':
                # If we have the listing and we're using a blacklist, don't give an IP
                return None
        elif self.list_mode == 'w':
            # If we don't have the listing and we're using a whitelist, don't give an IP
            return

        try:
            # Try to return object from the reservations
            return self.reservations[mac]

        except KeyError:
            # KeyError will be raised if trying to get
            # a reservation that does not exists.
            try:
                self.hosts.remove(ip)

            except ValueError:
                # ValueError will be raised if trying to get
                # an IP address that does not exists in our pool of hosts.
                try:
                    ip = self.hosts.pop(0)

                except IndexError:
                    # If the number of available addresses gets exhausted return None
                    return None
            finally:
                return Record(clientid, mac, ip)

    def add_ip(self, ip: ip_address):
        if ip in self._network:
            self.hosts.insert(0, ip)

    @property
    def broadcast(self):
        return self._network.broadcast_address

    @property
    def netmask(self):
        return self._network.netmask

    @property
    def network(self):
        return self._network.network_address

    def __contains__(self, ip):
        return ip in self.hosts

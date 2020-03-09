from ipaddress import ip_network
from sched import scheduler
from threading import Thread


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

    def insertabs(self, abstime, action, *args):
        self.schedule.enterabs(abstime, 1, action, args)

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

    def reserve(self, mac, ip):

        try:
            self.hosts.remove(ip)
            self.reservations[mac] = ip
        except ValueError:
            if mac in self.reservations:
                pass
            elif ip == self.broadcast:
                pass
            else:
                print(f'IP {ip} not in network {self._network}')

    def unreserve(self, mac):
        self.reservations.pop(mac, None)

    def is_reserved(self, mac):
        return mac in self.reservations

    def add_listing(self, mac):
        if mac not in self.listing:
            self.listing.append(mac)

    def remove_listing(self, mac):
        if mac in self.listing:
            self.listing.remove(mac)

    def toggle_listing_mode(self):
        if self.list_mode == 'w':
            self.list_mode = 'b'
            return
        self.list_mode = 'w'

    def get_ip(self, mac, requested_ip=None):

        if mac in self.listing:
            if self.list_mode == 'b':
                # If we have the listing and we're using a blacklist, don't give an IP
                return None
        elif self.list_mode == 'w':
            # If we don't have the listing and we're using a whitelist, don't give an IP
            return

        try:
            # Try to remove object from the reservations
            return self.reservations[mac]

        except KeyError:
            # KeyError will be raised if trying to get
            # a reservation that does not exists.
            try:
                self.hosts.remove(requested_ip)
                return requested_ip

            except ValueError:
                # ValueError will be raised if trying to get
                # an IP address that does not exists in our pool of hosts.
                try:
                    return self.hosts.pop(0)

                except IndexError:
                    # If the number of available addresses gets exhausted return None
                    return None

    def add_ip(self, ip):
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

    def __contains__(self, item):
        return item in self.hosts

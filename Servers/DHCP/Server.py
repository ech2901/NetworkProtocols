from configparser import ConfigParser
from ipaddress import ip_network, ip_address
from sched import scheduler
from socket import IPPROTO_UDP
from socketserver import BaseRequestHandler
from threading import Thread

from RawPacket import Ethernet, IPv4, UDP, MAC_Address
from Servers import RawServer
from Servers.DHCP import Options, Packet

defaults = ConfigParser()
defaults.read(r'Servers/DHCP/config.ini')


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
        self.schedule.empty()


class Pool(object):
    def __init__(self, network='192.168.0.0', mask='255.255.255.0'):
        self._network = ip_network(fr'{network}/{mask}')
        self.hosts = list(self._network.hosts())
        self.reservations = dict()

    def reserve(self, mac, ip):
        try:
            self.hosts.remove(ip)
            self.reservations[mac] = ip
        except ValueError:
            print(f'IP {ip} not in network {self._network}')

    def unreserve(self, mac):
        self.reservations.pop(mac, None)

    def is_reserved(self, mac):
        return mac in self.reservations

    def get_ip(self, mac, requested_ip=None):
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


class DHCPHandler(BaseRequestHandler):
    def setup(self):
        self.eth = Ethernet.disassemble(self.request[0])
        self.ip = self.eth.payload
        if (self.ip.protocol == IPPROTO_UDP):
            self.udp = self.ip.payload
            if (self.udp.destination == self.server.server_port):
                self.is_dhcp = True
                self.send_packet = False
                self.packet = Packet.DHCPPacket.disassemble(self.udp.payload)
                return

        self.is_dhcp = False

    def handle(self):
        if(self.is_dhcp):

            packet = None

            if (Options.DHCPMessageType(1) in self.packet.options):
                packet = self.handle_disco()
            elif (Options.DHCPMessageType(3) in self.packet.options):
                packet = self.handle_req()
            elif (Options.DHCPMessageType(4) in self.packet.options):
                packet = self.handle_decline()
            elif (Options.DHCPMessageType(7) in self.packet.options):
                packet = self.handle_release()
            elif (Options.DHCPMessageType(8) in self.packet.options):
                packet = self.handle_inform()

            if (packet):

                # Building UDP Packet

                udp = UDP(self.server.server_port, self.server.client_port, packet.build())

                # Building IP packet

                ip = IPv4(self.server.server_ip, ip_address('255.255.255.255'), udp)

                if (self.packet.hops):
                    packet.hops = self.packet.hops
                    packet.giaddr = self.packet.giaddr
                    ip.destination = packet.giaddr

                elif (self.packet.ciaddr._ip):
                    # If client has a put a reachable IP address in this field
                    # Send to this specific address
                    ip.destination = self.packet.ciaddr

                # Building Ethernet packet

                eth = Ethernet(self.packet.chaddr, self.server.server_address[-1], ip)

                if (self.server.broadcast):
                    eth.destination = MAC_Address('FF:FF:FF:FF:FF:FF')

                eth.calc_checksum()
                self.request[1].send(eth.build())

    def handle_disco(self):
        # Building DHCP offer Packet

        offer = Packet.DHCPPacket(op=2, xid=self.packet.xid, _chaddr=self.eth.source,
                                  broadcast=self.packet.broadcast or self.server.broadcast)
        offer.options.append(Options.DHCPMessageType(2))
        offer.options.extend(self.server.server_options.values())

        client_hostname = b''
        offer_ip = None

        for option in self.packet.options:
            if (option.code == Options.ParameterRequestList.code):
                for code in option.data:
                    if code in self.server.options:
                        offer.options.append(self.server.options[code])

            if (option.code == Options.RequestedIP.code):
                offer_ip = option.data

            if (option.code == Options.HostName.code):
                client_hostname = option.data

        offer.options.append(Options.End())

        offer.siaddr = self.server.server_ip
        offer.yiaddr = self.server.pool.get_ip(self.packet.chaddr, offer_ip)

        self.server.register_offer(offer.chaddr, offer.xid, offer.yiaddr, client_hostname)

        return offer

    def handle_req(self):

        # Building DHCP acknowledge Packet

        ack = Packet.DHCPPacket(op=2, xid=self.packet.xid, _chaddr=self.eth.source,
                                broadcast=self.packet.broadcast or self.server.broadcast)
        ack.options.append(Options.DHCPMessageType(5))
        ack.options.extend(self.server.server_options.values())

        offer_ip, client_hostname = self.server.offers[(ack.chaddr, ack.xid)]


        for option in self.packet.options:
            if (option.code == Options.ParameterRequestList.code):
                for code in option.data:
                    if code in self.server.options:
                        ack.options.append(self.server.options[code])

            if (option.code == Options.RequestedIP.code):
                offer_ip = option.data

            if (option.code == Options.HostName.code):
                client_hostname = option.data

            if (option.code == Options.DHCPServerID.code):
                if option.data != self.server.server_ip:
                    return None

        ack.options.append(Options.End())

        ack.siaddr = self.server.server_ip
        ack.yiaddr = self.server.pool.get_ip(self.packet.chaddr, offer_ip)

        self.server.register_client(ack.chaddr, client_hostname, ack.yiaddr)

        return ack

    def handle_decline(self):
        pass

    def handle_release(self):
        pass

    def handle_inform(self):
        pass


class DHCPServer(RawServer):

    clients = dict()  # Keys will be a tuple of (MAC address, ClientID). ClientID defaults to b''
    offers = dict()  # Keys will be a tuple of (MAC Address, XID).

    server_options = dict()
    options = dict()  # Keys will be an int being the code of the option.

    def __init__(self, interface=defaults.get('optional', 'interface'), **kwargs):
        RawServer.__init__(self, interface, DHCPHandler)

        # Server addressing information

        self.server_ip = ip_address(kwargs.get('server_ip', defaults.get('ip addresses', 'server_ip')))
        self.server_port = kwargs.get('server_port', defaults.getint('numbers', 'server_port'))
        self.client_port = kwargs.get('client_port', defaults.getint('numbers', 'client_port'))

        # Server IP pool setup

        self.pool = Pool(kwargs.get('network', defaults.get('ip addresses', 'network')),
                         kwargs.get('mask', defaults.get('ip addresses', 'mask')))
        self.pool.reserve(self.mac_address, self.server_ip)
        self.broadcast = kwargs.get('broadcast', defaults.getboolean('optional', 'broadcast'))

        # Timing information
        self.offer_hold_time = kwargs.get('offer_hold_time', defaults.getint('numbers', 'offer_hold_time'))
        # Default lease time of 8 days
        IPLeaseTime = kwargs.get('ipleasetime', defaults.getint('numbers', 'ipleasetime'))
        # Default renew time of 4 days
        RenewalT1 = kwargs.get('renewalt1', defaults.getint('numbers', 'renewalt1'))
        # Default rebind time of 3 days
        RenewalT2 = kwargs.get('renewalt2', defaults.getint('numbers', 'renewalt2'))



        self.register_server_option(Options.Subnet(self.pool.netmask))
        self.register_server_option(Options.BroadcastAddress(self.pool.broadcast))
        self.register_server_option(Options.DHCPServerID(self.server_ip))

        self.register_server_option(Options.IPLeaseTime(IPLeaseTime))
        self.register_server_option(Options.RenewalT1(RenewalT1))
        self.register_server_option(Options.RenewalT2(RenewalT2))

        self.gb = GarbageCollector()


    def register_offer(self, address, xid, offer_ip, client_hostname):
        self.offers[(address, xid)] = (offer_ip, client_hostname)
        self.gb.insert(self.offer_hold_time, self.release_offer, address, xid)

    def release_offer(self, address, xid):
        # clear short term reservation of ip address.
        if ((address, xid) in self.offers):
            self.pool.add_ip(self.offers.pop((address, xid))[0])

    def register_client(self, address, clientid, client_ip):
        self.clients[(address, clientid)] = client_ip
        self.gb.insert(self.get(Options.IPLeaseTime).data, self.release_client, address, clientid)

    def release_client(self, address, clientid):
        # clear long term reservation of ip address.
        if ((address, clientid) in self.clients):
            self.pool.add_ip(self.clients.pop((address, clientid)))

    def register_server_option(self, option):
        # These options always are included in server DHCP packets
        self.server_options[option.code] = option

        try:
            try:
                if option.data in self.pool.network:
                    # If option data is an ip address, reserve it
                    self.pool.reserve(option.code, option.data)
            except:
                # Otherwise, try to iterate through the data as a list
                # and if it is an ip address in the network pool
                # reserve it
                for index, addr in enumerate(option.data, start=1):
                    if addr not in self.pool.network:
                        continue
                    self.pool.reserve(f'{option.code}-{index}', addr)

        except:
            # option data isn't an IP Address
            pass

    def register(self, option):
        # These options are included in server DHCP packets by request of client
        self.options[option.code] = option

        try:
            try:
                if option.data in self.pool.network:
                    # If option data is an ip address, reserve it
                    self.pool.reserve(option.code, option.data)
            except:
                # Otherwise, try to iterate through the data as a list
                # and if it is an ip address in the network pool
                # reserve it
                for index, addr in enumerate(option.data, start=1):
                    if addr not in self.pool.network:
                        continue
                    self.pool.reserve(f'{option.code}-{index}', addr)

        except:
            # option data isn't an IP Address
            pass

    def get(self, option):
        if (option.code in self.options):
            return self.options[option.code]

        elif (option.code in self.server_options):
            return self.server_options[option.code]

    def start(self):
        self.gb.start()
        super().start()

    def shutdown(self):

        self.gb.shutdown()
        super().shutdown()

    def __enter__(self):
        self.start()

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.shutdown()

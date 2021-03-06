from configparser import ConfigParser
from ipaddress import ip_address
from json import load, dump
from socket import IPPROTO_UDP
from socketserver import BaseRequestHandler

from BaseServers import BaseRawServer
from RawPacket import Ethernet, IPv4, UDP, MAC_Address
from . import Packet, Options
from .GarbageCollection import GarbageCollector
from .Pool import Pool

defaults = ConfigParser()
defaults.read(r'Servers/DHCP/config.ini')


class RawHandler(BaseRequestHandler):
    eth = None
    ip = None
    udp = None
    packet = None
    is_dhcp = False

    def setup(self):
        self.eth = Ethernet.disassemble(self.request[0])
        self.ip = self.eth.payload
        if self.ip.protocol == IPPROTO_UDP:
            self.udp = self.ip.payload
            if self.udp.destination == self.server.server_port:
                self.is_dhcp = True
                self.packet = Packet.DHCPPacket.disassemble(self.udp.payload)
                return

    def handle(self):
        if self.is_dhcp:

            packet = None

            if Options.DHCPMessageType(1) in self.packet.options:
                packet = self.handle_disco()
            elif Options.DHCPMessageType(3) in self.packet.options:
                packet = self.handle_req()
            elif Options.DHCPMessageType(4) in self.packet.options:
                packet = self.handle_decline()
            elif Options.DHCPMessageType(7) in self.packet.options:
                packet = self.handle_release()
            elif Options.DHCPMessageType(8) in self.packet.options:
                packet = self.handle_inform()

            if packet:

                # Building UDP Packet

                udp = UDP(self.server.server_port, self.server.client_port, packet.build())

                # Building IP packet

                ip = IPv4(self.server.server_ip, ip_address('255.255.255.255'), udp)

                if self.packet.hops:
                    packet.hops = self.packet.hops
                    packet.giaddr = self.packet.giaddr
                    ip.destination = packet.giaddr

                elif self.packet.ciaddr._ip:
                    # If client has a put a reachable IP address in this field
                    # Send to this specific address
                    ip.destination = self.packet.ciaddr

                # Building Ethernet packet

                eth = Ethernet(self.packet.chaddr, self.server.server_address[-1], ip)

                if self.server.broadcast or self.packet.broadcast:
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
            if option.code == Options.ParameterRequestList.code:
                for code in option.data:
                    if code in self.server.options:
                        offer.options.append(self.server.options[code])

            if option.code == Options.RequestedIP.code:
                offer_ip = option.data

            if option.code == Options.HostName.code:
                client_hostname = option.data

        offer.options.append(Options.End())

        offer.siaddr = self.server.server_ip
        offer.yiaddr = self.server.pool.get_ip(self.packet.chaddr, offer_ip)

        if offer.yiaddr:
            # If we're offering a valid IP (EG not None), proceed with offer
            self.server.register_offer(offer.chaddr, offer.xid, offer.yiaddr, client_hostname)
            return offer

    def handle_req(self):

        # Building DHCP acknowledge Packet

        ack = Packet.DHCPPacket(op=2, xid=self.packet.xid, _chaddr=self.eth.source,
                                broadcast=self.packet.broadcast or self.server.broadcast)
        ack.options.append(Options.DHCPMessageType(5))
        ack.options.extend(self.server.server_options.values())

        offer_ip, client_hostname = self.server.offers[(ack.chaddr, ack.xid)]
        req_ip = None

        for option in self.packet.options:
            if option.code == Options.ParameterRequestList.code:
                for code in option.data:
                    if code in self.server.options:
                        ack.options.append(self.server.options[code])

            if option.code == Options.RequestedIP.code:
                # If the client didn't request a specific IP in the discover packet
                req_ip = option.data

            if option.code == Options.HostName.code:
                # If the client didn't specify a hostname in the discover packet
                client_hostname = option.data

            if option.code == Options.DHCPServerID.code:
                if option.data != self.server.server_ip:
                    # If the client is trying to request from a server other than us.
                    return None

        ack.options.append(Options.End())

        ack.siaddr = self.server.server_ip

        if req_ip and req_ip != offer_ip:
            ack.yiaddr = self.server.pool.get_ip(self.packet.chaddr, offer_ip)
        else:
            ack.yiaddr = offer_ip

        if ack.yiaddr:
            self.server.register_client(ack.chaddr, client_hostname, ack.yiaddr)

            return ack

    def handle_decline(self):
        pass

    def handle_release(self):
        pass

    def handle_inform(self):
        pass


class RawServer(BaseRawServer):
    clients = dict()  # Keys will be a tuple of (MAC address, ClientID). ClientID defaults to b''
    offers = dict()  # Keys will be a tuple of (MAC Address, XID).

    server_options = dict()
    options = dict()  # Keys will be an int being the code of the option.

    def __init__(self, interface=defaults.get('optional', 'interface'), **kwargs):
        BaseRawServer.__init__(self, interface, RawHandler)

        # Savefile
        self.file = kwargs.get('savefile', defaults.get('optional', 'savefile'))

        # Server addressing information
        self.server_ip = ip_address(kwargs.get('server_ip', defaults.get('ip addresses', 'server_ip')))
        self.server_port = kwargs.get('server_port', defaults.getint('numbers', 'server_port'))
        self.client_port = kwargs.get('client_port', defaults.getint('numbers', 'client_port'))
        self.broadcast = kwargs.get('broadcast', defaults.getboolean('optional', 'broadcast'))

        # Server IP pool setup
        self.pool = Pool(ip_address(kwargs.get('network', defaults.get('ip addresses', 'network'))),
                         ip_address(kwargs.get('mask', defaults.get('ip addresses', 'mask'))))

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
        if (address, xid) in self.offers:
            self.pool.add_ip(self.offers.pop((address, xid))[0])

    def register_client(self, address, clientid, client_ip):
        self.release_client(address, clientid)  # Release previously given IP client may have for reuse
        self.clients[(address, clientid)] = client_ip
        self.gb.insert(self.get(Options.IPLeaseTime), self.release_client, address, clientid, client_ip)

    def release_client(self, address, clientid, client_ip=None):
        # clear long term reservation of ip address.
        if (address, clientid) in self.clients:
            if client_ip:
                if self.clients[(address, clientid)] == client_ip:
                    # Prevent pre-mature removal of a client that was previously connected to network.
                    self.pool.add_ip(self.clients.pop((address, clientid)))
            else:
                # If we're just trying to clear the client from the server.
                self.pool.add_ip(self.clients.pop((address, clientid)))

    def register_server_option(self, option):
        # These options always are included in server DHCP packets
        self.server_options[option.code] = option

        try:
            try:
                if option.data in self.pool._network:
                    # If option data is an ip address, reserve it
                    self.pool.reserve(option.__class__.__name__, option.data)
            except AttributeError:
                # Otherwise, try to iterate through the data as a list
                # and if it is an ip address in the network pool
                # reserve it
                for index, addr in enumerate(option.data, start=1):
                    if addr not in self.pool._network:
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
                if option.data in self.pool._network:
                    # If option data is an ip address, reserve it
                    self.pool.reserve(option.__class__.__name__, option.data)
            except AttributeError:
                # Otherwise, try to iterate through the data as a list
                # and if it is an ip address in the network pool
                # reserve it
                for index, addr in enumerate(option.data, start=1):
                    if addr not in self.pool._network:
                        continue
                    self.pool.reserve(f'{option.__class__.__name__}-{index}', addr)

        except:
            # option data isn't an IP Address
            pass

    def get(self, option):
        if option.code in self.options:
            return self.options[option.code].data

        elif option.code in self.server_options:
            return self.server_options[option.code].data

    def reserve(self, mac, ip):
        mac = MAC_Address(mac)
        ip = ip_address(ip)
        self.pool.reserve(mac, ip)

    def unreserve(self, mac):
        mac = MAC_Address(mac)
        self.pool.unreserve(mac)

    def add_listing(self, mac):
        mac = MAC_Address(mac)
        self.pool.add_listing(mac)

    def remove_listing(self, mac):
        mac = MAC_Address(mac)
        self.pool.remove_listing(mac)

    def start(self):
        self.gb.start()
        super().start()

    def shutdown(self):
        self.save()
        self.gb.shutdown()
        super().shutdown()

    def save(self):
        data = dict()

        setup = dict()
        setup['server_ip'] = self.server_ip._ip
        setup['server_port'] = self.server_port
        setup['client_port'] = self.client_port
        setup['broadcast'] = self.broadcast
        setup['network'] = self.pool.network._ip
        setup['mask'] = self.pool.netmask._ip
        setup['offer_hold_time'] = self.offer_hold_time
        setup['ipleasetime'] = self.get(Options.IPLeaseTime)
        setup['renewalt1'] = self.get(Options.RenewalT1)
        setup['renewalt2'] = self.get(Options.RenewalT2)
        data['setup_info'] = setup

        reservations = dict()
        for address, ip in self.pool.reservations.items():
            try:
                # If we're saving a MAC_Address instance
                reservations[address.address] = ip._ip
            except AttributeError:
                # If we're trying to save something other than a MAC_Address
                continue

        data['reservations'] = reservations

        listing = list()
        for listing in self.pool.listing:
            listing.append(listing.address)
        data['listings'] = (listing, self.pool.list_mode)

        data['server_options'] = [
            list(option.pack()) for option in self.server_options.values()
        ]

        data['options'] = [
            list(option.pack()) for option in self.options.values()
        ]

        with open(self.file, 'w') as file:
            dump(data, file)

    @classmethod
    def load(cls, savefile, **kwargs):
        try:
            with open(savefile, 'r') as file:
                data = load(file)

            setup_info = data['setup_info']
            reservations = data['reservations']
            listing, list_mode = data['listings']

            server_options_bytes = b''.join([bytes(option_data) for option_data in data['server_options']])
            server_options = Options.BaseOption.unpack(server_options_bytes)

            options_bytes = b''.join([bytes(option_data) for option_data in data['options']])
            options = Options.BaseOption.unpack(options_bytes)

            setup_info.update(kwargs)

            out = cls(savefile=savefile, **setup_info)

            for mac, ip in reservations.items():
                out.reserve(mac, ip)

            for mac in listing:
                out.add_listing(mac)

            out.pool.list_mode = list_mode

            for option in server_options:
                out.register_server_option(option)

            for option in options:
                out.register(option)

            return out

        except FileNotFoundError:
            return cls(**kwargs)

        except Exception as e:
            print(f'{e.__class__.__name__}: {e}')

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.shutdown()

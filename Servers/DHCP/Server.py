from configparser import ConfigParser
from ipaddress import ip_address
from json import load, dump
from socket import IPPROTO_UDP
from socketserver import BaseRequestHandler

from RawPacket import Ethernet, IPv4, UDP, MAC_Address
from Servers import RawServer
from Servers.DHCP import Options, Packet
from Servers.DHCP.Classes import Pool, GarbageCollector, Record

defaults = ConfigParser()
defaults.read(r'Servers/DHCP/config.ini')


class DHCPHandler(BaseRequestHandler):
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

        client_hostname = ''
        offer_ip = None

        for option in self.packet.options:
            if option.code == Options.ParameterRequestList.code:
                for code in option.data:
                    if code in self.server.options:
                        offer.options.append(self.server.options[code])

            if option.code == Options.RequestedIP.code:
                offer_ip = option.data

            if option.code == Options.HostName.code:
                client_hostname = option.data.encode(errors='ignore')

        offer.options.append(Options.End())

        # Record we'll use to reference client.
        offer_record = self.server.pool.get_ip(client_hostname, self.packet.chaddr, offer_ip)


        offer.siaddr = self.server.server_ip
        offer.yiaddr = offer_record.ip

        # If we're offering a valid IP (EG not None), proceed with offer
        self.server.register_offer(offer_record, offer.xid)
        return offer

    def handle_req(self):

        # Building DHCP acknowledge Packet

        ack = Packet.DHCPPacket(op=2, xid=self.packet.xid, _chaddr=self.eth.source,
                                broadcast=self.packet.broadcast or self.server.broadcast)
        ack.options.append(Options.DHCPMessageType(5))
        ack.options.extend(self.server.server_options.values())

        offer_record = self.server.offers[(ack.chaddr, ack.xid)]
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
                offer_record.name = option.data.encode(errors='ignore')

            if option.code == Options.DHCPServerID.code:
                if option.data != self.server.server_ip:
                    # If the client is trying to request from a server other than us.
                    return None

        ack.options.append(Options.End())

        if req_ip and req_ip != offer_record.ip:
            self.server.pool.add_ip(offer_record.ip)
            offer_record = self.server.pool.get_ip(offer_record.name, offer_record.mac, req_ip)

        ack.siaddr = self.server.server_ip
        ack.yiaddr = offer_record.ip

        self.server.register_client(offer_record)
        return ack

    def handle_decline(self):
        pass

    def handle_release(self):
        pass

    def handle_inform(self):
        pass


class DHCPServer(RawServer):
    clients = list()  # Keys will be a tuple of (MAC address, ClientID). ClientID defaults to b''
    offers = dict()  # Keys will be a tuple of (MAC Address, XID).

    server_options = dict()
    options = dict()  # Keys will be an int being the code of the option.

    def __init__(self, interface=defaults.get('optional', 'interface'), **kwargs):
        RawServer.__init__(self, interface, DHCPHandler)

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

    def register_offer(self, record: Record, xid: bytes):
        self.offers[(record.mac, xid)] = record
        self.gb.insert(self.offer_hold_time, self.release_offer, record.mac, xid)

    def release_offer(self, mac: MAC_Address, xid: bytes):
        # clear short term reservation of ip address.
        try:
            self.pool.add_ip(self.offers.pop((mac, xid)).ip)
        except KeyError:
            pass

    def register_client(self, record: Record):
        self.release_client(record)  # Release previously given IP client may have for reuse
        self.clients.append(record)
        self.gb.insert(self.get(Options.IPLeaseTime), self.release_client, record)

    def release_client(self, record: Record):
        # clear long term reservation of ip address.
        try:
            self.clients.remove(record)
            self.pool.add_ip(record.ip)
        except ValueError:
            pass

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

    def reserve(self, name: str, mac: str, ip: str):
        record = Record(name, MAC_Address(mac), ip_address(ip))

        self.pool.reserve(record)

    def unreserve(self, mac: str):
        mac = MAC_Address(mac)
        self.pool.unreserve(mac)

    def add_listing(self, mac: str):
        mac = MAC_Address(mac)
        self.pool.add_listing(mac)

    def remove_listing(self, mac: str):
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
    def load(cls, savefile: str, **kwargs):
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

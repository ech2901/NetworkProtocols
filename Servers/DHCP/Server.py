from configparser import ConfigParser
from ipaddress import ip_address
from socket import IPPROTO_UDP
from socketserver import BaseRequestHandler

from RawPacket import Ethernet, IPv4, UDP, MAC_Address
from Servers import RawServer
from Servers.DHCP import Options, Packet
from Servers.DHCP.Classes import GarbageCollector, Pool

config = ConfigParser()
config.read(r'Servers/DHCP/config.ini')
defaults = config['DEFAULT']


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

            packet, hostname = self.build_packet()

            if packet:

                if Options.DHCPMessageType(1) in self.packet.options:
                    self.server.register_offer(packet, hostname)
                elif Options.DHCPMessageType(3) in self.packet.options:
                    self.server.register_client(packet, hostname)


                # Building UDP Packet
                udp = UDP(self.server.server_port, self.server.client_port, packet.build())

                # Building IP packet
                ip = IPv4(self.server.server_ip, ip_address('255.255.255.255'), udp)

                if self.packet.hops:
                    packet.hops = self.packet.hops
                    packet.giaddr = self.packet.giaddr
                    ip.destination = self.packet.giaddr

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

    def build_packet(self):

        packet = Packet.DHCPPacket(
            op=2,
            xid=self.packet.xid,
            _chaddr=self.eth.source,
            broadcast=self.packet.broadcast or self.server.broadcast
        )

        if Options.DHCPMessageType(1) in self.packet.options:
            packet.options.append(Options.DHCPMessageType(2))
            client_hostname = b''
            client_ip = self.server.pool.get_ip(packet.chaddr)

        elif Options.DHCPMessageType(3) in self.packet.options:
            packet.options.append(Options.DHCPMessageType(5))
            try:
                client_hostname, client_ip = self.server.offers[(self.packet.chaddr, self.packet.xid)]
            except KeyError:
                return

        else:
            return

        for option in self.packet.options:
            if option.code == Options.DHCPServerID.code:
                if option.data != self.server.server_ip:
                    # If the client is trying to request from a server other than us.
                    return None

            elif option.code == Options.RequestedIP.code:
                if option.data != client_ip:
                    self.server.pool.add_ip(client_ip)
                    client_ip = self.server.pool.get_ip(packet.chaddr, option.data)

            elif option.code == Options.HostName.code:
                client_hostname = option.data

            elif option.code == Options.ParameterRequestList.code:
                for code in option.data:
                    try:
                        packet.options.append(self.server.options[code])
                    except KeyError:
                        # If we don't have the option as part of the server, continue without issue.
                        pass

        for required in self.server.required:
            try:
                option = self.server.options[required]
            except KeyError:
                # Should not !-!-! ever !-!-! happen
                print('Error: Requested Required option not available.')
                print(f'Required Option Requested: {required}')
            else:
                # If no error thrown do this.
                if option in packet.options:
                    continue
                packet.options.append(option)

        packet.options.append(Options.End())

        if client_ip:
            packet.siaddr = self.server.server_ip
            packet.yiaddr = client_ip

            return packet, client_hostname




class DHCPServer(RawServer):

    clients = dict()  # Keys will be a tuple of (MAC address, ClientID). ClientID defaults to b''
    offers = dict()  # Keys will be a tuple of (MAC Address, XID).

    options = dict()  # Keys will be an int being the code of the option.
    required = list()

    def __init__(self, **kwargs):
        defaults.update(kwargs)

        RawServer.__init__(self, defaults.get('interface'), DHCPHandler)

        # Savefile
        self.file = defaults.get('optional', 'savefile')

        # Server addressing information
        self.server_ip = defaults.get('ip addresses', 'server_ip')
        self.server_port = defaults.getint('numbers', 'server_port')
        self.client_port = defaults.getint('numbers', 'client_port')
        self.broadcast = defaults.getboolean('optional', 'broadcast')

        # Server IP pool setup
        self.pool = Pool(
            ip_address(
                defaults.get('ip addresses', 'network')
            ),
            ip_address(
                defaults.get('ip addresses', 'mask')
            )
        )

        self.register(
            Options.Subnet(
                self.pool.netmask
            ),
            required=True
        )

        self.register(
            Options.BroadcastAddress(
                self.pool.broadcast
            ),
            required=True
        )

        self.register(
            Options.DHCPServerID(
                self.server_ip
            ),
            required=True
        )

        # Timing information
        self.offer_hold_time = defaults.getint('numbers', 'offer_hold_time')
        # Default lease time of 8 days
        self.register(
            Options.IPLeaseTime(
                defaults.getint('numbers', 'ipleasetime')
            ),
            required=True
        )

        # Default renew time of 4 days
        self.register(
            Options.RenewalT1(
                defaults.getint('numbers', 'renewalt1')
            ),
            required=True
        )

        # Default rebind time of 3 days
        self.register(
            Options.RenewalT2(
                defaults.getint('numbers', 'renewalt2')
            ),
            required=True
        )

        self.gb = GarbageCollector()

    @property
    def required_options(self):
        return [self.get(i) for i in self.required]

    def register_offer(self, packet, hostname, ):
        self.offers[(packet.chaddr, packet.xid)] = (hostname, packet.yiaddr)
        self.gb.insert(self.offer_hold_time, self.release_offer, packet.yiaddr, packet.xid)

    def release_offer(self, address, xid):
        # clear short term reservation of ip address.
        if (address, xid) in self.offers:
            self.pool.add_ip(self.offers.pop((address, xid))[0])

    def register_client(self, packet, clientid):
        self.release_client(packet.chaddr, clientid)  # Release previously given IP client may have for reuse
        self.clients[(packet.chaddr, clientid)] = packet.yiaddr
        self.gb.insert(self.get(Options.IPLeaseTime), self.release_client, packet.chaddr, clientid, packet.yiaddr)

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

    def register(self, option, required=False):
        # These options are included in server DHCP packets by request of client
        self.options[option.code] = option
        if required:
            self.required.append(option.code)

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
        pass

    @classmethod
    def load(cls, savefile, **kwargs):
        pass

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.shutdown()

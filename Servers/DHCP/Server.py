from ipaddress import ip_network, ip_address
from sched import scheduler
from socket import IPPROTO_UDP
from socketserver import BaseRequestHandler
from threading import Thread

from RawPacket import Ethernet, IPv4, UDP
from Servers import RawServer
from Servers.DHCP import Options, Packet


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

                udp = UDP(self.server.server_ip, self.udp.source, packet.build())

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

                eth.calc_checksum()
                self.request[1].send(eth.build())


    def handle_disco(self):
        # Building DHCP offer Packet

        offer = Packet.DHCPPacket(op=2, xid=self.packet.xid, _chaddr=self.eth.source, broadcast=self.packet.broadcast)
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
                if (ip_address(option.data) in self.server.hosts):
                    offer_ip = option.data

            if (option.code == Options.HostName.code):
                client_hostname = option.data

        offer.options.append(Options.End())

        offer.siaddr = self.server.server_ip
        offer.yiaddr = self.server.get_host_addr(offer_ip)

        self.server.gb.insert(60, self.server.release_offer, offer.chaddr, offer.xid)
        self.server.register_offer(offer.chaddr, offer.xid, offer.yiaddr, client_hostname)

        return offer


    def handle_req(self):

        # Building DHCP acknowledge Packet

        ack = Packet.DHCPPacket(op=2, xid=self.packet.xid, _chaddr=self.eth.source, broadcast=self.packet.broadcast)
        ack.options.append(Options.DHCPMessageType(5))
        ack.options.extend(self.server.server_options.values())

        offer_ip, client_hostname = self.server.offers[(ack.chaddr, ack.xid)]


        for option in self.packet.options:
            if (option.code == Options.ParameterRequestList.code):
                for code in option.data:
                    if code in self.server.options:
                        ack.options.append(self.server.options[code])

            if (option.code == Options.RequestedIP.code):
                if (ip_address(option.data) in self.server.hosts):
                    offer_ip = option.data

            if (option.code == Options.HostName.code):
                client_hostname = option.data

        ack.options.append(Options.End())

        ack.siaddr = self.server.server_ip
        ack.yiaddr = self.server.get_host_addr(offer_ip)
        self.server.gb.insert(self.server.get(Options.IPLeaseTime.code).data,
                              self.server.release_client, ack.chaddr, client_hostname)
        self.server.register_client(ack.chaddr, client_hostname, ack.yiaddr)

        return ack

    def handle_decline(self):
        pass

    def handle_release(self):
        pass

    def handle_inform(self):
        pass


class DHCPServer(RawServer):
    server_port = 67
    client_port = 68

    clients = dict()  # Keys will be a tuple of (MAC address, ClientID). ClientID defaults to b''
    offers = dict()  # Keys will be a tuple of (XID, MAC Address).

    server_options = dict()
    options = dict()  # Keys will be an int being the code of the option.

    def __init__(self, interface: str = 'eth0', **kwargs):
        RawServer.__init__(self, interface, DHCPHandler)

        self.pool = ip_network((kwargs.get('network', '192.168.0.0'), kwargs.get('mask', '255.255.255.0')))
        self.hosts = list(self.pool.hosts())  # used to better track used addresses to prevent race conditions.

        if ('server_ip' in kwargs):
            self.server_ip = self.get_host_addr(ip_address(kwargs['server_ip']))
        else:
            self.server_ip = self.get_host_addr()

        self.register_server_option(Options.Subnet(self.pool.netmask))
        self.register_server_option(Options.BroadcastAddress(self.broadcast))
        self.register_server_option(Options.DHCPServerID(self.server_ip))

        # Default lease time of 8 days
        self.register_server_option(Options.IPLeaseTime(60 * 60 * 24 * 8))

        # Default renew time of 4 days
        self.register_server_option(Options.RenewalT1(60 * 60 * 24 * 4))

        # Default rebind time of 3 days
        self.register_server_option(Options.RenewalT2(60 * 60 * 24 * 3))

        self.gb = GarbageCollector()

    @property
    def broadcast(self):
        return self.pool.broadcast_address

    @property
    def network(self):
        return self.pool.network_address

    def get_host_addr(self, requested_ip=None):
        try:
            # Try to remove object from self.hosts
            self.hosts.remove(requested_ip)
            return requested_ip

        except ValueError:
            # ValueError will be raised if trying to remove
            # item from self.hosts that does not exists.
            try:
                return self.hosts.pop(0)

            except IndexError:
                # If the number of available addresses gets exhausted return None
                return None

    def register_offer(self, address, xid, offer_ip, client_hostname):
        self.offers[(address, xid)] = (offer_ip, client_hostname)

    def release_offer(self, address, xid):
        # clear short term reservation of ip address.
        if ((address, xid) in self.offers):
            self.hosts.append(self.offers.pop((address, xid)))

    def register_client(self, address, clientid, client_ip):
        self.clients[(address, clientid)] = client_ip

    def release_client(self, address, clientid):
        # clear long term reservation of ip address.
        if ((address, clientid) in self.clients):
            self.hosts.append(self.clients.pop((address, clientid))[0])

    def register_server_option(self, option):
        self.server_options[option.code] = option

    def register(self, option):
        self.options[option.code] = option

    def get(self, option):
        if (option.code in self.options):
            return self.options[option.code]

    def start(self):
        self.gb.start()
        super().start()

    def shutdown(self):
        self.gb.shutdown()
        super().shutdown()

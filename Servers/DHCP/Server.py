from ipaddress import ip_network, ip_address
from sched import scheduler
from socket import IPPROTO_UDP
from socketserver import BaseRequestHandler
from threading import Thread

from RawPacket import Ethernet
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
                return

        self.is_dhcp = False

    def handle(self):
        if(self.is_dhcp):
            self.packet = Packet.DHCPPacket.disassemble(self.udp.payload)

            self.eth.swap()
            self.eth.source = self.server.server_address[-1]
            self.ip.source = self.server.server_ip

            if (self.packet.ciaddr._ip):
                # If client has a put a reachable IP address in this field
                # Send to this specific address
                self.ip.destination = self.packet.ciaddr

            if self.packet.hops:
                self.ip.destination = self.packet.giaddr

            if (Options.DHCPMessageType(1) in self.packet.options):
                self.handle_disco()
            elif (Options.DHCPMessageType(3) in self.packet.options):
                self.handle_req()
            elif (Options.DHCPMessageType(4) in self.packet.options):
                self.handle_decline()
            elif (Options.DHCPMessageType(7) in self.packet.options):
                self.handle_release()
            elif (Options.DHCPMessageType(8) in self.packet.options):
                self.handle_inform()

            if (self.send_packet):
                self.udp.payload = self.packet.build()
                self.ip.payload = self.udp
                self.eth.payload = self.ip
                self.eth.calc_checksum()
                self.request[1].send(self.eth.build())

    def handle_disco(self):
        return_options = list()
        return_options.append(Options.DHCPMessageType(2))

        self.packet.op = 2

        self.packet.siaddr = self.server.server_ip

        temp_yiaddr = self.server.get_host_addr()

        temp_client_id = b''

        for option in self.packet.options:
            if (option.code == Options.ParameterRequestList.code):
                for requested_option in option.data:
                    if (requested_option in self.server.options):
                        return_options.append(self.server.options[requested_option])
            elif (option.code == Options.RequestedIP.code):
                if (option.data in self.server.hosts):
                    self.server.hosts.append(temp_yiaddr)
                    self.server.hosts.remove(option.data)
                    temp_yiaddr = option.data
            elif (option.code == Options.ClientID.code):
                temp_client_id = option.data

        self.packet.yiaddr = temp_yiaddr
        self.server.offers[(self.packet.xid, self.packet.chaddr)] = (self.packet.yiaddr, temp_client_id)

        return_options.append(Options.End())

        self.packet.options = return_options
        self.send_packet = True
        self.server.gb.insert(60, self.server.clear_reservation, self.packet.xid, self.packet.chaddr)

    def handle_req(self):

        return_options = list()
        return_options.append(Options.DHCPMessageType(2))

        self.packet.op = 2

        self.packet.siaddr = self.server.server_ip

        temp_yiaddr, temp_client_id = self.server.offers[(self.packet.xid, self.packet.chaddr)]

        for option in self.packet.options:
            if (option.code == Options.ParameterRequestList.code):
                for requested_option in option.data:
                    if (requested_option in self.server.options):
                        return_options.append(self.server.options[requested_option])
            elif (option.code == Options.RequestedIP.code):
                if (option.data in self.server.hosts):
                    self.server.hosts.append(temp_yiaddr)
                    self.server.offers.remove((self.packet.xid, temp_client_id))
                    temp_yiaddr = option.data
            elif (option.code == Options.ClientID.code):
                temp_client_id = option.data

        self.packet.yiaddr = temp_yiaddr

        return_options.append(Options.End())

        self.packet.options = return_options
        self.send_packet = True

        self.server.clients[(self.packet.chaddr, temp_client_id)] = self.packet.yiaddr
        self.server.gb.insert(self.server.get(Options.IPLeaseTime).data,
                              self.server.release_reservation, self.packet.chaddr,
                              temp_client_id
                              )

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
    options = dict()  # Keys will be an int being the code of the option.

    def __init__(self, interface: str = 'eth0', **kwargs):
        RawServer.__init__(self, interface, DHCPHandler)

        self.pool = ip_network((kwargs.get('network', '192.168.0.0'), kwargs.get('mask', '255.255.255.0')))
        self.hosts = list(self.pool.hosts())  # used to better track used addresses to prevent race conditions.

        self.server_ip = ip_address(kwargs.get('server_ip', self.get_host_addr()))

        self.register(Options.Subnet(self.pool.netmask))
        self.register(Options.BroadcastAddress(self.broadcast))

        self.gb = GarbageCollector()

    @property
    def broadcast(self):
        return self.pool.broadcast_address

    @property
    def network(self):
        return self.pool.network_address

    def get_host_addr(self):
        if(len(self.hosts)):
            return self.hosts.pop(0)
        return None  # If the number of available addresses gets exhausted return None

    def clear_reservation(self, xid, address):
        # clear short term reservation of ip address.
        if ((xid, address) in self.offers):
            self.hosts.append(self.offers.pop((xid, address)))

    def release_client(self, address, clientid):
        # clear long term reservation of ip address.
        if ((address, clientid) in self.clients):
            self.hosts.append(self.clients.pop((address, clientid))[0])

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

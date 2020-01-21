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
                return

        self.is_dhcp = False
        self.send_packet = False

    def handle(self):
        if(self.is_dhcp):
            self.packet = Packet.DHCPPacket.disassemble(self.udp.payload)

            self.eth.swap()
            self.eth.source = self.server.server_address[-1]
            self.ip.source = self.server.server_ip

            if (self.packet.op == 1):
                self.handle_disco()
            elif (self.packet.op == 3):
                self.handle_req()
            elif (self.packet.op == 4):
                self.handle_decline()
            elif (self.packet.op == 7):
                self.handle_release()
            elif (self.packet.op == 8):
                self.handle_inform()

            if (self.send_packet):
                self.udp.payload = self.packet
                self.ip.payload = self.udp
                self.eth.payload = self.ip
                self.eth.calc_checksum()
                self.request[1].send(self.eth.build())

    def handle_disco(self):
        pass

    def handle_req(self):
        pass

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
    offers = dict()  # Keys will be a tuple of (XID, MAC Address)
    options = dict()  # Keys will be an int being the code of the option.

    def __init__(self, interface: str = 'eth0', **kwargs):
        RawServer.__init__(self, interface, DHCPHandler)

        self.pool = ip_network((kwargs.get('network', '192.168.0.0'), kwargs.get('mask', '255.255.255.0')))
        self.hosts = self.pool.hosts()  # used to better track used addresses to prevent race conditions.

        self.server_ip = ip_address(kwargs.get('server_ip', self.get_host_addr()))

        self.register(Options.BroadcastAddress(self.broadcast))


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
        self.hosts.append(self.offers.pop((xid, address)))

    def release_client(self, address, clientid):
        # clear long term reservation of ip address.
        self.hosts.append(self.offers.pop((address, clientid)))

    def register(self, option):
        self.options[option.code] = option

from ipaddress import ip_network
from socket import IPPROTO_UDP
from socketserver import BaseRequestHandler
from struct import unpack

from RawPacket import Ethernet, MAC_Address
from Servers import RawServer
from Servers.DHCP import Options

BROADCAST_MAC = MAC_Address('FF:FF:FF:FF:FF:FF')



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

    def handle(self):
        if(self.is_dhcp):
            keys = ('op', 'htype', 'hlen', 'hops', 'xid', 'secs', 'flags', 'ciaddr',
                    'yiaddr', 'siaddr', 'giaddr', 'chaddr')
            values = unpack('! 4B L 2H 4L 6s 10x', self.udp['payload'][:44])

            self.dhcp_packet = dict()
            for key, value in zip(keys, values):
                self.dhcp_packet[key] = value


            if(self.dhcp_packet['op'] == 2):
                # Only handle DHCP request packets, not reply messages
                return

            checkup = 44
            while(True):
                if(self.udp['payload'][checkup:checkup+4] == b'\x63\x82\x53\x63'):
                    # check for magic cookie to notify start of options.
                    self.dhcp_packet['options'] = Options.unpack_options(self.udp['payload'][checkup+4:])
                    break
                elif(checkup == 44):
                    # If sname isn't being used for option overload
                    self.dhcp_packet['sname'] = unpack('! 64s', self.udp['payload'][44:108])
                    checkup = 108
                elif(checkup == 108):
                    # If file isn't being used for option overload
                    self.dhcp_packet['file'] = unpack('! 128s', self.udp['payload'][108:236])
                    checkup = 236

    def handle_discover(self):
        pass

    def handle_request(self):
        pass


class DHCPServer(RawServer):
    server_port = 67
    client_port = 68

    def __init__(self, interface: str = 'eth0', **kwargs):
        RawServer.__init__(self, interface, DHCPHandler)

        self.pool = ip_network((kwargs.get('network', '192.168.0.0'), kwargs.get('mask', '255.255.255.0')))
        self.hosts = self.pool.hosts()  # used to better track used addresses to prevent race conditions.


    def verify_request(self, request, client_address):
        """
        Verify the request is for our MAC address or a broadcast MAC address
        Return True if we should proceed with this request.
        """

        is_broadcast = request[1][-1] == BROADCAST_MAC
        is_to_interface = request[1][-1] == self.server_address[-1]

        return (is_broadcast or is_to_interface)


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








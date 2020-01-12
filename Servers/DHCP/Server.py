from socketserver import BaseRequestHandler

from Servers import RawServer
from RawPacket import disassemble_ethernet, disassemble_ipv4, disassemble_udp


class DHCPHandler(BaseRequestHandler):
    def setup(self):
        packet = self.request[0]

        self.ethernet = disassemble_ethernet(packet)
        if(self.ethernet['type'] == 0x0800):
            self.ip = disassemble_ipv4(self.ethernet['payload'])
            if(self.ip['protocol'] == 17):
                self.udp = disassemble_udp(self.ip['payload'])
                if(self.udp['destination'] == self.server.server_port):
                    self.is_dhcp = True
                    return

        self.is_dhcp = False



    def handle(self):
        if(self.is_dhcp):
            print('DHCP packet recieved.')
        else:
            print('Non-DHCP packet recieved.')










class DHCPServer(RawServer):
    server_port = 67
    client_port = 68

    def __init__(self, interface):
        RawServer.__init__(self, interface, DHCPHandler)

    def verify_request(self, request, client_address):
        """
        Verify the request is for our MAC address or a broadcast MAC address
        Return True if we should proceed with this request.
        """

        is_broadcast = request[:6] == b'\xff'*6
        is_to_interface = request[:6] == self.server_address[-1]

        return (is_broadcast or is_to_interface)






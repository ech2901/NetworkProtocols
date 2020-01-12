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
                    return
        print('None DHCP packet recieved')
        raise ValueError('Packet not a DHCP packet')

    def handle(self):
        print(self.udp['payload'])










class DHCPServer(RawServer):
    server_port = 67
    client_port = 68

    def verify_request(self, request, client_address):
        """
        Verify the request is for our MAC address or a broadcast MAC address
        Return True if we should proceed with this request.
        """

        return (request[:6] == b'\xff'*6 or request[:6] == self.server_address[-1])






from Servers import UDPServer
from Servers.DHCP.Server import Packet
from socketserver import BaseRequestHandler

from Clients.DHCP import dhcp_client

class PacketSniffer(BaseRequestHandler):
    def setup(self):
        self.packet = Packet.from_bytes(self.request[0])

    def handle(self):
        print(str(self.packet.data)[1:-1].replace(', ', '\n'))
        for option in self.packet.options:
            print(option)

        print()


class ClientSniffer(UDPServer):
    def __init__(self):
        UDPServer.__init__(self, '', 67, PacketSniffer)


if __name__ == '__main__':
    server = ClientSniffer()
    server.start()

    while True:
        pass


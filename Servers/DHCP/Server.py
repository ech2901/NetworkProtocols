from socketserver import BaseRequestHandler
from uuid import getnode
from struct import pack, unpack

from socket import socket, AF_INET, SOCK_DGRAM, SOL_SOCKET, SO_BROADCAST, IPPROTO_IP, SO_REUSEADDR
from ipaddress import ip_address, ip_network

print('test1')
from Servers.DHCP.Options import OptionCodes
print('test2')
from Servers import UDPServer
print('test3')


class Packet(object):
    def __init__(self, **kwargs):
        self.data = kwargs

    def setopt(self, key, value):
        self.data[key] = value

    @classmethod
    def from_bytes(cls, data):
        keys = (
                'op', 'htype', 'hlen', 'hops', 'xid', 'secs', 'flags',
                'ciaddr','yiaddr','siaddr', 'giaddr', 'chaddr', 'cookie'
                )
        values = unpack('! 4B I 2H 4I 6s 10x 64x 128x L', data[:240])

        data_out = dict()
        for key, value in zip(keys, values):
            data_out[key] = value

        if len(data) > 240:
            data_out['options'] = data[240:]


        return cls(**data_out)

    def to_bytes(self):
        return pack(
                    '! 4B I 2H 4I 6s 10x 64x 128x L',
                    self.data.get('op', 1),
                    self.data.get('htype', 1),
                    self.data.get('hlen', 6),
                    self.data.get('hops', 0),
                    self.data.get('xid', 0),
                    self.data.get('secs', 0),
                    self.data.get('flags', 1 << 15),
                    self.data.get('ciaddr', 0),
                    self.data.get('yiaddr', 0),
                    self.data.get('siaddr', 0),
                    self.data.get('giaddr', 0),
                    self.data.get('chaddr', getnode().to_bytes(6, 'big')),
                    self.data.get('cookie', 0x63825363),
                    ) + self.data.get('options', b'')

    @property
    def xid(self):
        return self.data.get('xid', 0)

    @property
    def mac(self):
        mac = self.data.get('chaddr', getnode().to_bytes(6, 'big'))
        out = ':'.join([hex(i)[2:].upper() for i in mac])
        return out

    @property
    def client_ip(self):
        return ip_address(self.data.get('ciaddr', 0)).exploded

    @property
    def given_ip(self):
        return ip_address(self.data.get('yiaddr', 0)).exploded

    @property
    def server_ip(self):
        return ip_address(self.data.get('siaddr', 0)).exploded

    @property
    def gateway_ip(self):
        return ip_address(self.data.get('giaddr', 0)).exploded

    @property
    def options(self):
        out = list()
        data = self.data.get('options', b'')

        while data:
            option, data = OptionCodes.from_bytes(data)
            out.append(option)

        return out

    def __len__(self):
        return len(self.to_bytes())

    def __str__(self):
        out = str(self.data)[1:-1].replace(', ', '\n')
        for option in self.options:
            out = f'{out}\n\n{option}'

        return out


class DHCPCommandHandler(BaseRequestHandler):
    def setup(self):
        self.packet = Packet.from_bytes(self.request[0])
        self.sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP)
        self.sock.setsockopt(SOL_SOCKET, SO_BROADCAST, 1)

    def handle(self):
        print(f'Mac Address: {self.packet.mac}')
        print(f'Options: {self.packet.options}')

        if OptionCodes.DHCP_MESSAGE_TYPE(1) in self.packet.options:

            options_list = [
                OptionCodes.DHCP_MESSAGE_TYPE(2),
                OptionCodes.SUBNET(self.server.network.netmask),
                OptionCodes.SERVER_ID(self.server.address.compressed),
                OptionCodes.ROUTER('192.168.0.1'),
                OptionCodes.DNS_SERVER('8.8.8.8'),
                OptionCodes.DOMAIN_NAME('Home Network'),
                OptionCodes.INTERFACE_MTU(1500),
                OptionCodes.BROADCAST_ADDRESS(str(self.server.network.broadcast_address)),
                OptionCodes.IP_LEASE_TIME(86400),
                OptionCodes.END()
            ]

            options = b''
            for option in options_list:
                options = options + option.bytes

            address = ip_address('192.168.0.250')

            self.packet.setopt('op', 2)
            self.packet.setopt('yiaddr', address._ip)
            self.packet.setopt('siaddr', self.server.address._ip)
            self.packet.setopt('options', options)

            resp = Packet(op=2, xid=self.packet.xid, yiaddr=address._ip, siaddr=self.server.address._ip,
                          options=options)
            # resp = self.packet

            self.server.offers[(self.packet.xid, self.packet.mac)] = address


        elif OptionCodes.DHCP_MESSAGE_TYPE(3) in self.packet.options:

            options_list = [
                OptionCodes.DHCP_MESSAGE_TYPE(4),
                OptionCodes.SUBNET(self.server.network.netmask),
                OptionCodes.SERVER_ID(self.server.address.compressed),
                OptionCodes.ROUTER('192.168.0.1'),
                OptionCodes.DNS_SERVER('8.8.8.8'),
                OptionCodes.DOMAIN_NAME('Home Network'),
                OptionCodes.INTERFACE_MTU(1500),
                OptionCodes.BROADCAST_ADDRESS(str(self.server.network.broadcast_address)),
                OptionCodes.IP_LEASE_TIME(86400),
                OptionCodes.END()
            ]

            options = b''
            for option in options_list:
                options = options + option.bytes

            address = ip_address('192.168.0.250')
            resp = Packet(op=4, yiaddr=address._ip, siaddr=self.server.address._ip, options=options)

        else:
            resp = Packet()

        self.client_address = ('255.255.255.255', self.client_address[1])

        print(self.client_address)
        self.server.socket.sendto(resp.to_bytes(), self.client_address)


    def finish(self):
        self.sock.close()



class DHCPCommandServer(UDPServer):
    def __init__(self, server_ip, ip_addr='192.168.0.0', mask=24):
        UDPServer.__init__(self, '', 67, DHCPCommandHandler)
        self.socket.setsockopt(SOL_SOCKET, SO_BROADCAST, 1)

        self.network = ip_network((ip_addr, mask))
        self.address = ip_address(server_ip)
        assert self.address in self.network

        self.offers = dict()
        self.assigned = list()




if __name__ == '__main__':
    print('Server ready.')
    #server = DHCPCommandServer('192.168.0.200', '192.168.0.0')
    print('Server started.')
    #server.start()
    input('Press enter to stop.\n')
    #server.shutdown()
    print('Server stopped.')
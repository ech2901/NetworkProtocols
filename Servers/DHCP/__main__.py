import argparse
from configparser import ConfigParser
from ipaddress import ip_address
from socket import socket, SOCK_DGRAM, AF_INET

import Options
from Server import DHCPServer

config = ConfigParser()
config.read(r'Servers/DHCP/config.ini')

parser = argparse.ArgumentParser()
parser.add_argument('-i', '--serverip', dest='server_ip', default=config.get('DEFAULT', 'server_ip'), type=ip_address,
                    help='Assign server an IP address')

parser.add_argument('-s', '--serverport', dest='server_port', default=config.get('DEFAULT', 'server_port'), type=int,
                    help='Assign server an port')

parser.add_argument('-c', '--clientport', dest='client_port', default=config.get('DEFAULT', 'client_port'), type=int,
                    help='Assign client port')

parser.add_argument('-n', '--network', default=config.get('DEFAULT', 'network'), type=ip_address,
                    help='Assign network')

parser.add_argument('-m', '--mask', default=config.get('DEFAULT', 'mask'), type=ip_address,
                    help='Assign mask')

parser.add_argument('-b', '--broadcast', default=config.getboolean('DEFAULT', 'broadcast'), action='store_true',
                    help='Have server broadcast responses')

if config['DEFAULT']['routers']:
    config_routers = [ip_address(addr) for addr in config.get('DEFAULT', 'routers').split(' ', -1)]
else:
    config_routers = []

parser.add_argument('-r', '--routers', nargs='*', default=config_routers,
                    type=ip_address, help='Assign list of routers')

if config['DEFAULT']['dnsservers']:
    config_dns = [ip_address(addr) for addr in config.get('DEFAULT', 'dnsservers').split(' ', -1)]
else:
    config_dns = []

parser.add_argument('-d', '--dns', default=config_dns, nargs='*',
                    type=ip_address, help='Assign list of DNS servers')

kwargs = dict(config['DEFAULT'])
kwargs.update(vars(parser.parse_args()))

sock = socket(AF_INET, SOCK_DGRAM)
loopback_addr = ('127.0.0.1', 69)
sock.bind(loopback_addr)
sock.sendto(b'stop', loopback_addr)

with DHCPServer(**kwargs) as server:
    print('Server started.')

    if kwargs['routers']:
        server.register(Options.Router(*kwargs['routers']))
    if kwargs['dns']:
        server.register(Options.DNSServers(*kwargs['dns']))

    while True:
        data, addr = sock.recvfrom(4)
        if data == b'stop' and addr == loopback_addr:
            break

print('Server stopped')

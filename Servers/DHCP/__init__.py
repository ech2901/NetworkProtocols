from sys import platform

TESTING = True

if ('linux' not in platform and not TESTING):
    raise OSError('DHCP can only be used in a linux environment.')

from configparser import ConfigParser
from ipaddress import ip_address
from socket import socket, SOCK_DGRAM, AF_INET

import Servers.DHCP.Options
from Servers.DHCP.Server import DHCPServer

config = ConfigParser()
config.read(r'Servers/DHCP/config.ini')

if config['DEFAULT']['routers']:
    config_routers = [ip_address(addr) for addr in config.get('DEFAULT', 'routers').split(' ', -1)]
else:
    config_routers = []

if config['DEFAULT']['dnsservers']:
    config_dns = [ip_address(addr) for addr in config.get('DEFAULT', 'dnsservers').split(' ', -1)]
else:
    config_dns = []

kwargs = dict(config['DEFAULT'])
kwargs.update(dnsservers=config_dns, routers=config_routers)

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

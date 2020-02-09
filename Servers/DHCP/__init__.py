from sys import platform

TESTING = False

if ('linux' not in platform and not TESTING):
    raise OSError('DHCP can only be used in a linux environment.')

from Servers.DHCP.Server import DHCPServer
from Servers.DHCP import Options

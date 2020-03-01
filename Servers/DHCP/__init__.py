from sys import platform

TESTING = True

if 'linux' in platform and not TESTING:
    from Servers.DHCP.Server import DHCPServer
    from Servers.DHCP import Options


elif TESTING:
    pass

else:
    raise OSError('DHCP can only be used in a linux environment.')

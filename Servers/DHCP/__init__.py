from sys import platform

TESTING = True

if TESTING:
    pass

elif 'linux' not in platform:
    raise OSError('DHCP can only be used in a linux environment.')

else:
    from Servers.DHCP.Server import DHCPServer
    from Servers.DHCP import Options

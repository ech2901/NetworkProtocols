TESTING = True

try:
    from Servers.DHCP.Server import DHCPServer
    from Servers.DHCP import Options
except ImportError as e:
    if TESTING:
        print('Can not import properly. OS not supported.')
    else:
        print(e)

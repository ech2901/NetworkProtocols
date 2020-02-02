from sys import platform

TESTING = True

if ('linux' not in platform and not TESTING):
    raise OSError('DHCP can only be used in a linux environment.')

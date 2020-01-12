from sys import platform
if('linux' not in platform):
    raise OSError('DHCP can only be used in a linux environment.')
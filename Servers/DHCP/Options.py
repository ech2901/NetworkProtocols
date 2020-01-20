from collections import namedtuple
from dataclasses import dataclass, field
from ipaddress import ip_address, ip_interface
from struct import pack, unpack
from typing import Dict, List

Option = namedtuple('Option', ['code', 'length', 'data'])


class BaseOption(object):
    classes: Dict = dict()

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        cls.classes[cls.code.default] = cls

    def handle(self):
        pass

    @classmethod
    def unpack(cls, data: bytes):
        out = []
        option_list = list(data)

        while (len(data)):
            code = option_list.pop(0)

            if (code == 0 or code == 255):
                out.append(cls.classes.default[code]())
                continue

            length = option_list.pop(0)
            data = b''.join([option_list.pop(0) for _ in range(length)])

            if (code in cls.classes.default):
                out.append(cls.classes.default[code](data))
            else:
                out.append(cls.classes.default[-1](code, length, data))

        return out

    def pack(self):
        return pack(f'! 2B {self.length}s', self.code, self.length, self.data)


@dataclass
class UnknownOption(BaseOption):
    code: int = field(default=-1)
    length: int = field(default=0)
    data: bytes = field(default=b'')


# --------------------------------------------------
# Vendor Extension classes
#
# Most of these will be sent from the server
# exclusively in response to requests.
# --------------------------------------------------


@dataclass(init=False)
class Pad(BaseOption):
    code: int = field(default=0)
    length: int = field(default=0)
    data: bytes = field(default=b'')

    def pack(self):
        return b'\x00'


@dataclass(init=False)
class Subnet(BaseOption):
    code: int = field(default=1)
    length: int = field(default=4)
    data: ip_address = field(default=ip_address(0))

    def __init__(self, data):
        self.data = ip_address(data)

    def pack(self):
        return pack('! 2B 4s', self.code, self.length, self.data.packed)


@dataclass(init=False)
class TimeOffset(BaseOption):
    code: int = field(default=2, init=False)
    length: int = field(default=4, init=False)
    data: int

    def __init__(self, data):
        if (type(data) == int):
            self.data = data
        elif (type(data) == bytes):
            self.data = int.from_bytes(data[:4], 'big')
        else:
            raise TypeError(f'data must be of type int or bytes. Recieved a {type(data)} object instead.')

    def pack(self):
        return pack('! 2B L', self.code, self.length, self.data)


@dataclass(init=False)
class Router(BaseOption):
    code: int = field(default=3, init=False)
    length: int
    data: List

    def __init__(self, address, *addresses):
        self.data = list()

        if (type(address) == bytes):
            self.length = len(address)
            addresses = unpack(f'! {len(address) // 4}L', address)
        else:
            self.length = 4 + (len(addresses) * 4)
            self.data.append(ip_address(address))

        for addr in addresses:
            self.data.append(ip_address(addr))

    def pack(self):
        return pack('! 2B', self.code, self.length) + b''.join(map(lambda a: a.packed, self.data))


@dataclass(init=False)
class TimeServer(Router):
    code: int = field(default=4, init=False)


@dataclass(init=False)
class NameServer(Router):
    code: int = field(default=5, init=False)


@dataclass(init=False)
class DNSServer(Router):
    code: int = field(default=6, init=False)


@dataclass(init=False)
class LogServer(Router):
    code: int = field(default=7, init=False)


@dataclass(init=False)
class CookieServer(Router):
    code: int = field(default=8, init=False)


@dataclass(init=False)
class LPRServer(Router):
    code: int = field(default=9, init=False)


@dataclass(init=False)
class ImpressServer(Router):
    code: int = field(default=10, init=False)


@dataclass(init=False)
class ResourceLocationServer(Router):
    code: int = field(default=11, init=False)


@dataclass(init=False)
class HostName(BaseOption):
    code: int = field(default=12, init=False)
    length: int
    data: bytes

    def __init__(self, data):
        self.length = len(data)
        self.data = data


@dataclass(init=False)
class BootFileSize(BaseOption):
    code: int = field(default=13, init=False)
    length: int = field(default=2, init=False)
    data: int

    def __init__(self, data):
        if (type(data) == int):
            self.data = data
        elif (type(data) == bytes):
            self.data = int.from_bytes(data[:2], 'big')
        else:
            raise TypeError(f'data must be of type int or bytes. Recieved a {type(data)} object instead.')

    def pack(self):
        return pack('! 2B H', self.code, self.length, self.data)


@dataclass
class MeritDumpFile(HostName):
    code: int = field(default=14, init=False)


@dataclass
class DomainName(HostName):
    code: int = field(default=15, init=False)


@dataclass
class SwapServer(Subnet):
    code: int = field(default=16, init=False)


@dataclass
class RootPath(HostName):
    code: int = field(default=17, init=False)


@dataclass
class ExtensionsPath(HostName):
    code: int = field(default=18, init=False)


@dataclass(init=False)
class End(BaseOption):
    code: int = field(default=255)
    length: int = field(default=0)
    data: bytes = field(default=b'')

    def pack(self):
        return b'\xff'


# --------------------------------------------------
# IP Layer Parameters classes
#
# These parameters control operation of IP on a
# host as a whole.
# --------------------------------------------------

@dataclass(init=False)
class Forwarding(BaseOption):
    code: int = field(default=19)
    length: int = field(default=1)
    data: bool = field(default=False)

    def __init__(self, data):
        self.data = bool(data)

    def pack(self):
        return pack('! 2B ?', self.code, self.length, self.data)


@dataclass(init=False)
class NonlocalRouting(Forwarding):
    code: int = field(default=20)


@dataclass(init=False)
class PolicyFilter(BaseOption):
    code: int = field(default=21)
    length: int = field(default=8)
    data: List = field(default=False)

    def __init__(self, address, *addresses):
        self.data = list()

        if (type(address) == bytes):
            self.length = len(address)
            addresses = unpack(f'! {len(address) // 8}L', address)
        else:
            self.length = 8 + (len(addresses) * 8)
            self.data.append(ip_interface(address))

        for addr in addresses:
            self.data.append(ip_interface(addr))

    def pack(self):
        return pack('! 2B', self.code, self.length) + b''.join(map(lambda a: a.packed + a.netmask.packed, self.data))


@dataclass(init=False)
class MaxDatagramReassembly(BootFileSize):
    code: int = field(default=22)


@dataclass(init=False)
class DefaultTTL(BaseOption):
    code: int = field(default=23)
    length: int = field(default=1)
    data: int = field(default=255)

    def __init__(self, data):
        if (type(data) == bytes):
            self.data = data[0]
        elif (type(data) == int):
            self.data = data
        else:
            raise TypeError(f'data must be of type int or bytes. Recieved a {type(data)} object instead.')

    def pack(self):
        return pack('! 3B', self.code, self.length, self.data)


@dataclass(init=False)
class MTUTimeout(TimeOffset)
    code: int = field(default=24)


@dataclass(init=False)
class MTUTable(BaseOption):
    code: int = field(default=25)
    length: int = field(default=2)
    data: List = field(default_factory=list)

    def __init__(self, value, *values):
        self.data = list()

        if (type(value) == bytes):
            values = unpack(f'! {len(value) // 2}H', value)
        elif (type(value) == int):
            self.data.append(value)
        else:
            raise TypeError(f'data must be of type int or bytes. Recieved a {type(value)} object instead.')

        for val in values:
            self.data.append(val)

        self.length = len(self.data) * 2

    def pack(self):
        return pack(f'! 2B L {self.length // 2}H', self.code, self.length, *self.data)


# --------------------------------------------------
# IP Layer Parameters classes
#
# These parameters control operation of IP on a
# host's particular interface.
# --------------------------------------------------


@dataclass(init=False)
class InterfaceMTU(BootFileSize):
    code: int = field(default=26)


@dataclass(init=False)
class SubnetsLocal(Forwarding):
    code: int = field(default=27)


@dataclass(init=False)
class BroadcastAddress(Subnet):
    code: int = field(default=28)


@dataclass(init=False)
class PerformMaskDisco(Forwarding):
    code: int = field(default=29)


@dataclass(init=False)
class MaskSupplier(Forwarding):
    code: int = field(default=30)


@dataclass(init=False)
class PerformRouterDisco(Forwarding):
    code: int = field(default=31)


@dataclass(init=False)
class RouterSolicitaionAddress(Subnet):
    code: int = field(default=32)


@dataclass(init=False)
class StaticRoute(PolicyFilter):
    code: int = field(default=33)


# --------------------------------------------------
# Link Layer Parameters classes
#
# These parameters control operation of IP on a
# specific link layer interface
# --------------------------------------------------


@dataclass(init=False)
class TrailerEncapsulation(Forwarding):
    code: int = field(default=34)


@dataclass(init=False)
class ARPCacheTimeout(TimeOffset):
    code: int = field(default=35)


@dataclass(init=False)
class EthernetEncapsulation(Forwarding):
    code: int = field(default=36)


# --------------------------------------------------
# TCP Parameters classes
#
# These parameters control operation of IP for
# TCP stream connections
# --------------------------------------------------


@dataclass(init=False)
class TCPDefaultTTL(DefaultTTL):
    code: int = field(default=37)


@dataclass(init=False)
class TCPKeepaliveInterval(TimeOffset):
    code: int = field(default=38)


@dataclass(init=False)
class TCPKeepaliveGarbage(Forwarding):
    code: int = field(default=39)


# --------------------------------------------------
# Application and Service Parameters classes
#
# These parameters control operation of various
# applications and services.
# --------------------------------------------------


@dataclass(init=False)
class NISDomain(HostName):
    code: int = field(default=40)


@dataclass(init=False)
class NetworkInformationServers(Router):
    code: int = field(default=41)


@dataclass(init=False)
class NTPServers(Router):
    code: int = field(default=42)


@dataclass(init=False)
class VendorSpecificInformation(HostName):
    code: int = field(default=43)


@dataclass(init=False)
class NetBIOSNameServers(Router):
    code: int = field(default=44)


@dataclass(init=False)
class NetBIOSDistroServers(Router):
    code: int = field(default=45)


@dataclass(init=False)
class NetBIOSNodeType(Router):
    code: int = field(default=46)


@dataclass(init=False)
class NetBIOSScope(HostName):
    code: int = field(default=47)


@dataclass(init=False)
class XWindowFontServers(Router):
    code: int = field(default=48)


@dataclass(init=False)
class XWindowDisplayManager(Router):
    code: int = field(default=49)


@dataclass(init=False)
class NISplusDomain(Router):
    code: int = field(default=64)


@dataclass(init=False)
class NISplusServers(Router):
    code: int = field(default=65)


@dataclass(init=False)
class MovileIPHomeAgent(Router):
    code: int = field(default=68)


@dataclass(init=False)
class SMTPServers(Router):
    code: int = field(default=69)


@dataclass(init=False)
class POP3Servers(Router):
    code: int = field(default=70)


@dataclass(init=False)
class NNTPServers(Router):
    code: int = field(default=71)


@dataclass(init=False)
class DefaultWWWServers(Router):
    code: int = field(default=72)


@dataclass(init=False)
class DefaultFingerServers(Router):
    code: int = field(default=73)


@dataclass(init=False)
class DefaultIRCServers(Router):
    code: int = field(default=74)


@dataclass(init=False)
class StreetTalkServers(Router):
    code: int = field(default=75)


@dataclass(init=False)
class STDAServers(Router):
    code: int = field(default=76)


# --------------------------------------------------
# DHCP Extension classes
#
# These parameters control operation the
# DHCP protocol
# --------------------------------------------------


@dataclass(init=False)
class RequestedIP(Subnet):
    code: int = field(default=50)


@dataclass(init=False)
class IPLeaseTime(TimeOffset):
    code: int = field(default=51)


@dataclass(init=False)
class OptionOverload(DefaultTTL):
    code: int = field(default=52)


@dataclass(init=False)
class DHCPMessageType(DefaultTTL):
    code: int = field(default=53)


@dataclass(init=False)
class ServerID(TimeOffset):
    code: int = field(default=54)


@dataclass(init=False)
class ParameterRequestList(BaseOption):
    code: int = field(default=55)
    length: int = field(default=1)
    data: List = field(default_factory=list)

    def __init__(self, code, *codes):
        self.data = list()

        if (type(code) == bytes):
            codes = list(code)
        elif (type(code) == list):
            codes = code
        elif (type(code) == int):
            self.data.append(code)
        else:
            raise TypeError(f'data must be of type bytes, list, or int. Recieved a {type(code)} object instead.')

        for code in codes:
            self.data.append(code)
        self.length = len(self.data)

    def pack(self):
        return pack(f'! 2B {self.length}B', self.code, self.length, *self.data)


@dataclass(init=False)
class IPLeaseTime(TimeOffset):
    code: int = field(default=51)


@dataclass(init=False)
class IPLeaseTime(TimeOffset):
    code: int = field(default=51)


@dataclass(init=False)
class IPLeaseTime(TimeOffset):
    code: int = field(default=51)


@dataclass(init=False)
class IPLeaseTime(TimeOffset):
    code: int = field(default=51)


@dataclass(init=False)
class IPLeaseTime(TimeOffset):
    code: int = field(default=51)

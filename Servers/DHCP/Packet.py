from dataclasses import dataclass, field, InitVar
from ipaddress import ip_address
from struct import pack, unpack
from typing import List

from RawPacket import MAC_Address
from Servers.DHCP.Options import BaseOption


@dataclass
class DHCPPacket(object):
    op: int = field(default=1)
    htype: int = field(default=1)
    hlen: int = field(default=6)
    hops: int = field(default=0)
    xid: int = field(default=0)
    secs: int = field(default=0)
    broadcast: bool = field(default=False)
    ciaddr: ip_address = field(init=False)
    _ciaddr: InitVar = field(default=0)
    yiaddr: ip_address = field(init=False)
    _yiaddr: InitVar = field(default=0)
    siaddr: ip_address = field(init=False)
    _siaddr: InitVar = field(default=0)
    giaddr: ip_address = field(init=False)
    _giaddr: InitVar = field(default=0)
    chaddr: MAC_Address = field(init=False)
    _chaddr: InitVar = field(default=0)
    sname: bytes = b''
    filename: bytes = b''
    options: List = field(default_factory=list)

    def __post_init__(self, _ciaddr, _yiaddr, _siaddr, _giaddr, _chaddr):
        self.ciaddr = ip_address(_ciaddr)
        self.yiaddr = ip_address(_yiaddr)
        self.siaddr = ip_address(_siaddr)
        self.giaddr = ip_address(_giaddr)
        self.chaddr = MAC_Address(_chaddr)

    def build(self):
        return pack(f'! 4B L 2H 4L {self.hlen}s {16 - self.hlen}x', self.op, self.htype, self.hlen,
                    self.hops, self.xid, self.secs, self.broadcast << 16, self.ciaddr._ip,
                    self.yiaddr._ip, self.siaddr._ip, self.giaddr._ip, self.chaddr.packed,
                    ) + self.sname + self.filename + \
               b'\x63\x82\x53\x63' + b''.join([option.pack() for option in self.options])

    @classmethod
    def disassemble(cls, packet: bytes):
        out = dict()

        keys = ('op', 'htype', 'hlen', 'hops', 'xid', 'secs', 'broadcast', '_ciaddr',
                '_yiaddr', '_siaddr', '_giaddr', '_chaddr')
        values = unpack(f'! 4B L 2H 4L {packet[2]}s {16 - packet[2]}x', packet[:44])

        for key, value in zip(keys, values):
            if (key == 'broadcast'):
                out[key] = bool(value)
            else:
                out[key] = value

        checkup = 44
        while (True):
            if (packet[checkup:checkup + 4] == b'\x63\x82\x53\x63'):
                # check for magic cookie to notify start of options.
                out['options'] = BaseOption.unpack(packet[checkup + 4:])
                break
            elif (checkup == 44):
                # If sname isn't being used for option overload
                out['sname'] = unpack('! 64s', packet[44:108])[0]
                checkup = 108
            elif (checkup == 108):
                # If file isn't being used for option overload
                out['filename'] = unpack('! 128s', packet[108:236])[0]
                checkup = 236

        return cls(**out)

    def __len__(self):
        pass

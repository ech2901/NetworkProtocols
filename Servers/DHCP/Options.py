from collections import namedtuple

Option = namedtuple('Option', ['code', 'length', 'data'])


def unpack_options(options: bytes):
    out = []

    option_list = list(options)

    while option_list:
        code = option_list.pop(0)
        length = option_list.pop(0)
        data = b''.join([option_list.pop(0) for _ in range(length)])

        out.append(Option(code, length, data))

    return out

def pack_options(*options):
    out = b''

    for option in options:
        out = out + option.code.to_bytes(1, 'big') + option.length.to_bytes(1, 'big') + option.data

    return out



def to_complement(data: int, size: int):
    if data == 0:
        return 0

    if data < 0:
        out = -data
    else:
        compliment = 1 << size
        out = compliment - data

    return int(out)


def from_complement(data: int, size: int):
    if data == 0:
        return 0

    compliment = 1 << size
    out = compliment - data

    mask_check = compliment >> 1
    if mask_check & out:
        out = (out ^ mask_check) - mask_check

    return int(out)

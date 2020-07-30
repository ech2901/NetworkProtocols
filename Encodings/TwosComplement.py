def to_complement(data: int, size: int, *, output=int):
    if data < 0:
        return output((1 << size) + data)
    else:
        return output(data)


def from_complement(data: int, size: int):
    compliment = 1 << (size - 1)
    if data & compliment:
        return -((1 << size) - data)
    return data

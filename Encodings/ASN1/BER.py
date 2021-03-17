from dataclasses import dataclass

from .EncodingClasses import Identity, BaseFormatter, decode_bytes


@dataclass
class BER(object):
    ber_id: Identity
    ber_length: int
    ber_content: BaseFormatter

    @classmethod
    def decode(cls, data):
        output = list()
        while data:
            ber_id, ber_length, ber_content, data = decode_bytes(data)
            output.append(cls(ber_id, ber_length, ber_content))
        return output

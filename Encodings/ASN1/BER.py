from dataclasses import dataclass

from .EncodingClasses import Identity, UniversalFormatter, decode_bytes


@dataclass
class BER(object):
    ber_id: Identity
    ber_length: int
    ber_content: UniversalFormatter

    @classmethod
    def decode(cls, data):
        output = list()
        while data:
            ber_id, ber_length, ber_content, data = decode_bytes(data)
            output.append(cls(ber_id, ber_length, ber_content))
        return output

    def __repr__(self):
        return f'BER(id={repr(self.ber_id)}, length={self.ber_length}, content={self.ber_content})'

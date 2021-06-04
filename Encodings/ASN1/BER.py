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

        if len(output) == 1:
            return output[0]
        return output

    def __repr__(self):
        return f'BER(id={repr(self.ber_id)}, length={self.ber_length}, content={self.ber_content})'

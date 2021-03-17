from dataclasses import dataclass

from .EncodingClasses import Identity, BaseFormatter, IdentityTag


@dataclass
class BER(object):
    ber_id: Identity
    ber_length: int
    ber_content: BaseFormatter

    @classmethod
    def decode(cls, data):
        list_data = list(data)
        ber_id, list_data = Identity.decode(list_data)
        ber_length = list_data.pop(0)

        if ber_length == 128:
            # Indefinate form being used.
            # Should only be used for BitString, OctetString, and String types.
            ber_indef, data = cls.decode(bytes(list_data))
            ber_content = ber_indef.ber_content
            while True:
                ber_indef, data = cls.decode(data)
                if ber_indef.ber_id.id_tag == IdentityTag.EOC:
                    break
                ber_content = ber_content + ber_indef.ber_content

            return cls(ber_id, 0, ber_content), data

        elif ber_length & 128:
            # Long form of length being used.
            byte_count = ber_length & 127
            ber_length = 0
            for i in range(byte_count):
                ber_length = ber_length + list_data.pop(0)

        ber_content = bytes(list_data[:ber_length])
        list_data = list_data[ber_length:]

        if list_data:
            return cls(ber_id, ber_length, BaseFormatter.get(ber_id.id_tag, ber_content)), bytes(list_data)
        return cls(ber_id, ber_length, BaseFormatter.get(ber_id.id_tag, ber_content)), None

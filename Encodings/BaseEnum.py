from enum import IntFlag


class BaseEnum(IntFlag):
    def __repr__(self):
        return self.name.replace('_', ' ', -1)

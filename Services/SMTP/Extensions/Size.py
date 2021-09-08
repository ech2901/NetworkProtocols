from Services.SMTP.Extensions.BaseExtension import BaseExtension


class Size(BaseExtension):
    def __init__(self, size=0):
        self.size = size

    def __str__(self):
        return f'SIZE {self.size}'

    def __call__(self, handler):
        handler.send('501 Unrecognized Command.')

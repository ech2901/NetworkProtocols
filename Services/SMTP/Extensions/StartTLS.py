import ssl

from Services.SMTP.Extensions.BaseExtension import BaseExtension


class StartTLS(BaseExtension):
    def __init__(self, certfile, keyfile, password=None):
        self.context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        self.context.load_cert_chain(certfile, keyfile, password if password else input('Enter cert password: '))

    def __str__(self):
        return 'STARTTLS'

    def __call__(self, handler):
        handler.send('220 Ready to start TLS')
        handler.request = self.context.wrap_socket(handler.request, server_side=True)
        handler.setup()

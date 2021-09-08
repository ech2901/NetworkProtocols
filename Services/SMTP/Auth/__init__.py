class Auth(object):
    def __init__(self, **kwargs):
        self.auth_methods = list(
            filter(
                lambda key: f'auth_{key}' in self.__class__.__dict__ and kwargs[key],
                kwargs.keys()
            )
        )

    def __str__(self):
        return f"AUTH {' '.join(map(str.upper, self.auth_methods))}"

    def __getitem__(self, item: str):
        if item in self.auth_methods:
            return getattr(self, f'auth_{item}')
        else:
            raise KeyError(f'Auth method {item} does not exist.')

    def __call__(self, handler, method, data=None):
        print(self[method.lower()](handler, data))

    def auth_plain(self, handler, data: str):
        # https://www.rfc-editor.org/rfc/rfc4616.html

        # https://www.rfc-editor.org/rfc/rfc4422#page-17
        # Typically, mechanisms that have special characters
        # require these special characters to be escaped or encoded in the
        # character string (after encoding it in a particular Unicode
        # transformation format) using a data encoding scheme such as Base64

        from base64 import b64decode  # Only import if this function gets used at least once
        auth_data = b64decode(data).decode().split('\x00')

        # check if any values of auth_data are above limit of 255 characters per RFC
        for val in auth_data:
            if len(val) > 255:
                raise ValueError(f'Value size too large.\nMust be less than 255 characters.\nSize is {len(val)}')
        return auth_data

    def auth_login(self, handler, data: str):
        # SASL login method. Obsolete for plain method.
        # https://www.ietf.org/archive/id/draft-murchison-sasl-login-00.txt

        # Only use if legacy support is needed.

        from base64 import b64decode

        if data:
            username = b64decode(data)
        else:
            handler.send('334 VXNlcm5hbWU6')  # Send base64 encoded "Username"
            username = b64decode(handler.recv(decode=False))

        if len(username) > 64:
            raise ValueError(f'Username length must be >= 64 characters. Username length: {len(username)}')

        handler.send('334 UGFzc3dvcmQ6')  # Send base64 encoded "Password"
        password = b64decode(handler.recv(decode=False))
        handler.send('235 2.7.0 Authentication successful')
        return username, password

if __name__ == '__main__':
    print(Auth().auth_methods)  # Empty list
    print(Auth(plain=True).auth_methods)  # Only plain auth capable
    print(Auth(plain=True))
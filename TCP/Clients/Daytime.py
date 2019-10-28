from socket import socket, AF_INET, SOCK_STREAM


# This doesn't really need to be a class because the server should disconnect after sending data
def get_daytime(ip: str):
    """
    Provided an IP address, retrieve daytime info from a server

    :param ip: str
    :return: bytes
    """
    with socket(AF_INET, SOCK_STREAM) as sock:
        sock.connect((ip, 13))
        data = sock.recv(1024)
    return data

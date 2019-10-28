from socket import socket, AF_INET, SOCK_DGRAM


def echo(ip: str, message: bytes):
    """
    Send data to echo server
    Expect sent data to be returned from server

    :param ip: str
    :param message: bytes
    :return: bytes
    """
    with socket(AF_INET, SOCK_DGRAM) as sock:
        sock.sendto(message, (ip, 7))
        data = sock.recvfrom(1024)
    return data


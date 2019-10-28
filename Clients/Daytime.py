from socket import socket, AF_INET, SOCK_STREAM, SOCK_DGRAM


# This doesn't really need to be a class because the server should disconnect after sending data
def TCPDaytime(ip: str):
    """
    Provided an IP address, retrieve daytime info from a server

    :param ip: str
    :return: bytes
    """
    with socket(AF_INET, SOCK_STREAM) as sock:
        sock.connect((ip, 13))
        data = sock.recv(1024)
    return data


# This doesn't really need to be a class because the server should disconnect after sending data
def UDPDaytime(ip: str):
    """
    Provided an IP address, retrieve daytime info from a server

    :param ip: str
    :return: bytes
    """
    with socket(AF_INET, SOCK_DGRAM) as sock:
        sock.sendto(b'', (ip, 13))
        data = sock.recvfrom(1024)
    return data[0]

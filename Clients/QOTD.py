from socket import socket, AF_INET, SOCK_STREAM, SOCK_DGRAM


# This doesn't really need to be a class because the server should disconnect after sending data
def TCPQOTD(ip: str):
    """
    Provided an IP address, retrieve QOTD from a server

    :param ip: to_str
    :return: bytes
    """
    with socket(AF_INET, SOCK_STREAM) as sock:
        sock.connect((ip, 17))
        data = sock.recv(1024)
    return data


# This doesn't really need to be a class because the server should disconnect after sending data
def UDPQOTD(ip: str):
    """
    Provided an IP address, retrieve QOTD from a server

    :param ip: to_str
    :return: bytes
    """
    with socket(AF_INET, SOCK_DGRAM) as sock:
        sock.sendto(b'', (ip, 17))
        data = sock.recvfrom(1024)
    return data[0]

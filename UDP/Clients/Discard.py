from socket import socket, AF_INET, SOCK_DGRAM



def discard(ip: str, message: bytes):
    """
    Send data to the discard server
    Expect no returned information

    :param ip: str
    :param message: bytes
    :return: None
    """
    with socket(AF_INET, SOCK_DGRAM) as sock:
        sock.sendto(message, (ip, 9))


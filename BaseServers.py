from socket import htons
from socketserver import ThreadingTCPServer, ThreadingUDPServer, BaseServer, ThreadingMixIn
from sys import platform
from threading import Thread

from RawPacket import MAC_Address


# Base server that runs in it's own daemonic thread
# Allows you to operate on server while running
# IE: stop it, change a variable, etc
class BaseTCPServer(Thread, ThreadingTCPServer):
    def __init__(self, ip, port, handler):
        ThreadingTCPServer.__init__(self, (ip, port), handler)
        Thread.__init__(self, target=self.serve_forever)

        # Set the thread name to the class name
        Thread.setName(self, f'TCP-{self.__class__.__name__} Server')
        self.daemon = True

    def shutdown(self):
        """
        Safely shutdown server and thread

        :return: None
        """
        ThreadingTCPServer.shutdown(self)
        Thread.join(self)


# Base server that runs in it's own daemonic thread
# Allows you to operate on server while running
# IE: stop it, change a variable, etc
class BaseUDPServer(Thread, ThreadingUDPServer):
    def __init__(self, ip, port, handler):
        ThreadingUDPServer.__init__(self, (ip, port), handler)
        Thread.__init__(self, target=self.serve_forever)

        # Set the thread name to the class name
        Thread.setName(self, f'UDP-{self.__class__.__name__} Server')
        self.daemon = True

    def shutdown(self):
        """
        Safely shutdown server and thread

        :return: None
        """
        ThreadingUDPServer.shutdown(self)
        Thread.join(self)


if ('linux' in platform):
    import socket


    class BaseRawServer(BaseServer, ThreadingMixIn, Thread):

        address_family = socket.AF_PACKET

        socket_type = socket.SOCK_RAW

        request_queue_size = 5

        allow_reuse_address = False

        max_packet_size = 65536

        def __init__(self, interface, RequestHandlerClass, bind_and_activate=True, *, ethertype=0x0800):
            """Constructor.  May be extended, do not override."""
            BaseServer.__init__(self, (interface, 0), RequestHandlerClass)
            Thread.__init__(self, target=self.serve_forever)

            self.socket = socket.socket(self.address_family,
                                        self.socket_type,
                                        htons(ethertype))
            if bind_and_activate:
                try:
                    self.server_bind()
                    self.server_activate()
                except:
                    self.server_close()
                    raise

            # Set the thread name to the class name
            Thread.setName(self, f'{self.__class__.__name__} Server')
            self.daemon = True

        def server_bind(self):
            """Called by constructor to bind the socket.

            May be overridden.

            """
            if self.allow_reuse_address:
                self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind(self.server_address)
            server_address = self.socket.getsockname()
            self.server_address = (*server_address[:-1], MAC_Address(server_address[-1]))
            self.mac_address = self.server_address[-1]

        def server_activate(self):
            # No need to call listen() for UDP.
            pass

        def server_close(self):
            """Called to clean-up the server.

            May be overridden.

            """
            self.socket.close()

        def fileno(self):
            """Return socket file number.

            Interface required by selector.

            """
            return self.socket.fileno()

        def get_request(self):
            data, client_addr = self.socket.recvfrom(self.max_packet_size)
            client_addr = (*client_addr[:-1], MAC_Address(client_addr[-1]))
            return (data, self.socket), client_addr

        def shutdown_request(self, request):
            # No need to shutdown anything.
            self.close_request(request)

        def close_request(self, request):
            # No need to close anything.
            pass

        def shutdown(self):
            """
            Safely shutdown server and thread

            :return: None
            """

            BaseServer.shutdown(self)
            Thread.join(self)
            self.socket.close()

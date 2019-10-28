from socketserver import ThreadingTCPServer, ThreadingUDPServer
from threading import Thread


# Base server that runs in it's own daemonic thread
# Allows you to operate on server while running
# IE: stop it, change a variable, etc
class TCPServer(Thread, ThreadingTCPServer):
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
class UDPServer(Thread, ThreadingUDPServer):
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
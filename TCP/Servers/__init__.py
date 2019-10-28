from socketserver import ThreadingTCPServer
from threading import Thread

# Base server that runs in it's own daemonic thread
# Allows you to operate on server while running
# IE: stop it, change a variable, etc
class BaseThreadedServer(Thread, ThreadingTCPServer):
    def __init__(self, ip, port, handler):
        ThreadingTCPServer.__init__(self, (ip, port), handler)
        Thread.__init__(self, target=self.serve_forever)

        # Set the thread name to the class name
        Thread.setName(self, self.__class__.__name__)
        self.daemon = True

    def shutdown(self):
        """
        Safely shutdown server and thread


        :return: None
        """
        ThreadingTCPServer.shutdown(self)
        Thread.join(self)

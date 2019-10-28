from socketserver import ThreadingTCPServer
from threading import Thread


class BaseThreadedServer(Thread, ThreadingTCPServer):
    def __init__(self, ip, port, handler):
        ThreadingTCPServer.__init__(self, (ip, port), handler)
        Thread.__init__(self, target=self.serve_forever)

        Thread.setName(self, self.__class__.__name__)
        self.daemon = True

    def shutdown(self):
        ThreadingTCPServer.shutdown(self)
        Thread.join(self)

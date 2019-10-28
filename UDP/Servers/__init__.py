from socketserver import ThreadingUDPServer
from threading import Thread


class BaseThreadedServer(Thread, ThreadingUDPServer):
    def __init__(self, ip, port, handler):
        ThreadingUDPServer.__init__(self, (ip, port), handler)
        Thread.__init__(self, target=self.serve_forever)

        Thread.setName(self, self.__class__.__name__)
        self.daemon = True

    def shutdown(self):
        ThreadingUDPServer.shutdown(self)
        Thread.join(self)

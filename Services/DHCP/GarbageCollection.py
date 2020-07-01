from sched import scheduler
from threading import Thread


class GarbageCollector(Thread):
    def __init__(self):
        super().__init__()
        self.schedule = scheduler()
        self.keep_alive = True

    def run(self):
        while self.keep_alive:
            self.schedule.run()

    def insert(self, delay, action, *args):
        self.schedule.enter(delay, 1, action, args)

    def shutdown(self):
        self.keep_alive = False
        for event in self.schedule.queue:
            self.schedule.cancel(event)

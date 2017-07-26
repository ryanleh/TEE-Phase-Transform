import threading
from counter import Counters
from counterdb import CounterDatabaseClass

class CounterMonitorClass(threading.Thread):
    def __init__(self, databaseName):
        threading.Thread.__init__(self)
        self.Started = False
        self.StopEvent = threading.Event()
        self.StopEvent.clear()
        self.CounterDatabase = CounterDatabaseClass(databaseName)

    def Start(self):
        if self.CounterDatabase.Initialize():
            self.start()
            self.Started = True
            return True
        else:
            return False

    def Stop(self):
        if self.Started:
            self.StopEvent.set()
            self.join(5)
            self.Started = False

    def run(self):
        while not self.StopEvent.isSet():
            self.StopEvent.wait(10)
            self.CounterDatabase.UpdateCounterData()
        Counters.Dump()

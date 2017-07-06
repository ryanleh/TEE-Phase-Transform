import logging
import socket
from threading import Thread
from threading import Event
from Queue import Queue
import itertools

Counter = itertools.count()

class ScannerClass(Thread):
    def __init__(self, inQueue, outQueue):
        Thread.__init__(self)
        self.setDaemon(1)
        self.inQueue = inQueue
        self.outQueue = outQueue
        self.id = Counter.next()

    def run(self):
      while True:
        host, port = self.inQueue.get()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
          s.settimeout(1)
          s.connect((host, port))
        except:
          self.outQueue.put((host, port, 'CLOSED'))
        else:
          self.outQueue.put((host, port, 'OPEN'))
          s.close()
      logging.info('closing scanner tid:{0}'.format(self.id))

def Scan(ipAddress, minPort, maxPort, nthreads, on_found_port = None):
  portsToScanQueue = Queue()
  scannedPortsQueue = Queue()
  hostports = [(ipAddress, port) for port in xrange(minPort, maxPort + 1)]
  for hostport in hostports:
    portsToScanQueue.put(hostport)
  scanners = [ScannerClass(portsToScanQueue, scannedPortsQueue) for i in range(nthreads)]
  for scanner in scanners:
    scanner.start()
  scanResults = []
  while True:
    temp_host, temp_port, temp_status = scannedPortsQueue.get()
    result = {
      'host' : temp_host,
      'port' : temp_port,
      'status' : temp_status
    }
    scanResults.append(result)
    if on_found_port and result['status'] == 'OPEN':
      on_found_port(result)
    if len(scanResults) == maxPort - minPort + 1:
      break
  return scanResults

import threading
import logging
import socket
import Queue

class NetworkScanUtilsClass(object):

  @staticmethod
  def GetAliveHosts(ipList, nThreads=50, timeout=1, useARP=False):
    """This method scans the specified IPs in order to identify if they are up.

    Kwargs:
       ipList (list): A list of strings identifying the IPs to scan.. If the parameter is not passed, the local IP
       and its netmask will be retrieved and all the network will be scanned.

    Returns:
       list.  A list of IPs up.
    """
    logging.info(NetworkScanUtilsClass.INFO1)
    return ScanAliveHosts(ipList, nThreads, timeout, useARP).Scan()

  @staticmethod
  def GetPortStatus(ipList, nThreads=50, timeout=1):
    """This method scans the specified IPs in order to identify if they are up.

    Args:
       ipList (list): A list of strings identifying the IPs to scan.

    Returns:
       dict.  A dictionary with the IPs as keys containing another dictionary with 'open', 'closed' and 'filtered' as
       keys and the respective ports inside as a list of integers.
    """
    raise NotImplementedError('GetPortStatus not implemented')
    logging.info(NetworkScanUtilsClass.INFO2.format(ipList))
    success = False
    return success

  @staticmethod
  def GetServices(ipList, nThreads=50, timeout=1):
    """This method scans the specified IP in order to identify if they are up.

    Args:
       ipList (list): A list of strings identifying the IPs to scan.

    Returns:
       dict.  A dictionary with the IPs as keys containing a list with the open port and the service. The port will
       always be in the first position of the list.
    """
    raise NotImplementedError('GetServices not implemented')
    logging.info(NetworkScanUtilsClass.INFO3.format(ipList))
    success = False
    return success

  ###
  # Internal Methods
  ##################


  ##
  # Constant strings
  ##################

  INFO1 = 'Scanning alive hosts...'
  INFO2 = 'Retrieving open ports for {0}'
  INFO3 = 'Retrieving services for {0}'


class ScanAliveHosts(object):

  PORT = 22

  def __init__(self, ipList, nThreads, timeout, useARP=False):
    assert isinstance(ipList, list)
    self.IPList = self._SetupIPList(ipList)
    self.nThreads = self._SetupNumberOfThreads(nThreads)
    self.Timeout = self._SetupTimeOut(timeout)
    self.IPQueue = self._InitializeThreadQueue(ipList)
    self.UseARP = self._SetupUseARP(useARP)
    self.AliveHosts = []

  def Scan(self):
    self._StartThreads()
    return self.AliveHosts

  def _StartThreads(self):
    for _ in range(self.nThreads):
      thread = threading.Thread(target=self._ThreaderLaunchConnection)
      thread.daemon = True
      thread.start()
    self.IPQueue.join()

  def _ThreaderLaunchConnection(self):
    while True:
      try:
        ip = self.IPQueue.get()
      except Queue.Empty:
        logging.warning('Queue is empty. No more IPs to fetch. Thread will finish.')
      else:
        self._ExecuteScan(ip)
        self.IPQueue.task_done()

  def _ExecuteScan(self, ip):
    if self.UseARP:
      self._ConnectUsingGetHostByAddr(ip)
    self._SimpleConnect(ip)

  def _InitializeThreadQueue(self, ipList):
    q = Queue.Queue()
    [q.put(ip) for ip in ipList]
    return q

  def _ConnectUsingGetHostByAddr(self, remote_address):
    success = True
    try:
      # This approach can give some false positives but is much better than connect(), given that connect() gives
      # some false negatives
      name = socket.gethostbyaddr(remote_address)  # timeout cannot be set for gethostbyaddr
      self.AliveHosts.append((remote_address, name[0]))
    except Exception as e:
      logging.info('Could not connect to {0}. Error: {1}'.format(remote_address, e))
      success = False
    return success

  def _SimpleConnect(self, remote_address):
    success = True
    con = None
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(self.Timeout)
    try:
      con = s.connect((remote_address, self.PORT))
    except Exception as e:
      if not '[Errno 10061]' in str(e):  # target machine actively refuse connection
        logging.info('Could not connect to {0}. Error: {1}'.format(remote_address, e))
        success = False
    finally:
      if con:
        con.shutdown(socket.SHUT_RDWR)
        con.close()
    if success:
      self.AliveHosts.append(remote_address)
    return success

  def _SetupIPList(self, ipList):
    param = ipList
    logging.info('Hosts to check: {0}'.format(ipList))
    return param

  def _SetupNumberOfThreads(self, nThreads):
    ipListLength = len(self.IPList)
    param = nThreads if nThreads < ipListLength else ipListLength
    logging.info('Number of threads: {0}'.format(param))
    return param

  def _SetupTimeOut(self, timeout):
    param = timeout
    logging.info('Timeout: {0}'.format(param))
    return param

  def _SetupUseARP(self, useARP):
    param = useARP
    logging.info('UseARP: {0}'.format(param))
    return param

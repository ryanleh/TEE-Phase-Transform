import os
import sys
import logging
import platform
from functools import wraps
from ai_utils.scenarios.globals import HostInfo
from ai_utils.exceptions import MissingBinaryError
from ai_utils.cache import EncryptedFileCacheClass
from ai_utils.cache import EncryptedFileCacheError
from ai_utils.ai_logging.simplelogger import AiLoggerClass
from ai_utils.exceptions import PlatformNotSupportedError

from ai_utils.utils.offensive.nmap_utils.winpcap_installer import WinPcapInstalled
try:
  from ai_utils.utils.offensive.nmap_utils.custom_libnmap.process import NmapProcess
  from ai_utils.utils.offensive.nmap_utils.custom_libnmap.parser import NmapParser
except ImportError:
  logging.error('python-libnmap module could not be imported')


AiLoggerClass().Enable()


def winpcap_installed(f):
  """
  Checks if on Windows. Uses context manager if on Windows, if not does
  nothing.
  """
  @wraps(f)
  def wrapped_function(*args, **kwargs):

    _platform = platform.platform()

    if 'Windows' in _platform:
      with WinPcapInstalled():
        return f(*args, **kwargs)
    else:
      return f(*args, **kwargs)

  return wrapped_function


def nmap_installed(f):
  """
  Download and install temporary nmap from encrypted cache.
  """
  @wraps(f)
  def wrapped_function(ips, parameters, callback=None, safeMode=True, nmapPath=None, timeout='1m'):

    if not nmapPath:

      URL_OSX = '09ba8839-0ab0-4a85-ac17-9d6686112d2f/nmap-osx.zip'
      URL_WIN = '25898598-a555-4b4e-a40a-ca73818ac6f4/nmap-win32.zip'
      URL_LIN = '7e30875a-d4d8-4374-8568-04c3ff7bc04e/nmap-linux.zip'

      file_cache = EncryptedFileCacheClass()
      if os.name == 'nt':
        directory = file_cache.get(URL_WIN)
        nmapPath = os.path.join(directory, 'win32/nmap.exe')
      elif sys.platform == 'darwin':
        directory = file_cache.get(URL_OSX)
        nmapPath = os.path.join(directory, 'osx/bin/nmap')
      elif sys.platform == 'linux2':
        directory = file_cache.get(URL_LIN)
        nmapPath = os.path.join(directory, 'linux/bin/nmap')
      else:
        raise PlatformNotSupportedError('Platform is not supported.')

      os.chmod(nmapPath, 0777)

    return f(ips, parameters, callback, safeMode, nmapPath, timeout)

  return wrapped_function


class NmapUtilsClass(object):

  @staticmethod
  def GetAliveHosts(ips=None, callback=None, nmapPath=None, timeout='1m'):
    """
    This method returns the IPs of the systems that are up in the range of hosts passed as a parameter. In local
    networks, this method will trigger an ARP Ping scan. If more information is needed, an ICMP echo request, a TCP
    SYN packet to port 443, a TCP ACK packet to port 80, and an ICMP timestamp request are sent (-PE -PS443 -PA80 -PP).
    The Nmap options used to retrieve this information are:
      -sn: no port scan phase
      -n: no hostname resolution
    :param ips: List of IPs to scan. If empty, the whole network segment will be scanned.
    :param callback: Function object that will be called each time that Nmap has results to process. By default, the
    callback is handled by the library so you do not have to handle it yourself.
    :param nmapPath: String specifying the location of the nmap binary (including the filename).
    :return: List of IPs that are up
    """
    logging.info('Scanning alive hosts...')
    if not ips:
      ips = [HostInfo.BuildLocalIPCIDRBlock()]
    NmapUtilsClass._CheckIPsParameter(ips)
    logging.info('{} will be scanned for alive hosts'.format(ips))
    scanParameters = ''
    callback = callback or NmapUtilsClass._DefaultCallback
    nmapReport = NmapUtilsClass.ExecuteSyncNmap(ips, scanParameters, callback, nmapPath=nmapPath, timeout=timeout)
    return [host.address for host in nmapReport.hosts if host.is_up()]

  @staticmethod
  def GetHostnames(ips=None, callback=None, nmapPath=None, timeout='1m'):
    """
    This method returns the IPs of the systems that have a hostnames assigned that are up in the range of hosts passed
    as a parameter . In local networks, this method will trigger an ARP Ping scan.
    If more information is needed, an ICMP echo request, a TCP SYN packet to port 443, a TCP ACK packet to port 80,
    and an ICMP timestamp request are sent (-PE -PS443 -PA80 -PP).
    The Nmap options used to retrieve this information are:
      -sn: no port scan phase
    :param ips: List of IPs to scan. If empty, the whole network segment will be scanned.
    :param callback: Function object that will be called each time that Nmap has results to process. By default, the
    callback is handled by the library so you do not have to handle it yourself.
    :param nmapPath: String specifying the location of the nmap binary (including the filename).
    :return: List of IPs that are up
    """
    logging.info('Scanning alive hosts...')
    if not ips:
      ips = [HostInfo.BuildLocalIPCIDRBlock()]
    NmapUtilsClass._CheckIPsParameter(ips)
    logging.info('{} will be scanned for alive hosts'.format(ips))
    scanParameters = '-sn'
    callback = callback or NmapUtilsClass._DefaultCallback
    nmapReport = NmapUtilsClass.ExecuteSyncNmap(ips, scanParameters, callback, nmapPath=nmapPath, timeout=timeout)
    return [(host.address, host.hostnames) for host in nmapReport.hosts if host.is_up() and host.hostnames]

  @staticmethod
  def GetOperatingSystems(ips, callback=None, nmapPath=None, timeout='1m'):
    """
    This method returns a list of tuples specifying the operating system of each available host inside the range passed
    using the ips parameter. In order to detect the OS, different TCP, UDP and ICMP probes are sent. The responses of
    open and closed ports are inspected in order to provide a more accurate detection. This means that this method also
    triggers a SYN Stealth scan in order to detect ports, in addition to the ARP Ping scan so as to identify which
    systems are up.
    The Nmap options used to retrieve this information:
      -O: Operating system detection
      --max-os-tries: Set the maximum number of OS detection tries (set to 3 instead of the default 5)
      -n: no hostname resolution
    :param ips: List of IPs to scan.
    :param callback: Function object that will be called each time that Nmap has results to process. By default, the
    callback is handled by the library so you do not have to handle it yourself.
    :param nmapPath: String specifying the location of the nmap binary (including the filename).
    :return: Returns a list of tuples being their items strings of the form (<ip_address>, <os>).
    """
    logging.info('Detecting operating systems for {}...'.format(ips))
    NmapUtilsClass._CheckIPsParameter(ips)
    scanParameters = '-O --max-os-tries 3 -n'
    callback = callback or NmapUtilsClass._DefaultCallback
    nmapReport = NmapUtilsClass.ExecuteSyncNmap(ips, scanParameters, callback, nmapPath=nmapPath, timeout=timeout)
    return NmapUtilsClass._BuildOSResults(nmapReport)

  @staticmethod
  def GetOpenPorts(ips, ports='', callback=None, nmapPath=None, timeout='1m'):
    """
    This method returns a list of tuples specifying the open TCP and UDP ports for each available host
    inside the range passed using the ips parameter. For all the ports passed using the ports parameter, if they are
    not shown in the results it means that they are closed, filtered or open|filtered. If you want more information,
    you can directly execute ExecuteAsyncNmap or ExecuteSyncNmap methods.
    This method combines the capabilities of GetOpenTCPPorts and GetOpenUDPPorts methods.
    The Nmap options used to retrieve this information:
      -sU: UDP port scan
      -sS: TCP SYN port scan
      -n: no hostname resolution
    :param ips: List of IPs to scan.
    :param ports: String expression with the ports to be scanned. If "-", all the ports will be scanned. If None, most
    common ports will be scanned (usually about a thousand of ports are scanned).
    Examples of valid ports parameter are: "80,81,8080" or "1-1024" or "8080-9000,10000-20000,35000" or "-".
    :param callback: Function object that will be called each time that Nmap has results to process. By default, the
    callback is handled by the library so you do not have to handle it yourself.
    :param nmapPath: String specifying the location of the nmap binary (including the filename).
    :return: Returns a list of tuples being its first item a string and the second item a list of strings:
    (<ip_address>, [(<port1>, <type>), ...,(<portN>, <type>))]).
    """
    logging.info('Scanning both TCP and UDP ports ({}) for {}...'.format(ports, ips))
    NmapUtilsClass._CheckIPsParameter(ips)
    NmapUtilsClass._CheckPortsParameter(ports)
    scanParameters = '-sU -sS -n -p' + ports if ports else '-sU -sS -n'
    callback = callback or NmapUtilsClass._DefaultCallback
    nmapReport = NmapUtilsClass.ExecuteSyncNmap(ips, scanParameters, callback, nmapPath=nmapPath, timeout=timeout)
    return NmapUtilsClass._BuildCompletePortsResults(nmapReport)

  @staticmethod
  def GetOpenTCPPorts(ips, ports='', callback=None, nmapPath=None, timeout='1m'):
    """
    This method returns a list of tuples specifying the open TCP ports for each available host inside the range passed
    using the ips parameter. For all the ports passed using the ports parameter, if they are not shown in the results
    it means that they are closed or filtered. If you want more information, you can directly execute ExecuteAsyncNmap
    or ExecuteSyncNmap methods.
    This method retrieves open ports by triggering a SYN scan. This means that SYN packets will be sent to all the
    specified ports. If a SYN or SYN/ACK response is received from the destination host, the port is set as open.
    This method does not closes the connections by answering the host SYN or SYN/ACK with a ACK. This means that this
    scan never creates a connection with the remote host, thus being able to scan the network faster and stealthier.
    If this method is executed without root or administrator privileges, the scan falls back to a regular TCP Connect
    scan, in which the connections are established against the remote hosts.
    The Nmap options used to retrieve this information:
      -sS: TCP SYN port scan
      -n: no hostname resolution
    :param ips: List of IPs to scan.
    :param ports: String expression with the ports to be scanned. If "-", all the ports will be scanned. If None, most
    common ports will be scanned (usually about a thousand of ports are scanned).
    Examples of valid ports parameter are: "80,81,8080" or "1-1024" or "8080-9000,10000-20000,35000" or "-".
    :param callback: Function object that will be called each time that Nmap has results to process. By default, the
    callback is handled by the library so you do not have to handle it yourself.
    :param nmapPath: String specifying the location of the nmap binary (including the filename).
    :return: Returns a list of tuples being its first item a string and the second item a list of strings:
    (<ip_address>, [<port1>, ...,<portN>]).
    """
    logging.info('Scanning TCP ports ({}) for {}...'.format(ports, ips))
    NmapUtilsClass._CheckIPsParameter(ips)
    NmapUtilsClass._CheckPortsParameter(ports)
    scanParameters = '-sS -n -p' + ports if ports else '-sS -n'
    callback = callback or NmapUtilsClass._DefaultCallback
    nmapReport = NmapUtilsClass.ExecuteSyncNmap(ips, scanParameters, callback, nmapPath=nmapPath, timeout=timeout)
    return NmapUtilsClass._BuildPortsResults(nmapReport)

  @staticmethod
  def GetOpenTCPPortsUsingFullConnectScan(ips, ports='', callback=None, nmapPath=None, timeout='1m'):
    """
    This method returns a list of tuples specifying the open TCP ports for each available host inside the range passed
    using the ips parameter. For all the ports passed using the ports parameter, if they are not shown in the results
    it means that they are closed or filtered. If you want more information, you can directly execute ExecuteAsyncNmap
    or ExecuteSyncNmap methods.
    This method retrieves open ports by triggering a Connect scan. Full connections (three-way handshake) will be made
    against the remote specified ports. Executing this type of scan does not require administrator/root privileges.
    The Nmap options used to retrieve this information:
      -sT: Connect port scan
      -n: no hostname resolution
    :param ips: List of IPs to scan.
    :param ports: String expression with the ports to be scanned. If "-", all the ports will be scanned. If None, most
    common ports will be scanned (usually about a thousand of ports are scanned).
    Examples of valid ports parameter are: "80,81,8080" or "1-1024" or "8080-9000,10000-20000,35000" or "-".
    :param callback: Function object that will be called each time that Nmap has results to process. By default, the
    callback is handled by the library so you do not have to handle it yourself.
    :param nmapPath: String specifying the location of the nmap binary (including the filename).
    :return: Returns a list of tuples being its first item a string and the second item a list of strings:
    (<ip_address>, [<port1>, ...,<portN>]).
    """
    logging.info('Scanning TCP ports ({}) for {}...'.format(ports, ips))
    NmapUtilsClass._CheckIPsParameter(ips)
    NmapUtilsClass._CheckPortsParameter(ports)
    _platform = platform.platform()
    if "Windows" in _platform:
      scanParameters = '--unprivileged -sT -n -p' + ports if ports else '--unprivileged -sT -n'
    else:
      scanParameters = '-sT -n -p' + ports if ports else '-sT -n'
    callback = callback or NmapUtilsClass._DefaultCallback
    nmapReport = NmapUtilsClass.ExecuteSyncNmap(ips, scanParameters, callback, nmapPath=nmapPath, timeout=timeout)
    return NmapUtilsClass._BuildPortsResults(nmapReport)


  @staticmethod
  def GetOpenTCPPortsUsingAckScan(ips, callback=None, nmapPath=None, timeout='1m'):
    """
    This scan is different than the others discussed so far in that it never determines open (or even open|filtered)
    ports. It is used to map out firewall rulesets, determining whether they are stateful or not and which ports are filtered.
      -sA: Ack scan.
      -n: no hostname resolution
    :param ips: List of IPs to scan.
    :param ports: String expression with the ports to be scanned. If "-", all the ports will be scanned. If None, most
    common ports will be scanned (usually about a thousand of ports are scanned).
    Examples of valid ports parameter are: "80,81,8080" or "1-1024" or "8080-9000,10000-20000,35000" or "-".
    :param callback: Function object that will be called each time that Nmap has results to process. By default, the
    callback is handled by the library so you do not have to handle it yourself.
    :param nmapPath: String specifying the location of the nmap binary (including the filename).
    :return: Returns a list of tuples being its first item a string and the second item a list of strings:
    (<ip_address>, [<port1>, ...,<portN>]).
    """
    logging.info('Scanning open ports (ACK) {}...'.format(ips))
    NmapUtilsClass._CheckIPsParameter(ips)
    scanParameters = '-sA -n'
    callback = callback or NmapUtilsClass._DefaultCallback
    nmapReport = NmapUtilsClass.ExecuteSyncNmap(ips, scanParameters, callback, nmapPath=nmapPath, timeout=timeout)
    return NmapUtilsClass._BuildPortsResults(nmapReport)

  @staticmethod
  def GetOpenUDPPorts(ips, ports='', callback=None, nmapPath=None, timeout='1m'):
    """
    This method returns a list of tuples specifying the open UDP ports for each available host inside the range passed
    using the ips parameter. For all the ports passed using the ports parameter, if they are not shown in the results
    it means that they are closed or open|filtered. If you want more information, you can directly execute
    ExecuteAsyncNmap or ExecuteSyncNmap methods.
    This method retrieves open ports by triggering a UDP scan. This means that UDP packets will be sent to all the
    specified ports.
    Given that UDP ports do not usually answer when they are open, sometimes it is hard to distinguish an UDP open port
    from a firewall filtered port. Executing UDP scans can take a lot of time because of that. Scanning closed UDP
    ports is also time consuming because when UDP ports are closed, a ICMP host unreachable paquet is sent as a
    response. In Linux systems identifying UDP closed ports is very time consuming because only one ICMP packet is
    allowed to be sent each second meaning that a complete scan can take up to 18 hours.
    For commonly used UDP ports, special packets are sent in order to get some response and being able to easily
    identify the state of the port.
    The Nmap options used to retrieve this information:
      -sU: UDP port scan
      -n: no hostname resolution
    :param ips: List of IPs to scan.
    :param ports: String expression with the ports to be scanned. If "-", all the ports will be scanned. If None, most
    common ports will be scanned (usually about a thousand of ports are scanned).
    Examples of valid ports parameter are: "80,81,8080" or "1-1024" or "8080-9000,10000-20000,35000" or "-".
    :param callback: Function object that will be called each time that Nmap has results to process. By default, the
    callback is handled by the library so you do not have to handle it yourself.
    :param nmapPath: String specifying the location of the nmap binary (including the filename).
    :return: Returns a list of tuples being its first item a string and the second item a list of strings:
    (<ip_address>, [<port1>, ...,<portN>]).
    """
    logging.info('Scanning UDP ports ({}) for {}...'.format(ports, ips))
    NmapUtilsClass._CheckIPsParameter(ips)
    NmapUtilsClass._CheckPortsParameter(ports)
    scanParameters = '-sU -n -p' + ports if ports else '-sU -n'
    callback = callback or NmapUtilsClass._DefaultCallback
    nmapReport = NmapUtilsClass.ExecuteSyncNmap(ips, scanParameters, callback, nmapPath=nmapPath, timeout=timeout)
    return NmapUtilsClass._BuildServiceResults(nmapReport)

  @staticmethod
  def GetTCPServices(ips, ports='', callback=None, nmapPath=None, timeout='1m'):
    """
    This method returns a list of tuples specifying the open TCP ports and their respective service banner for each
    available host inside the range passed using the ips parameter. For all the ports passed using the ports parameter,
    if they are not shown in the results it means that they are closed or filtered. If you want more information,
    you can directly execute ExecuteAsyncNmap or ExecuteSyncNmap methods.
    This method retrieves the service banners for open ports by triggering a Nmap Service scan.
    This scan has different phases: ARP Ping to detect available hosts, SYS Stealth scan to detect open ports, Service
    Scan to get the banners of each open port and generic NSE script execution to retrieve more information about the
    services.
    This type of scan takes significantly more time than a Syn Stealth Scan or a Host Discovery Scan.
    The Nmap options used to retrieve this information:
      -sV: Service scan
      -n: no hostname resolution
    :param ips: List of IPs to scan.
    :param ports: String expression with the ports to be scanned. If "-", all the ports will be scanned. If None, most
    common ports will be scanned (usually about a thousand of ports are scanned).
    Examples of valid ports parameter are: "80,81,8080" or "1-1024" or "8080-9000,10000-20000,35000" or "-".
    :param callback: Function object that will be called each time that Nmap has results to process. By default, the
    callback is handled by the library so you do not have to handle it yourself.
    :param nmapPath: String specifying the location of the nmap binary (including the filename).
    :return: Returns a list of tuples being its first item an string and the second item a list of tuples of strings
     of the form (<ip_address>, [(<port1>, <service1>), ...,(<portN>, <serviceN>)]).
    """
    logging.info('Scanning TCP Services ({}) for {}...'.format(ports, ips))
    NmapUtilsClass._CheckIPsParameter(ips)
    NmapUtilsClass._CheckPortsParameter(ports)
    scanParameters = '-sV -n -p' + ports if ports else '-sV -n'
    callback = callback or NmapUtilsClass._DefaultCallback
    nmapReport = NmapUtilsClass.ExecuteSyncNmap(ips, scanParameters, callback, nmapPath=nmapPath, timeout=timeout)
    return NmapUtilsClass._BuildServiceResults(nmapReport)

  @staticmethod
  def GetUDPServices(ips, ports='', callback=None, nmapPath=None, timeout='1m'):
    """
    This method returns a list of tuples specifying the open UDP ports and their respective service banner for each
    available host inside the range passed using the ips parameter. For all the ports passed using the ports parameter,
    if they are not shown in the results it means that they are closed or open|filtered. If you want more information,
    you can directly execute ExecuteAsyncNmap or ExecuteSyncNmap methods.
    This method retrieves the service banners for open ports by triggering a Nmap Service scan.
    Given that UDP ports do not usually answer when they are open, sometimes it is hard to distinguish an UDP open port
    from a firewall filtered port. Executing UDP scans can take a lot of time because of that. Scanning closed UDP
    ports is also time consuming because when UDP ports are closed, a ICMP host unreachable paquet is sent as a
    response. In Linux systems identifying UDP closed ports is very time consuming because only one ICMP packet is
    allowed to be sent each second meaning that a complete scan can take up to 18 hours.
    For commonly used UDP ports, special packets are sent in order to get some response and being able to easily
    identify the state of the port.
    The Nmap options used to retrieve this information:
      -sV: Service scan
      -sU: UDP Port Scan
      -n: no hostname resolution
    :param ips: List of IPs to scan.
    :param ports: String expression with the ports to be scanned. If "-", all the ports will be scanned. If None, most
    common ports will be scanned (usually about a thousand of ports are scanned).
    Examples of valid ports parameter are: "80,81,8080" or "1-1024" or "8080-9000,10000-20000,35000" or "-".
    :param callback: Function object that will be called each time that Nmap has results to process. By default, the
    callback is handled by the library so you do not have to handle it yourself.
    :param nmapPath: String specifying the location of the nmap binary (including the filename).
    :return: Returns a list of tuples being its first item an string and the second item a list of tuples of strings
     of the form (<ip_address>, [(<port1>, <service1>), ...,(<portN>, <serviceN>)]).
    """
    logging.info('Scanning UDP Services ({}) for {}...'.format(ports, ips))
    NmapUtilsClass._CheckIPsParameter(ips)
    NmapUtilsClass._CheckPortsParameter(ports)
    scanParameters = '-sU -sV -n -p' + ports if ports else '-sU -sV -n'
    callback = callback or NmapUtilsClass._DefaultCallback
    nmapReport = NmapUtilsClass.ExecuteSyncNmap(ips, scanParameters, callback, nmapPath=nmapPath, timeout=timeout)
    return NmapUtilsClass._BuildServiceResults(nmapReport)

  @staticmethod
  def GetServices(ips, ports='', callback=None, nmapPath=None, timeout='1m'):
    """
    This method returns a list of tuples specifying the TCP and UDP services for each available host
    inside the range passed using the ips parameter. For all the ports passed using the ports parameter, if they are
    not shown in the results it means that they are closed, filtered or open|filtered. If you want more information,
    you can directly execute ExecuteAsyncNmap or ExecuteSyncNmap methods.
    This method combines the capabilities of GetTCPServices and GetUDPServices methods.
    The Nmap options used to retrieve this information:
      -sU: UDP port scan
      -sS: TCP SYN port scan
      -sV: Service scan
      -n: no hostname resolution
    :param ips: List of IPs to scan.
    :param ports: String expression with the ports to be scanned. If "-", all the ports will be scanned. If None, most
    common ports will be scanned (usually about a thousand of ports are scanned).
    Examples of valid ports parameter are: "80,81,8080" or "1-1024" or "8080-9000,10000-20000,35000" or "-".
    :param callback: Function object that will be called each time that Nmap has results to process. By default, the
    callback is handled by the library so you do not have to handle it yourself.
    :param nmapPath: String specifying the location of the nmap binary (including the filename).
    :return: Returns a list of tuples being its first item a string and the second item a list of strings:
    (<ip_address>, [(<port1>, <service1>, <type>), ...,(<portN>, <serviceN>, <type>))]).
    """
    logging.info('Scanning both TCP and UDP ports ({}) for {}...'.format(ports, ips))
    NmapUtilsClass._CheckIPsParameter(ips)
    NmapUtilsClass._CheckPortsParameter(ports)
    scanParameters = '-sU -sS -sV -n -p' + ports if ports else '-sU -sS -sV -n'
    callback = callback or NmapUtilsClass._DefaultCallback
    nmapReport = NmapUtilsClass.ExecuteSyncNmap(ips, scanParameters, callback, nmapPath=nmapPath, timeout=timeout)
    return NmapUtilsClass._BuildCompleteServiceResults(nmapReport)


  @staticmethod
  @nmap_installed
  @winpcap_installed
  def ExecuteAsyncNmap(ips, parameters, callback=None, safeMode=True, nmapPath=None, timeout='1m'):
    """
    This method executes Nmap in a asynchronous approach and calls a callback method each time that Nmap has new
    results.
    By executing Nmap asynchronously, it's the caller's responsibility to check when the scan has  finished. If you do
    not want to handle this situation, use a synchronous scan.
    :param ips: List of IPs to scan.
    :param parameters: List of parameters with which Nmap will be executed. Input and output parameters are ignored.
    :param callback: Function object that will be called each time that Nmap has results to process. By default, the
    callback is handled by the library so you do not have to handle it yourself.
    :param safeMode: Boolean value. If True (default) input and output parameters will be ignored.
    :param nmapPath: String value defining the path in which nmap_utils binary is located. By default, nmap_utils binary will be
    searched in the directories defined in the PATH environment variable.
    :param timeout: Host timeout value. Default 1 minute.
    :return: It returns a NmapProcess object.
    """
    nmapProcess = NmapProcess(ips, 
                              '--host-timeout {} {}'.format(timeout, parameters), 
                              callback, 
                              safeMode, 
                              nmapPath)
    nmapProcess.run_background()
    return nmapProcess


  @staticmethod
  @nmap_installed
  @winpcap_installed
  def ExecuteSyncNmap(ips, parameters, callback=None, safeMode=True, nmapPath=None, timeout='1m'):
    """
    This method executes Nmap in a synchronous approach and calls a callback method each time that Nmap has new
    results.
    :param ips: List of IPs to scan.
    :param parameters: List of parameters with which Nmap will be executed. Input and output parameters are ignored.
    :param callback: Function object that will be called each time that Nmap has results to process. By default, the
    callback is handled by the library so you do not have to handle it yourself.
    :param safeMode: Boolean value. If True (default) input and output parameters will be ignored.
    :param nmapPath: String value defining the path in which nmap_utils binary is located. By default,
    nmap_utils binary will be searched in the directories defined in the PATH environment variable.
    :param timeout: Host timeout value. Default 1 minute.
    :return: The Nmap report object as defined in https://libnmap.readthedocs.org/en/latest/objects/nmapreport.html
    """
    nmapProcess = NmapProcess(ips, 
                              '--host-timeout {} {}'.format(timeout, parameters), 
                              callback, 
                              safeMode, 
                              nmapPath)
    nmapProcess.run()
    if nmapProcess.is_successful():
      nmapReport = NmapParser.parse(nmapProcess.stdout)
      return nmapReport
    NmapUtilsClass._RaiseNmapScanException(nmapProcess)

  ###
  # Internal Methods
  ##################

  @staticmethod
  def _DefaultCallback(nmapProcessObject):
    if nmapProcessObject.is_running() and nmapProcessObject.current_task:
      nmapTask = nmapProcessObject.current_task
      logging.info("{0}: {1}%".format(nmapTask.name, nmapTask.progress))

  @staticmethod
  def _BuildOSResults(nmapReport):
    results = []
    for host in nmapReport.hosts:
      try:
        if NmapUtilsClass._ValidOSDetected(host):
          results.append((host.address, host.os.osmatches[0].name))
      except Exception as e:
        logging.warning('OS could not be parsed out from Host instance ({}). Error: {}'.format(host, e))
    return results

  @staticmethod
  def _ValidOSDetected(host):
    return host.is_up() and host.os_fingerprinted and host.os.osmatches and host.os.osmatches[0].name

  @staticmethod
  def _BuildPortsResults(nmapReport):
    results = []
    for host in nmapReport.hosts:
      try:
        if host.is_up():
          openPorts = NmapUtilsClass._GetOpenPortsFromServices(host.services)
          results.append((host.address, openPorts))
      except Exception as e:
        logging.warning('Service/Port could not be parsed out from Host instance ({}). Error: {}'.format(host, e))
    return results

  @staticmethod
  def _GetOpenPortsFromServices(services):
    openPorts = []
    for service in services:
      if service.open():
        openPorts.append(service.port)
    return openPorts

  @staticmethod
  def _BuildCompletePortsResults(nmapReport):
    results = []
    for host in nmapReport.hosts:
      try:
        if host.is_up():
          openPorts = NmapUtilsClass._GetOpenPortsAndTypeFromServices(host.services)
          results.append((host.address, openPorts))
      except Exception as e:
        logging.warning('TCP/UDP Service/Port could not be parsed from Host instance ({}). Error: {}'.format(host, e))
    return results

  @staticmethod
  def _GetOpenPortsAndTypeFromServices(services):
    openPorts = []
    for service in services:
      if service.open():
        openPorts.append((service.port, service.protocol))
    return openPorts

  @staticmethod
  def _BuildServiceResults(nmapReport):
    results = []
    for host in nmapReport.hosts:
      try:
        if host.is_up():
          services = NmapUtilsClass._GetServiceNamesFromServices(host.services)
          results.append((host.address, services))
      except Exception as e:
        logging.warning('Service Name/Port could not be parsed out from Host instance ({}). Error: {}'.format(host, e))
    return results

  @staticmethod
  def _GetServiceNamesFromServices(services):
    serviceNames = []
    for service in services:
      if service.open():
        product = service.service_dict.get('product', '')
        extrainfo = service.service_dict.get('extrainfo', '')
        version = service.service_dict.get('version', '')
        fullBanner = product + ', ' + version + ' ' + extrainfo if version or extrainfo else product
        customBanner = fullBanner.strip() or service.service
        serviceNames.append((service.port, customBanner))
    return serviceNames

  @staticmethod
  def _BuildCompleteServiceResults(nmapReport):
    results = []
    for host in nmapReport.hosts:
      try:
        if host.is_up():
          services = NmapUtilsClass._GetCompleteServiceNamesFromServices(host.services)
          results.append((host.address, services))
      except Exception as e:
        logging.warning('Service Name/Port could not be parsed out from Host instance ({}). Error: {}'.format(host, e))
    return results

  @staticmethod
  def _GetCompleteServiceNamesFromServices(services):
    serviceNames = []
    for service in services:
      if service.open():
        product = service.service_dict.get('product', '')
        extrainfo = service.service_dict.get('extrainfo', '')
        version = service.service_dict.get('version', '')
        fullBanner = product + ', ' + version + ' ' + extrainfo if version or extrainfo else product
        customBanner = fullBanner.strip() or service.service
        serviceNames.append((service.port, customBanner, service.protocol))
    return serviceNames

  @staticmethod
  def _CheckIPsParameter(ips):
    if not ips:
      raise IPsParameterNotDefined('IPs parameter must not be empty')
    if not isinstance(ips, list):
      raise InvalidIPsParameterType('IPs parameter should be a list')
    if any(True for ip in ips if not ip):
      raise EmptyIPsParameter('IPs parameter is a list but it contains empty elements. Remove empty elements')
    return True

  @staticmethod
  def _CheckPortsParameter(ports):
    if not isinstance(ports, basestring):
      raise InvalidIPsParameterType('Ports parameter should be a string')
    return True

  @staticmethod
  def _RaiseNmapScanException(nmapProcess):
    errorMessage = 'Nmap scan failed. '
    if nmapProcess and hasattr(nmapProcess, 'rc') and hasattr(nmapProcess, 'get_command_line'):
      errorMessage += 'Return code: {}, Command line: {}'.format(nmapProcess.rc, nmapProcess.get_command_line())
    if nmapProcess.stderr:
      errorMessage += ', Error: {}'.format(nmapProcess.stderr)
    raise NmapExecutionError(errorMessage)


class IPsParameterNotDefined(ValueError):
  pass


class InvalidIPsParameterType(TypeError):
  pass


class EmptyIPsParameter(TypeError):
  pass


class InvalidPortsParameterType(TypeError):
  pass


class NmapExecutionError(Exception):
  pass

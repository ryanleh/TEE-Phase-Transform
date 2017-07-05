from ai_utils.utils.agent_config import AgentConfigClass
from ai_utils.utils.pathutils import PathUtilsClass as PathUtils
from urlparse import urlparse
import logging
import socket
import sys
import re
import os

try:
  from requests import get
except ImportError as e:
  logging.warning('"Requests" module could not be imported. Some network utilities will not be available. Error: {}'.format(e))

try:
  from ipaddr import IPAddress, IPNetwork
except ImportError as e:
  logging.warning('"ipaddr" module could not be imported. Some network utilities will not be available. Error: {}'.format(e))

try:
  from nmb.NetBIOS import NetBIOS
except ImportError as e:
  logging.warning('"nmb" module could not be imported. Some network utilities will not be available. Error: {}'.format(e))

try:
  import aipythonlib
except Exception as e:
  logging.warning('"aipythonlib" module could not be imported. Some network utilities will not be available. Error: {}'.format(e))


class PortRange(object):
  lower = 0
  upper = 0
  def __init__(self, lower=0):
    self.lower = lower
  def __str__(self):
    if self.upper:
      return '{}-{}'.format(self.lower, self.upper)
    else:
      return '{}'.format(self.lower)


class NetworkUtilsClass(object):
  def __init__(self):
    pass

  @staticmethod
  def IsValidEmailAddress(email):
    if not re.match(r"^[A-Za-z0-9\.\+_-]+@[A-Za-z0-9\._-]+\.[a-zA-Z]*$", email):
      return False
    else:
      return True
  
  @staticmethod
  def ValidateUrl(url):
    match = None
    try:
      regex = re.compile(
            r'^(?:http|ftp)s?://'  # http:// or https://
            r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'  # domain
            r'localhost|'  # localhost
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ip
            r'(?::\d+)?'  # optional port
            r'(?:/?|[/?]\S+)$', re.IGNORECASE)
      match = regex.match(url)
    except Exception as e:
      logging.error('An error occurred validating the URL. Error: {0}'.format(e))
    if not match:
      logging.error("{0} is not a valid URL".format(url))
      return False
    else:
      logging.info("{0} is a valid URL".format(url))
    return True

  @staticmethod
  def GetFilenameFromUrl(url):
    parsed = urlparse(url)
    return parsed.path.split('/')[-1].split('=')[-1].split('&')[-1]

  @staticmethod
  def CheckUrlPrefix(url):
    if not url.startswith(('http://', 'https://')):
      url = 'http://' + url
    return url
  
  @staticmethod
  def DownloadFile(url):
    try:
      response = get(url, verify=False, stream=True)
      if not response.ok:
        logging.error("Unable to download file at {0}".format(url))
        return False, None
    except:
      logging.exception('Failed to download {0}'.format(url))
      return False, None
    logging.info("Successfully downloaded file from {0}".format(url))
    finalUrl = response.url
    if finalUrl != url:
      logging.info("URI was redirected to {0}".format(finalUrl))
    return True, response

  @staticmethod
  def DownloadFileFromConsole(url):
    try:
      AgentConfig = AgentConfigClass()
      response = get(url, verify=False, stream=True, headers=AgentConfig.HttpHeaders)
      if not response.ok:
        logging.error("Unable to download file at {0}".format(url))
        return False, None
    except:
      logging.exception('Failed to download {0}'.format(url))
      return False, None
    logging.info("Successfully downloaded file from {0}".format(url))
    finalUrl = response.url
    if finalUrl != url:
      logging.info("URI was redirected to {0}".format(finalUrl))
    return True, response

  # https://gist.github.com/pklaus/856268
  @staticmethod
  def Checksum(source_string):
    checkSum = 0
    count_to = (len(source_string) / 2) * 2
    count = 0
    while count < count_to:
      this_val = ord(source_string[count + 1])*256+ord(source_string[count])
      checkSum = checkSum + this_val
      checkSum = checkSum & 0xffffffff # Necessary?
      count = count + 2
    if count_to < len(source_string):
      checkSum = checkSum + ord(source_string[len(source_string) - 1])
      checkSum = checkSum & 0xffffffff # Necessary?
    checkSum = (checkSum >> 16) + (checkSum & 0xffff)
    checkSum = checkSum + (checkSum >> 16)
    answer = ~checkSum
    answer = answer & 0xffff
    # Swap bytes. Bugger me if I know why.
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer

  @staticmethod
  def GetIPList(cidr):
    ip_range = []
    try:
      if cidr.find('/') != -1:
        ipNetwork = IPNetwork(cidr, strict=False)
        ip_range = [str(host) for host in ipNetwork]
      else:
        ipAddress = IPAddress(cidr)
        ip_range.append(str(ipAddress))
    except Exception, e:
      logging.error('Error parsing {0}. {1}'.format(cidr, e))
    return ip_range

  @staticmethod
  def GetHostName(ipAddress, timeout=5):
    hostName = None
    netBios = NetBIOS()
    try:
      hostInfo = socket.gethostbyaddr(ipAddress)
      if hostInfo:
        hostName = hostInfo[0]
      else:
        hostName = netBios.queryIPForName(ipAddress, port=139, timeout=timeout)
    except Exception as e:
      logging.warning('Error getting name for ip {0}: {1}'.format(ipAddress, e))
    finally:
      netBios.close()
    return hostName or ''

  @staticmethod
  def GetIPFromHostName(hostName):
    ipAddress = ''
    try:
      ipAddress = socket.gethostbyname(hostName)
    except Exception as e:
      logging.warning('Error getting IP for host {0}: {1}'.format(hostName, e))
    return ipAddress

  @staticmethod
  def GetMachineFQDN():
    param = ''
    if sys.platform != 'win32':
      return param
    # First approach to retrieve domain (locatization agnostic). But doesn't work for local admin users
    # Correctly tested on Windows 2012 Domain Controller
    correctDomain = False
    domain = PathUtils.GetUserEnvVar('USERDNSDOMAIN')
    if domain == '%USERDNSDOMAIN%':
      domain = ''
    if not domain:
      domain = os.environ.get('USERDNSDOMAIN')
    if domain:
      param = domain.strip()
      logging.info("Retrieved FQDN from USERDNSDOMAIN environment variable: {0}".format(param))
      correctDomain = True
    # Second approach to retrive domain.
    if not correctDomain:
      logging.info("FQDN could not be read from USERDNSDOMAIN environment variable. Executing ipconfig...")
      timeout = 5000
      errorCode, exitCode, stdOut, stdError = aipythonlib.AiRunCommand('ipconfig', '/ALL', timeout)
      if errorCode == 0 and stdError == '' and exitCode == 0:
        domain = re.search('Primary Dns Suffix.*', stdOut)
        # domain = re.search("Sufijo DNS principal.*", stdOut)  # keep this comment here to state localization issues
        if domain:
          domain = domain.group()
          if domain.find(':') != -1 and len(domain.split(':')) > 1:
            param = domain.split(':')[1].strip()
            logging.info("Retrieved FQDN from ipconfig output: {0}".format(param))
      else:
        logging.warning('Error executing ipconfig. ErrorCode: {0} Error Message: {1}'.format(errorCode, stdError))

    if not param:
      logging.warning('FQDN value could not be retrieved from USERDNSDOMAIN variable or from ipconfig.')
    return param

  @staticmethod
  def GetDomainControllerMachineName():
    param = ''
    # For LOGONSERVER envvar to be set to the domain controller machine, user must have logged in against the DC
    targetMachine = PathUtils.GetUserEnvVar('LOGONSERVER')
    if targetMachine == '%LOGONSERVER%':
      targetMachine = ''
    if not targetMachine:
      targetMachine = os.environ.get('LOGONSERVER')
    if targetMachine:
      targetMachine = targetMachine.strip()
      if targetMachine.startswith('\\\\'):
        targetMachine = targetMachine[2:]
      param = targetMachine
      logging.info("Retrieved Domain Controller machine name from LOGONSERVER environment variable: {0}".format(param))
    if not param:
      logging.warning('Domain Controller machine name could not be retrieved from LOGONSERVER environment variable.')
      logging.warning('To obtain this value, a windows domain user should be logged in asset machine.')
    return param

  @staticmethod
  def GetLocalIP():
    logging.info('Getting local IP...')
    ip = ''
    try:
      ip = socket.gethostbyname(socket.gethostname())
      if ip == '127.0.0.1':
        logging.info('Detected IP address 127.0.0.1. Getting local IP through remote connection...')
        ip = NetworkUtilsClass._GetLocalIPThroughRemoteConnection()
      logging.info('Local IP: {0}'.format(ip))
    except Exception as ex:
      logging.error('Local IP could not be identified. Error: {0}'.format(ex))
    return ip

  @staticmethod
  def _GetLocalIPThroughRemoteConnection():
    logging.info('Getting local IP through remote connection...')
    ip = ''
    try:
      s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
      s.connect(("google.com", 80))
      ip = s.getsockname()[0]
      s.close()
    except Exception as ex:
      logging.error('Local IP could not be identified through remote connection. Error: {0}'.format(ex))
    return ip

  @staticmethod
  def GetLocalNetmaskForIP(ip):
    logging.info('Getting local netmask...')
    netmask = ''
    try:
      netmask = NetworkUtilsClass._GetNetmaskFromIpconfig(ip)
      logging.info('Local netmask: {0}'.format(netmask))
    except Exception as ex:
      logging.error('Local netmask could not be identified. Error: {0}'.format(ex))
    return netmask

  @staticmethod
  def _GetNetmaskFromIpconfig(ip):
    logging.info('Executing ipconfig to get netmask for {0}...'.format(ip))
    netmask = ''
    timeout = 5000
    errorCode, exitCode, stdOut, stdError = aipythonlib.AiRunCommand('ipconfig', '', timeout)
    if errorCode == 0 and stdError == '' and exitCode == 0:
      lines = stdOut.splitlines()
      for index, line in enumerate(lines):
        if ip in line:
          netmaskLine = lines[index+1]
          netmask = netmaskLine.split(':')[1].strip()
          break
    else:
      logging.warning('Error executing ipconfig. ErrorCode: {0} Error Message: {1}'.format(errorCode, stdError))
    return netmask

  @staticmethod
  def GetHostsFromIPAndNetmask(ip, netmask):
    ipList = []
    try:
      network = IPNetwork('{0}/{1}'.format(ip, netmask))
      ipList = [str(ip) for ip in network.iterhosts()]
    except Exception as ex:
      logging.error('IP list could not be generated from IP: {0} and netmask: {1}. Error: {2}'.format(ip, netmask, ex))
    return ipList

  @staticmethod
  def GetLocalNetworkHosts():
    hosts = []
    try:
      localIP = NetworkUtilsClass.GetLocalIP()
      localNetmask = NetworkUtilsClass.GetLocalNetmaskForIP(localIP)
      hosts = NetworkUtilsClass.GetHostsFromIPAndNetmask(localIP, localNetmask)
    except Exception as ex:
      logging.error('Hosts could not be retrieved for local network configuration. Error: {0}'.format(ex))
    return hosts

  @staticmethod
  def GetNetworkInCIDRFormat(ip, netmask):
    network = ''
    try:
      network = IPNetwork('{0}/{1}'.format(ip, netmask))
      network = str(network)
    except Exception as ex:
      logging.error('CIDR format for IP {0} and netmask {1} could not be generated. Error: {2}'.format(ip, netmask, ex))
    return network

  @staticmethod
  def GetLocalNetworkInCIDRFormat():
    network = ''
    try:
      localIP = NetworkUtilsClass.GetLocalIP()
      localNetmask = NetworkUtilsClass.GetLocalNetmaskForIP(localIP)
      network = NetworkUtilsClass.GetNetworkInCIDRFormat(localIP, localNetmask)
    except Exception as ex:
      logging.error('Hosts could not be retrieved for local network configuration. Error: {0}'.format(ex))
    return network

  @staticmethod
  def GeneratePortRanges(ports):
    """
    This method takes a list [] of ports in ordered or unordered state and will look for sequential 'port-ranges'
    within the list. 
    :param ports: List of ports. Example: [1,2,3,5,7,8] 
    :return: Returns a list of PortRange objects. Example: ['1-3', '5', '7-8'] (Note these aren't strings but 
    PortRange objects that has a __str__ method)
    """
    port_ranges = []
    try:
      if ports:
        ports_sorted = sorted(ports)
        new = PortRange(ports_sorted[0])                    # create a new portrange starting on the first port
        port_ranges.append(new)                             # add to port_ranges
        previous = ports_sorted[0]                          # set previous to the first port
        for port in ports_sorted[1:]:                       # iterate through ports, start on second port
          if port != previous+1:                            # check if port breaks range
            if previous != new.lower:                       # is previous port different than new.lower (meaning this is not a one port range)
              new.upper = previous                          # if so set the new.upper
            new = PortRange(port)                           # create new PortRange object
            port_ranges.append(new)                         # and append it to the port_ranges list
          elif port==previous+1 and port==ports_sorted[-1]: # special case if this is last port and its different than the previous port
            new.upper = port                                # make sure to set the upper
          previous = port                                   # update the previous pointer
    except Exception as ex:
      logging.error('PortRange could not be compiled. Error: {0}'.format(ex))
      return ports 
    return port_ranges

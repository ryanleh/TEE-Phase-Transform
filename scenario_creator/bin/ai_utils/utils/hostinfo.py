import logging
from socket import gethostbyname, gethostname
from requests import get
from json import loads
from platform import architecture
from ai_utils.utils.scanner import Scan
import subprocess
import platform

MAX_THREADS = 50

class HostInfoClass(object):
  def __init__(self):
    pass

  @staticmethod
  def GetPublicIpAddress():
    logging.info("Attempting to get public IP address")
    try:
      response = get('http://httpbin.org/ip')
      if response.ok:
        text = loads(response.text)
        ip = text['origin']
        logging.info("Public IP Address: {0}".format(ip))
        return ip
      else:
        logging.error("Unable to retrieve public IP address - {0} {1}".format(response.status_code, response.text))
        return None
    except Exception, e:
      logging.exception('locals:{0}'.format(locals()))
      return None

  @staticmethod
  def GetLocalIpAddress():
    ipAddress = gethostbyname(gethostname())
    logging.info("Local IP Address: {0}".format(ipAddress))
    return ipAddress

  @staticmethod
  def GetGeolocation():
    # http://www.ip2location.com/
    pass

  @staticmethod
  def GetOpenLocalPorts(minimumPortToCheck=1, maximumPortToCheck=1024, on_found_port = None):
    logging.info("Beginning local scan of ports {0}-{1}".format(minimumPortToCheck, maximumPortToCheck))
    localPorts = Scan('localhost', minimumPortToCheck, maximumPortToCheck, MAX_THREADS, on_found_port)
    if localPorts:
      logging.info("Local open port scan successful")
      return localPorts
    else:
      logging.error("Local open port scan failed")
      return None

  @staticmethod
  def GetNeighborOpenPorts(numberOfNeighbors, minimumPortToCheck=1, maximumPortToCheck=1024, on_found_port = None):
    openPortsList = []
    if maximumPortToCheck < minimumPortToCheck:
      logging.error('max_port:{0} cannot be less than min_port:{1}'.format(maximumPortToCheck, minimumPortToCheck))
      return openPortsList
    ipAddress = HostInfoClass.GetLocalIpAddress()
    logging.info("Looking for open ports between {0}-{1} on {2} neighboring IP addresses of {3}".format(minimumPortToCheck, maximumPortToCheck, numberOfNeighbors, ipAddress))
    firstOctet, secondOctet, thirdOctet, fourthOctet = str(ipAddress).split('.')
    for i in range(1, numberOfNeighbors):
      neighborIpAddress = "{0}.{1}.{2}.{3}".format(firstOctet, secondOctet, thirdOctet, i)
      openPorts = Scan(neighborIpAddress, minimumPortToCheck, maximumPortToCheck, MAX_THREADS, on_found_port)
      if openPorts:
        openPortsList.append(openPorts)
    return openPortsList

  @staticmethod
  def GetArchitecture():
    return architecture()[0]

  @staticmethod
  def GetHostname():
    return gethostname()

  @staticmethod
  def BuildLocalIPCIDRBlock():
    cidrBlock = ''
    try:
      ipOctets = HostInfoClass.GetLocalIpAddress().split('.')
      ip = '{}.{}.{}.0'.format(ipOctets[0], ipOctets[1], ipOctets[2])
      cidrMask = HostInfoClass.MaskAddressToCIDR(HostInfoClass.GetMaskAddress())
      cidrBlock = '{}/{}'.format(ip, cidrMask)
    except Exception as e:
      logging.info('Local CIDR Block could not be retrieved. Error: {}'.format(e))
    return cidrBlock

  @staticmethod
  def GetMaskAddress():
    mask = ''
    try:
      ip = HostInfoClass.GetLocalIpAddress()
      isWindows = platform.system() == 'Windows'
      command = 'ipconfig' if isWindows else 'ifconfig'
      proc = subprocess.Popen(command, stdout=subprocess.PIPE)
      line = ''
      while True:
          line = proc.stdout.readline()
          if ip.encode() in line:
              break
      if isWindows:
        mask = proc.stdout.readline().rstrip().split(b':')[-1].replace(b' ',b'').decode()
      else:
        mask = line.rstrip().split(b':')[-1].replace(b' ',b'').decode()
    except Exception as e:
      logging.error('Network mask could not be retrieved. Error: {}'.format(e))
    return mask

  @staticmethod
  def MaskAddressToCIDR(maskAddress):
    return sum([bin(int(x)).count('1') for x in maskAddress.split('.')])


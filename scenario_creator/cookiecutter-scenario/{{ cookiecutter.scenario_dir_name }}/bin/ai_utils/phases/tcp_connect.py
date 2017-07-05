from ai_utils.phases.abstract_phase import AbstractPhaseClass
import socket



class Tcp_connectPhaseClass(AbstractPhaseClass):
  TrackerId = "PHS-e79ea5e8-5aac-11e7-b3e3-000c29c2ba76"
  Subject = "tcp_connect"
  Description = "Test scenario that sends a message over TCP"

  def __init__(self, isPhaseCritical, model):
    AbstractPhaseClass.__init__(self, isPhaseCritical)
    self.ip = model.get('Host IP')
    self.port = model.get('Host Port')
    if model.get('Message'):
      self.message = model.get('Message')
    else:
      self.message = "Hello World!"

  def Setup(self):
    """
    Call validation functions for IP and Host arguments
    """

    if not self.SetupIP(self.ip):
      return False
    self.PhaseReporter.Info('Host IP is: {}'.format(self.ip))

    if not self.SetupPort(self.port):
      return False
    self.PhaseReporter.Info('Host Port is: {}'.format(self.port))

    return True

  def SetupIP(self, ip):
    """
    Checks that string is a valid IP and is routeable from the agent

    :param ip: IP argument specified in model.json
    :type ip: string
    """
    # Check if valid IP format and range
    pieces = ip.split(".")
    if len(pieces) != 4 or not all(0 <= int(p) < 256 for p in pieces):
      self.PhaseReporter.Info('Invalid IP {}'.format(ip))
      return False



    try:
      # Sketchy socket connection to grab local ip
      s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
      s.connect(("8.8.8.8", 80))
      local_ip = s.getsockname()[0]
      lip_split = local_ip.split('.')

      #See if given IP is on same subnet... if not, check if it's routable
      if not all(l == p for l,p in zip(lip_split[:3],pieces[:3])):
        socket.gethostbyaddr(ip)


    except socket.herror:
      self.PhaseReporter.Info('No route to host {} detected'.format(ip))
      return False


    return True

  def SetupPort(self, port):
    """
    Checks that given string is an int and within port range

    :param port: Port argument specified in model.json
    :type port: string
    """
    try:
      self.port = int(port)
    except ValueError:
      self.PhaseReporter.Info('Invalid Port {}'.format(port))
      return False

    return True

  def Run(self):

    self.PhaseReporter.Info('Starting TCP_connect phase with options: {} {}'.format(self.ip, self.port))
    phaseSuccess = self.run()
    self.PhaseReporter.Info('Phase result: {}'.format(phaseSuccess))
    return phaseSuccess

  def run(self):
    """
    Phase executor - creates socket object, forms connection to specified host
      and port, and sends specified message
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
      sock.connect((self.ip, self.port))
      sock.sendall(self.message)
      sock.sendall("\n")
    except socket.error as e:
      self.PhaseReporter.Info('Socket Error: {}'.format(e))
      return False

    self.PhaseReporter.Info('Successfully sent message: {}'.format(self.message))
    return True





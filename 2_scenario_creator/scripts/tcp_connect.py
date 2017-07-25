from abstract_circadence_phase import AbstractCircadencePhase
import socket



class Tcp_connectPhaseClass(AbstractCircadencePhase):
  TrackerId = "PHS-e79ea5e8-5aac-11e7-b3e3-000c29c2ba76"
  Subject = "tcp_connect"
  Description = "Test scenario that sends a message over TCP"

  required_input_parameters = {'RHOST': None, 'RPORT': None}
  optional_input_parameters = {'Message': "Hello World!"}
  output_parameters = {}


  def __init__(self, info):
    AbstractCircadencePhase.__init__(self, info)

    assert RHOST in info
    assert RPORT in info
    assert MESSAGE in info


  def Setup(self):
    """
    Call validation functions for IP and Host arguments
    """

    if not self.SetupIP(self.PhaseResult['RHOST']):
      return False
    else:
      self.PhaseReporter.Info('Host IP is: {}'.format(self._rhost))

    if not self.SetupPort(self.PhaseResult['RPORT']):
      return False
    else:
      self.PhaseReporter.Info('Host Port is: {}'.format(self._rport))

    self._message = self.PhaseResult['MESSAGE']


    return True

  def SetupIP(self, rhost):
    """
    Checks that string is a valid IP and is routeable from the agent

    :param rhost: IP argument specified in model.json
    :type rhost: string
    """
    # Check if valid IP format and range
    pieces = rhost.split(".")
    if len(pieces) != 4 or not all(0 <= int(p) < 256 for p in pieces):
      self.PhaseReporter.Info('Invalid IP {}'.format(rhost))
      return False



    try:
      # Sketchy socket connection to grab local ip
      s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
      s.connect(("8.8.8.8", 80))
      local_ip = s.getsockname()[0]
      lip_split = local_ip.split('.')

      #See if given IP is on same subnet... if not, check if it's routable
      if not all(l == p for l,p in zip(lip_split[:3],pieces[:3])):
        socket.gethostbyaddr(rhost)


    except socket.herror:
      self.PhaseReporter.Info('No route to host {} detected'.format(rhost))
      return False

    self._rhost = rhost
    return True

  def SetupPort(self, port):
    """
    Checks that given string is an int and within port range

    :param port: Port argument specified in model.json
    :type port: string
    """
    try:
      self._rport = int(rport)
    except ValueError:
      self.PhaseReporter.Info('Invalid Port {}'.format(_rport))
      return False

    return True

  def Run(self):

    self.PhaseReporter.Info('Starting TCP_connect phase with options: {} {} {}'.format(self._rhost, self._rport, self._message))
    phaseSuccess = self.run()

    self._progress = 100
    self.PhaseReporter.Info('Phase result: {}'.format(phaseSuccess))
    return phaseSuccess

  def run(self):
    """
    Phase executor - creates socket object, forms connection to specified host
      and port, and sends specified message
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
      sock.connect((self._rhost, self._rport))
      sock.sendall(self._message)
      sock.sendall("\n")
    except socket.error as e:
      self.PhaseReporter.Info('Socket Error: {}'.format(e))
      return False

    self.PhaseReporter.Info('Successfully sent message: {}'.format(self._message))
    return True

def create(info):
    """
        Create a new instance of the stage object.
        @return: instance of the stage object
    """
    return Tcp_connectPhaseClass(info)



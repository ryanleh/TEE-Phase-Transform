import logging
import socket
try:
  from ipaddr import IPAddress
  # noinspection PyUnresolvedReferences
  import dns.resolver
except:
  logging.exception('error importing')
from ai_utils.phases.abstract_phase import AbstractPhaseClass

class DNSSinkholePhaseClass(AbstractPhaseClass):
  TrackerId = "230"
  Subject = "Validate Domain Points to Internal Nameserver"
  Description = "Validate Domain Points to Internal Nameserver"

  def __init__(self, isPhaseCritical, sinkholedDomainList):
    AbstractPhaseClass.__init__(self, isPhaseCritical)
    self.SinkholedDomainList = sinkholedDomainList
    self.PubliclyResolvedCount = 0

  def Setup(self):
    return len(self.SinkholedDomainList) > 0

  @staticmethod
  def QueryDomain(domain):
    try:
      return dns.resolver.query(domain, 'NS')
    except Exception, e:
      logging.exception(e)
      return None

  @staticmethod
  def GetIpOfHost(hostName):
    try:
      return socket.gethostbyname(hostName)
    except Exception, e:
      logging.exception(e)
      return None

  @staticmethod
  def CheckIfIpIsPrivate(ip):
    successful = False
    try:
      ipaddr_obj = IPAddress(ip)
      successful = True
      return successful, ipaddr_obj.is_private
    except Exception, e:
      logging.exception(e)
      return successful

  def ResolveDomain(self, domain):
    answers = self.QueryDomain(domain)
    if not answers:
      self.PhaseReporter.Info('domain {0} can not be resolved'.format(domain))
      return
    for server in answers:
      nameserver_domain =  server.target.labels[0] + "." + server.target.labels[1] + "." + server.target.labels[2]
      ip = self.GetIpOfHost(nameserver_domain)
      if not ip:
        self.PhaseReporter.Info('name server {0} for domain {1} can not be resolved)'.format(nameserver_domain, domain))
        continue
      successful, private = self.CheckIfIpIsPrivate(ip)
      if successful and not private:
        self.PubliclyResolvedCount += 1
        self.PhaseReporter.Info('domain {0} resolves to an external name server {1} ({2})'.format(domain,nameserver_domain, ip))

  def ResolveDomains(self):
    for domain in self.SinkholedDomainList:
      self.ResolveDomain(domain)
    return self.PubliclyResolvedCount > 0

  def Run(self):
    phaseSuccessful = self.ResolveDomains()
    if phaseSuccessful:
      self.PhaseReporter.Info('Successfully resolved name using external name server')
      self.PhaseReporter.Report('A list of domains that should be sinkholed by your DNS server resolved to an external name server.')
      self.PhaseReporter.Mitigation('The following domains should be sinkholed by your DNS server: {}'.format(",".join(self.SinkholedDomainList)))
    else:
      self.PhaseReporter.Info('Failed to resolve name using external name server')
    return phaseSuccessful
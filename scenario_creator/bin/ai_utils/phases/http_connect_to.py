import logging
import requests
from ai_utils.phases.abstract_phase import AbstractPhaseClass
from ai_utils.scenarios.globals import NetworkUtils, StringUtils


class HttpConnectToPhaseClass(AbstractPhaseClass):
  TrackerId = "221"
  Subject = "HTTP Connection"
  Description = "Try to connect to url using HTTP protocol"

  def __init__(self, isPhaseCritical, listOfUrlsToConnect):
    AbstractPhaseClass.__init__(self, isPhaseCritical)
    logging.info('Executing HTTP Connect To phase...')
    assert isinstance(listOfUrlsToConnect, list)
    self.ListOfUrlsToConnect = []
    self.ListOfUrlsAvailable = []
    self.AppendUrlPrefixTo(listOfUrlsToConnect)

  def AppendUrlPrefixTo(self, listOfUrlsToConnect):
    for url in listOfUrlsToConnect:
      self.ListOfUrlsToConnect.append(NetworkUtils.CheckUrlPrefix(url))

  def Setup(self):
    if len(self.ListOfUrlsToConnect) == 0:
      return False
    return True

  def ConnectToUrl(self, urlToConnectTo):
    logging.info('Connecting to {}'.format(urlToConnectTo))
    successful = False
    try:
      response = requests.get(urlToConnectTo, timeout=10)
      if response and response.status_code == 200:
        self.ListOfUrlsAvailable.append(urlToConnectTo)
        successful = True
    except requests.Timeout:
      self.PhaseReporter.Debug('Request to {} timed out'.format(urlToConnectTo))
    except Exception as e:
      self.PhaseReporter.Debug('Could not connect to the address {}. Error: {}'.format(urlToConnectTo, e))
    return successful

  def ConnectToUrls(self):
    self.PhaseReporter.Info('Attempting to connect to provided site(s)')
    for urlToConnectTo in self.ListOfUrlsToConnect:
      if self.ConnectToUrl(urlToConnectTo):
        self.PhaseReporter.Info('Successfully connected to {0}'.format(urlToConnectTo))
      else:
        self.PhaseReporter.Info('Failed to connect to {0}'.format(urlToConnectTo))
    return len(self.ListOfUrlsAvailable)

  def Run(self):
    phaseSuccessful = self.ConnectToUrls()
    if phaseSuccessful:
      self.PhaseReporter.Info('HTTP connections successfully established with: {}'.format(', '.join(self.ListOfUrlsAvailable)))
      self.PhaseResult['urls_can_be_connected_to'] = StringUtils.ConvertListToString(self.ListOfUrlsAvailable)
    return phaseSuccessful
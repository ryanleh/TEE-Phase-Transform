import logging
from ai_utils.phases.abstract_phase import AbstractPhaseClass
from ai_utils.scenarios.globals import FileUtils, PathUtils
from ai_utils.net.packet_injector import AiPacketInjector

class ReplayPCAPPhaseClass(AbstractPhaseClass):
    TrackerId = "PHS-50527e5e-d60d-11e4-8745-0002723df7f2"
    Subject = "Replay PCAP"
    Description = "This phase injects to the network traffic defined in a PCAP file"

    def __init__(self, isPhaseCritical, pcapFilename):
        AbstractPhaseClass.__init__(self, isPhaseCritical)
        logging.info(Messages.INFO1)
        self.PCAPFilename = self._SetupPCAPFilename(pcapFilename)

    def Setup(self):
        if FileUtils.GetFilesize(self.PCAPFilename) <= 0:
            self.PhaseReporter.Error(Messages.ERROR2)
            return False
        return True

    def Run(self):
        phaseSuccessful = self._InjectTraffic()
        self._LogSuccess(phaseSuccessful)
        return phaseSuccessful

    ###
    # Internal Methods
    ##################

    def _InjectTraffic(self):
        logging.info(Messages.INFO3)
        try:
            with AiPacketInjector() as injector:
                success = injector.InjectPCAP(self.PCAPFilename)
            self._LogInjectionSuccess(success)
        except Exception as ex:
            success = False
            logging.error(Messages.ERROR1.format(ex))
        return success

    def _LogInjectionSuccess(self, success):
        if success:
            logging.info(Messages.INFO7)
        else:
            logging.warning(Messages.INFO6)

    def _LogSuccess(self, success):
        if success:
            self.PhaseReporter.Info(Messages.WARN1.format(self.PCAPFilename))
        else:
            self.PhaseReporter.Info(Messages.INFO2.format(self.PCAPFilename))

    def _SetupPCAPFilename(self, pcapFilename):
        param = ''
        if pcapFilename:
            param = str(pcapFilename)
            logging.info(Messages.INFO4.format(param))
        else:
            param = PathUtils.GetScenarioBinDirectory() + '\\ping.pcap'
            logging.error(Messages.INFO5.format(param))
        return param


class Messages(object):
    INFO1 = 'Executing PCAP Replay phase...'
    INFO2 = 'Failed to inject network traffic from PCAP file: {0}'
    INFO3 = 'Injecting PCAP file traffic...'
    INFO4 = 'PCAP filename parameter is {0}'
    INFO5 = 'Using default PCAP file: {0}'
    INFO6 = 'Traffic could not be injected using AiPacketInjector'
    INFO7 = 'Traffic was correctly injected using AiPacketInjector'

    WARN1 = 'Network traffic was successfully injected from PCAP file: {0}'

    ERROR1 = 'Error injecting traffic from pcap file: {0}'
    ERROR2 = 'Error checking PCAP path parameter. File is empty or not accessible.'

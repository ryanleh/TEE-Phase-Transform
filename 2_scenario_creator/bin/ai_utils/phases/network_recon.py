from ai_utils.utils.hostinfo import HostInfoClass as HostInfo
from ai_utils.phases.abstract_phase import AbstractPhaseClass

class NoisyReconPhaseClass(AbstractPhaseClass):
    TrackerId = "126"
    Subject = "Local Network Reconnaissance"
    Description = "Local Network Reconnaissance"

    def __init__(self, isPhaseCritical, minimumPortToCheck, maximumPortToCheck, numberOfNeighbors):
        AbstractPhaseClass.__init__(self, isPhaseCritical)
        self.MinimumPortToCheck = minimumPortToCheck
        self.MaximumPortToCheck = maximumPortToCheck
        self.NumberOfNeighbors = numberOfNeighbors
        self.ReconData = {
          'public_ip' : None,
          'open_ports' : []
        }

    def Setup(self):
        if self.MaximumPortToCheck < self.MinimumPortToCheck:
            self.PhaseReporter.Error('MaximumPortToCheck {0} smaller than MinimumPortToCheck {1}'.format(self.MaximumPortToCheck, self.MinimumPortToCheck))
            return False
        return True

    def OnFoundPort(self, result):
        self.PhaseReporter.Info(result)
        self.ReconData['open_ports'].append(result)

    def Recon(self):
        self.PhaseReporter.Info("Beginning local reconnaissance")
        publicIp = HostInfo.GetPublicIpAddress()
        if publicIp:
            self.ReconData['public_ip'] = publicIp
        HostInfo.GetOpenLocalPorts(self.MinimumPortToCheck, self.MaximumPortToCheck, self.OnFoundPort)
        HostInfo.GetNeighborOpenPorts(self.NumberOfNeighbors, self.MinimumPortToCheck, self.MaximumPortToCheck, self.OnFoundPort)
        return self.ReconData is not None

    def Run(self):
        phaseSuccessful = self.Recon()
        if phaseSuccessful:
            self.PhaseResult['recon_data_retrieved'] = str(self.ReconData)
            self.PhaseReporter.Info('Local network reconnaissance was successful')
        else:
            self.PhaseReporter.Info('Local network reconnaissance failed')
        return phaseSuccessful

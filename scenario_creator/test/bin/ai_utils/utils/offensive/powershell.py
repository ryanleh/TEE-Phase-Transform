from ai_utils.scenarios.globals import PathUtils, FileUtils
from ai_utils.utils.filecollector import FileCollectorClass
import logging
import os
try:
  import aipythonlib
except Exception as e:
  logging.error('Error importing aipythonlib: {0}'.format(e))


class PowershellUtilsClass(object):

  PathUtils.AddToSearchPath(r'C:\WINDOWS\system32\WindowsPowerShell')
  fc = FileCollectorClass([r'C:\WINDOWS\system32\WindowsPowerShell'], ['powershell.exe'], maximumCount=1)
  if fc.Collect():
    POWERSHELL_BINARY = fc.ListOfFiles[0]
  else:
    POWERSHELL_BINARY = None
  POWERSHELL_GENERIC_CMD = '{0}'

  @staticmethod
  def ExecutePowerShellCommand(PowerShellCmd, format='Format-List', timeout=3000, print_output=True):
    """
    This method executes a PowerShell command. By default, the output of the command is send back in Format-List.
    Kwargs:
       command (str): PowerShell command.
       format (str): The format used to show the command output. Default: Format-List.
       timeout (int): Number of milliseconds to wait until killing the process executing the PowerShell command.
       print_output (bool): Variable to specify if powershell command output should be printed in the logs

    Returns:
       str.  The output of the command.
       int.  The exit code of the command.
    """
    logging.debug('Executing ExecutePowerShellCommand. PowerShellCmd: {}, format: {}, timeout: {}'.format(PowerShellCmd, format, timeout))
    result = ''
    exitCode = -1
    if format:
      command = PowershellUtilsClass.POWERSHELL_GENERIC_CMD.format(PowerShellCmd, format)
    else:
      command = PowershellUtilsClass.POWERSHELL_GENERIC_CMD.format(PowerShellCmd)
    if PowershellUtilsClass.POWERSHELL_BINARY:
      logging.info(PowershellUtilsClass.INFO4.format(PowershellUtilsClass.POWERSHELL_BINARY + ' ' + command))
      errorCode, exitCode, stdOut, stdError = aipythonlib.AiRunCommand(PowershellUtilsClass.POWERSHELL_BINARY, command, timeout, True)
      if print_output:
        logging.info(PowershellUtilsClass.INFO5.format(errorCode, exitCode, stdOut, stdError))
      else:
        logging.info(PowershellUtilsClass.INFO6.format(errorCode, exitCode, stdError))
      if PowershellUtilsClass._LogSuccess(exitCode, errorCode, stdError):
        result = stdOut.strip()
    else:
      logging.error(PowershellUtilsClass.ERROR1)
    return result, exitCode

  @staticmethod
  def ParseFormatListString(formatListString):
    """
    This method parses the output of a PowerShell command in Format-List format and returns a list with each result as
    a dictionary.

    Kwargs:
       formatListString (str): A Format-List formatted string coming from the output of PowerShell.

    Returns:
       list.  A list with each result in the formatListString parameter built as a dictionary object.
    """
    resultList = []
    try:
      formatListString = formatListString.strip()
      objects = formatListString.split(2 * os.linesep)
      for object in objects:
        objectItems = object.split(os.linesep)
        resultDict = {}
        for item in objectItems:
          key_value = item.split(':', 1)
          resultDict[key_value[0].strip()] = key_value[1].strip()
        resultList.append(resultDict)
    except Exception as e:
      logging.error(PowershellUtilsClass.ERROR3.format(e))
    return resultList

  @staticmethod
  def _LogSuccess(exitCode, errorCode, stdError):
    success = False
    if exitCode == 0 and errorCode == 0 and not stdError:
      logging.info(PowershellUtilsClass.INFO2)
      success = True
    else:
      logging.error(PowershellUtilsClass.ERROR2.format(exitCode, errorCode, stdError.strip()))
    return success

  ###
  # Constant strings
  ##################

  INFO2 = 'PowerShell command was successful. Exit Code is 0, Error Code is 0 and no error message.'
  INFO3 = 'Output: {0}'
  INFO4 = 'Command: {0}'
  INFO5 = 'PowerShell execution: error_code: "{}", exit_code: "{}", std_output: "{}", std_error: "{}"'
  INFO6 = 'PowerShell execution: error_code: "{}", exit_code: "{}", std_error: "{}"'

  ERROR1 = 'PowerShell application (powershell.exe) could not be found in the system'
  ERROR2 = 'Failed to execute PowerShell command. Exit Code: {0}, Error Code: {1}. Error Message: {2}'
  ERROR3 = 'CSV string could not be correctly parsed'
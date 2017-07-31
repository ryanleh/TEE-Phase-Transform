from ai_utils.phases.abstract_phase import AbstractPhaseClass
from platform import system
import subprocess
import logging
import sys
import os

try:
    import aipythonlib
except Exception as err:
    logging.error('Unable to import aipythonlib. Scenario may not function correctly. Error: {}'.format(err))


class ValidateDiskEncryptionPhaseClass(AbstractPhaseClass):
    TrackerId = "PHS-88f5fa1c-1a26-11e7-b887-e4a471d9d2ee"
    Subject = "validate_encryption"
    Description = "Validate that full disk encryption is enabled for Windows and macOS"

    def __init__(self, is_phase_critical):
        """
        This phase is intended to validate whether or not disk encryption is enabled for Windows or macOS.

        For Windows, this phase will be successful if BitLocker is enabled.
        For macOS, this phase will be successful if FileVault is enabled.

        Args:
          is_phase_critical (bool): Identifies whether phase is critical to scenario execution.

        Returns:
          bool: True if phase successful, otherwise False.
        """
        AbstractPhaseClass.__init__(self, is_phase_critical)
        logging.debug('Executing ValidateEncryptionPhaseClass constructor')

    def Run(self):
        logging.debug('Executing Run method')
        operating_system = system()
        encryption_enabled = False
        if operating_system == "Windows":
            encryption_enabled = self.windows_validate_encryption()
        elif operating_system == "Darwin":
            encryption_enabled = self.macos_validate_encryption()
        self.log_phase_results(encryption_enabled)
        return encryption_enabled

    def windows_validate_encryption(self):
        logging.debug('Executing validate_encryption_windows method')
        bitlocker_status_command = '-status %SYSTEMDRIVE% -p'
        error_code, exit_code, std_out, std_err = aipythonlib.AiRunCommand('manage-bde', bitlocker_status_command, 0)
        if error_code:
            logging.error('Unable to get Bitlocker encryption status. '
                          'ERRORCODE: {} STDOUT: {} STDERR: {}'.format(error_code, std_out, std_err))
            self.PhaseReporter.Error('An error occurred while attempting to get the BitLocker encryption status.')
        self.PhaseReporter.Debug('Command "manage-bde -status %SYSTEMDRIVE% -p" returned with '
                                 'exit code {} and '
                                 'error_code {}.'.format(exit_code, error_code))
        return error_code == 0 and exit_code == 0

    def macos_validate_encryption(self):
        logging.debug('Executing execute_command_windows method')
        try:
            return_code = subprocess.check_call(['fdesetup', 'isactive'])
        except subprocess.CalledProcessError as e:
            logging.error('Error occurred while attempting to determine the encryption status. '
                          'Return Code: {} Output: {}'.format(e.returncode, e.output))
            return_code = e.returncode
        self.PhaseReporter.Debug('Command "fdesetup isactive" returned with status code {}.'.format(return_code))
        return return_code == 0

    def log_phase_results(self, encryption_enabled):
        if encryption_enabled:
            self.PhaseReporter.Info('Validation Passed. Hard drive is fully or partially encrypted.')
        else:
            self.PhaseReporter.Info('Validation Failed. Encryption is disabled.')

from ai_utils.phases.abstract_phase import AbstractPhaseClass
from ai_utils.ai_logging.simplelogger import AiLoggerClass
import logging
import base64
try:
    import aipythonlib
except Exception as e:
    logging.error('Error importing aipythonlib: {0}'.format(e))


class EncodeAndExecutePowershellScriptPhaseClass(AbstractPhaseClass):
    TrackerId = "843"
    Subject = "EncodeAndExecutePowershellScript"
    Description = "This phase base64 encodes a user defined powershell script, and executes it from the powershell command line."

    def __init__(self, is_phase_critical, shell_input, run_as_logged_in_user, timeout=5000):
        """
        This phase attempts to encode and execute a powershell command/script.

        :param is_phase_critical(boolean): Determines if the phase is critical to scenario execution.
        :param shell_input(string): The shell command/script that is to be encoded and executed.
        :param run_as_logged_in_user(boolean): Determines if Powershell script will be executed as a logged in user.
        :param timeout(int): Used to specify a maximum amount of time that the Powershell script/command is allowed to run for.

        :return: True if powershell command/script was executed successful, false otherwise
        """
        AbstractPhaseClass.__init__(self, is_phase_critical)
        AiLoggerClass(loggingLevel=logging.DEBUG).Enable()
        logging.debug('Executing Encode and Execute Powershell Script Phase')
        self.run_as_logged_in_user = self.setup_run_as_logged_in_user(run_as_logged_in_user)
        self.shell_input = self.setup_shell_input(shell_input)
        self.timeout = self.setup_timeout(timeout)
        self.default_timeout = 5000

    def Setup(self):
        logging.debug('Executing Setup method')
        if not self.timeout > 0:
            self.PhaseReporter.Error('Invalid timeout parameter provided. Phase execution will halt.')
            return False
        if not self.shell_input:
            self.PhaseReporter.Error('Invalid shell input parameter provided. Phase execution will halt.')
            return False
        return True

    def Run(self):
        logging.debug('Executing Run method')
        shell_command = self.prepare_powershell_command()
        phase_outcome = self.execute_powershell_command(shell_command)
        self.log_phase_success(phase_outcome)
        return phase_outcome

    def prepare_powershell_command(self):
        logging.debug('Executing prepare_powershell_command method')
        encoded_shell_command = self.encode_powershell_command(self.shell_input)
        encoded_shell_command = ' -InputFormat None -EncodedCommand "{0}" '.format(encoded_shell_command)
        return encoded_shell_command

    @staticmethod
    def encode_powershell_command(shell_command):
        logging.debug('Executing encode_powershell_command method')
        encoded_shell_command = shell_command.encode('UTF-16LE')
        base64encoded_shell_command = base64.b64encode(encoded_shell_command)
        return base64encoded_shell_command

    def execute_powershell_command(self, shell_command):
        logging.debug('Executing execute_powershell_command method. shell_command: {}'.format(shell_command))
        execution_outcome = False
        try:
            execution_outcome = self.execute_powershell_command_aipython(shell_command)
        except Exception as e:
            self.PhaseReporter.Error('An error occurred while executing the powershell script. Error: {}'.format(e))
        return execution_outcome

    def execute_powershell_command_aipython(self, shell_command):
        logging.debug('Executing execute_powershell_command_aipython method. shell_command: {}'.format(shell_command))
        self.PhaseReporter.Info('Executing powershell command: {}. . .'.format(shell_command[:48]))
        if not self.run_as_logged_in_user:
            error_code, exit_code, stdout, stderr = aipythonlib.AiRunCommand('powershell', shell_command, self.timeout)
        else:
            error_code, exit_code, stdout, stderr = aipythonlib.AiRunCommandAsActiveLoggedInUser('powershell',
                                                                                                 shell_command, self.timeout)
        execution_outcome = self.get_execution_outcome(exit_code, error_code)
        return execution_outcome

    def get_execution_outcome(self, exit_code, error_code):
        logging.debug('Executing get_execution_outcome method. exit_code: {} error_code: {}'.format(exit_code, error_code))
        if exit_code == 0 and error_code == 0:
            return True
        return False

    def log_phase_success(self, phase_successful):
        logging.debug('Executing log_phase_success method. phase_successful: {}'.format(phase_successful))
        if phase_successful:
            self.PhaseReporter.Info('Execution of encoded PowerShell script succeeded')
        else:
            self.PhaseReporter.Info('Execution of encoded Powershell script failed')

    def setup_shell_input(self, shell_input):
        logging.debug('Executing setup_shell_input method. shell_input: {}'.format(shell_input))
        self.PhaseReporter.Debug('Shell Input is {0}'.format(shell_input))
        return shell_input

    def setup_run_as_logged_in_user(self, run_as_logged_in_user):
        logging.debug('Executing setup_run_as_logged_in_user method. '
                      'run_as_logged_in_user: {}'.format(run_as_logged_in_user))
        self.PhaseReporter.Debug('Run as Logged In User parameter: {}'.format(run_as_logged_in_user))
        return run_as_logged_in_user

    def setup_timeout(self, timeout):
        logging.debug('Executing setup_timeout method. timeout: {}'.format(timeout))
        if type(timeout) == int and timeout > 0:
            param = timeout
        else:
            self.PhaseReporter.Debug('Invalid timeout parameter passed. Using default timeout value: '
                                     '{}'.format(self.timeout_default))
            param = self.timeout_default
        self.PhaseReporter.Debug('Timeout parameter: {}'.format(param))
        return param

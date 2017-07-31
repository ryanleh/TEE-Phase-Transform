from ai_utils.utils.offensive.pass_the_hash.undetectable_mimikatz.undetectable_mimikatz_agent import UndetectableMimikatzAgent
from ai_utils.utils.offensive.pass_the_hash.mimikatz.mimikatz_agent import MimikatzAgent
import logging


class PassTheHashFactory(object):

    def __init__(self, pth_tool, password_hash, target_machine='', username='', fqdn='', remote_command_script='', command_log_path='', test_success_pattern='', timeout=30000, phase_reporter=None):
        logging.debug('Executing PassTheHashFactory constructor. pth_tool: {}, password_hash: {}(...), target_machine: {}, username: {}, fqdn: {}, remote_command_script: {}, command_log_path: {}, test_success_pattern: {}, timeout: {}, phase_reporter: {}'.format(pth_tool, password_hash[:3], target_machine, username, fqdn, remote_command_script, command_log_path, test_success_pattern, timeout, phase_reporter))
        self.pth_tool = pth_tool
        self.phase_reporter = phase_reporter
        self.password_hash = password_hash
        self.target_machine = target_machine
        self.username = username
        self.fqdn = fqdn
        self.remote_command_script = remote_command_script
        self.command_log_path = command_log_path
        self.test_success_pattern = test_success_pattern
        self.timeout = timeout

    def create_agent(self):
        logging.debug('Executing create_agent')
        if self.pth_tool == 'mimikatz':
            return MimikatzAgent(self.password_hash, self.target_machine, self.username, self.fqdn, self.remote_command_script, self.command_log_path, self.test_success_pattern, self.timeout, self.phase_reporter)
        elif self.pth_tool == 'undetectable_mimikatz':
            return UndetectableMimikatzAgent(self.password_hash, self.target_machine, self.username, self.fqdn, self.remote_command_script, self.command_log_path, self.test_success_pattern, self.timeout, self.phase_reporter)
        else:
            self.phase_reporter.Warn('Agent creation with invalid pass the hash tool "{}". Falling back to Mimikatz'.format(self.pth_tool or 'empty'))
            return MimikatzAgent(self.password_hash, self.target_machine, self.username, self.fqdn, self.remote_command_script, self.command_log_path, self.test_success_pattern, self.timeout, self.phase_reporter)

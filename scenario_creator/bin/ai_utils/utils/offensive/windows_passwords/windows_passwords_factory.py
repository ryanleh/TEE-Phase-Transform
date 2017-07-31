from ai_utils.utils.offensive.windows_passwords.mimikatz.mimikatz_agent import MimikatzAgent
from ai_utils.utils.offensive.windows_passwords.undetectable_mimikatz.undetectable_mimikatz_agent import UndetectableMimikatzAgent
import logging


class WindowsPasswordsFactory(object):

    def __init__(self, pwd_dumping_tool, cred_types=None, usernames=None, phase_reporter=None):
        logging.debug('Executing WindowsPasswordsFactory constructor. pwd_dumping_tool: {}'.format(pwd_dumping_tool))
        self.pwd_dumping_tool = pwd_dumping_tool
        self.phase_reporter = phase_reporter
        self.cred_types = cred_types
        self.usernames = usernames
    
    def create_agent(self):
        logging.debug('Executing create_agent')
        if self.pwd_dumping_tool == 'mimikatz':
            return MimikatzAgent(self.cred_types, self.usernames, self.phase_reporter)
        elif self.pwd_dumping_tool == 'undetectable_mimikatz':
            return UndetectableMimikatzAgent(self.cred_types, self.usernames, self.phase_reporter)
        else:
            self.phase_reporter.Warn('Agent creation with invalid password dumping tool "{}". Falling back to Mimikatz'.format(self.pwd_dumping_tool or 'empty'))
            return MimikatzAgent(self.cred_types, self.usernames, self.phase_reporter)

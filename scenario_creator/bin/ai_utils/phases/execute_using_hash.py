from ai_utils.utils.offensive.pass_the_hash.pth_factory import PassTheHashFactory
from ai_utils.phases.abstract_phase import AbstractPhaseClass
import logging

try:
  # noinspection PyUnresolvedReferences
  import aipythonlib
except Exception as e:
  logging.error('Error importing aipythonlib: {0}'.format(e))


class ExecuteUsingHashPhaseClass(AbstractPhaseClass):
  TrackerId = "129"
  Subject = "Pass the hash"
  Description = "Pass the hash"

  mimikatz_binary_name = 'mimikatz.exe'

  def __init__(self, is_phase_critical, pth_tool, password_hash, target_machine='', username='', fqdn='', remote_command_script='', command_log_path='', test_success_pattern='', timeout=30000):
    logging.debug('Executing Execute Using Hash phase constructor. pth_tool: {}, password_hash: {}(...), target_machine: {}, username: {}, fqdn: {}, remote_command_script: {}, command_log_path: {}, test_success_pattern: {}, timeout: {}'.format(pth_tool, password_hash[:3], target_machine, username, fqdn, remote_command_script, command_log_path, test_success_pattern, timeout))
    AbstractPhaseClass.__init__(self, is_phase_critical)
    self.pth_agent = PassTheHashFactory(
      pth_tool, password_hash, target_machine, username, fqdn, remote_command_script,command_log_path, test_success_pattern, timeout, self.PhaseReporter
    ).create_agent()

  def Run(self):
    logging.debug('Executing Run')
    return self.pth_agent.pass_the_hash()

  def Cleanup(self):
    logging.debug('Executing Cleanup')
    # Do not remove log or script here given that user may need them for scenario fulfill purposes
    # Adding removals here will break golden_ticket scenario
    return True

  def remove_output_log(self):
    logging.debug('Executing remove_output_log')
    return self.pth_agent.remove_output_log()

  def remove_script(self):
    logging.debug('Executing remove_script')
    return self.pth_agent.remove_script()

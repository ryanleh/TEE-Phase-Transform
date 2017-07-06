from ai_utils.scenarios.globals import PathUtils, NetworkUtils, FileUtils
import logging


class MimikatzSetup(object):

  def __init__(self, phase_reporter):
    logging.debug('Executing MimikatzSetup constructor')
    self.phase_reporter = phase_reporter

  def setup_timeout(self, timeout):
    logging.debug('Executing setup_timeout. timeout: {}'.format(timeout))
    if timeout <= 0:
      logging.warning('Timeout is lesser than 0. Set to 30000 by default')
      param = 30000
    else:
      param = timeout or 30000
    return param

  def setup_fqdn(self, fqdn):
    logging.debug('Executing setup_fqdn. fqdn: {}'.format(fqdn))
    param = str(fqdn) or NetworkUtils.GetMachineFQDN()
    return param

  def setup_user(self, user):
    logging.debug('Executing setup_user. user: {}'.format(user))
    param = str(user) or 'Administrator'
    return param

  def setup_remote_command_script(self, remote_command_script, fqdn, remote_machine_name='', log_file=''):
    logging.debug('Executing setup_remote_command_script. remote_command_script: {}, remote_machine_name: {}, log_file: {}'.format(remote_command_script, remote_machine_name, log_file))
    from_user = False
    if remote_command_script:
      from_user = True
      param = str(remote_command_script)
    else:
      param = self._build_remote_command_script(remote_machine_name, log_file, fqdn)
    self._log_remote_command_script(param, from_user)
    return param

  @staticmethod
  def get_domain_from_fqdn(fqdn):
    logging.debug('Executing get_domain_from_fqdn. fqdn: {}'.format(fqdn))
    return fqdn.split('.')[-2] if fqdn.find('.') != -1 else fqdn

  def setup_target_machine(self, target_machine, fqdn=''):
    logging.debug('Executing setup_target_machine. target_machine: {}, fqdn: {}'.format(target_machine, fqdn))
    if target_machine:
      param = str(target_machine)
    else:
      param = self._find_domain_controller(fqdn)
    self._log_target_machine(target_machine, fqdn)
    return param

  def setup_remote_command_output_log_path(self, remote_command_output_log_path):
    logging.debug('Executing setup_remote_command_output_log_path. remote_command_output_log_path: {}'.format(remote_command_output_log_path))
    from_user = False
    if remote_command_output_log_path:
      param = str(remote_command_output_log_path)
      from_user = True
    else:
      param = PathUtils.GetTempFile(prefixArg='ai_euh_log_', suffixArg='.log')
    self._log_remote_command_output_log_path(param, from_user)
    return param

  @staticmethod
  def setup_test_success_pattern(test_success_pattern):
    logging.debug('Executing setup_test_success_pattern. test_success_pattern: {}'.format(test_success_pattern))
    param = str(test_success_pattern) or 'Pass the Hash Successful'
    if param:
      logging.info('Test Success Pattern value used to execute passing the hash: {0}'.format(param))
    else:
      logging.warning('Test Success Pattern value to execute passing the hash could not be retrieved.')
    return param

  ##
  # Internal methods
  ###

  def _find_domain_controller(self, fqdn):
    logging.debug('Executing _find_domain_controller. fqdn: {}'.format(fqdn))
    self._log_debug('User has not specified target machine. Searching domain controller machine...')
    dc_machine_name = NetworkUtils.GetDomainControllerMachineName()
    if fqdn:
      param = dc_machine_name + '.' + fqdn
    else:
      new_fqdn = NetworkUtils.GetMachineFQDN()
      param = dc_machine_name + '.' + new_fqdn if new_fqdn else dc_machine_name
    return param

  def _log_target_machine(self, target_machine, from_user):
    logging.debug('Executing _log_target_machine. target_machine: {}, from_user: {}'.format(target_machine, from_user))
    if target_machine:
      if not from_user:
        self._log_debug('Retrieved target machine name (Domain Controller): {0}'.format(target_machine))
    else:
      logging.warning('Target Machine name to execute passing the hash could not be retrieved.')

  def _log_remote_command_script(self, remote_command_script, from_user):
    logging.debug('Executing _log_remote_command_script. remote_command_script: {}, from_user: {}'.format(remote_command_script, from_user))
    if remote_command_script:
      if not from_user:
        self._log_debug('Command to be executed using Pass The Hash has not been specified by the user. Default command will map the remote admin$ share')
    else:
      logging.warning('Remote Command Script value to execute passing the hash could not be retrieved.')

  def _build_remote_command_script(self, remote_machine_name, log_file, fqdn):
    logging.debug('Executing _build_remote_command_script. remote_machine_name: {}, log_file: {}'.format(remote_machine_name, log_file))
    param = ''
    if remote_machine_name and log_file:
      param = PathUtils.GetTempFile(prefixArg='ai_cmd_epth_', suffixArg='.bat')
      if not self._write_remote_command_script(param, remote_machine_name, log_file, fqdn):
        self._log_error('Batch file to be executed using Pass The Hash could not be built. Phase will fail.')
        param = ''
    else:
      self._log_error('Empty remote machine name or log file when building remote command to execute using Pass the Hash. Phase will fail.')
    return param

  def _write_remote_command_script(self, script_path, remote_machine_name, log_file, fqdn):
    logging.debug('Executing _write_remote_command_script. script_path: {}, remote_machine_name: {}, log_file: {}'.format(script_path, remote_machine_name, log_file))
    success = False
    ip_address = self._get_ip_from_computer_name(remote_machine_name, fqdn)  # if hostname is used, error 1396 can be triggered!
    command = self._get_batch_script_contents(remote_machine_name, ip_address, log_file)
    if script_path and command:
      success = FileUtils.WriteToFile(script_path, command)
    return success

  def _get_ip_from_computer_name(self, computer_name, fqdn):
    logging.debug('Executing _get_ip_from_computer_name. computer_name: {}'.format(computer_name))
    ip_address = NetworkUtils.GetIPFromHostName(computer_name)
    if not ip_address:
      ip_address = NetworkUtils.GetIPFromHostName(computer_name.replace('.' + fqdn, '', 1))
    if not ip_address:
      self._log_error('Error getting IP for host {0}. Phase might fail'.format(computer_name))
    return ip_address

  @staticmethod
  def _get_batch_script_contents(remote_machine_name, remote_machine_ip, log_file):
    logging.debug('Executing _get_batch_script_contents. remote_machine_name: {}, remote_machine_ip: {}, log_file: {}'.format(remote_machine_name, remote_machine_ip, log_file))
    return r"""
    setlocal enabledelayedexpansion

    :detectfreedrive
    set drive=
    for %%i in (a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p,q,r,s,t,u,v,w,x,y,z) do (
        set "drive=%%i:"
        subst !drive! %_system_drive%\ >nul
        if !errorlevel! == 0 (
            rem subst makes better check than "if exist" (optical drives w/o media)
            subst !drive! /d >nul
            goto :detectedfreedrive
        )
    )
    exit /b 2
    :detectedfreedrive

    >{1} 2>&1 (
      echo "Mapping drive using name: {0} and also ip: {2}"
      net use !drive! "\\{0}\admin$"
      net use !drive! "\\{2}\admin$"
      echo "Checking drive existence"
      if exist !drive!\ echo Pass the Hash Successful
      echo "Deleting drive"
      net use /delete !drive!
    )

    exit /b 0
    """.format(remote_machine_name, log_file, remote_machine_ip or remote_machine_name)

  @staticmethod
  def _log_remote_command_output_log_path(remote_command_output_log_path, from_user):
    logging.debug('Executing _log_remote_command_output_log_path. remote_command_output_log_path: {}, from_user: {}'.format(remote_command_output_log_path, from_user))
    if remote_command_output_log_path:
      if from_user:
        logging.info("Remote Command Output Log Path value passed as parameter to execute passing the hash: {0}".format(remote_command_output_log_path))
      else:
        logging.info('Remote Command Output Log Path value used to execute passing the hash: {0}'.format(remote_command_output_log_path))
    else:
      logging.warning('Remote Command Output Log Path value could not be retrieved.')

  def _log_debug(self, msg):
    if self.phase_reporter:
      self.phase_reporter.Debug(msg)
    else:
      logging.debug(msg)

  def _log_error(self, msg):
    if self.phase_reporter:
      self.phase_reporter.Error(msg)
    else:
      logging.error(msg)
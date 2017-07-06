import logging
from ai_utils.phases.abstract_phase import AbstractPhaseClass
from ai_utils.utils.registryutils import RegistryUtils
from ai_utils.scenarios.globals import Globals


class CheckUACLevelPhaseClass(AbstractPhaseClass):
  TrackerId = "PHS-78627a94-184c-11e7-8a5e-d0577b10c5b1"
  Subject = "Check UAC Level"
  Description = "Retrieves Windows's UAC level and checks if it is equal or better than the expected level"

  uac_levels = {0: 'Never Notify (UAC is Disabled)',
                1: 'UAC is Enabled with a Custom Configuration',
                2: 'Notify on Computer Changes (Not Dimming Desktop)',
                3: 'Notify on Computer Changes (Dimming Desktop)',
                4: 'Always Notify'}
  registry_root = 'hklm'
  registry_subkey = 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System'

  def __init__(self, is_phase_critical, uac_expected_level, strict_mode):
    """
    By using this phase the current Windows UAC level can be validated against the one provided by the user.

    This phase will be successful when the current Windows UAC level is equal o better than the one provided by the user (using non strict
    mode), or only when current Windows UAC level is equal as the user's provided level (strict mode).

    In order to determine if the phase is successful, several UAC registry keys will be retrieved and matched to specific values.
    Then these specific values can be translated into a predefined UAC setting, which is the value that will be checked against the one
    that user has provided.

    Args:
      is_phase_critical: Identify if the phase is critical. If it is critical, its outcome will be taken into account
      to define the overall scenario outcome.
      uac_expected_level: Windows UAC configuration mapped to an integer from 1 to 4.
      strict_mode: Defines criteria to phase successful, in strict mode the current UAC mode has to be the same as the expected.
                   Otherwise, current UAC can be the same as expected or more secure.
    Returns: True if the phase is successful, False otherwise
    """
    AbstractPhaseClass.__init__(self, is_phase_critical)
    logging.debug('Executing CheckUACLevelPhaseClass constructor. is_phase_critical:{}, uac_expected_level:{}, strict_mode:{}'.format(is_phase_critical, uac_expected_level, strict_mode))
    self.uac_expected_level = uac_expected_level
    self.strict_mode = strict_mode
    self.phase_running_as_attack = False
    self.consent_prompt_behavior_admin = None
    self.prompt_on_secure_desktop = None

  def Setup(self):
    logging.debug('Executing Setup')
    if self.uac_expected_level is None or self.uac_expected_level not in self.uac_levels:
      self.PhaseReporter.Error("UAC expected level parameters is not set or it is not a valid option")
      return False
    if Globals.ScenarioType == 1:
      self.phase_running_as_attack = True
    return True

  def Run(self):
    logging.debug('Executing Run')
    current_uac_level = self.get_current_UAC_level()
    success = self.log_success(current_uac_level)
    if self.phase_running_as_attack:
      return not success
    return success

  def get_current_UAC_level(self):
    logging.debug('Executing get_current_UAC_level')
    if not self.get_current_UAC_level_values():
      return None
    if self.consent_prompt_behavior_admin == 2 and self.prompt_on_secure_desktop == 1:
      return 4
    elif self.consent_prompt_behavior_admin == 5 and self.prompt_on_secure_desktop == 1:
      return 3
    elif self.consent_prompt_behavior_admin == 5 and self.prompt_on_secure_desktop == 0:
      return 2
    elif self.consent_prompt_behavior_admin == 0 and self.prompt_on_secure_desktop == 0:
      return 0
    self.PhaseReporter.Info("Cannot match current UAC level with the ones provided by Windows by default, UAC is enabled with a custom UAC profile")
    return 1

  def get_current_UAC_level_values(self):
    logging.debug('Executing get_current_UAC_level_values')
    if not self.get_consent_prompt_behavior_admin():
      self.PhaseReporter.Error("Cannot get ConsentPromptBehaviorAdmin value, current UAC level cannot be obtained")
      return False
    if not self.get_prompt_on_secure_desktop():
      self.PhaseReporter.Error("Cannot get PromptOnSecureDesktop value, current UAC level cannot be obtained")
      return False
    return True

  def get_consent_prompt_behavior_admin(self):
    logging.debug('Executing get_consent_prompt_behavior_admin')
    consent_prompt_behavior_admin = RegistryUtils.get_data(self.registry_root, self.registry_subkey, "ConsentPromptBehaviorAdmin")
    if consent_prompt_behavior_admin is None:
      return False
    self.consent_prompt_behavior_admin = consent_prompt_behavior_admin
    return True

  def get_prompt_on_secure_desktop(self):
    logging.debug('Executing get_prompt_on_secure_desktop')
    prompt_on_secure_desktop = RegistryUtils.get_data(self.registry_root, self.registry_subkey, "PromptOnSecureDesktop")
    if prompt_on_secure_desktop is None:
      return False
    self.prompt_on_secure_desktop = prompt_on_secure_desktop
    return True

  def log_success(self, current_uac_level):
    success = False
    if current_uac_level is not None:
      if self.strict_mode:
        success = self.log_success_strict_mode(current_uac_level, self.uac_expected_level)
      else:
        success = self.log_success_non_strict_mode(current_uac_level, self.uac_expected_level)
      self.PhaseReporter.Info('UAC level successfully validated')
    return success

  def log_success_strict_mode(self, current_uac_level, uac_expected_level):
    logging.debug('Executing log_success_strict_mode. current_uac_level={}, uac_expected_level={}'.format(current_uac_level, uac_expected_level))
    if current_uac_level == uac_expected_level:
      self.PhaseReporter.Report('Current UAC level is the same as the expected UAC level \'{}\''.format(self.uac_levels[current_uac_level]))
      return True
    else:
      self.PhaseReporter.Report('Current UAC level \'{}\' is different than the expected UAC level \'{}\''.format(self.uac_levels[current_uac_level], self.uac_levels[uac_expected_level]))
      if self.phase_running_as_attack:
        self.PhaseReporter.Mitigation("Consider to set the current UAC level to the expected level  \'{}\'".format(self.uac_levels[uac_expected_level]))
      return False

  def log_success_non_strict_mode(self, current_uac_level, uac_expected_level):
    logging.debug('Executing log_success_non_strict_mode. current_uac_level={}, uac_expected_level={}'.format(current_uac_level, uac_expected_level))
    if current_uac_level == uac_expected_level:
      self.PhaseReporter.Report('Current UAC level is the same as the expected UAC level \'{}\''.format(self.uac_levels[current_uac_level]))
      return True
    elif current_uac_level > uac_expected_level:
      self.PhaseReporter.Report('Current UAC level \'{}\' is more secure than the expected UAC level \'{}\''.format(self.uac_levels[current_uac_level], self.uac_levels[uac_expected_level]))
      return True
    else:
      self.log_validation_failed_non_strict_mode(current_uac_level, uac_expected_level)
      return False

  def log_validation_failed_non_strict_mode(self, current_uac_level, uac_expected_level):
    if current_uac_level == 1:
      self.PhaseReporter.Report('Current UAC level is custom, so it cannot be validated against Windows\'s default configurations')
      if uac_expected_level == 4 and self.phase_running_as_attack:
        self.PhaseReporter.Mitigation("Verify that current custom UAC level is as secure as the expected UAC level \'{}\'. Otherwise consider to set the current UAC level to the expected UAC level".format(self.uac_levels[uac_expected_level]))
      elif self.phase_running_as_attack:
        self.PhaseReporter.Mitigation("Verify that current custom UAC level is as secure as the expected UAC level \'{}\'. Otherwise consider to set the current UAC level to \'{}\', or at least to the expected UAC level".format(self.uac_levels[uac_expected_level], self.uac_levels[4]))
    else:
      self.PhaseReporter.Report("Current UAC level \'{}\' is less secure than the expected UAC level \'{}\'".format(self.uac_levels[current_uac_level], self.uac_levels[uac_expected_level]))
      if uac_expected_level == 4 and self.phase_running_as_attack:
        self.PhaseReporter.Mitigation("Consider to set the current UAC level to \'{}\'".format(self.uac_levels[4]))
      elif self.phase_running_as_attack:
        self.PhaseReporter.Mitigation("Consider to set the current UAC level to \'{}\', or at least to the expected UAC level \'{}\'".format(self.uac_levels[4], self.uac_levels[uac_expected_level]))
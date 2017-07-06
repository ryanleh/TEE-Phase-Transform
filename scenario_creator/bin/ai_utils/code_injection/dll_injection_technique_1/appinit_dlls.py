from ai_utils.code_injection.abstract_code_injection import AbstractCodeInjectionAgentClass
import logging

class AppInitDLLsAgentClass(AbstractCodeInjectionAgentClass):

  def __init__(self, dllPath):
    AbstractCodeInjectionAgentClass.__init__(self)
    logging.info(Messages.INFO1)
    self.DLLPath = dllPath
    self.is32bits = False

    self.PreviousAppInit_DLLsValue = ''
    self.PreviousLoadAppInit_DLLsValue = ''
    self.PreviousRequireSignedAppInit_DLLsValue = ''

  ###
  # OVERRIDDEN METHODS
  ####################

  def InjectCode(self):
    return True

  ###
  # INTERNAL METHODS
  ##################

  def _SetAppInitDLLsRegistryKeys(self):
    pass

  def _UnsetAppInitDLLsRegistryKeys(self):
    pass

  def _CheckIfDLLIsInjected(self):
    pass

  def _RestoreRegistryState(self):
    pass


class Messages(object):

  INFO1 = 'Executing AppInitDLLsAgentClass...'
import logging
import sys
from ai_utils.scenarios.descriptor import ScenarioDescriptorClass
from ai_utils.scenarios.globals import FileUtils, StringUtils, GenericReporter, Globals
from ai_utils.scenarios.globals import LoggingUtils
from ai_utils.ai_types import AI_SIMPLE_TRACE_TYPE

class ScenarioExecutorClass(object):
  def __init__(self):
    self.ScenarioDescriptor = ScenarioDescriptorClass()
    LoggingUtils.AddLoggingLevel('report', AI_SIMPLE_TRACE_TYPE['report'][0])
    LoggingUtils.AddLoggingLevel('mitigation', AI_SIMPLE_TRACE_TYPE['mitigation'][0])

  @staticmethod
  def StripArgs(args):
    strippedArgs = []
    for arg in args:
      strippedArgs = strippedArgs + [arg.strip(),]
    return strippedArgs

  def GetArgsFromEnv(self):
    logging.info('original args: {0}'.format(sys.argv))
    sys.argv = self.StripArgs(sys.argv)
    if sys.argv[0].endswith('ai_python.exe'):
      sys.argv = sys.argv[1:]
    elif sys.argv[0].endswith('ai_python'):
      sys.argv = sys.argv[1:]
    elif sys.argv[0] == '': # redhat pyinstaller set first arg as empty
      sys.argv = sys.argv[1:]
    logging.info('post cleanup args: {0}'.format(sys.argv))
    if len(sys.argv) != 2:
      return False
    modelFile = sys.argv[1]
    self.ModelString = FileUtils.ReadFromFile(modelFile)
    if StringUtils.IsEmptyOrNull(self.ModelString):
      GenericReporter.Error('Error reading model.json')
      return False
    return True

  def ValidateArgs(self):
    if not self.GetArgsFromEnv():
      logging.error('Usage: main.py model.json')
      return False
    return True

  def _SetScenarioTypeGlobalVariable(self):
    try:
      scenarioTypeFromModel = self.ScenarioDescriptor.Model.get('scenario_type')
      scenarioTypeFromDescriptor = self.ScenarioDescriptor.Descriptor['resources'][0]['scenario_type']
      Globals.ScenarioType = scenarioTypeFromModel or scenarioTypeFromDescriptor
    except:
      GenericReporter.Error("Error reading 'scenario_type' in order to set global variable")
      return False
    return True

  def Run(self):
    if not self.ScenarioDescriptor.ValidateDescriptorJson():
      GenericReporter.Error('Error validating descriptor.json')
      sys.exit(1)
    if not self.ScenarioDescriptor.LoadScenarioAndPhaseClasses():
      sys.exit(1)
    if not self.ValidateArgs():
      exitCode = 0 if self.ScenarioDescriptor.ProcessDescriptorJson() else 1
      sys.exit(exitCode)
    if not self.ScenarioDescriptor.ValidateModel(self.ModelString):
      GenericReporter.Error('Error validating model.json')
      sys.exit(1)
    self._SetScenarioTypeGlobalVariable()
    try:
      sys.exit(self.ScenarioDescriptor.StartScenario())
    except Exception as e:
      GenericReporter.Error('An unexpected error occurred while executing the scenario. Error: {}'.format(e))
      sys.exit(1)
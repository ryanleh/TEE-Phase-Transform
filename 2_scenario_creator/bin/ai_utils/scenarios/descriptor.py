import sys
import logging
try:
    import json
    import jsonschema as js
except Exception, e:
    logging.error(e)
from ai_utils.scenarios.abstract_scenario import AbstractScenarioClass
from ai_utils.phases.abstract_phase import AbstractPhaseClass
from ai_utils.scenarios.globals import FileUtils, PathUtils, GenericReporter

class ScenarioDescriptorClass(object):
    def __init__(self):
        self.Schema = None
        self.Form = None
        self.Model = None
        self.ScenarioClass = None
        self.PhaseClasses = None

    def ValidateSchemaAndForm(self):
        if not isinstance(self.Schema, dict):
            logging.error("'schema' has to be dict")
            return False
        if not isinstance(self.Form, list):
            logging.error("'form' has to be dict")
            return False
        if self.Schema:
            properties = self.Schema.get('properties')
            return properties is not None
        else:
            return True

    def ValidateDescriptorJson(self):
        jsonPath = PathUtils.GetScenarioDescriptorPath()
        if not FileUtils.FileExists(jsonPath):
            logging.error("{0} not found".format(jsonPath))
            return False
        self.Descriptor = FileUtils.ReadJsonFromFile(jsonPath)
        if self.Descriptor is None:
            logging.error("{0} is invalid JSON".format(jsonPath))
            return False
        if 'resources' not in self.Descriptor:
            logging.error("Descriptor does not contain 'resources' field")
            return False
        resources = self.Descriptor['resources']
        if len(resources) < 1:
            logging.error("There should be minimum 1 resource")
            return False
        resource = resources[0]
        if not self._ValidateSupportedPlatforms(resource):
            logging.error("Invalid supported platforms field")
            return False
        if 'engine' not in resource:
            logging.error("'resource' must have 'engine'")
            return False
        if 'entryscript' not in resource:
            logging.error("'resource' must have 'entryscript'")
            return False
        if 'schema' not in resource:
            logging.error("'resource' must have 'schema'")
            return False
        self.Schema = resource['schema']
        if 'form' not in resource:
            logging.error("'resource' must have 'form'")
            return False
        self.Form = resource['form']
        if 'scenario_type' not in resource:
            logging.error("'resource' must have 'scenario_type'")
            return False
        if resource['scenario_type'] != 1 and resource['scenario_type'] != 2:
            logging.error("'scenario_type' must be set to 1 (attack) or 2 (validation)")
            return False
        return self.ValidateSchemaAndForm()

    def _ValidateSupportedPlatforms(self, resource):
        success = True
        valid_oses = ['windows', 'osx', 'redhat', 'linuxmint', 'debian', 'centos', 'fedora', 'ubuntu']
        supported_platforms = resource.get('supported_platforms')
        if supported_platforms:
            if isinstance(supported_platforms, dict):
                supported_oses = supported_platforms.keys()
                for supported_os in supported_oses:
                    if not supported_os.lower() in valid_oses:
                        logging.error('Supported platform: "{}" is not supported. Valid values: "{}"'.format(supported_os.lower(), ', '.join(valid_oses)))
                        success = False
            else:
                logging.error('Supported platforms must be a dictionary')
                success = False
        return success

    def ValidateModel(self, modelString):
        try:
            self.Model = json.loads(modelString)
            js.validate(self.Model, self.Schema)
            return True
        except:
            logging.exception('scenario argument model is not validating with scenario schema')
            return False

    @classmethod
    def GetScenarioClass(cls):
        scenarios = []
        for scenario in AbstractScenarioClass.__subclasses__():
            if scenario not in scenarios:
                if not scenario.IsValidScenarioClass():
                    return False
                logging.info("Detected Scenario to Run:{0}".format(scenario.__name__))
                scenarios.append(scenario)
        if len(scenarios) == 1:
            return scenarios[0]
        else:
            logging.error('Incorrect number of scenario classes detected')
            return None

    @classmethod
    def GetPhases(cls):
        phases = []
        logging.info('All the phases in this scenario:')
        for phase in AbstractPhaseClass.__subclasses__():
            if phase not in phases:
                if not phase.IsValidPhaseClass():
                    return False
                logging.info("Phase:{0} TrackerId:{1}".format(phase.__name__, phase.TrackerId))
                phases.append(phase)
        return phases

    def LoadScenarioAndPhaseClasses(self):
        self.ScenarioClass = ScenarioDescriptorClass.GetScenarioClass()
        if not self.ScenarioClass:
            GenericReporter.Error('No scenario classes for this platform {} detected in this scenario'.format(sys.platform))
            return False
        self.PhaseClasses = ScenarioDescriptorClass.GetPhases()
        if not self.PhaseClasses:
            GenericReporter.Error('No phase classes for this platform {} detected in this scenario'.format(sys.platform))
            return False
        return True

    @staticmethod
    def GetSourceUrl():
        sourceUrl = ''
        sourceJsonFilePath = PathUtils.GetSourceJsonPath()
        if FileUtils.FileExists(sourceJsonFilePath):
            sourceJson = FileUtils.ReadJsonFromFile(PathUtils.GetSourceJsonPath())
            if sourceJson and sourceJson.get('url'):
                sourceUrl = sourceJson.get('url')
        return sourceUrl

    def ProcessDescriptorJson(self):
        assert self.ScenarioClass
        assert self.PhaseClasses
        assert self.Descriptor
        self.Descriptor['trackerId'] = self.ScenarioClass.TrackerId
        self.Descriptor['subject'] = self.ScenarioClass.Subject
        self.Descriptor['description'] = self.ScenarioClass.Description
        self.Descriptor['sourceUrl'] = ScenarioDescriptorClass.GetSourceUrl()
        aiPhaseIds = ''
        phaseItems = []
        for phase in self.PhaseClasses:
            phaseItem = {}
            aiPhaseIds += '#' + phase.TrackerId + ','
            phaseItem['trackerId'] = phase.TrackerId
            phaseItem['subject'] = phase.Subject
            phaseItem['description'] = phase.Description
            phaseItems.append(phaseItem)
        aiPhaseIds = aiPhaseIds[:-1] if len(aiPhaseIds) else aiPhaseIds
        self.Descriptor['aiPhaseIds'] = aiPhaseIds
        self.Descriptor['phases'] = phaseItems
        processedJsonPath = PathUtils.GetProcessedScenarioDescriptorPath()
        if FileUtils.WriteJsonToFile(processedJsonPath, self.Descriptor):
            logging.warn('Created {0}'.format(processedJsonPath))
            return True
        else:
            return False

    def StartScenario(self):
        assert self.ScenarioClass
        logging.info('Executing {0}'.format(self.ScenarioClass.__name__))
        return self.ScenarioClass(self.Model).Execute()

import logging
from base64 import b64encode
from os.path import join
from requests import get, codes
from struct import pack
from ai_utils.utils.agent_config import AgentConfigClass
from ai_utils.utils.fileutils import FileUtilsClass as FileUtils
from ai_utils.utils.pathutils import PathUtilsClass as PathUtils
import platform


class ScenarioUtilsClass(object):
    @staticmethod
    def ValidateJson(jsonPath, numberOfUserArguments):
        if not FileUtils.FileExists(jsonPath):
            errorMessage = "{0} not found".format(jsonPath)
            logging.error(errorMessage)
            return False, errorMessage
        descriptor = FileUtils.ReadJsonFromFile(jsonPath)
        if descriptor is None:
            errorMessage = "{0} is invalid JSON".format(jsonPath)
            logging.error(errorMessage)
            return False, errorMessage
        logging.info(descriptor)
        if len(descriptor['resources'][0]['fields']) != numberOfUserArguments:
            errorMessage = "Number of user arguments passed do not match number of descriptor.json arguments expected: {0} passed by user".format(numberOfUserArguments)
            logging.error(errorMessage)
            return False, errorMessage
        return True, "Validated"

    @staticmethod
    def PackData(part, data):
        packFormat = 'L8s'
        return pack(packFormat, part, data)

    @staticmethod
    def Base64EncodeData(data):
        return b64encode(data)

    @staticmethod
    def GetStrippedArgs(args):
        strippedArgs = ()
        for arg in args:
            strippedArgs = strippedArgs + (arg.strip(),)
        return strippedArgs

    @staticmethod
    def GetFilesFromConsole(files):
        filepaths = []
        AgentConfig = AgentConfigClass()
        for filepath in files.split(','):
            filepath = filepath.strip()
            url = AgentConfig.ServerUrl + '/downloads/files/' + filepath
            logging.info('url:{}'.format(url))
            http_headers = {'Authorization': AgentConfig.HttpHeaders['Authorization']}
            response = get(url, stream=True, verify=False, headers=http_headers, allow_redirects=False) #dont enable redirect for s3 since auth token is not valid there
            if response.status_code == 302:
                redirect_url = response.headers.get('location')
                logging.info('redirect_url:{}'.format(redirect_url))
                response = get(redirect_url, stream=True, verify=False)
            if response.status_code != codes.ok:
                logging.info('request failed with status_code:{}'.format(response.status_code))
                continue
            #logging.info('Content for file retrieved from console (80 bytes): {}'.format(response.content[:80]))
            folder_name = filepath.split('/')[0]
            PathUtils.MakeDirectory(join(PathUtils.GetScenarioRootDirectory(), folder_name))
            local_filepath = join(PathUtils.GetScenarioRootDirectory(), filepath)
            with open(local_filepath, 'wb') as f:
                for chunk in response.iter_content(chunk_size=1024):
                    if chunk:
                        f.write(chunk)
            filepaths.append(local_filepath)
        return filepaths

    @staticmethod
    def GetURLsFromConsole(files):
        urls = []
        AgentConfig = AgentConfigClass()
        for filepath in files.split(','):
            url = AgentConfig.ServerUrl + '/downloads/files/' + filepath
            urls.append(url)
        return urls

    @classmethod
    def ValidOS(cls):
        success, error_msg = False, ''
        supported_platforms = cls._GetSupportedPlatforms()
        if supported_platforms:
            success, error_msg = cls._CheckIfHostOSIsInSupportedPlatforms(supported_platforms)
        else:
            success = True
        return success, error_msg

    @staticmethod
    def _GetSupportedPlatforms():
        supported_platforms = {}
        descriptor = FileUtils.ReadJsonFromFile(PathUtils.GetScenarioDescriptorPath())
        if descriptor:
            supported_platforms = descriptor['resources'][0].get('supported_platforms', {})
            if not supported_platforms:
                logging.error('Scenario does not have supported platforms. Setting supported platforms would help the user executing the scenario. Execution will continue')
        else:
            logging.warning('Scenario "descriptor.json" file could not be read to determine supported platforms. Execution will continue')
        return supported_platforms

    @staticmethod
    def _CheckIfHostOSIsInSupportedPlatforms(supported_platforms):
        success, error_msg = False, ''
        supported_oses = supported_platforms.keys()
        detected_os = platform.system().lower()
        for supported_os in supported_oses:
            supported_os = 'darwin' if supported_os == 'osx' else supported_os
            supported_os = 'linux' if supported_os in ['ubuntu', 'linuxmint', 'redhat', 'centos', 'debian', 'fedora'] else supported_os
            if supported_os in detected_os:
                success = True
                break
        if not success:
            error_msg = 'The scenario does not support the operating system in which it is being executed. Supported platforms: "{}", detected OS: "{}"'.format(', '.join(supported_oses), detected_os)
        return success, error_msg

import json
import logging
import requests
from ConfigParser import ConfigParser
from ai_utils.utils.pathutils import PathUtilsClass as PathUtils

class AgentConfigClass(object):
    def __init__(self):
        self.AgentIni = self.ReadConfigIni()
        self.ConsoleAddress = self.AgentIni.get('General', 'ConsoleServerAddress')
        self.ConsolePort = self.AgentIni.get('General', 'ConsoleServerPort')
        self.UseHttps = self.AgentIni.get('General', 'UseHttps') == '1'
        self.ServerUrl = self.GetConsoleUrl()
        self.Username = self.AgentIni.get('General', 'Username')
        self.Password = self.AgentIni.get('General', 'Password')
        self.AuthorizationToken = self.AgentIni.get('General', 'AuthorizationToken') or None
        self.HttpHeaders = {'Accept': 'application/json', 'content-type': 'application/json'}
        self.InitializeSession()

    def ReadConfigIni(self):
        self.AgentConfigPath = PathUtils.GetAgentConfigPath()
        logging.debug("AgentConfigPath is {0}".format(self.AgentConfigPath))
        iniParser = ConfigParser()
        iniParser.read(self.AgentConfigPath)
        return iniParser

    def GetConsoleUrl(self):
        if self.UseHttps:
            if self.ConsolePort == '443':
                return 'https://' + self.ConsoleAddress
            else:
                return 'https://' + self.ConsoleAddress + ':' + self.ConsolePort
        else:
            if self.ConsolePort == '80':
                return 'http://' + self.ConsoleAddress
            else:
                return 'http://' + self.ConsoleAddress + ':' + self.ConsolePort

    def InitializeSession(self):
        try:
            if not self.AuthorizationToken:
                self.AuthorizationToken = self.GetAuthorizationToken()
            self.HttpHeaders['Authorization'] = 'Token {}'.format(self.AuthorizationToken)
        except Exception as err:
            logging.exception(err)

    def GetAuthorizationToken(self):
        tokenRequestCreds = json.dumps({'username' : self.Username, 'password' : self.Password})
        response = requests.post(self.ServerUrl + '/api-token-auth/', data=tokenRequestCreds, headers=self.HttpHeaders, verify=False)
        return json.loads(response.content)['token']

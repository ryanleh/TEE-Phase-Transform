import logging
import re


class PortParser(object):

    def __init__(self, phase_reporter=None):
        logging.debug('Executing PortParser constructor. phase_reporter: {}'.format(phase_reporter))
        self.number_of_ports = 65535
        self.phase_logger = phase_reporter

    def parse_ports(self, ports_string):  # on failure, this method returns None
        logging.debug('Executing parse_ports. ports_string: {}'.format(ports_string))
        result = []
        if PortParser._match_valid_ports_regex(ports_string):
            if '' == ports_string:
                self._log_info('Port expression is empty. All ports are expected to be closed')
                result = []
            elif '-' == ports_string:
                self._log_info('Nmap expression "-" found. All ports set as valid egress ports')
                result = range(1, self.number_of_ports + 1)
            elif ',' in ports_string:  # it is a list of comma-separated ports
                for ports_block in ports_string.split(','):
                    result += self._parse_single_port_or_range(ports_block)
            else:  # it is not a list of comma-separated ports. If the range is wrong, we return None
                result = self._parse_single_port_or_range(ports_string) or None
            if not self._check_port_list_correctness(result):
                self._log_error('After being processed, port list is not valid. You port expression is wrong.')
                result = None
        else:
            self._log_error('Port expression {} is not valid'.format(ports_string))
            result = None
        return result

    @staticmethod
    def _match_valid_ports_regex(ports):
        logging.debug('Executing _match_valid_ports_regex. ports: {}'.format(ports))
        if ports == '':
            return True
        if re.match('^[\d, -]*$', ports):
            return True
        return False

    def _parse_single_port_or_range(self, port_or_range):
        logging.debug('Executing _parse_single_port_or_range. port_or_range: {}'.format(port_or_range))
        result = []
        port_or_range = port_or_range.strip()
        if '-' in port_or_range:  # port range
            result += self._parse_port_range(port_or_range)
        elif port_or_range.isdigit():  # single port
            result += [int(port_or_range)]
        else:
            self._log_error('Symbol not a dash or number in a port or range variable ({0}). Wrong port format. Ignoring value.'.format(port_or_range))
        return result

    def _parse_port_range(self, port_range):
        logging.debug('Executing _parse_port_range. port_range: {}'.format(port_range))
        lower_and_upper_limits = [port.strip() for port in port_range.split('-')]
        if PortParser._check_range_list_correctness(port_range):
            result = range(int(lower_and_upper_limits[0]), int(lower_and_upper_limits[1]) + 1)
        else:
            self._log_error('Range expression is incorrect. Ignoring range: {0}'.format(port_range))
            result = []
        return result

    @staticmethod
    def _check_range_list_correctness(port_range):
        logging.debug('Executing _check_range_list_correctness. port_range: {}'.format(port_range))
        success = True
        lower_and_upper_limits = [port.strip() for port in port_range.split('-')]
        for item in lower_and_upper_limits:
            if not item.isdigit():
                return False
        if len(lower_and_upper_limits) != 2 or int(lower_and_upper_limits[0]) >= int(lower_and_upper_limits[1]):
            success = False
        return success

    def _check_port_list_correctness(self, ports):
        logging.debug('Executing _check_port_list_correctness. ports: {}(...)'.format(ports[:10] if type(ports) == list else ports))
        success = True
        if not ports is None:
            for port in ports:
                if not isinstance(port, int) or port <= 0 or port > self.number_of_ports:
                    success = False
                    break
        return success

    def _log_info(self, log_msg):
        logging.debug('Executing _log_info. log_msg {}'.format(log_msg))
        if self.phase_logger:
            self.phase_logger.Info(log_msg)
        else:
            msg = 'Phase Logger not Initialized. Following message will not be shown in the Firedrill UI: {}'.format(log_msg)
            logging.info(msg)

    def _log_error(self, log_msg):
        logging.debug('Executing _log_error. log_msg {}'.format(log_msg))
        if self.phase_logger:
            self.phase_logger.Info(log_msg)
        else:
            msg = 'Phase Logger not Initialized. Following message will not be shown in the Firedrill UI: {}'.format(log_msg)
            logging.info(msg)

from ai_utils.scenarios.globals import NetworkUtils
import logging


class MimikatzReporter(object):

    def __init__(self, username, target_machine_with_fqdn, fqdn, phase_reporter=None):
        self.username = username
        self.target_machine_with_fqdn = target_machine_with_fqdn
        self.fqdn = fqdn
        self.phase_reporter = phase_reporter

    def report(self, phase_successful):
        if phase_successful:
            self.log_info('Successfully passed the hash for password of user: {0}, to machine: {1}'.format(self.username, self.target_machine_with_fqdn))
            local_ip = NetworkUtils.GetLocalIP()
            self.log_report('A command was executed using Pass the Hash technique through Mimikatz. From: {}, To: {}, Username: {}'.format(local_ip, self.target_machine_with_fqdn, self.username))
        else:
            self.log_info('Failed to pass the hash with user: {0}, to machine: {1}'.format(self.username, self.target_machine_with_fqdn))
            self.check_if_critical_failure_and_log_it()

    def check_if_critical_failure_and_log_it(self):
        logging.debug('Executing check_if_critical_failure_and_log_it')
        critical_error = False
        correct_dc_machine = self.is_dc_machine_name_correct(self.target_machine_with_fqdn)
        if not correct_dc_machine and not self.fqdn:
            self.log_info('Most probably the phase failed because there is not a user logged in the asset machine. Environment variables could not be retrieved.')
            critical_error = True
        else:
            if not self.fqdn:
                self.log_info('Most probably the phase failed because asset machine is not inside a Windows Domain. FQDN could not be retrieved.')
                critical_error = True
            if not correct_dc_machine:
                self.log_info('Most probably the phase failed because the user logged in the asset machine is not a domain user. DC machine name could not be retrieved.')
                critical_error = True
        if critical_error:
            self.show_requirements()
        return critical_error

    def is_dc_machine_name_correct(self, machine_name):
        logging.debug('Executing is_dc_machine_name_correct. machine_name: {}'.format(machine_name))
        return machine_name and machine_name != '.' + self.fqdn

    def show_requirements(self):
        logging.debug('Executing show_requirements')
        self.log_info("")
        self.log_info("For this phase to succeed with the default parameters, these requirements should be satisfied:")
        self.log_info("  1. The asset machine should be inside a windows domain.")
        self.log_info("  2. The domain administrator password hash should be passed as a parameter.")
        self.log_info("  3. The asset machine should have a user session opened (a user should be logged in while the scenario is executed).")
        self.log_info("  4. The logged in user should have logged in against the domain controller (so the user should be a domain user).")

    def log_info(self, msg):
        if self.phase_reporter:
            self.phase_reporter.Info(msg)
        else:
            logging.info(msg)

    def log_report(self, msg):
        if self.phase_reporter:
            self.phase_reporter.Report(msg)
        else:
            logging.info(msg)

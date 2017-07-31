from ai_utils.phases.abstract_phase import AbstractPhaseClass
import logging
try:
    import psutil
    valid_import = True
except ImportError as e:
    valid_import = False
    logging.error('psutil library could not be imported. Error: {}'.format(e))


class ProcessCheckerPhaseClass(AbstractPhaseClass):
    TrackerId = "PHS-7b4c5b8b-efa3-11e5-b088-d8cb8a2a09d1"
    Subject = "Process Checker"
    Description = "This phase checks if the specified processes are running in the system"

    def __init__(self, isPhaseCritical, or_and, processes):
        AbstractPhaseClass.__init__(self, isPhaseCritical)
        self.parameter_type = self.setup_type_parameter(or_and)
        self.processes = self.setup_processes_parameter(processes)
        self.running_processes = []

    def Setup(self):
        if not valid_import:
            self.PhaseReporter.Error(Messages.ERROR1)
            return False
        if not self.parameter_type or self.parameter_type not in ['or', 'and']:
            self.PhaseReporter.Error(Messages.ERROR2)
            return False
        if not self.processes:
            self.PhaseReporter.Error(Messages.ERROR3)
            return False
        return True

    def Run(self):
        phase_successful = self.execute_phase()
        self.log_success(phase_successful)
        return phase_successful

    def execute_phase(self):
        success = False
        real_processes = self.get_processes()
        if self.parameter_type == 'and':
            success = self.check_process_and(real_processes)
        elif self.parameter_type == 'or':
            success = self.check_process_or(real_processes)
        else:
            pass
        return success

    def get_processes(self):
        logging.info(Messages.INFO6)
        real_processes = []
        for proc in psutil.process_iter():
            try:
                pinfo = proc.as_dict(attrs=['pid', 'name'])
            except psutil.NoSuchProcess:
                pass
            else:
                real_processes.append(pinfo)
        logging.info(real_processes)
        return real_processes

    def check_process_and(self, real_processes):
        logging.info(Messages.INFO7)
        success = False
        process_names = [real_process['name'] for real_process in real_processes if 'name' in real_process]
        processes_count = len(self.processes)
        processes_found = 0
        for process in self.processes:
            if process in process_names:
                self.PhaseReporter.Info(Messages.INFO3.format(process))
                self.running_processes.append(process)
                processes_found += 1
            else:
                self.PhaseReporter.Info(Messages.INFO8.format(process))
        if processes_found == processes_count:
            success = True
        return success

    def check_process_or(self, real_processes):
        logging.info(Messages.INFO9)
        success = False
        process_names = [real_process['name'] for real_process in real_processes if 'name' in real_process]
        for process in self.processes:
            if process in process_names:
                self.PhaseReporter.Info(Messages.INFO3.format(process))
                self.running_processes.append(process)
                success = True
            else:
                self.PhaseReporter.Info(Messages.INFO8.format(process))
        return success

    def log_success(self, phase_successful):
        if phase_successful:
            self.PhaseReporter.Report('The following processes were found running in the system: {}'.format(', '.join(self.running_processes)))
            self.PhaseReporter.Mitigation('Stop the execution of the following processes: {}'.format(', '.join(self.running_processes)))
            self.PhaseReporter.Info(Messages.INFO4)
        else:
            self.PhaseReporter.Info(Messages.INFO5)

    def setup_type_parameter(self, param_type):
        param = ''
        if param_type:
            param = param_type
        logging.info(Messages.INFO1.format(param))
        return param

    def setup_processes_parameter(self, processes):
        param = ''
        if processes:
            param = processes
        logging.info(Messages.INFO2.format(param))
        return param


class Messages(object):

    INFO1 = 'Parameter type: {}'
    INFO2 = 'Processes parameter: {}'
    INFO3 = 'Process {} found among the system running processes'
    INFO4 = 'Phase was successful'
    INFO5 = 'Phase failed'
    INFO6 = 'Getting processes running in the system'
    INFO7 = 'Checking if all specified processes are running in the system'
    INFO8 = 'Process {} was not found among the sytem running processes'
    INFO9 = 'Checking if any of the specified processes are running in the system'

    ERROR1 = '"psutil" could not be imported. The phase will fail'
    ERROR2 = 'Type parameter is not set. Valid options: or, and. Phase will fail'
    ERROR3 = 'Processes parameter is not set. Phase will fail.'
    ERROR4 = 'Type parameter is not valid. Valid options: AND or OR. Phase will fail.'


class AbstractWindowsPasswordsAgent(object):

    def get_windows_passwords(self):
        success = False
        if self.setup_password_dumping_tool():
            success = self.dump_windows_passwords()
            self.log_results(success)
        return success
    
    def setup_password_dumping_tool(self):
        raise NotImplementedError('Method setup_password_dumping_tool must be implemented')
    
    def dump_windows_passwords(self):
        raise NotImplementedError('Method dump_windows_passwords must be implemented')
    
    def log_results(self, phase_successful):
        raise NotImplementedError('Method log_results must be implemented')

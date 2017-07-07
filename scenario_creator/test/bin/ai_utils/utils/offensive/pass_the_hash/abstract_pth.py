import logging


class AbstractPassTheHashAgent(object):

  def __init__(self, phase_reporter):
    self.phase_reporter = phase_reporter

  def pass_the_hash(self):
    success = False
    if self.setup_pth():
      success = self.pth()
      self.log_results(success)
    else:
      self.log_error('Pass the hash utility setup was not successful')
    return success

  def setup_pth(self):
    raise NotImplementedError('Method setup_pth must be implemented')

  def pth(self):
    raise NotImplementedError('Method pth must be implemented')

  def log_results(self, phase_successful):
    raise NotImplementedError('Method log_results must be implemented')

  def log_info(self, msg):
    if self.phase_reporter:
      self.phase_reporter.Info(msg)
    else:
      logging.info(msg)

  def log_error(self, msg):
    if self.phase_reporter:
      self.phase_reporter.Error(msg)
    else:
      logging.error(msg)

  def log_debug(self, msg):
    if self.phase_reporter:
      self.phase_reporter.Debug(msg)
    else:
      logging.debug(msg)

  def log_report(self, msg):
    if self.phase_reporter:
      self.phase_reporter.Report(msg)
    else:
      logging.info(msg)
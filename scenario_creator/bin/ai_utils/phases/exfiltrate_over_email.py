from ai_utils.phases.abstract_phase import AbstractPhaseClass
from ai_utils.ai_email.email_factory import EmailAgentFactoryClass
import logging

class ExfiltrateOverEmailPhaseClass(AbstractPhaseClass):
  TrackerId = "167"
  Subject = "Ex-Filtrate data Over email"
  Description = "Ex-Filtrate data Over email"

  def __init__(self, isPhaseCritical, sendFromAddress, userPassword, listOfSendtoAddress, subject, body, listOfFilesToAttach):
    AbstractPhaseClass.__init__(self, isPhaseCritical)
    logging.info('Executing Exfiltrate Over Email phase...')
    factory = EmailAgentFactoryClass(sendFromAddress, userPassword, listOfSendtoAddress, subject, body, listOfFilesToAttach)
    self.MailAgent = factory.CreateAgent()
  
  def Run(self):
    self.PhaseReporter.Info('Exfitltrating files using email...')
    phaseSuccessful = self.MailAgent.SendEmail()
    if phaseSuccessful:
      self.PhaseReporter.Info('Successfully ex-filtrated over email')
      self.PhaseReporter.Report('Data was exfiltrated using email to the following addresses: {}'.format(', '.format(self.MailAgent.ListOfSendToAddres)))
      self.PhaseReporter.Mitigation('Disable or inspect emails sent to: {}'.format(', '.format(self.MailAgent.ListOfSendToAddres)))
    else:
      self.PhaseReporter.Info('Failed to ex-filtrate over email')
    return phaseSuccessful
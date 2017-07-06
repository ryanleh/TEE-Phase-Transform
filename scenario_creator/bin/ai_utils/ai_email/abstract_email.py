import logging
import smtplib, os
try:
  # noinspection PyUnresolvedReferences,PyUnresolvedReferences
  from email.MIMEMultipart import MIMEMultipart
  # noinspection PyUnresolvedReferences,PyUnresolvedReferences
  from email.MIMEBase import MIMEBase
  # noinspection PyUnresolvedReferences,PyUnresolvedReferences
  from email.MIMEText import MIMEText
  # noinspection PyUnresolvedReferences,PyUnresolvedReferences
  from email.Utils import COMMASPACE, formatdate
  from email import Encoders
except:
  logging.error('error importing')

class AbstractEmailAgentClass(object):
  def __init__(self, sendFromAddress, userPassword, listOfSendtoAddress, subject, body, listOfFilesToAttach, smtpSeverAddress, smtpServerPort):
    logging.info('sendFromAddress:{0} listOfSendToAddress:{1} subject:{2} body:{3} listOfFilesToAttach:{4} smtpServerAddres:{5} smtpServerPort: {6}'.format(
      sendFromAddress, listOfSendtoAddress, subject, body, listOfFilesToAttach, smtpSeverAddress, smtpServerPort))
    self.SendFromAddress = sendFromAddress
    self.UserPassword = userPassword
    assert isinstance(listOfSendtoAddress, list)
    self.ListOfSendToAddres = listOfSendtoAddress
    assert listOfFilesToAttach is None or isinstance(listOfFilesToAttach, list)
    self.ListOfFilesToAttach = listOfFilesToAttach
    self.Subject = subject
    self.Body = body
    self.SmtpServer = smtplib.SMTP(smtpSeverAddress, smtpServerPort)

  def PrepareMessage(self):
    message = MIMEMultipart()
    message['From'] = self.SendFromAddress
    message['To'] = COMMASPACE.join(self.ListOfSendToAddres)
    message['Date'] = formatdate(localtime=True)
    message['Subject'] = self.Subject

    message.attach(MIMEText(self.Body))

    for fileToAttach in self.ListOfFilesToAttach:
        attachment = MIMEBase('application', "octet-stream")
        attachment.set_payload(open(fileToAttach,"rb").read())
        Encoders.encode_base64(attachment)
        attachment.add_header('Content-Disposition', 'attachment; filename="%s"' % os.path.basename(fileToAttach))
        message.attach(attachment)
    self.Message = message

  def ConnectToSmtpServer(self):
    """override to connect smptserver over tls or provide user name or password"""
    return True

  def SendEmail(self):
    emailSent = False
    try:
      self.PrepareMessage()
      if self.ConnectToSmtpServer():
        self.SmtpServer.sendmail(self.SendFromAddress, self.ListOfSendToAddres, self.Message.as_string())
        self.SmtpServer.close()
        emailSent = True
    except Exception, e:
      logging.exception(e)
    return emailSent
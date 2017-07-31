from ai_utils.ai_email.abstract_email import AbstractEmailAgentClass

class GmailAgentClass(AbstractEmailAgentClass):
    def __init__(self, sendFromAddress, userPassword, listOfSendtoAddress, subject, body, listOfFilesToAttach):
        AbstractEmailAgentClass.__init__(self, sendFromAddress, userPassword, listOfSendtoAddress, subject, body, listOfFilesToAttach, 'smtp.gmail.com', 587)

    def ConnectToSmtpServer(self):
        self.SmtpServer.starttls()
        self.SmtpServer.login(self.SendFromAddress, self.UserPassword)
        return True

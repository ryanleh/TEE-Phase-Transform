from ai_utils.ai_email.gmail import GmailAgentClass
from ai_utils.ai_email.yahoo_mail import YahooMailAgentClass
from ai_utils.ai_email.live_mail import LiveMailAgentClass
from ai_utils.scenarios.globals import StringUtils

class EmailAgentFactoryClass(object):
    def __init__(self, sendFromAddress, userPassword, listOfSendtoAddress, subject, body, listOfFilesToAttach):
        self.SendFromAddress = sendFromAddress
        self.UserPassword = userPassword
        self.ListOfSendToAddress = listOfSendtoAddress
        self.Subject = subject
        self.Body = body
        self.ListOfFilesToAttach = listOfFilesToAttach

    def CreateAgent(self):
        if self.IsGmailAddress():
            return GmailAgentClass(self.SendFromAddress, self.UserPassword, self.ListOfSendToAddress, self.Subject, self.Body, self.ListOfFilesToAttach)
        elif self.IsYahooAddress():
            return YahooMailAgentClass(self.SendFromAddress, self.UserPassword, self.ListOfSendToAddress, self.Subject, self.Body, self.ListOfFilesToAttach)
        elif self.IsMicrosoftAddress():
            return LiveMailAgentClass(self.SendFromAddress, self.UserPassword, self.ListOfSendToAddress, self.Subject, self.Body, self.ListOfFilesToAttach)
        else:
            return None

    def IsGmailAddress(self):
        return StringUtils.EndsWithIgnoreCase(self.SendFromAddress, 'gmail.com')

    def IsYahooAddress(self):
        return StringUtils.EndsWithIgnoreCase(self.SendFromAddress, 'yahoo.com')

    def IsMicrosoftAddress(self):
        return StringUtils.EndsWithIgnoreCase(self.SendFromAddress, 'outlook.com') or \
               StringUtils.EndsWithIgnoreCase(self.SendFromAddress, 'live.com') or \
               StringUtils.EndsWithIgnoreCase(self.SendFromAddress, 'hotmail.com')

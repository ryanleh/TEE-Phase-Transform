from ai_utils.cloud.dropbox.dropbox_drive import DropboxAgentClass
from ai_utils.cloud.google.google_drive import GoogleDriveAgentClass
from ai_utils.cloud.microsoft.microsoft_drive import MicrosoftDriveAgentClass

class CloudAgentFactoryClass(object):
  def __init__(self, uploadTo, credentials):
      self.uploadTo = uploadTo
      self.credentials = credentials

  def CreateAgent(self):
    if self.uploadTo == 'dropbox':
      return DropboxAgentClass(self.credentials)
    elif self.uploadTo == 'google':
      return GoogleDriveAgentClass(self.credentials)
    elif self.uploadTo == 'microsoft':
      return MicrosoftDriveAgentClass(self.credentials)
    else:
      return None
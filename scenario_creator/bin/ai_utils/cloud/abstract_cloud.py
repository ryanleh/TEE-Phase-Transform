import logging

class AbstractCloudAgentClass(object):
    def __init__(self, credentials):
        logging.info('Credentials: {0}'.format(credentials))
        assert isinstance(credentials, dict)
        self.Credentials = credentials
        self.CountOfFilesExfiltrated = 0

    def Authenticate(self):
        """override to authenticate with the cloud service"""
        return True

    def UploadFiles(self, listOfFiles):
        if listOfFiles:
            for file in listOfFiles:
                success = self.UploadFile(file)
                if success:
                    self.CountOfFilesExfiltrated += 1
                else:
                    logging.warning('File \'{0}\' could not be uploaded'.format(file))
        return self.CountOfFilesExfiltrated > 0

    def UploadFile(self, file):
        """override to upload file to the cloud server"""
        return True

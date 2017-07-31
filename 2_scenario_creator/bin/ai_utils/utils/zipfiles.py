import os
import zipfile
import logging

class FileZipperClass(object):
    def __init__(self, zipFilePath, listOfFilesToZip):
        assert isinstance(listOfFilesToZip, list)
        self.ZipFilePath = zipFilePath
        self.ListOfFilesToZip = listOfFilesToZip

    def Zip(self):
        try:
            archiveFile = zipfile.ZipFile(self.ZipFilePath, "a", compression=zipfile.ZIP_DEFLATED)
            for file in self.ListOfFilesToZip:
                if os.path.isfile(file):
                    logging.info('adding to zip {0}'.format(file))
                    archiveFile.write(file)
            archiveFile.close()
            return True
        except Exception, e:
            logging.exception(e)
        return False

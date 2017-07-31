import os
import json
import zipfile
import shutil
import stat
import logging
import subprocess
import hashlib
from ai_utils.utils.pathutils import PathUtilsClass as PathUtils


def RemoveReadonly(function, path, excinfo):
    if function is os.rmdir:
        os.chmod(path, stat.S_IWRITE)
        os.rmdir(path)
    elif function is os.remove:
        os.chmod(path, stat.S_IWRITE)
        os.remove(path)


class FileUtilsClass(object):
    def __init__(self):
        pass

    @staticmethod
    def FileExists(filePath):
        res = False
        try:
            res = os.path.isfile(filePath)
        except Exception as e:
            logging.error('Error checking if file exists for file \'{0}\': {1}'.format(filePath, e))
        return res

    @staticmethod
    def DirExists(dirPath):
        res = False
        try:
            res = os.path.isdir(dirPath)
        except Exception as e:
            logging.error('Error checking if directory exists for path \'{0}\': {1}'.format(dirPath, e))
        return res

    @staticmethod
    def GetFilesize(filePath):
        res = -1
        try:
            res = os.stat(filePath).st_size
        except Exception as e:
            logging.error('Error getting size for file \'{0}\': {1}'.format(filePath, e))
        return res

    @staticmethod
    def WriteToFile(filePath, contents):
        try:
            with open(filePath, "wb") as dataFile:
                dataFile.write(contents)
            return True
        except Exception as e:
            logging.error('An error occurred writing to he file: {0}. Error: {1}'.format(filePath, e))
        return False

    @staticmethod
    def ReadFromFile(filePath):
        try:
            with open(filePath, "rb") as dataFile:
                contents = dataFile.read()
                return contents
        except (IOError, Exception) as e:
            logging.exception('locals: {0}'.format(locals()))
        return None

    @staticmethod
    def ReplaceString(fromFilePath, toFilePath, oldSubstring, newSubstring):
        logging.info("fromFilePath{0} replace oldSubstring:{1} to newSubstring:{2} toFilePath:{3}".format(fromFilePath, oldSubstring, newSubstring, toFilePath))
        oldFileContents = FileUtilsClass.ReadFromFile(fromFilePath)
        newFileContents = oldFileContents.replace(oldSubstring, newSubstring)
        FileUtilsClass.WriteToFile(toFilePath, newFileContents)

    @staticmethod
    def ReadLinesFromFile(filePath):
        with open(filePath, "rb") as dataFile:
            lines = dataFile.readlines()
            return lines

    @staticmethod
    def DeleteFile(filePath):
        successful = False
        try:
            if os.path.exists(filePath):
                os.remove(filePath)
            successful = True
        except Exception as e:
            logging.error('File ({0}) could not be removed: {1}'.format(filePath, e))
        return successful

    @staticmethod
    def DeleteFolder(directoryPath, safetyOn=True):
        if safetyOn and not PathUtils.DirectorySafeForDeletion(directoryPath):
            raise Exception("Not a safe directory to delete")
        shutil.rmtree(directoryPath, onerror=RemoveReadonly, ignore_errors=True)

    @staticmethod
    def WriteJsonToFile(filePath, dictionaryData):
        with open(filePath, "wb") as jsonFile:
            json.dump(dictionaryData, jsonFile, indent=2)
            return True

    @staticmethod
    def ReadJsonFromFile(filePath):
        try:
            with open(filePath, "rb") as jsonFile:
                dictionaryData = json.load(jsonFile)
                return dictionaryData
        except:
            logging.exception('locals:{0}'.format(locals()))
        return  None

    @staticmethod
    def ReadJsonFromString(dataString):
        dictionaryData = json.loads(dataString)
        return dictionaryData

    @staticmethod
    def GetFileContentsFromZip(zipFilepath, internalFilepath):
        zipFile = zipfile.ZipFile(zipFilepath, 'r')
        fileContents = zipFile.read(internalFilepath)
        return fileContents

    @staticmethod
    def ExecuteFile(filePath, arguments=None, wait=False):
        success = False
        try:
            if os.path.exists(filePath):
                execList = [filePath] + arguments if arguments and type(arguments) == list else [filePath]
                # We use wait() to stop execution until executed binary finishes. This can be modified.
                if wait:
                    subprocess.Popen(execList).wait()
                else:
                    subprocess.Popen(execList)
                success = True
            else:
                logging.error('File does not exist: {0}'.format(filePath))
        except Exception as e:
            logging.error('File "{0}" could not be executed": {1}'.format(filePath, e))
        return success

    @staticmethod
    def CopyFile(srcFilePath,dstFilePath):
        try:
            shutil.copyfile(srcFilePath, dstFilePath)
            return True
        except Exception as e:
            logging.error('File could not be copied from "{0}" to "{1}": {2}'.format(srcFilePath, dstFilePath, e))
        return False

    @staticmethod
    def SHA256ForFile(filename):
        try:
            hash = hashlib.sha256()
            with open(filename, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b''):
                    hash.update(chunk)
            return hash.hexdigest()
        except Exception as e:
            logging.error('Something went wrong while computing SHA256 hash. Error: {0}'.format(e))
        return None

    @staticmethod
    def GetFileNameFromFilePath(filePath):
        fileName = ''
        try:
            fileName = os.path.basename(filePath)
        except Exception as e:
            logging.error('File name could not be extracted from file path: {0}. Error: {1}'.format(filePath, e))
        return fileName

    @staticmethod
    def DeleteFilesInDirectory(directory, filetype=None):
        filelist = FileUtilsClass.GetFilesInDirectory(directory, filetype)
        for f in filelist:
            try:
                os.remove(os.path.join(directory, f))
            except Exception as e:
                logging.warning('File {0} could not be removed. Error: {1}'.format(f, e))

    @staticmethod
    def GetFilesInDirectory(directory, filetype):
        filelist = []
        try:
            if filetype:
                filelist = [f for f in os.listdir(directory) if f.endswith(filetype)]
            else:
                filelist = [f for f in os.listdir(directory)]
        except Exception as e:
            logging.error('Files in {0} directory could not be listed. Error: {1}'.format(directory, e))
        return filelist

    @staticmethod
    def Which(program):
        def is_exe(fpath):
            return os.path.isfile(fpath) and os.access(fpath, os.X_OK)

        fpath, fname = os.path.split(program)
        if fpath:
            if is_exe(program):
                return program
        else:
            for path in os.environ["PATH"].split(os.pathsep):
                path = path.strip('"')
                exe_file = os.path.join(path, program)
                if is_exe(exe_file):
                    return exe_file
        return None

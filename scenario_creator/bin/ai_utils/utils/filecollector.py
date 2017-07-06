from ai_utils.scenarios.globals import FileUtils
import logging
import os

try:
  from glob2 import iglob
except ImportError:
  logging.error('Module "glob2" could not be imported')


class FileCollectorClass(object):
  def __init__(self, listOfFolders, listOfPatterns, maximumCount = 10, maximumCumulativeSize = 10*1024*1024):
    assert isinstance(listOfFolders, list)
    assert isinstance(listOfPatterns, list)
    self.ListOfFolders = listOfFolders
    self.ListOfPatterns = listOfPatterns
    self.MaximumCount = maximumCount
    self.MaximumCumulativeSize = maximumCumulativeSize
    self.CumulativeSizeCollected = 0
    self.ListOfFiles = []

  def WithinCollectionLimits(self):
    if len(self.ListOfFiles) >= self.MaximumCount:
      logging.info("Hit maximum count limit {0}".format(self.MaximumCount))
      return False
    elif self.CumulativeSizeCollected > self.MaximumCumulativeSize:
      logging.info("Hit maximum size limit {0}".format(self.MaximumCumulativeSize))
      return False
    else:
      return True

  def Search(self, folder, filePattern):
    globPathPattern = os.path.join(folder, "**", filePattern)
    filesFoundItr = iglob(globPathPattern, with_matches=True)
    for fileMatch in filesFoundItr:
      file = fileMatch[0]
      fileSize = FileUtils.GetFilesize(file)
      if fileSize > self.MaximumCumulativeSize:
        logging.info("file {0}: with size {1} greater than MaximumCumulativeSize:{2}".format(file, fileSize, self.MaximumCumulativeSize))
        continue
      if self.WithinCollectionLimits():
        logging.info("adding to list {0}".format(file))
        self.ListOfFiles.append(file)
        self.CumulativeSizeCollected += fileSize
      else:
        return

  def Collect(self):
    try:
      for folder in self.ListOfFolders:
        for pattern in self.ListOfPatterns:
          if self.WithinCollectionLimits():
            self.Search(folder, pattern)
          else:
            break
      return len(self.ListOfFiles) > 0
    except TypeError as e:
      if 'buffer overflow' in str(e):
        logging.error('The path or the path pattern is too long. glob2 module could not work with it.')
    except Exception, e:
      logging.exception(e)
    return False
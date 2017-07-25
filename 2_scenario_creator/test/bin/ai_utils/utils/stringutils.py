import json
import logging
import re
import random
import string
from ai_utils.utils.fileutils import FileUtilsClass as FileUtils

class StringUtilsClass(object):
  def __init__(self):
    pass

  @staticmethod
  def IsEmptyOrNull(string):
    return not string or len(string) == 0

  @staticmethod
  def GetJsonForStr(dataStructure):
    try:
      return json.dumps(dataStructure)
    except:
      logging.exception('locals: {0}'.format(locals()))
      return str(dataStructure)

  @staticmethod
  def GetDictionaryFromJson(jsonString):
    try:
      return json.loads(jsonString)
    except:
      logging.exception('locals: {0}'.format(locals()))
      return None

  @staticmethod
  def GetLinesMatchingRegex(lines, regex):
    matches = []
    for line in lines:
      if re.match(regex, line.lower()):
        matches.append(line)
    return matches

  @staticmethod
  def GetFileLinesMatchingRegex(filePath, regex):
    lines = FileUtils.ReadLinesFromFile(filePath)
    return StringUtilsClass.GetLinesMatchingRegex(lines, regex)

  @staticmethod
  def RemoveSubstring(sourceString, stringToRemove):
    sourceString = sourceString.replace(stringToRemove, "")
    return sourceString

  @staticmethod
  def StripLines(lines):
    unformattedString = ""
    for line in lines:
      newline = line.strip()
      unformattedString = unformattedString + "\n" + newline
    return unformattedString

  @staticmethod
  def SplitAndTrim(commaSeparatedString):
    trimmedList = []
    for item in commaSeparatedString.split(','):
      trimmedItem = item.strip()
      trimmedList.append(trimmedItem)
    return trimmedList

  @staticmethod
  def EndsWithIgnoreCase(sourceString, suffix):
    return sourceString.lower().endswith(suffix.lower())

  @staticmethod
  def StartsWithIgnoreCase(sourceString, prefix):
    return sourceString.lower().startswith(prefix.lower())

  @staticmethod
  def Match(patternString, sourceString, ignoreCase = True):
    if not patternString or not sourceString:
      return False
    matchObject = re.match(patternString, sourceString, re.I if ignoreCase else 0)
    return matchObject is not None

  @staticmethod
  def ConvertListToString(listOfStrings):
    assert isinstance(listOfStrings, list)
    return ", ".join(map(str, listOfStrings))

  @staticmethod
  def GetRandomString(length=5):
    return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(length))

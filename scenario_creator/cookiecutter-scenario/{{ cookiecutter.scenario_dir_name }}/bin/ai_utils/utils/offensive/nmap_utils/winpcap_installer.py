from ai_utils.scenarios.globals import PathUtils, FileUtils
from ai_utils.utils.filecollector import FileCollectorClass
from ai_utils.ai_logging.simplelogger import AiLoggerClass
import subprocess
import logging
import os

AiLoggerClass().Enable()


class WinPcapInstalled(object):
  """
  This context manager should be used before executing Nmap in order to check if WinPcap is properly installed.
  By using this context manager when executing a Nmap scan, the Nmap WinPcap version will be silently installed before
  running the scan if it was not already installed and it will be silently uninstalled after the scan finishes.

  with WinPcapInstalled():
    <start_nmap_scan>
  """

  def __enter__(self):
    self.Installed = False
    self.PreviouslyInstalled = self._IsWinPcapInstalled()
    if not self.PreviouslyInstalled:
      logging.info('WinPcap not found in the system. Installing Nmap WinPcap...')
      self.Installed = self._InstallNmapWinPcap()
    else:
      logging.info('WinPcap already installed in the system. It will not be overridden')
    return self.Installed

  def __exit__(self, exc_type, exc_val, exc_tb):
    if not self.PreviouslyInstalled:
      if self.Installed:
        self._UninstallNmapWinPcap()
      else:
        logging.info('An error occurred while installing Nmap WinPcap, so it is not being uninstalled')
    else:
      logging.info('WinPCap was already installed in the system, so it is not being uninstalled')

  def _IsWinPcapInstalled(self):
    if self._FindNmapRelatedFiles():
      return True
    if self._FindWinPcapUninstaller():
      return True
    return False

  def _InstallNmapWinPcap(self):
    logging.info('Installing Nmap WinPcap...')
    installed = False
    winPcapInstallerPath = self._GetWinPcapInstallerPath()
    if winPcapInstallerPath:
      installed = self._ExecuteWinPcapCommandSilently(winPcapInstallerPath)
    return installed

  def _GetWinPcapInstallerPath(self):
    winPcapInstaller = ''
    try:
      fc = FileCollectorClass([PathUtils.GetScenarioRootDirectory()], ['winpcap-nmap*'], maximumCount=1)
      if fc.Collect():
        winPcapInstaller = fc.ListOfFiles[0]
        logging.info('Nmap WinPcap installer found in {}'.format(winPcapInstaller))
      else:
        logging.error('Nmap WinPcap installer could not be found. Nmap scan will fail.')
    except:
      logging.error('Nmap WinPcap installer could not be found. Nmap scan will fail.')
    return winPcapInstaller

  def _ExecuteWinPcapCommandSilently(self, winpcapCommand):
    success = False
    try:
      args = [winpcapCommand, '/S']
      logging.info('Executing: {}'.format(args))
      rc = subprocess.call(args)
      success = rc == 0
    except:
      pass
    return success

  def _UninstallNmapWinPcap(self):
    logging.info('Uninstalling Nmap WinPcap...')
    uninstalled = False
    winpcapUninstaller = self._FindWinPcapUninstaller()
    if winpcapUninstaller:
      uninstalled = self._ExecuteWinPcapCommandSilently(winpcapUninstaller)
    return uninstalled

  def _FindNmapRelatedFiles(self):
    found = False
    dlls = ['Packet.dll', 'wpcap.dll', 'drivers\\npf.sys']
    for dll in dlls:
      if self._FindNmapRelatedFile(dll):
        found = True
        break
    return found

  def _FindNmapRelatedFile(self, file):
    exists = False
    try:
      s32 = PathUtils.GetSystem32()
      s64 = PathUtils.GetSysWOW64()
      exists = FileUtils.FileExists(os.path.join(s32, file)) or \
               FileUtils.FileExists(os.path.join(s64, file))
    except:
      pass
    return exists

  def _FindWinPcapUninstaller(self):
    winpcapUninstaller = ''
    try:
      pf32 = PathUtils.GetProgramFiles32()
      pf64 = PathUtils.GetProgramFiles64()
      winpcap32 = os.path.join(pf32, 'winpcap')
      winpcap64 = os.path.join(pf64, 'winpcap')
      if FileUtils.DirExists(winpcap32) and FileUtils.FileExists(os.path.join(winpcap32, 'uninstall.exe')):
        winpcapUninstaller = os.path.join(winpcap32, 'uninstall.exe')
      if FileUtils.DirExists(winpcap64) and FileUtils.FileExists(os.path.join(winpcap64, 'uninstall.exe')):
        winpcapUninstaller = os.path.join(winpcap64, 'uninstall.exe')
    except:
      pass
    return winpcapUninstaller

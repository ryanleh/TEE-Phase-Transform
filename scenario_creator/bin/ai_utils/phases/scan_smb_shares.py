import os
import logging
import fnmatch
from ai_utils.phases.abstract_phase import AbstractPhaseClass
from ai_utils.scenarios.globals import NetworkUtils
from ai_utils.scenarios.globals import StringUtils
try:
    from smb.SMBConnection import SMBConnection
    from smb.smb_structs import OperationFailure
except Exception, e:
    logging.error(e)

class ScanSMBSharesPhaseClass(AbstractPhaseClass):
    TrackerId = '342'
    Subject = "Scan SMB Resources"
    Description = "Scan SMB Resources"

    def __init__(self, isPhaseCritical, cidr, username, password, domain, pattern='', maximumCount=100, maximumCumulativeSize=10*1024*1024):
        AbstractPhaseClass.__init__(self, isPhaseCritical)
        logging.info('Executing Scan SMB Shares phase...')
        self._check_string_instance([cidr, username, password, domain, pattern])
        self._ProcessIPs(cidr)
        self.Username = username
        self.Password = password
        self.Domain = domain
        self.Pattern = pattern
        self.MaximumCount = maximumCount
        self.MaximumCumulativeSize = maximumCumulativeSize
        self.CumulativeFileCount = 0
        self.CumulativeSizeCollected = 0
        self.Result = []
        self.TargetsToScan = []

    def _ProcessIPs(self, cidr):
        self.IpAddressList = []
        for ip in StringUtils.SplitAndTrim(str(cidr)):
            self.IpAddressList += NetworkUtils.GetIPList(ip)
        # remove duplicates keeping order
        known_ips = set()
        new_list = []
        for ip in self.IpAddressList:
            if ip in known_ips: continue
            new_list.append(ip)
            known_ips.add(ip)
        self.IpAddressList = new_list

    def _check_string_instance(self, params):
        for param in params:
            assert isinstance(param, type('')) or isinstance(param, type(u''))
        return True

    def Setup(self):
        if len(self.IpAddressList) == 0:
            self.PhaseReporter.Error('Invalid IP Range')
            return False
        if not self.Username or not self.Password or not self.Domain:
            self.PhaseReporter.Error('Invalid parameters')
            return False
        return True

    def _InitShare(self, shared_device, path, source):
        result = {
          'source': source,
          'shared_device': shared_device,
          'file_path': path,
          'file_size': -1
        }
        return result

    def _GetNextShare(self, smb_con, shared_device, path, source):
        share = {}
        try:
            # Initialize result in case it an exception is triggered (e.g. no privileges to access attributes)
            share = self._InitShare(shared_device, path, source)
            share_attributes = smb_con.getAttributes(shared_device, path)
            if share_attributes.isDirectory:
                for f in smb_con.listPath(shared_device, path):
                    if f.filename != '.' and f.filename != '..':
                        childPath = os.path.join(path, f.filename)
                        for share in self._GetNextShare(smb_con, shared_device, childPath, source):
                            yield share
            else:
                share['file_path'] = path
                share['file_size'] = share_attributes.file_size
                yield share
        except OperationFailure:
            logging.error('Most probably not enough privileges to access {0}.'.format(path))
        except Exception as e:
            logging.error('Error traversing {0}. {1}'.format(path, e))

    def _GetNextShareForIpAddress(self, item):
        try:
            remote_name = NetworkUtils.GetHostName(item['ip']) or item['ip']
            smb_con = SMBConnection(item['username'], item['password'], my_name='attackiq_client',  remote_name=remote_name, domain=item['domain'], use_ntlm_v2=True)
            if smb_con and smb_con.connect(item['ip'], item['port'], timeout=5):
                for shared_device in smb_con.listShares():
                    # returns a generator that will traverse all shared device (IPC$, PRINT$, etc)
                    for share in self._GetNextShare(smb_con, shared_device.name, '/', item['ip']):
                        yield share
        except Exception as e:
            logging.info('Error getting share info for ip {0}. {1}'.format(item['ip'], e))

    def _WithinScanLimits(self, share):  # Files without proper permissions are not taken in account for limit checks
        if self.CumulativeFileCount > self.MaximumCount:
            self.PhaseReporter.Info('Maximum count({0}) of files collected: {1}'.format(self.MaximumCount, share))
            return False
        elif self.CumulativeSizeCollected > self.MaximumCumulativeSize:
            self.PhaseReporter.Info('Maximum size({0}) of files collected: {1}'.format(self.MaximumCumulativeSize, share))
            return False
        return True

    def _AddShareToGlobalResult(self, share):
        reportShare = fnmatch.fnmatch(share['file_path'], self.Pattern) if self.Pattern else True
        if reportShare:
            self.Result.append(share)
            self.PhaseReporter.Info(share)
            self.CumulativeFileCount += 1
            self.CumulativeSizeCollected += share['file_size']

    def _GetSharesForIpAddressList(self):
        self._BuilTargetsToScan()
        for target in self.TargetsToScan:
            self.PhaseReporter.Info('Scanning {0}...'.format(target['ip']))
            for share in self._GetNextShareForIpAddress(target):
                if share['file_size'] == -1:
                    continue
                if self._WithinScanLimits(share):
                    self._AddShareToGlobalResult(share)
                else:
                    return len(self.Result)
        return len(self.Result)

    def _BuilTargetsToScan(self):  # This method should be executed after Setup()
        for idx, ipAddr in enumerate(self.IpAddressList):
            self.TargetsToScan.append(
              {
                'ip': ipAddr,
                'port': 139,
                'domain': self.Domain,
                'username': self.Username,
                'password': self.Password
              }
            )

    def Run(self):
        phaseSuccessful = self._GetSharesForIpAddressList()
        if phaseSuccessful:
            self.PhaseResult['SharedFiles'] = self.Result
            self.PhaseResult['NumberOfItems'] = phaseSuccessful
            self.PhaseReporter.Info('Successful scanning smb shares')
        else:
            self.PhaseReporter.Info('Failed scanning smb shares')
        return phaseSuccessful

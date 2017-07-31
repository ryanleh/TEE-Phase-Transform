import logging
import json
from ai_utils.cloud.abstract_cloud import AbstractCloudAgentClass
from ai_utils.utils.fileutils import FileUtilsClass
import requests

class MicrosoftDriveAgentClass(AbstractCloudAgentClass):
    def __init__(self, credentials):
        AbstractCloudAgentClass.__init__(self, credentials)
        self.Authenticated = False
        self.SessionParameters = None
        self.UploadMethod = -1
        self.Credentials = None
        if credentials.get('api_key'):
            self.Credentials = credentials['api_key']
            self.UploadMethod = 0
        elif credentials.get('userpwd'):
            self.Credentials = credentials['userpwd']
            self.UploadMethod = 1

    ###
    # OVERRIDDEN METHODS
    #######

    def Authenticate(self):
            # it depends on if we have API key or we have user/pwd, giving priority to API key
        if self.UploadMethod == 0:
            pass
        elif self.UploadMethod == 1:
            self.SessionParameters = self.__authenticateUserPwd()
            if self.SessionParameters:
                self.Authenticated = True
            else:
                return False
        return True

    def UploadFile(self, file):
        success = False
        if not self.Authenticated or not self.SessionParameters:
            logging.warning('Before uploading files to Microsoft Drive using user/pwd you have to authenticate. File not uploaded.')
            return success
        # it depends on if we have API key or we have user/pwd, giving priority to API key
        if self.UploadMethod == 0:
            pass
        elif self.UploadMethod == 1:
            success = self.__uploadFileUserPwd(file)
        return success

    ###
    # INTERNAL METHODS
    #######

    def __authenticateUserPwd(self):
        session_parameters = {}
        if self.Credentials and len(self.Credentials) == 2:
            user = self.Credentials[0]
            pwd = self.Credentials[1]

            url = "https://login.live.com/ppsecure/post.srf"
            response = requests.post("https://login.live.com")
            PPFT = ''
            MSPOK = ''
            MSPRequ = ''
            if response.content.find('<input type="hidden" name="PPFT" id="i0327" value="') != -1:          #TODO: this should be more stable (i.e.: using bs4)
                tmp_value = response.content.split('<input type="hidden" name="PPFT" id="i0327" value="')[1]
                PPFT = tmp_value.split('"')[0]
                MSPOK = response.cookies['MSPOK']
                MSPRequ = response.cookies['MSPRequ']

            post_params = {
              'login': user,
              'passwd': pwd,
              'PPFT': PPFT,
            }
            headers= {
              'User-Agent': 'Mozilla/5.0 (X11; Linux i686) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/37.0.2062.120 Safari/537.36',
              'Content-Type': 'application/x-www-form-urlencoded',
            }
            cookies = {
              'MSPRequ':MSPRequ,
              'MSPOK': MSPOK,
            }
            response = requests.post(url, data=post_params, headers=headers, cookies=cookies, allow_redirects=False, verify=False)
            if response.status_code == 302:  # in case of bad login, status_code = 200
                cookies = requests.utils.dict_from_cookiejar(response.cookies)
                session_parameters = {
                  'WLSSC': cookies.get('WLSSC'),
                  'USERID': cookies.get('MSPPre').split('|')[1],
                }
        logging.debug('Session parameters: {0}'.format(session_parameters))
        return session_parameters

    def __uploadFileUserPwd(self, file):
        success = False
        try:
            filesize = FileUtilsClass().GetFilesize(file)
            filename = file.split('\\')[-1]
            user_id = self.SessionParameters['USERID']
            url_1 = 'https://cid-{0}.users.storage.live.com/users/0x{1}/LiveFolders/{2}'.format(user_id, user_id.upper(), filename)
            headers_1 = {
              'User-Agent': 'Mozilla/5.0 (X11; Linux i686) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/37.0.2062.120 Safari/537.36',
              'BITS-Packet-Type': 'Create-Session',
              'BITS-Supported-Protocols': '{7df0354d-249b-430f-820d-3d2a9bef4931}',
              'X-Http-Method-Override': 'BITS_POST',
              'X-RequestStats': 'upType=h5,dragDrop=,SourceId=SkyApi%3A1141147648,size={0},fileType=,batchId=1418228225767,folderUpload=false'.format(filesize),
              'Overwrite': 'true',
              'Content-Type': 'application/octet-stream',
              'Accept': 'application/wls-response-headers+json'
            }
            cookies = {
              'WLSSC': self.SessionParameters['WLSSC']
            }
            response_1 = requests.post(url_1, headers=headers_1, cookies=cookies)
            if response_1.status_code == 200:
                response_1_dict = json.loads(response_1.content)
                if response_1_dict.get('StatusCode') == '201':
                    headers_2 = {
                      'User-Agent': 'Mozilla/5.0 (X11; Linux i686) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/37.0.2062.120 Safari/537.36',
                      'BITS-Packet-Type': 'Fragment',
                      'X-Http-Method-Override': 'BITS_POST',
                      'X-RequestStats': 'upType=h5,dragDrop=,SourceId=SkyApi%3A1141147648,size={0},fileType=,batchId=1418228225767,folderUpload=false'.format(filesize),
                      'Overwrite': 'true',
                      'Content-Type': 'application/octet-stream',
                      'Accept': 'application/wls-response-headers+json',
                      'BITS-Session-Id': response_1.headers['BITS-Session-Id'],
                      'Content-Range': 'bytes 0-{0}/{1}'.format(filesize-1, filesize)
                    }
                    filecontents = FileUtilsClass().ReadFromFile(file)
                    response_2 = requests.post(url_1, headers=headers_2, data=filecontents)
                    if response_2.status_code == 200:
                        response_2_dict = json.loads(response_2.content)
                        if response_2_dict.get('StatusCode') == '200':
                            headers_2['BITS-Packet-Type'] = 'Close-Session'
                            del headers_2['Content-Range']
                            cookies['PPLState'] = '1'
                            response_3 = requests.post(url_1, headers=headers_2, cookies=cookies)
                            if response_3.status_code == 200:
                                response_3_dict = json.loads(response_2.content)
                                success = response_3_dict.get('StatusCode') == '200'
        except Exception:
            logging.warning('File could not be uploaded to Google Drive.')
            success = False

        return success

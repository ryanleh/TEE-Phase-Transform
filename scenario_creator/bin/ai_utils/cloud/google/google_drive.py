import logging
import json
from ai_utils.cloud.abstract_cloud import AbstractCloudAgentClass
from ai_utils.utils.fileutils import FileUtilsClass
import requests

class GoogleDriveAgentClass(AbstractCloudAgentClass):
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
            logging.warning('Before uploading files to Google Drive using user/pwd you have to authenticate. File not uploaded.')
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

            url = "https://accounts.google.com/ServiceLoginAuth"
            post_params = {
              'GALX': 'this_can_be_tampered', 'Email': user,
              'Passwd': pwd, 'PersistentCookie': 'yes'
            }
            headers= {
              'User-Agent': 'Mozilla/5.0 (X11; Linux i686) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/37.0.2062.120 Safari/537.36'
            }
            cookies = {
              'GALX': 'this_can_be_tampered'
            }
            response = requests.post(url, data=post_params, headers=headers, cookies=cookies, allow_redirects=False)
            if response.status_code == 302:  # in case of bad login, status_code = 200
                cookies = requests.utils.dict_from_cookiejar(response.cookies)
                session_parameters = {
                  'NID': cookies.get('NID'),
                  'SID': cookies.get('SID'),
                  'HSID': cookies.get('HSID'),
                  'SSID': cookies.get('SSID'),
                  'APISID': cookies.get('APISID'),
                  'SAPISID': cookies.get('SAPISID')
                }
        logging.debug('Session parameters: {0}'.format(session_parameters))
        return session_parameters

    def __uploadFileUserPwd(self, file):
        success = False
        filezise = FileUtilsClass().GetFilesize(file)
        filename = file.split('\\')[-1]
        url_1 = 'https://drive.google.com/upload/resumableuploadsc?authuser=0'
        headers= {
          'User-Agent': 'Mozilla/5.0 (X11; Linux i686) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/37.0.2062.120 Safari/537.36'
        }
        cookies = {
          'NID': self.SessionParameters['NID'],
          'SID': self.SessionParameters['SID'],
          'HSID': self.SessionParameters['HSID'],
          'SSID': self.SessionParameters['SSID'],
          'APISID': self.SessionParameters['APISID'],
          'SAPISID': self.SessionParameters['SAPISID']
        }
        post_data_1 = {
        "protocolVersion":  "0.8",
        "createSessionRequest":
          {"fields":
            [
              {"external":
                {
                  "name": "file",
                  "filename":filename,
                  "put":{},
                  "size":filezise
                }
              },
              {"inlined":
                {
                  "name": "driveSourceClientService",
                  "content": "UploadWeb",
                  "contentType": "text/plain"
                }
              },
              {"inlined":
                {
                  "name": "modifiedTime",
                  "content": "1416237954000", # it can change
                  "contentType":"text/plain"
                }
              }
            ]
          }
        }
        try:
            response_1 = requests.post(url_1, headers=headers, cookies=cookies, data=json.dumps(post_data_1))
            if response_1.status_code == 200:
                response_1_dict = json.loads(response_1.content)
                upload_id = response_1_dict.get('sessionStatus').get('upload_id')
                url_2 = response_1_dict.get('sessionStatus').get('externalFieldTransfers')[0].get('putInfo').get('cross_domain_url')
                filecontents = FileUtilsClass().ReadFromFile(file)
                response_2 = requests.post(url_2, headers=headers, data=filecontents)
                if response_2.status_code == 200:
                    response_2_dict = json.loads(response_2.content)
                    success = response_2_dict['sessionStatus']['state'] == 'FINALIZED'
        except Exception as e:
            logging.warning('File could not be uploaded to Google Drive.')
            success = False

        return success

from ai_utils.cloud.abstract_cloud import AbstractCloudAgentClass
import requests
import logging


class DropboxAgentClass(AbstractCloudAgentClass):
  def __init__(self, credentials):
    AbstractCloudAgentClass.__init__(self, credentials)
    self.Authenticated = False
    self.SessionParameters = None
    self.UploadMethod = -1
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
      logging.warning('Before uploading files to Dropbox using user/pwd you have to authenticate. File not uploaded.')
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

      csrf, gvc, t, request_id = self.__get_required_tokens()
      self.__send_web_timing_request(csrf, gvc, t, request_id)
      self.__send_ajax_register_request(csrf, gvc, t)
      self.__send_captcha_request(csrf, gvc, t)
      self.__send_ualogger_request(csrf, gvc, t)
      self.__send_sso_request(csrf, gvc, t, user[:len(user) - 1])
      self.__send_sso_request(csrf, gvc, t, user)
      session_parameters = self.__send_login_request(csrf, gvc, t, user, pwd)
    return session_parameters

  def __send_login_request(self, csrf, gvc, t, user, pwd):
    session_parameters = {}
    url = "https://www.dropbox.com/ajax_login"
    post_params = {
      't': t,
      'login_email': user,
      'login_password': pwd,
      'remember_me': 'True',

      'is_xhr': 'true',
      'cont': '/',
      'require_role': '',
      'refresh_token': '',
      'email_sig': '',
      'login_sd': 'cfv,0.9:dlm:d,Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:44.0) Gecko/20100101 Firefox/44.0,uaend,2867,20100101,en-US,Gecko,2,0,0,0,2752,1548,2752,1548,2752,1412,2752,,cpen:0,i1:0,dm:0,cwen:0,non:1,opc:0,fc:1,sc:0,wrc:1,isc:136.1666717529297,vib:1,bat:1,x11:0,x12:1,5573,0.10966393154107856,728355015014.5,loc::dlm:e,do_en,dm_en,t_dis:dlm:if,0,-1,0,0,661,1152,0;1,-1,0,0,664,1515,0;0,-1,0,0,663,411,0;0,0,0,0,669,411,0;0,-1,0,0,669,519,0;0,-1,0,0,663,525,0;0,-1,0,0,666,520,0;1,0,0,0,669,883,0;:dlm:f,0,-1,1,0,661,1152,0;1,-1,1,0,664,1515,0;0,-1,0,0,663,411,0;0,0,0,0,669,411,0;0,-1,0,0,669,519,0;0,-1,0,0,663,525,0;0,-1,0,0,666,520,0;1,0,0,0,669,883,0;:dlm:l,0,1,2828,-2,0,0,1152;1,3,2829,0,0,0,1152;2,2,2948,-2,0,0,1152;3,1,3100,-2,0,0,1152;4,3,3101,0,0,0,1152;5,2,3164,-2,0,0,1152;6,1,3236,-2,0,0,1152;7,3,3236,0,0,0,1152;8,1,3300,-2,0,0,1152;9,3,3301,0,0,0,1152;10,2,3329,-2,0,0,1152;11,2,3419,-2,0,0,1152;12,1,4516,-2,0,0,1152;13,3,4516,0,0,0,1152;14,2,4588,-2,0,0,1152;15,1,4692,-2,0,0,1152;16,3,4692,0,0,0,1152;17,2,4756,-2,0,0,1152;18,1,4887,-2,0,0,1152;19,3,4888,0,0,0,1152;20,2,4940,-2,0,0,1152;21,1,4980,-2,0,0,1152;22,3,4981,0,0,0,1152;23,2,5060,-2,0,0,1152;24,1,5244,-2,0,0,1152;25,3,5245,0,0,0,1152;26,2,5332,-2,0,0,1152;27,1,5412,-2,0,0,1152;28,3,5413,0,0,0,1152;29,1,5531,-2,0,0,1152;30,3,5532,0,0,0,1152;31,2,5533,-2,0,0,1152;32,2,5587,-2,0,0,1152;33,1,5668,-2,0,0,1152;34,3,5668,0,0,0,1152;35,2,5812,-2,0,0,1152;36,1,5813,-2,0,0,1152;37,3,5813,0,0,0,1152;38,2,5884,-2,0,0,1152;39,1,6028,16,0,0,1152;40,1,6244,-2,0,8,1152;41,3,6244,0,0,8,1152;42,2,6284,16,0,8,1152;43,2,6331,-2,0,0,1152;44,1,6532,-2,0,0,1152;45,3,6532,0,0,0,1152;46,2,6604,-2,0,0,1152;47,1,6652,-2,0,0,1152;48,3,6652,0,0,0,1152;49,1,6701,-2,0,0,1152;50,3,6701,0,0,0,1152;51,2,6728,-2,0,0,1152;52,2,6787,-2,0,0,1152;53,1,6844,-2,0,0,1152;54,3,6844,0,0,0,1152;55,2,6948,-2,0,0,1152;56,1,7028,-2,0,0,1152;57,3,7028,0,0,0,1152;58,2,7132,-2,0,0,1152;59,1,7132,-2,0,0,1152;60,3,7133,0,0,0,1152;61,2,7244,-2,0,0,1152;62,1,7244,-2,0,0,1152;63,3,7245,0,0,0,1152;64,2,7332,-2,0,0,1152;65,1,7412,-2,0,0,1152;66,3,7412,0,0,0,1152;67,1,7492,-2,0,0,1152;68,3,7493,0,0,0,1152;69,2,7517,-2,0,0,1152;70,2,7555,-2,0,0,1152;71,1,7668,9,0,0,1152;72,3,7671,9,0,0,1152;73,2,7739,9,0,0,1515;74,1,10075,-2,0,0,1515;75,3,10077,0,0,0,1515;76,2,10147,-2,0,0,1515;77,1,10699,-2,0,0,1515;78,3,10700,0,0,0,1515;79,2,10755,-2,0,0,1515;80,1,10843,-2,0,0,1515;81,3,10844,0,0,0,1515;82,2,10899,-2,0,0,1515;83,1,10965,-2,0,0,1515;84,3,10965,0,0,0,1515;85,2,11029,-2,0,0,1515;86,3,11164,0,0,0,1515;87,3,11268,0,0,0,1515;88,3,11420,0,0,0,1515;89,3,11547,0,0,0,1515;90,1,11763,16,0,8,1515;91,3,11900,0,0,8,1515;92,2,11987,16,0,0,1515;93,1,12875,8,0,0,1515;94,3,12876,8,0,0,1515;95,1,13376,8,0,0,1515;96,3,13376,8,0,0,1515;97,1,13405,8,0,0,1515;98,3,13406,8,0,0,1515;99,1,13435,8,0,0,1515;100,3,13436,8,0,0,1515;101,1,13466,8,0,0,1515;102,3,13466,8,0,0,1515;103,1,13496,8,0,0,1515;104,3,13497,8,0,0,1515;105,1,13527,8,0,0,1515;106,3,13528,8,0,0,1515;107,1,13557,8,0,0,1515;108,3,13558,8,0,0,1515;109,1,13587,8,0,0,1515;110,3,13587,8,0,0,1515;111,1,13617,8,0,0,1515;112,3,13618,8,0,0,1515;113,2,13628,8,0,0,1515;114,1,13813,18,0,0,1515;115,1,22372,17,0,4,1515;116,1,22483,86,0,4,1515;117,3,22484,0,0,4,1515;118,2,22571,86,0,4,1515;119,2,22611,17,0,0,1515;:dlm:n,0,1,372,1045,23;1,1,378,1069,33;2,1,379,1094,43;3,1,390,1124,53;4,1,399,1148,63;5,1,405,1172,73;6,1,416,1197,83;7,1,596,1521,222;8,1,598,1529,234;9,1,606,1529,235;10,1,611,1529,237;11,1,620,1528,239;12,1,631,1528,242;13,1,635,1528,244;14,1,644,1527,245;15,1,651,1527,248;16,1,663,1525,251;17,1,667,1524,252;18,1,675,1522,254;19,1,683,1522,255;20,1,691,1521,257;21,1,699,1521,258;22,1,707,1519,259;23,1,726,1518,259;24,3,931,1518,259;25,4,1043,1518,259;26,2,1046,1518,259;27,1,21635,1296,221;28,1,21643,1300,221;29,1,21651,1304,221;30,1,21659,1309,222;31,1,21667,1313,224;32,1,21675,1317,225;33,1,21683,1323,226;34,1,21691,1330,231;35,1,21699,1340,234;36,1,21707,1352,239;37,1,21720,1362,245;38,1,21723,1372,251;39,1,21733,1383,257;40,1,21739,1393,262;41,1,21747,1405,265;42,1,21755,1413,269;43,1,21763,1420,272;44,1,21771,1428,275;45,1,21779,1433,278;46,1,21787,1435,278;47,1,21795,1436,280;48,1,21803,1438,281;49,1,21811,1439,281;50,1,21819,1439,282;51,1,21827,1439,284;52,1,21835,1441,284;53,1,21843,1441,285;54,1,21852,1441,287;55,1,21859,1442,288;56,1,21867,1442,290;57,1,21875,1443,291;58,1,21884,1445,292;59,1,21891,1445,294;60,1,21899,1445,295;61,1,21907,1446,298;62,1,21917,1446,300;63,1,21923,1448,301;64,1,21931,1449,302;65,1,21939,1449,304;66,1,21947,1449,307;67,1,21956,1451,310;68,1,21965,1451,311;69,1,21971,1451,314;70,1,21979,1452,315;71,1,21987,1452,317;72,1,21995,1452,318;73,1,22003,1453,318;74,1,22029,1453,321;75,1,22038,1453,323;76,3,22196,1453,323;77,1,22243,1453,324;78,4,22300,1453,324;79,2,22308,1453,324;80,1,22747,1458,324;81,1,22755,1466,325;82,1,22763,1482,328;83,1,22771,1498,331;84,1,22779,1512,334;85,1,22787,1528,334;86,1,22795,1547,337;87,1,22803,1568,337;88,1,22811,1590,341;89,1,22819,1611,341;90,1,22827,1633,344;91,1,22837,1654,347;92,1,22843,1673,347;93,1,22851,1688,347;94,1,22859,1704,347;95,1,22867,1717,347;96,1,22875,1723,347;97,1,22883,1729,350;98,1,22891,1730,350;99,1,22940,1731,350;100,1,22947,1731,351;101,1,22958,1731,353;102,1,22978,1733,355;103,1,22979,1733,357;104,1,22987,1734,358;105,1,22995,1734,360;106,3,23652,1678,410;107,4,23772,1678,410;108,2,23776,1678,410;:dlm:u,:dlm:doe,:dlm:dme,:dlm:page_url,:dlm:misc,1203718,2038402,0,0,0,3242120,23779,1456710029871,1456710030029,96,140,23782:dlm:aj,-1,0:dlm:df,--cfp:-1682343582,--fonts:Arial,Batang,Courier,Courier New,Droid Sans,Droid Serif,Helvetica,Open Sans,Roboto,Times,Times New Roman,Ubuntu,Ubuntu Condensed,--plugins:Shockwave Flash,--ss:true,--ls:true,--idb:true,--tzo:480,--rtc:true,--colorDepth:24,--pixelDepth:24,--cookies:true,--java:false,--dnt:1:dlm:fps,26192:dlm:yy:dlm:zz',
      'third_party_auth_experiment': 'EXPERIMENT',
      'signup_data': '',
      'signup_tag': ''
    }
    headers = {
      'Host': 'www.dropbox.com',
      'Accept': 'text/plain, */*; q=0.01',
      'Accept-Language': 'en-US,en;q=0.5',
      'Accept-Encoding': 'gzip, deflate, br',
      'DNT': '1',
      'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
      'Connection': 'close',
      'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:44.0) Gecko/20100101 Firefox/44.0',
      'X-Requested-With': 'XMLHttpRequest',
      'Referer': 'https://www.dropbox.com/login'
    }
    cookies = {
      't': t,
      'locale': 'en',
      '__Host-js_csrf': csrf,
      'gvc': gvc
    }

    response = requests.post(url, post_params, headers=headers, cookies=cookies, verify=False)
    if response.status_code == 200 and not response.content.startswith('err'):
      cookies = requests.utils.dict_from_cookiejar(response.cookies)
      data = response.json()
      session_parameters = {
        'locale': data.get('locale'),
        'forumjar': cookies.get('forumjar'),
        'blid': cookies.get('blid'),
        't': cookies.get('js_csrf'),
        'bjar': cookies.get('bjar'),
        'forumlid': cookies.get('forumlid'),
        'id': data.get('id'),
      }
    else:
      logging.error('Authentication was not successful. Response: {}'.format(response.content))
    logging.debug('Session parameters: {0}'.format(session_parameters))
    return session_parameters

  def __get_required_tokens(self):
    csrf, gvc, t, request_id = '', '', '', ''
    url = "https://www.dropbox.com/login"
    headers = {
      'Host': 'www.dropbox.com',
      'Accept-Language': 'en-US,en;q=0.5',
      'Accept-Encoding': 'gzip, deflate, br',
      'DNT': '1',
      'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:44.0) Gecko/20100101 Firefox/44.0',
    }
    try:
      response = requests.get(url, headers=headers, verify=False)
      if response.status_code == 200 and not response.content.startswith('err'):
        csrf = response.cookies['__Host-js_csrf']
        gvc = response.cookies['gvc']
        t = response.cookies['t']
        request_id = response.headers['x-dropbox-request-id']
    except Exception:
      logging.error('CSRF token could not be retrieved from response')
    return csrf, gvc, t, request_id

  def __send_web_timing_request(self, csrf, gvc, t, request_id):
    import time
    a= time.time()
    url = "https://www.dropbox.com/web_timing_log"
    post_params = {
      'is_xhr': 'true',
      't': t,
      'navigation_type': 'navigate',
      'server_request_start_time': '1456710029640',
      'browser_time': '0',
      'redirect_time': '0',
      'dns_time': '0',
      'tcp_connect_time': '71',
      'ssl_connect_time': '71',
      'time_to_first_byte': '31',
      'dom_load_time': '578',
      'page_load_time': '1286',
      'extra_columns': '{}',
      'url': 'https://www.dropbox.com/login',
      'request_id': request_id,
      'source_type': 'web',
      'request_tracing_enabled': 'false'
    }
    headers= {
      'Host': 'www.dropbox.com',
      'Accept': 'text/plain, */*; q=0.01',
      'Accept-Language': 'en-US,en;q=0.5',
      'Accept-Encoding': 'gzip, deflate, br',
      'DNT': '1',
      'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
      'Connection': 'close',
      'User-Agent': 'Mozilla/5.0 (X11; Linux i686) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/37.0.2062.120 Safari/537.36',
      'X-Requested-With': 'XMLHttpRequest',
      'Referer': 'https://www.dropbox.com/'
    }
    cookies = {
      't': t,

      'locale': 'en',
      '__Host-js_csrf': csrf,
      'gvc': gvc
    }
    response = requests.post(url, post_params, headers=headers, cookies=cookies, verify=False)
    return response.status_code == 200 and not response.content.startswith('err')

  def __send_ajax_register_request(self, csrf, gvc, t):
    url = "https://www.dropbox.com/ajax_register"
    post_params = {
      'is_xhr': 'true',
      't': t
    }
    headers= {
      'Host': 'www.dropbox.com',
      'Accept': 'text/plain, */*; q=0.01',
      'Accept-Language': 'en-US,en;q=0.5',
      'Accept-Encoding': 'gzip, deflate, br',
      'DNT': '1',
      'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
      'Connection': 'close',
      'User-Agent': 'Mozilla/5.0 (X11; Linux i686) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/37.0.2062.120 Safari/537.36',
      'X-Requested-With': 'XMLHttpRequest',
      'Referer': 'https://www.dropbox.com/'
    }
    cookies = {
      't': t,
      'locale': 'en',
      '__Host-js_csrf': csrf,
      'gvc': gvc
    }
    response = requests.options(url, params=post_params, headers=headers, cookies=cookies, verify=False)
    return response.status_code == 200 and not response.content.startswith('err')

  def __send_captcha_request(self, csrf, gvc, t):
    url = "https://www.dropbox.com/ajax_needs_signup_captcha"
    post_params = {
      'is_xhr': 'true',
      't': t,
      'email': ''
    }
    headers= {
      'Host': 'www.dropbox.com',
      'Accept': 'text/plain, */*; q=0.01',
      'Accept-Language': 'en-US,en;q=0.5',
      'Accept-Encoding': 'gzip, deflate, br',
      'DNT': '1',
      'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
      'Connection': 'close',
      'User-Agent': 'Mozilla/5.0 (X11; Linux i686) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/37.0.2062.120 Safari/537.36',
      'X-Requested-With': 'XMLHttpRequest',
      'Referer': 'https://www.dropbox.com'
    }
    cookies = {
      't': t,
      'locale': 'en',
      '__Host-js_csrf': csrf,
      'gvc': gvc
    }
    response = requests.post(url, post_params, headers=headers, cookies=cookies, verify=False)
    return response.status_code == 200 and not response.content.startswith('err')

  def __send_ualogger_request(self, csrf, gvc, t):
    url = "https://www.dropbox.com/ualogger"
    post_params = {
      'is_xhr': 'true',
      't': t,
      'event_name': 'web_login',
      'extra': '{}',
      'for_uids': '[]',
      'platform': ''
    }
    headers= {
      'Host': 'www.dropbox.com',
      'Accept': 'text/plain, */*; q=0.01',
      'Accept-Language': 'en-US,en;q=0.5',
      'Accept-Encoding': 'gzip, deflate, br',
      'DNT': '1',
      'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
      'Connection': 'close',
      'User-Agent': 'Mozilla/5.0 (X11; Linux i686) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/37.0.2062.120 Safari/537.36',
      'X-Requested-With': 'XMLHttpRequest',
      'Referer': 'https://www.dropbox.com'
    }
    cookies = {
      't': t,
      'locale': 'en',
      '__Host-js_csrf': csrf,
      'gvc': gvc
    }
    response = requests.post(url, post_params, headers=headers, cookies=cookies, verify=False)
    return response.status_code == 200 and not response.content.startswith('err')

  def __send_sso_request(self, csrf, gvc, t, user):
    url = "https://www.dropbox.com/sso_state"
    post_params = {
      'is_xhr': 'true',
      't': t,
      'email': user
    }
    headers= {
      'Host': 'www.dropbox.com',
      'Accept': 'text/plain, */*; q=0.01',
      'Accept-Language': 'en-US,en;q=0.5',
      'Accept-Encoding': 'gzip, deflate, br',
      'DNT': '1',
      'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
      'Connection': 'close',
      'User-Agent': 'Mozilla/5.0 (X11; Linux i686) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/37.0.2062.120 Safari/537.36',
      'X-Requested-With': 'XMLHttpRequest',
      'Referer': 'https://www.dropbox.com/login'
    }
    cookies = {
      't': t,
      'locale': 'en',
      '__Host-js_csrf': csrf,
      'gvc': gvc
    }
    response = requests.post(url, post_params, headers=headers, cookies=cookies, verify=False)
    return response.status_code == 200 and not response.content.startswith('err')

  def __uploadFileUserPwd(self, file):
    filename = file.split('\\')[-1]
    url = "https://dl-web.dropbox.com/upload"
    headers= {
      'User-Agent': 'Mozilla/5.0 (X11; Linux i686) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/37.0.2062.120 Safari/537.36'
    }
    cookies = {
      'locale': self.SessionParameters['locale'],
      'forumjar': self.SessionParameters['forumjar'],
      'blid': self.SessionParameters['blid'],
      't': self.SessionParameters['t'],
      'bjar': self.SessionParameters['bjar'],
      'forumlid': self.SessionParameters['forumlid']
    }
    filetype = ""
    if filename.endswith('.txt'):
      filetype = 'text/plain'
    else:
      filetype = 'application/octet-stream'
    files = {
        't': ('', str(self.SessionParameters['t'])),
        '_subject_uid': ('', str(self.SessionParameters['id'])),
        'plain': ('', 'yes'),
        'dest': ('', ''),
        'file': (filename, open(file, 'r'), filetype),
        'mtime_utc': ('', '1416322610')
    }
    response = requests.post(url, headers=headers, cookies=cookies, files=files)
    return 'home?select={0}'.format(filename) in response.content

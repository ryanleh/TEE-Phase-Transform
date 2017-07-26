from ai_utils.utils.offensive.windows_passwords.mimikatz.mimikatz_agent import MimikatzAgent
from ai_utils.ai_logging.simplelogger import AiLoggerClass
import unittest


class TestWPMimikatzReporter(unittest.TestCase):

  def setUp(self):
    AiLoggerClass().Enable()

  def test_log_success_with_valid_output(self):
    agent = MimikatzAgent()
    cred_objects = agent.process_mimikatz_command_output(self.valid_mimikatz_output)
    agent.credentials_object = cred_objects
    _ = agent.log_results(True)  # check no exception is thrown. This triggers MimikatzReporter execution
    _ = agent.log_results(False)

  def test_log_results_with_valid_output_with_user_and_cred_types(self):
    agent = MimikatzAgent(cred_types=['ntlm', 'cleartext'], usernames=['Administrator', 'WIN-H7MK73PJ720$'])
    cred_objects = agent.process_mimikatz_command_output(self.valid_mimikatz_output)
    agent.credentials_object = cred_objects
    _ = agent.log_results(True)  # check no exception is thrown

  def test_log_results_with_invalid_output_with_user_and_cred_types(self):
    agent = MimikatzAgent(cred_types=['ntlm', 'cleartext'], usernames=['Administrator', 'WIN-H7MK73PJ720$'])
    cred_objects = agent.process_mimikatz_command_output(self.invalid_mimikatz_output)
    agent.credentials_object = cred_objects
    _ = agent.log_results(True)  # check no exception is thrown


  invalid_mimikatz_output = ''

  valid_mimikatz_output = \
"""  .#####.   mimikatz 2.1 (x64) built on Jun 13 2016 21:04:46
 .## ^ ##.  "A La Vie, A L'Amour"
 ## / \ ##  /* * *
 ## \ / ##   Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 '## v ##'   http://blog.gentilkiwi.com/mimikatz             (oe.eo)
  '#####'                                     with 19 modules * * */

mimikatz(commandline) # privilege::debug
Privilege '20' OK

mimikatz(commandline) # sekurlsa::logonpasswords

Authentication Id : 0 ; 288662 (00000000:00046796)
Session           : Interactive from 1
User Name         : Administrator
Domain            : MYDOMAIN
Logon Server      : MYDOMAIN
Logon Time        : 1/9/2017 7:41:49 AM
SID               : S-1-5-21-1969217595-3321602994-1826570912-500
        msv :
         [00000003] Primary
         * Username : Administrator
         * Domain   : MYDOMAIN
         * LM       : LMHASH
         * NTLM     : NTLMHASH
         * SHA1     : SHA1HASH
        tspkg :
         * Username : Administrator
         * Domain   : MYDOMAIN
         * Password : MYPASSWORD
        wdigest :
         * Username : Administrator
         * Domain   : MYDOMAIN
         * Password : MYPASSWORD
        kerberos :
         * Username : Administrator
         * Domain   : MYDOMAIN.LOCAL
         * Password : MYPASSWORD
        ssp :
        credman :

Authentication Id : 0 ; 997 (00000000:000003e5)
Session           : Service from 0
User Name         : LOCAL SERVICE
Domain            : NT AUTHORITY
Logon Server      : (null)
Logon Time        : 1/9/2017 7:40:19 AM
SID               : S-1-5-19
        msv :
        tspkg :
        wdigest :
         * Username : (null)
         * Domain   : (null)
         * Password : (null)
        kerberos :
         * Username : (null)
         * Domain   : (null)
         * Password : (null)
        ssp :
        credman :

Authentication Id : 0 ; 996 (00000000:000003e4)
Session           : Service from 0
User Name         : WIN-H7MK73PJ720$
Domain            : MYDOMAIN
Logon Server      : (null)
Logon Time        : 1/9/2017 7:40:19 AM
SID               : S-1-5-20
        msv :
         [00000003] Primary
         * Username : WIN-H7MK73PJ720$
         * Domain   : MYDOMAIN
         * NTLM     : MYHASH
         * SHA1     : MYHASHSHA1
        tspkg :
        wdigest :
         * Username : WIN-H7MK73PJ720$
         * Domain   : MYDOMAIN
         * Password : pa ss wo rd
        kerberos :
         * Username : win-h7mk73pj720$
         * Domain   : attackiq.local
         * Password : pa ss wo rd
        ssp :
        credman :

Authentication Id : 0 ; 46511 (00000000:0000b5af)
Session           : UndefinedLogonType from 0
User Name         : (null)
Domain            : (null)
Logon Server      : (null)
Logon Time        : 1/9/2017 7:40:18 AM
SID               :
        msv :
         [00000003] Primary
         * Username : WIN-H7MK73PJ720$
         * Domain   : MYDOMAIN
         * NTLM     : MYHASH
         * SHA1     : MYHASHSHA1
        tspkg :
        wdigest :
        kerberos :
        ssp :
        credman :

Authentication Id : 0 ; 999 (00000000:000003e7)
Session           : UndefinedLogonType from 0
User Name         : WIN-H7MK73PJ720$
Domain            : MYDOMAIN
Logon Server      : (null)
Logon Time        : 1/9/2017 7:40:18 AM
SID               : S-1-5-18
        msv :
        tspkg :
        wdigest :
         * Username : WIN-H7MK73PJ720$
         * Domain   : MYDOMAIN
         * Password : pa ss wo rd
        kerberos :
         * Username : win-h7mk73pj720$
         * Domain   : MYDOMAIN.LOCAL
         * Password : pa ss wo rd
        ssp :
        credman :

mimikatz(commandline) # exit
Bye!"""
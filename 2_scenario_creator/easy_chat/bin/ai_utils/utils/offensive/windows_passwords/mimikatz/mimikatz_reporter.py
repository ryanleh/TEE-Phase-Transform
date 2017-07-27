import logging


class MimikatzReporter(object):

  def __init__(self, cred_types, usernames, credentials_object, phase_reporter=None, print_repeated=False):
    logging.debug('Executing MimikatzReporter constructor')
    self.cred_types = cred_types
    self.usernames = usernames
    self.credentials_object = credentials_object
    self.phase_reporter = phase_reporter
    self.print_repeated = print_repeated
    self.printed_objects = []

  def report(self):
    logging.debug('Executing report')
    valid_cred_objects = self.get_cred_objects_filtered_by_valid_usernames()  # only print cred_objects for valid users
    for cred_object in valid_cred_objects:
      if 'all' in self.cred_types:
        self.print_all_creds_in_ui(cred_object)
      else:
        if 'ntlm' in self.cred_types:
          self.print_ntlm_creds_in_ui(cred_object)
        if 'cleartext' in self.cred_types:
          self.print_cleartext_creds_in_ui(cred_object)

  def get_cred_objects_filtered_by_valid_usernames(self):
    if self.usernames:
      valid_cred_objects = [cred_object for cred_object in self.credentials_object if cred_object.get('user', '').lower() in self.usernames]
    else:
      valid_cred_objects = self.credentials_object
    return valid_cred_objects

  def print_all_creds_in_ui(self, cred_object):
    logging.debug('Executing print_cred_object_in_ui. cred_object: (redacted)')
    try:
      username = cred_object.get('user')
      if username and username != '(null)':  # mimikatz sets the user to (null)
        for cred_type in ['msv', 'tspkg', 'wdigest', 'livessp', 'kerberos', 'ssp', 'credman']:
          self.print_cred_object_in_ui(cred_object, cred_type)
    except Exception as print_cred_obj_ex:
      logging.warning('Error printing result object in UI. Error: {0}'.format(print_cred_obj_ex))

  def print_ntlm_creds_in_ui(self, cred_object):
    logging.debug('Executing print_ntlm_creds_in_ui. cred_object: (redacted)')
    username = cred_object.get('user')
    if username and username != '(null)':  # mimikatz sets the user to (null)
      self.print_cred_object_in_ui(cred_object, cred_type='msv')

  def print_cleartext_creds_in_ui(self, cred_object):
    logging.debug('Executing print_cleartext_creds_in_ui. cred_object: (redacted)')
    username = cred_object.get('user')
    if username and username != '(null)':  # mimikatz sets the user to (null)
      self.print_cred_object_in_ui(cred_object, cred_type='tspkg')
      self.print_cred_object_in_ui(cred_object, cred_type='wdigest')
      self.print_cred_object_in_ui(cred_object, cred_type='kerberos')

  def print_cred_object_in_ui(self, cred_object, cred_type):
    logging.debug('Executing print_cred_object_in_ui. cred_object: (redacted), cred_type: {}'.format(cred_type))
    printed = False
    cred_type_object = cred_object.get(cred_type)
    if cred_type_object:
      username = cred_type_object.get('user')
      if username and username != '(null)':
        printed = True
        pwd = self.get_password_from_cred_object(cred_type_object)
        domain = cred_type_object.get('domain', '(empty)')
        if not self.cred_already_printed(username, pwd, domain, cred_type):
          cred_info = 'Type: "{0}", Username: "{1}", Password: "{2}", Domain: "{3}"'.format(cred_type, username, pwd, domain)
          self.log_report(cred_info)
          self.printed_objects.append({'cred_type': cred_type, 'username': username, 'pwd': pwd, 'domain': domain})
      else:
        logging.debug('Credential object was not printed in the UI because it did not have a username')
    if not printed:
      # self.log_report('No credentials found for "{}" authentication provider'.format(cred_type))
      pass

  @staticmethod
  def get_password_from_cred_object(cred_type_object):
    logging.debug('Executing get_password_from_cred_object. cred_type_object: (redacted)')
    password = cred_type_object.get('password')
    if password and password != '(null)':
      password = '{0}'.format(password[:3] + '(redacted)')
    elif  password == '(could not be obtained)':
      pass
    else:
      password = '{0}'.format('(empty)')
    return password

  def cred_already_printed(self, username, pwd, domain, cred_type):
    return any([printed_obj['cred_type'].lower() == cred_type.lower() and
                printed_obj['username'].lower() == username.lower() and
                printed_obj['pwd'].lower() == pwd.lower() and
                printed_obj['domain'].lower() == domain.lower()
                for printed_obj in self.printed_objects])

  def log_report(self, msg):
    if self.phase_reporter:
      self.phase_reporter.Report(msg)
    else:
      logging.info(msg)

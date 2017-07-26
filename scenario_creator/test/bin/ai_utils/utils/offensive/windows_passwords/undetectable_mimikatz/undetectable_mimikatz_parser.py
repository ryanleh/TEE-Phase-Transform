import logging


class UndetectableMimikatzParser(object):

  @classmethod
  def parse_logongpasswords_output(cls, output):
    auth_blocks = cls.get_auth_blocks(output)
    return cls.process_auth_blocks(auth_blocks)

  @staticmethod
  def get_auth_blocks(output):
    logging.debug('Executing get_auth_blocks. output: {}(...)'.format(output[:20]))
    return [value.strip() for index, value in enumerate(output.split('Authentication Id : 0 ;')) if index != 0]

  @classmethod
  def process_auth_blocks(cls, auth_blocks):
    logging.debug('Executing process_auth_blocks. len(auth_blocks): {}'.format(len(auth_blocks)))
    credential_objects = []
    for block in auth_blocks:
      try:
        credential_object = cls.process_auth_block(block)
        credential_objects.append(credential_object)
      except Exception as process_auth_blocks_ex:
        logging.warning('There was a problem parsing an authentication block from mimikatz. Ignoring block.... Error: {0}'.format(process_auth_blocks_ex))
    return credential_objects

  @classmethod
  def process_auth_block(cls, auth_block):
    logging.debug('Executing process_auth_block. len(auth_block): {}'.format(len(auth_block)))
    credential_object = {}
    auth_block_lines = [line.strip() for line in auth_block.splitlines()]
    for generic_info in [('sid', 'SID'), ('user', 'User Name'), ('domain', 'Domain')]:
      credential_object[generic_info[0]] = cls.get_generic_info_from_auth_block(auth_block_lines, generic_info[1])
    for cred_type in ['tspkg', 'wdigest', 'livessp', 'kerberos', 'ssp', 'credman']:
      credential_object[cred_type] = cls.get_specific_credentials_from_auth_block(auth_block_lines, cred_type)
    credential_object['msv'] = cls.get_msv_credentials_from_auth_block(auth_block_lines)
    return credential_object

  @staticmethod
  def get_generic_info_from_auth_block(auth_block_lines, pattern):
    logging.debug('Executing get_generic_info_from_auth_block. len(auth_block_lines): {}, pattern: {}'.format(len(auth_block_lines), pattern))
    return_value = ''
    for line in auth_block_lines:
      if line.startswith(pattern):
        return_value = line.split(':')[1].strip()
        break
    return return_value

  @classmethod
  def get_specific_credentials_from_auth_block(cls, auth_block_lines, pattern):
    logging.debug('Executing get_specific_credentials_from_auth_block. len(auth_block_lines): {}, pattern: {}'.format(len(auth_block_lines), pattern))
    auth_data = {}
    for index, line in enumerate(auth_block_lines):
      if line.startswith(pattern) and cls.has_credentials_info(auth_block_lines, index):
        auth_data = cls.get_specific_auth_data(auth_block_lines, index)
        break
    return auth_data

  @classmethod
  def get_msv_credentials_from_auth_block(cls, auth_block_lines):
    logging.debug('Executing get_msv_credentials_from_auth_block. len(auth_block_lines): {}'.format(len(auth_block_lines)))
    auth_data = {}
    for index, line in enumerate(auth_block_lines):
      if line.startswith('[00000003] Primary') and cls.has_credentials_info(auth_block_lines, index):
        auth_data = cls.get_msv_auth_data(auth_block_lines, index)
        break
    return auth_data

  @staticmethod
  def has_credentials_info(auth_block_lines, index):
    logging.debug('Executing has_credentials_info. len(auth_block_lines): {}, index: {}'.format(len(auth_block_lines), index))
    # when creds type is found and it has contents, next line will always start with one of the following strings
    return index + 3 <= len(auth_block_lines) - 1 and auth_block_lines[index + 1].startswith('* Username')

  @staticmethod
  def get_specific_auth_data(auth_block_lines, index):
    logging.debug('Executing get_specific_auth_data. len(auth_block_lines): {}, index: {}'.format(len(auth_block_lines), index))
    return {
      'user': auth_block_lines[index + 1].split(':')[1].strip(),
      'domain': auth_block_lines[index + 2].split(':')[1].strip(),
      'password': auth_block_lines[index + 3].split(':')[1].strip()
    }

  @classmethod
  def get_msv_auth_data(cls, auth_block_lines, index):
    logging.debug('Executing get_msv_auth_data. len(auth_block_lines): {}, index: {}'.format(len(auth_block_lines), index))
    return {
      'user': auth_block_lines[index + 1].split(':')[1].strip(),
      'domain': auth_block_lines[index + 2].split(':')[1].strip(),
      'password': cls.process_msv_password_from_auth_block(auth_block_lines, index)
    }

  @staticmethod
  def process_msv_password_from_auth_block(auth_block_lines, index):
    logging.debug('Executing process_msv_password_from_auth_block. len(auth_block_lines): {}, index: {}'.format(len(auth_block_lines), index))
    if index + 4 <= len(auth_block_lines)-1:
      if auth_block_lines[index+3].startswith('* NTLM'):
        password = auth_block_lines[index + 3].split(':')[1].strip()
      elif auth_block_lines[index+4].startswith('* NTLM'):
        password = auth_block_lines[index + 4].split(':')[1].strip()
      else:
        password = '(null)'
    else:
      password = '(could not be obtained)'
    return password
import os
import json
import zipfile
import logging
import requests
from requests.exceptions import ConnectionError
from ai_utils.utils.pathutils import PathUtilsClass
from ai_utils.encryption.aes import AESEncryptionClass
from ai_utils.utils.agent_config import AgentConfigClass
from abstract_encrypted_file_cache import AbstractEncryptedFileCacheClass


SHA1_FILE_NAME = 'sha1.txt'

class EncryptedFileCacheError(Exception):
  pass

class EncryptedFileCacheClass(AbstractEncryptedFileCacheClass):

  def __init__(self, auto_delete=False):
    self._config = AgentConfigClass()
    self._aes = AESEncryptionClass()
    self._auto_delete = auto_delete

  def __del__(self):
    try:
      if self._auto_delete:
        PathUtilsClass.DeleteDirectory(self._get_temp_dir())
    except AttributeError as e:
      pass

  def _setup(self, partial_url):
    try:
      self._id, self._name = partial_url.split('/')
      self._partial_url = partial_url
      self._server_sha1 = None
    except ValueError:
      raise EncryptedFileCacheError("Invalid format partial_url. Needs to be '<guid>/filename.'")

  @staticmethod
  def _write_file(path, content, mode='wb'):
    try:
      with open(path, mode) as f:
        f.write(content)
        logging.debug('Wrote file: {}'.format(path))
        return path
    except (OSError, IOError) as e:
      raise EncryptedFileCacheError('Unable to write to file: {}.'.format(e))

  @staticmethod
  def _read_file(path, mode='rb'):
    try:
      with open(path, mode) as f:
        return f.read()
    except (OSError, IOError) as e:
      raise EncryptedFileCacheError('Unable to read file: {}'.format(e))

  @staticmethod
  def _is_acceptable_code(code, acceptable_codes=None):
    if code == requests.codes.ok:
      return True
    try:
      if code in acceptable_codes:
        return True
    except:
      return False

  def _requests_get(self, url, acceptable_status_codes=None, allow_redirects=False, no_headers=False):
    logging.debug('Downloading file:{}'.format(url))
    headers = {'Authorization': self._config.HttpHeaders['Authorization']}
    if no_headers:
      headers = {}
    response = requests.get(url, headers=headers, verify=False, allow_redirects=allow_redirects)
    if self._is_acceptable_code(response.status_code, acceptable_status_codes):
      return response
    else:
      raise ConnectionError('Unable to download file from server ({}).'.format(response.status_code))

  def _download(self):
    url = self._config.ServerUrl + '/downloads/files/' + self._partial_url
    response = self._requests_get(url, acceptable_status_codes=[200, 302])
    if response.status_code == 302:
      redirect_url = response.headers.get('location')
      response = self._requests_get(redirect_url, allow_redirects=True, no_headers=True)
    return response.content

  def _download_write_encrypt(self):
    if not os.path.isfile(self._get_encrypted_path()) or self._get_local_sha1() != self._get_server_sha1():
      logging.debug('Local and server sha1 are different.')
      content = self._download()
      self._write_file(self._get_encrypted_path(), self._aes.encrypt(content))
      self._write_file(self._get_sha1_path(), self._get_server_sha1(), 'w')
    else:
      logging.debug('Local and server sha1 are the same.')

  def _join_and_create_dir(self, path, paths):
    try:
      new_path = os.path.join(path, paths)
      return PathUtilsClass.MakeDirectory(new_path)
    except OSError as e:
      raise EncryptedFileCacheError('Unable to access/create directory: {}'.format(e))

  def _get_file_cache_dir(self):
    return self._join_and_create_dir(PathUtilsClass.GetFileCacheDirectory(), self._id)

  def _get_sha1_path(self):
    return os.path.join(self._get_file_cache_dir(), SHA1_FILE_NAME)

  def _get_encrypted_path(self):
    return os.path.join(self._get_file_cache_dir(), self._name)

  def _get_local_sha1(self):
    if os.path.isfile(self._get_sha1_path()):
      return  self._read_file(self._get_sha1_path(), 'r')
    else:
      logging.debug('No local sha1 file present.')
      return None

  def _get_temp_dir(self):
    return self._join_and_create_dir(PathUtilsClass.GetFilesDirectory(), self._id)

  def _get_server_sha1(self):
    if not self._server_sha1:
      url = self._config.ServerUrl + '/v1/files/' + self._id
      response = self._requests_get(url)
      data = json.loads(response.content)
      self._server_sha1 = data['sha1']
      logging.debug('Server sha1: {}'.format(self._server_sha1))
    return self._server_sha1

  def _decrypt_file(self):
    encrypted_content = self._read_file(self._get_encrypted_path())
    return self._aes.decrypt(encrypted_content)

  def _write_decrypted_file(self, content):
    decrypted_path = os.path.join(self._get_temp_dir(), self._name)
    return self._write_file(decrypted_path, content)

  def _unzip_file(self, path, ignore_unzip_errors):
    try:
      zip_ref = zipfile.ZipFile(path, 'r')
      zip_ref.extractall(self._get_temp_dir())
      zip_ref.close()
      logging.debug('Unzipped {} to {}'.format(path, self._get_temp_dir()))
    except Exception as e:
      if not ignore_unzip_errors:
        raise EncryptedFileCacheError('Unable to unzip file: {}'.format(e))
      else:
        logging.info('Unable to unzip file: {}'.format(path))

  def _try_download(self):
    try:
      self._download_write_encrypt()
    except ConnectionError as e:
      logging.debug('Got connection error connecting to server.')
      if os.path.isfile(self._get_encrypted_path()):
        logging.debug('Using cached version of file.')
      else:
        raise EncryptedFileCacheError('Unable to download file, and no existing cache: {}'.format(e))

  def get(self, partial_url, unzip=True, ignore_unzip_errors=False):
    self._setup(partial_url)
    self._try_download()
    decrypted_content = self._decrypt_file()
    decrypted_path = self._write_decrypted_file(decrypted_content)
    if unzip:
      self._unzip_file(decrypted_path, ignore_unzip_errors)
    return self._get_temp_dir()


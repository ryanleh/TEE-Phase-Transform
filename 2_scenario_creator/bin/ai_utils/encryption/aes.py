import os
import random
import base64
import hashlib
import logging
from ai_utils.exceptions import PrereqError
from ai_utils.utils.fileutils import FileUtilsClass
from ai_utils.utils.pathutils import PathUtilsClass
try:
    from Crypto import Random
    from Crypto.Cipher import AES
except ImportError:
    logging.error('Crypto (PyCrypto) library could not be imported')

if os.name == 'nt':
    from ai_utils.utils.registryutils import RegistryUtils


class AESEncryptionClass(object):

    def __init__(self, key=None):
        self._bs = 16
        self._key = self._prepare_key(key)

    def _pad(self, s):
        return s + (self._bs - len(s) % self._bs) * chr(self._bs - len(s) % self._bs)

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s) - 1:])]

    @staticmethod
    def _get_idv2():
        if os.name == 'nt':
            return RegistryUtils.get_data('hklm', 'SOFTWARE\\AiPersist', 'MachineGuidV2')
        else:
            idv2_path = PathUtilsClass.GetLocalIdv2()
            return FileUtilsClass.ReadFromFile(idv2_path)

    def _prepare_key(self, key):
        if key:
            logging.debug('Using provided key.')
        else: # Try to read idv2
            key = self._get_idv2()
            if key:
                logging.debug('Using idv2 key: {}'.format(key))
            else:
                raise PrereqError('Unable to determine machine-guid or idv2, can not encrypt.')
        key = hashlib.sha256(key.encode()).digest()
        return key

    def encrypt(self, raw):
        raw = self._pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self._key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw))

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        cipher = AES.new(self._key, AES.MODE_CBC, iv)
        return self._unpad(cipher.decrypt(enc[AES.block_size:]))

from itertools import cycle, izip

class XorEncryptionClass(object):
  def __init__(self, key):
    self.Key = key

  def Encrypt(self, message):
    cipher = ''.join(chr(ord(c)^ord(k)) for c, k in izip(message, cycle(self.Key)))
    return cipher

  def Decrypt(self, cipher):
    message = ''.join(chr(ord(c)^ord(k)) for c, k in izip(cipher, cycle(self.Key)))
    return message

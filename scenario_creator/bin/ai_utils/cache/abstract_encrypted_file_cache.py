class AbstractEncryptedFileCacheClass(object):
  def get(self, partial_url):
    raise NotImplementedError('subclasses must override get()!')

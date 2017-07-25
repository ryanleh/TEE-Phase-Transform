from ai_utils.phases.abstract_phase import AbstractPhaseClass
from contextlib import contextmanager
import datetime
import logging
import socket
import time


class CryptolockerDGAPhaseClass(AbstractPhaseClass):
  TrackerId = "201"
  Subject = "Cryptolcoker DGA"
  Description = "Domain Name Generation using Cryptolocker's DGA"

  MASK32 = 0xffffffff
  SUFFIXES = ["com", "net", "biz", "ru", "org", "co.uk", "info"]
  MAX_DOMAIN_NAME_TRYCOUNT = 50

  def __init__(self, is_phase_critical):
    AbstractPhaseClass.__init__(self, is_phase_critical)
    logging.debug('Executing ')
    now = datetime.datetime.now()
    self.day = now.day
    self.month = now.month
    self.year = now.year

  def Run(self):
    logging.debug('Executing Run')
    name_list = self.generate_domain_names()
    valid_name_tuple = self.get_valid_domain_info(name_list)
    phase_successful = len(valid_name_tuple) > 0
    self.log_success(phase_successful, name_list, valid_name_tuple)
    return phase_successful

  @contextmanager
  def exception_handler(self):
    try:
      yield
    except socket.gaierror as e:
      logging.info(e)
    except Exception as e:
      logging.exception(e)

  def generate_domain_name(self, day, month, year_plus_attempt):
    logging.debug('Executing generate_domain_name. day: {}, month: {}, year_plus_attempt: {}'.format(day, month, year_plus_attempt))
    domain = ''
    a = ((day << 16) + day) & self.MASK32
    b = ((month << 16) + month) & self.MASK32
    c = ((year_plus_attempt << 16) + year_plus_attempt) & self.MASK32
    length = ((a >> 3 ^ c >> 8 ^ c >> 11) & 3) + 12
    for _ in range(length):
      a = (((a << 13 & self.MASK32) >> 19) ^ ((a >> 1) << 13 & self.MASK32) ^ (a >> 19)) & self.MASK32
      b = (((b << 2 & self.MASK32) >> 25) ^ ((b >> 3) << 7 & self.MASK32) ^ (b >> 25)) & self.MASK32
      c = (((c << 3 & self.MASK32) >> 11) ^ ((c >> 4) << 21 & self.MASK32) ^ (c >> 11)) & self.MASK32
      domain += chr(ord('a') + (a ^ b ^ c) % 25)
    return domain

  def generate_domain_names(self):
    logging.debug('Executing generate_domain_names')
    domains = []
    self.PhaseReporter.Debug('Only {} domains will be generated using Cryptolocker\'s DGA'.format(self.MAX_DOMAIN_NAME_TRYCOUNT))
    for i in range(self.MAX_DOMAIN_NAME_TRYCOUNT):
      domains.append(self.generate_full_domain_name(i))
    return domains

  def generate_full_domain_name(self, attempt_count):
    logging.debug('Executing generate_full_domain_name. attempt_count: {}'.format(attempt_count))
    main_part = self.generate_domain_name(self.day, self.month, self.year + attempt_count)
    suffix = self.SUFFIXES[attempt_count % len(self.SUFFIXES)]
    return main_part + '.' + suffix

  def get_valid_domain_info(self, domain_name_list):
    logging.debug('Executing ')
    valid_domain_info = ()
    for try_count, domain in enumerate(domain_name_list):
      valid_domain_info = self.resolve_domain(domain, try_count)
      if valid_domain_info:
        break
      time.sleep(0.1)
    return valid_domain_info

  def resolve_domain(self, domain, try_count):
    valid_domain_info = ()
    with self.exception_handler():
      self.PhaseReporter.Debug('Trying to resolve domain name "{}"'.format(domain))
      ip_address = socket.gethostbyname(domain)
      if ip_address:
        self.PhaseReporter.Info('Domain name "{}" successfully resolved to IP "{}"'.format(domain, ip_address))
        valid_domain_info = (try_count, domain, ip_address)
    return valid_domain_info

  def log_success(self, phase_successful, name_list, valid_name_tuple):
    logging.debug('Executing log_success. phase_successful: {}, name_list: {}, valid_name_tuple: {}'.format(phase_successful, name_list, valid_name_tuple))
    self.PhaseResult['partial_name_list'] = str(name_list[:10])
    self.PhaseResult['valid_domain_info'] = str(valid_name_tuple)
    if phase_successful:
      self.PhaseReporter.Info('Successfully found domain name using Cryptolocker\'s DGA')
      self.PhaseReporter.Report('Domain name "{}" generated through CryptoLocker\'s DGA was successfully reached'.format(valid_name_tuple[1]))
      self.PhaseReporter.Mitigation('Your DNS servers should not resolve the following domain name: {}'.format(valid_name_tuple[1]))
    else:
      self.PhaseReporter.Info('Failed to find live domain names using CryptoLocker\'s DGA')

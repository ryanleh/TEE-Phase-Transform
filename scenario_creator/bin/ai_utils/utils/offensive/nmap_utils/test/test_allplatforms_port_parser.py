from ai_utils.utils.offensive.nmap_utils.port_parser import PortParser
from ai_utils.ai_logging.simplelogger import AiLoggerClass
import unittest
import logging


class TestPortParser(unittest.TestCase):

    def setUp(self):
        AiLoggerClass(loggingLevel=logging.DEBUG).Enable()

    def test_parse_ports(self):
        valid_port_expressions = {
          '': [],
          '80,53': [80, 53],
          '80,53, 52': [80, 53, 52],
          '80,53, 53': [80, 53, 53],
          '53-60': [53, 54, 55, 56, 57, 58, 59, 60],
          '1024-1026,80,40': [1024, 1025, 1026, 80, 40],
          '1024-1026,80,40-42': [1024, 1025, 1026, 80, 40, 41, 42],
          '1,,2': [1,2],
          '-': [port for port in range(1, 65535+1)]
        }
        invalid_port_expressions = {
          '60-40': None,
          '-1': None,
          '1,2,-1': [1,2],
          '1,2,60-40': [1,2],
          '1,2,60--1': [1,2],
          '1,2,60-60': [1, 2],
          '1,2,60-60,5,8-10': [1, 2, 5, 8, 9, 10],
          '-1-30': None,
          '0': None,
          '1,nondigit': None,
          '1,2,60-nondigit,5,8-10': None
        }
        for port_expressions in [valid_port_expressions, invalid_port_expressions]:
            for port_expression, expected_value in port_expressions.iteritems():
                port_list = PortParser().parse_ports(port_expression)
                self.assertEqual(port_list, expected_value)

from ai_utils.phases.create_volume_shadow_copy import CreateVolumeShadowCopyPhaseClass
from ai_utils.ai_logging.simplelogger import AiLoggerClass
import unittest
import logging


class TestCreateVolumeShadowCopyPhaseClass(unittest.TestCase):

  def setUp(self):
    AiLoggerClass(loggingLevel=logging.DEBUG).Enable()

  def test_valid_parameters(self):
    phase = CreateVolumeShadowCopyPhaseClass(True, True)
    success = phase.Execute()
    self.assertTrue(success)

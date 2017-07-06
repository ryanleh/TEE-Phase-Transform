from ai_utils.phases.check_uac_level import CheckUACLevelPhaseClass
import unittest
import logging


class TestCheckUACLevel(unittest.TestCase):

  def test_expect_custom_uac_level_non_strict_mode(self):
    self.run_test_assert_boolean(True, 1, False)

  def test_expect_only_computer_changes_not_dim_uac_level_non_strict_mode(self):
    self.run_test_assert_boolean(True, 2, False)

  def test_expect_only_computer_changes_dim_uac_level_non_strict_mode(self):
    self.run_test_assert_boolean(True, 3, False)

  def test_expect_always_notify_uac_level_non_strict_mode(self):
    self.run_test_assert_boolean(False, 4, False)

  def test_expect_custom_uac_level_strict_mode(self):
    self.run_test_assert_boolean(False, 1, True)

  def test_expect_only_computer_changes_not_dim_uac_level_strict_mode(self):
    self.run_test_assert_boolean(False, 2, True)

  def test_expect_only_computer_changes_dim_uac_level_strict_mode(self):
    self.run_test_assert_boolean(True, 3, True)

  def test_expect_always_notify_uac_level_strict_mode(self):
    self.run_test_assert_boolean(False, 4, True)

  def test_invalid_uac_level(self):
    self.run_test_assert_boolean(False, -1, True)

  def run_test_assert_boolean(self, assert_true, expected_uac_level, strict_mode):
    try:
      check_uac_level = CheckUACLevelPhaseClass(True, expected_uac_level, strict_mode)
      success = check_uac_level.Execute()
    except Exception as e:
      success = False
      logging.error(e)
    if assert_true:
      self.assertTrue(success)
    else:
      self.assertFalse(success)

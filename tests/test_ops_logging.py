"""Tests for brig.ops.logging — the canonical logging implementation."""

import io
import sys
import unittest
from unittest.mock import patch

from brig.ops.logging import (
    LOG_LEVEL_DEBUG,
    LOG_LEVEL_ERROR,
    LOG_LEVEL_INFO,
    LOG_LEVEL_WARN,
    Spinner,
    _state,
    colorize,
    configure,
    debug,
    info,
    is_color,
    is_debug,
    is_quiet,
    log,
    output,
    status_color,
    warn,
)


class TestConfigure(unittest.TestCase):
    """Test configure() sets state correctly."""

    def setUp(self):
        # Save original state.
        self._orig = dict(_state)

    def tearDown(self):
        _state.update(self._orig)

    def test_configure_debug(self):
        configure(debug=True)
        self.assertTrue(is_debug())
        self.assertEqual(_state["log_level"], LOG_LEVEL_DEBUG)

    def test_configure_quiet(self):
        configure(quiet=True)
        self.assertTrue(is_quiet())

    def test_configure_color_off(self):
        configure(color=False)
        self.assertFalse(is_color())

    def test_configure_partial_no_clobber(self):
        """Setting one flag does not reset others."""
        configure(debug=True)
        configure(quiet=True)
        self.assertTrue(is_debug())
        self.assertTrue(is_quiet())


class TestColorize(unittest.TestCase):
    """Test colorize() with colors on and off."""

    def setUp(self):
        self._orig = dict(_state)

    def tearDown(self):
        _state.update(self._orig)

    def test_colorize_enabled(self):
        _state["color"] = True
        result = colorize("hello", "green")
        self.assertIn("\033[32m", result)
        self.assertIn("hello", result)
        self.assertIn("\033[0m", result)

    def test_colorize_disabled(self):
        _state["color"] = False
        result = colorize("hello", "green")
        self.assertEqual(result, "hello")

    def test_colorize_unknown_color(self):
        _state["color"] = True
        result = colorize("hello", "neon")
        self.assertEqual(result, "hello")


class TestStatusColor(unittest.TestCase):
    """Test status_color() maps statuses to correct colors."""

    def setUp(self):
        self._orig = dict(_state)
        _state["color"] = True

    def tearDown(self):
        _state.update(self._orig)

    def test_running_green(self):
        result = status_color("running")
        self.assertIn("\033[32m", result)

    def test_paused_yellow(self):
        result = status_color("paused")
        self.assertIn("\033[33m", result)

    def test_exited_red(self):
        result = status_color("exited")
        self.assertIn("\033[31m", result)

    def test_stopped_red(self):
        result = status_color("stopped")
        self.assertIn("\033[31m", result)

    def test_created_blue(self):
        result = status_color("created")
        self.assertIn("\033[34m", result)

    def test_unknown_passthrough(self):
        result = status_color("unknown-state")
        self.assertEqual(result, "unknown-state")


class TestLog(unittest.TestCase):
    """Test log() respects log level and quiet mode."""

    def setUp(self):
        self._orig = dict(_state)
        _state["color"] = False

    def tearDown(self):
        _state.update(self._orig)

    def test_log_at_level(self):
        _state["log_level"] = LOG_LEVEL_INFO
        with patch("sys.stderr", new_callable=io.StringIO) as mock_err:
            log(LOG_LEVEL_INFO, "test message")
            self.assertIn("[INFO] test message", mock_err.getvalue())

    def test_log_below_level_suppressed(self):
        _state["log_level"] = LOG_LEVEL_WARN
        with patch("sys.stderr", new_callable=io.StringIO) as mock_err:
            log(LOG_LEVEL_INFO, "should not appear")
            self.assertEqual(mock_err.getvalue(), "")

    def test_quiet_suppresses_info(self):
        _state["log_level"] = LOG_LEVEL_DEBUG
        _state["quiet"] = True
        with patch("sys.stderr", new_callable=io.StringIO) as mock_err:
            log(LOG_LEVEL_INFO, "suppressed")
            self.assertEqual(mock_err.getvalue(), "")

    def test_quiet_allows_warn(self):
        _state["log_level"] = LOG_LEVEL_DEBUG
        _state["quiet"] = True
        with patch("sys.stderr", new_callable=io.StringIO) as mock_err:
            log(LOG_LEVEL_WARN, "should appear")
            self.assertIn("[WARN]", mock_err.getvalue())

    def test_custom_level_name(self):
        _state["log_level"] = LOG_LEVEL_DEBUG
        with patch("sys.stderr", new_callable=io.StringIO) as mock_err:
            log(LOG_LEVEL_DEBUG, "hi", level_name="TRACE")
            self.assertIn("[TRACE]", mock_err.getvalue())


class TestHelpers(unittest.TestCase):
    """Test debug(), info(), warn(), output()."""

    def setUp(self):
        self._orig = dict(_state)
        _state["color"] = False

    def tearDown(self):
        _state.update(self._orig)

    def test_debug_when_enabled(self):
        _state["log_level"] = LOG_LEVEL_DEBUG
        with patch("sys.stderr", new_callable=io.StringIO) as mock_err:
            debug("dbg")
            self.assertIn("[DEBUG] dbg", mock_err.getvalue())

    def test_info_at_default_level(self):
        _state["log_level"] = LOG_LEVEL_INFO
        with patch("sys.stderr", new_callable=io.StringIO) as mock_err:
            info("inf")
            self.assertIn("[INFO] inf", mock_err.getvalue())

    def test_warn(self):
        _state["log_level"] = LOG_LEVEL_DEBUG
        with patch("sys.stderr", new_callable=io.StringIO) as mock_err:
            warn("wrn")
            self.assertIn("[WARN] wrn", mock_err.getvalue())

    def test_output_normal(self):
        _state["quiet"] = False
        with patch("sys.stdout", new_callable=io.StringIO) as mock_out:
            output("hello")
            self.assertIn("hello", mock_out.getvalue())

    def test_output_quiet(self):
        _state["quiet"] = True
        with patch("sys.stdout", new_callable=io.StringIO) as mock_out:
            output("hello")
            self.assertEqual(mock_out.getvalue(), "")


class TestSpinner(unittest.TestCase):
    """Test Spinner context manager."""

    def test_spinner_no_tty(self):
        """Spinner does not start thread when stderr is not a TTY."""
        with Spinner("test") as s:
            self.assertFalse(s.running)

    def test_spinner_exit_returns_false(self):
        """Spinner.__exit__ returns False (does not suppress exceptions)."""
        s = Spinner("test")
        self.assertFalse(s.__exit__(None, None, None))

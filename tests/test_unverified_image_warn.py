"""The unverified-image warning fires by default but can be silenced
via `brig config set suppress_unverified_image_warn true`.

Why a kill-switch: experienced users who have made an explicit trust
decision (e.g. running their own internal registry, or curating images
externally) shouldn't have to see the same warning on every run. The
default remains warn — silence is opt-in.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


class TestUnverifiedImageWarn(unittest.TestCase):
    def _run_with_config(self, image: str, config: dict | None) -> list[str]:
        from brig.commands.lifecycle_cmd import _warn_unverified_image
        with tempfile.TemporaryDirectory() as td:
            cfg = Path(td) / "config.json"
            if config is not None:
                cfg.write_text(json.dumps(config))
            with patch("brig.config.CONFIG_FILE", cfg):
                msgs: list[str] = []
                with patch("brig.commands.lifecycle_cmd.info",
                           side_effect=msgs.append):
                    _warn_unverified_image(image)
                return msgs

    def test_warns_by_default(self):
        msgs = self._run_with_config("alpine", config=None)
        self.assertEqual(len(msgs), 1)
        self.assertIn("unpinned and unverified", msgs[0])

    def test_warning_mentions_suppress_path(self):
        msgs = self._run_with_config("alpine", config={})
        self.assertEqual(len(msgs), 1)
        self.assertIn("brig config set suppress_unverified_image_warn", msgs[0])

    def test_suppress_flag_silences(self):
        msgs = self._run_with_config(
            "alpine", config={"suppress_unverified_image_warn": True})
        self.assertEqual(msgs, [])

    def test_explicit_false_does_not_silence(self):
        msgs = self._run_with_config(
            "alpine", config={"suppress_unverified_image_warn": False})
        self.assertEqual(len(msgs), 1)

    def test_localhost_image_silent_regardless(self):
        msgs = self._run_with_config("localhost/foo:latest", config={})
        self.assertEqual(msgs, [])

    def test_digest_pinned_silent_regardless(self):
        msgs = self._run_with_config(
            "alpine@sha256:" + "a" * 64, config={})
        self.assertEqual(msgs, [])

    def test_malformed_config_treated_as_warn(self):
        from brig.commands.lifecycle_cmd import _warn_unverified_image
        with tempfile.TemporaryDirectory() as td:
            cfg = Path(td) / "config.json"
            cfg.write_text("{ not valid json")
            with patch("brig.config.CONFIG_FILE", cfg):
                msgs: list[str] = []
                with patch("brig.commands.lifecycle_cmd.info",
                           side_effect=msgs.append):
                    _warn_unverified_image("alpine")
                self.assertEqual(len(msgs), 1)


if __name__ == "__main__":
    unittest.main()

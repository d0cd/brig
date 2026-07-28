"""Tests for brig.security.image — image signature verification."""

import subprocess
import unittest
from unittest.mock import patch

from brig.security.image import _parse_cosign_output, verify_image_signature


class TestParseCosignOutput(unittest.TestCase):
    def test_valid_json_list(self):
        result = _parse_cosign_output('[{"verified": true}]')
        self.assertEqual(result, {"verified": True})

    def test_empty_list(self):
        self.assertEqual(_parse_cosign_output("[]"), {})

    def test_invalid_json(self):
        self.assertEqual(_parse_cosign_output("not json"), {})

    def test_empty_string(self):
        self.assertEqual(_parse_cosign_output(""), {})


class TestVerifyImageSignature(unittest.TestCase):
    @patch("brig.security.image.subprocess.run")
    def test_cosign_missing_fails_closed(self, mock_run):
        """When cosign is missing, verification fails closed (no podman trust fallback).

        The podman trust fallback was removed in M2 because `podman image
        trust show` returns a global policy that doesn't tell us whether the
        specific image is covered by an "accept" rule — vacuous trust.
        """
        def side_effect(cmd, **kwargs):
            if cmd[0] == "which":
                return subprocess.CompletedProcess(cmd, 1)
            return subprocess.CompletedProcess(cmd, 0, stdout="default  accept", stderr="")
        mock_run.side_effect = side_effect
        ok, msg, _ = verify_image_signature("alpine:latest", key="/path/to/key")
        self.assertFalse(ok)
        self.assertIn("cosign", msg.lower())

    @patch("brig.security.image.subprocess.run")
    def test_cosign_verify_success(self, mock_run):
        def side_effect(cmd, **kwargs):
            if cmd[0] == "which":
                return subprocess.CompletedProcess(cmd, 0)
            # cosign verify
            return subprocess.CompletedProcess(cmd, 0, stdout='[{"verified":true}]', stderr="")
        mock_run.side_effect = side_effect
        ok, msg, details = verify_image_signature("myimage:latest", key="/path/to/key")
        self.assertTrue(ok)
        self.assertIn("cosign", msg)

    @patch("brig.security.image.subprocess.run")
    def test_cosign_no_signature(self, mock_run):
        def side_effect(cmd, **kwargs):
            if cmd[0] == "which":
                return subprocess.CompletedProcess(cmd, 0)
            return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="no matching signatures")
        mock_run.side_effect = side_effect
        ok, msg, _ = verify_image_signature("myimage:latest", key="/path/to/key")
        self.assertFalse(ok)
        self.assertIn("no signature", msg)

    @patch("brig.security.image.subprocess.run")
    def test_cosign_failure(self, mock_run):
        def side_effect(cmd, **kwargs):
            if cmd[0] == "which":
                return subprocess.CompletedProcess(cmd, 0)
            return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="connection refused")
        mock_run.side_effect = side_effect
        ok, msg, _ = verify_image_signature("myimage:latest", key="/path/to/key")
        self.assertFalse(ok)
        self.assertIn("connection refused", msg)

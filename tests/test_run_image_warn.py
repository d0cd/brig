"""`brig run` warns about unverified, unpinned non-local images.

Doesn't refuse — verification is a publishing trust decision that
varies per user. But running `brig run someorg/img:latest` shouldn't
slip through quietly with no signal that a digest pin or signature
verification was skipped.
"""

from __future__ import annotations

import unittest
from unittest.mock import patch


def _capture(image: str) -> str:
    """Run the warning function and capture combined info/output."""
    # info() writes via configure_logging; in tests it goes to stderr or
    # stdout depending on color/quiet. Patch it directly for determinism.
    with patch("brig.commands.lifecycle_cmd.info") as mock_info:
        from brig.commands.lifecycle_cmd import _warn_unverified_image
        _warn_unverified_image(image)
    return " ".join(str(c.args[0]) for c in mock_info.call_args_list)


class TestImageWarn(unittest.TestCase):
    def test_local_image_silent(self):
        self.assertEqual(_capture("localhost/my-agent:latest"), "")
        self.assertEqual(_capture("localhost/foo:dev"), "")

    def test_digest_pinned_silent(self):
        digest = "@sha256:" + "a" * 64
        self.assertEqual(_capture(f"alpine{digest}"), "")
        self.assertEqual(_capture(f"docker.io/library/alpine{digest}"), "")

    def test_sha512_digest_silent(self):
        digest = "@sha512:" + "b" * 128
        self.assertEqual(_capture(f"alpine{digest}"), "")

    def test_implicit_dockerhub_warns(self):
        out = _capture("alpine")
        self.assertIn("unpinned and unverified", out)
        self.assertIn("brig image verify", out)

    def test_tagged_registry_image_warns(self):
        out = _capture("quay.io/some/img:latest")
        self.assertIn("unpinned and unverified", out)

    def test_empty_silent(self):
        # brig run --file (image comes from yaml) may pass image="" here
        # before the cell spec fills it in. Don't crash.
        self.assertEqual(_capture(""), "")


if __name__ == "__main__":
    unittest.main()

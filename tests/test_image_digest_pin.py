"""image_digest pin format — sha256 only, exact hex length.

Only sha256 is accepted: OCI registry manifest digests (what podman matches at
pull time and reports as {{.ImageDigest}} for the start-time re-check) are
sha256, so a sha384/sha512 pin could never match and would fail on restart with
a spurious "digest drift". Rejecting them at validation fails fast with a clear
message. The pin must be exactly sha256:<64 hex>.
"""

from __future__ import annotations

import subprocess
import unittest
from unittest.mock import patch

from brig.cell.lifecycle import _apply_image_digest_pin
from brig.cell.spec import CellSpec
from brig.errors import BrigError


def _spec(digest: str) -> CellSpec:
    return CellSpec(name="c", image="alpine", image_digest=digest)


class TestImageDigestPin(unittest.TestCase):

    def test_valid_sha256_pins(self):
        spec = _spec("sha256:" + "a" * 64)
        _apply_image_digest_pin(spec)
        self.assertEqual(spec.image, "alpine@sha256:" + "a" * 64)

    def test_sha512_pin_rejected(self):
        # Well-formed sha512, but only sha256 works end-to-end — reject it at
        # validation rather than let the cell fail to restart on digest drift.
        with self.assertRaises(BrigError):
            _apply_image_digest_pin(_spec("sha512:" + "b" * 128))

    def test_sha384_pin_rejected(self):
        with self.assertRaises(BrigError):
            _apply_image_digest_pin(_spec("sha384:" + "b" * 96))

    def test_over_long_sha256_rejected(self):
        with self.assertRaises(BrigError):
            _apply_image_digest_pin(_spec("sha256:" + "a" * 65))

    def test_short_sha256_rejected(self):
        with self.assertRaises(BrigError):
            _apply_image_digest_pin(_spec("sha256:" + "a" * 63))

    def test_sha512_with_sha256_length_rejected(self):
        with self.assertRaises(BrigError):
            _apply_image_digest_pin(_spec("sha512:" + "c" * 64))

    def test_trailing_newline_rejected(self):
        # .strip() handles a trailing newline on the digest, but an embedded
        # one must not pass via a `$`-style anchor.
        with self.assertRaises(BrigError):
            _apply_image_digest_pin(_spec("sha256:" + "a" * 32 + "\n" + "a" * 32))


class TestVerifyDigestOnStartFailsClosed(unittest.TestCase):
    """A pinned cell must refuse to start when the container's ImageDigest is
    empty/unavailable — that's the commit-swap window the check exists for."""

    def test_empty_actual_digest_raises(self):
        from brig.commands import lifecycle_control
        with patch("brig.cell.metadata.read_image_digest",
                          return_value="sha256:" + "a" * 64), \
             patch.object(lifecycle_control, "vm_run",
                          return_value=subprocess.CompletedProcess([], 0, "", "")):
            with self.assertRaises(BrigError) as ctx:
                lifecycle_control._verify_image_digest_on_start("c")
        self.assertIn("digest", str(ctx.exception).lower())

    def test_matching_digest_passes(self):
        from brig.commands import lifecycle_control
        pinned = "sha256:" + "a" * 64
        with patch("brig.cell.metadata.read_image_digest",
                          return_value=pinned), \
             patch.object(lifecycle_control, "vm_run",
                          return_value=subprocess.CompletedProcess([], 0, pinned + "\n", "")):
            lifecycle_control._verify_image_digest_on_start("c")  # no raise

    def test_unpinned_cell_is_noop(self):
        from brig.commands import lifecycle_control
        with patch("brig.cell.metadata.read_image_digest", return_value=None):
            lifecycle_control._verify_image_digest_on_start("c")  # no raise


if __name__ == "__main__":
    unittest.main()

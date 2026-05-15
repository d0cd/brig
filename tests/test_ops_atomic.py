"""Tests for brig.ops.atomic — host-side atomic write helper."""

import json
import tempfile
import unittest
from pathlib import Path

from brig.ops.atomic import atomic_write_json, atomic_write_text


class TestAtomicWriteJson(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.target = Path(self.tmpdir) / "out.json"

    def test_writes_data(self):
        atomic_write_json(self.target, {"k": "v"})
        self.assertEqual(json.loads(self.target.read_text()), {"k": "v"})

    def test_creates_parent_dirs(self):
        nested = Path(self.tmpdir) / "a" / "b" / "c.json"
        atomic_write_json(nested, [1, 2, 3])
        self.assertEqual(json.loads(nested.read_text()), [1, 2, 3])

    def test_overwrites_existing(self):
        atomic_write_json(self.target, {"first": 1})
        atomic_write_json(self.target, {"second": 2})
        self.assertEqual(json.loads(self.target.read_text()), {"second": 2})

    def test_failure_leaves_target_untouched(self):
        atomic_write_json(self.target, {"original": True})
        with self.assertRaises(TypeError):
            atomic_write_json(self.target, {"bad": {1, 2, 3}})  # set is not JSON-serializable
        self.assertEqual(json.loads(self.target.read_text()), {"original": True})

    def test_no_temp_file_left_behind_on_failure(self):
        with self.assertRaises(TypeError):
            atomic_write_json(self.target, object())
        leftovers = list(Path(self.tmpdir).glob("*.tmp"))
        self.assertEqual(leftovers, [])


class TestAtomicWriteText(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.target = Path(self.tmpdir) / "out.txt"

    def test_writes_text(self):
        atomic_write_text(self.target, "hello\nworld\n")
        self.assertEqual(self.target.read_text(), "hello\nworld\n")


if __name__ == "__main__":
    unittest.main()

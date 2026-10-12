from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from maccleaner import sizes
from maccleaner.safety import SafetyError, assert_writable_target, is_protected


class TestSizes(unittest.TestCase):
    def test_human(self) -> None:
        self.assertEqual(sizes.human(0), "0 B")
        self.assertEqual(sizes.human(1023), "1023 B")
        self.assertEqual(sizes.human(1024), "1.0 KB")
        self.assertEqual(sizes.human(1024**3 * 5), "5.0 GB")

    def test_parse_size(self) -> None:
        self.assertEqual(sizes.parse_size("500"), 500)
        self.assertEqual(sizes.parse_size("500M"), 500 * 1024**2)
        self.assertEqual(sizes.parse_size("1.5gb"), int(1.5 * 1024**3))
        with self.assertRaises(ValueError):
            sizes.parse_size("abc")

    def test_parse_age_days(self) -> None:
        self.assertEqual(sizes.parse_age_days("30d"), 30)
        self.assertEqual(sizes.parse_age_days("1y"), 365)
        self.assertAlmostEqual(sizes.parse_age_days("12h"), 0.5)
        with self.assertRaises(ValueError):
            sizes.parse_age_days("5x")

    def test_dir_size_skips_symlinks(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "real").mkdir()
            (root / "real" / "a.bin").write_bytes(b"x" * 100)
            os.symlink(root / "real", root / "link")
            self.assertEqual(sizes.dir_size(root), 100)

    def test_iter_files_respects_skip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "keep").mkdir()
            (root / "keep" / "a.txt").write_text("a")
            (root / "node_modules").mkdir()
            (root / "node_modules" / "b.txt").write_text("b")
            found = {p.name for p in sizes.iter_files(root, frozenset({"node_modules"}))}
            self.assertEqual(found, {"a.txt"})


class TestSafety(unittest.TestCase):
    def test_system_paths_protected(self) -> None:
        self.assertTrue(is_protected(Path("/System/Library/Kernels")))
        self.assertTrue(is_protected(Path("/usr/bin/python3")))
        self.assertFalse(is_protected(Path.home() / "Downloads"))

    def test_assert_rejects_protected(self) -> None:
        with self.assertRaises(SafetyError):
            assert_writable_target(Path("/usr/local/bin"))

    def test_assert_rejects_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            link = Path(tmp) / "link"
            os.symlink(tmp, link)
            with self.assertRaises(SafetyError):
                assert_writable_target(link)


if __name__ == "__main__":
    unittest.main()
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from maccleaner.context import Context
from maccleaner.scanners import cache, devjunk, duplicates, large, tmpfiles


def _write(path: Path, size: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"\0" * size)


class Fixture(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        _write(self.root / "Library/Caches/AppOne/blob.bin", 4096)
        _write(self.root / "Library/Logs/Old/app.log", 2048)
        _write(self.root / "proj/node_modules/left-pad/index.js", 1024)
        _write(self.root / "Library/Caches/AppTwo/data.bin", 1024)
        _write(self.root / "media/one.dmg", 8192)
        _write(self.root / "media/two.dmg", 8192)
        _write(self.root / "media/big.mov", 512 * 1024)
        _write(self.root / "media/clip.bin", 8192)
        (self.root / "media/clip.bin").write_bytes(b"unique-clip-content")
        self.ctx = Context(home=self.root, roots=[self.root], max_depth=6)

    def tearDown(self) -> None:
        self._tmp.cleanup()


class TestCacheScanner(Fixture):
    def test_finds_cache_and_logs(self) -> None:
        findings = cache.scan(self.ctx)
        paths = {str(f.path) for f in findings}
        self.assertIn(str(self.root / "Library/Caches/AppOne"), paths)
        self.assertIn(str(self.root / "Library/Logs/Old"), paths)

    def test_min_size_filter(self) -> None:
        ctx = Context(home=self.root, roots=[self.root], min_size=3000)
        findings = cache.scan(ctx)
        self.assertTrue(all(f.size >= 3000 for f in findings))

    def test_skips_system_only_when_requested(self) -> None:
        self.assertEqual(tmpfiles.scan(self.ctx), [])
        self.assertIsInstance(tmpfiles.scan(self.ctx, include_system=True), list)


class TestDevJunkScanner(Fixture):
    def test_finds_node_modules(self) -> None:
        findings = devjunk.scan(self.ctx)
        self.assertTrue(any(f.path.name == "node_modules" for f in findings))

    def test_node_modules_contents_not_reported(self) -> None:
        findings = devjunk.scan(self.ctx)
        self.assertFalse(any("index.js" in str(f.path) for f in findings))


class TestLargeScanner(Fixture):
    def test_min_size(self) -> None:
        findings = large.scan(self.ctx, min_size=256 * 1024)
        names = {f.path.name for f in findings}
        self.assertEqual(names, {"big.mov"})

    def test_extension_filter(self) -> None:
        findings = large.scan(self.ctx, min_size=4096, extensions_only=True)
        self.assertTrue(all(f.path.suffix in {".dmg", ".mov"} for f in findings))
        self.assertNotIn("clip.bin", {f.path.name for f in findings})


class TestDuplicateScanner(Fixture):
    def test_keeps_one_copy(self) -> None:
        findings = duplicates.scan(self.ctx, min_size=4096)
        self.assertEqual([f.path.name for f in findings], ["two.dmg"])
        self.assertIn("one.dmg", findings[0].detail)

    def test_ignores_unique_files(self) -> None:
        findings = duplicates.scan(self.ctx, min_size=600 * 1024)
        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
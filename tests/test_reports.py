import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from airroute_data.pipeline import shard_issue_report


class ReportTests(unittest.TestCase):
    def test_lossless_bounded_deterministic_parts(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            original = b"".join((json.dumps({"id": i}, sort_keys=True) + "\n").encode() for i in range(100))
            results = []
            for name in ["one", "two"]:
                base = root / name
                base.mkdir()
                path = base / "geo-issues.jsonl"
                path.write_bytes(original)
                parts = shard_issue_report(path, max_bytes=64)
                self.assertFalse(path.exists())
                self.assertEqual(sum(p["records"] for p in parts), 100)
                self.assertTrue(all(p["bytes"] <= 64 for p in parts))
                joined = b"".join((base / p["path"]).read_bytes() for p in parts)
                self.assertEqual(hashlib.sha256(joined).digest(), hashlib.sha256(original).digest())
                results.append(parts)
            self.assertEqual(results[0], results[1])

    def test_empty_report_is_indexed_and_incomplete_or_oversized_line_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "empty.jsonl"
            path.write_bytes(b"")
            parts = shard_issue_report(path, 32)
            self.assertEqual(parts, [{"path": "empty/part-00001.jsonl", "bytes": 0, "records": 0}])
            for i, value in enumerate([b"missing-newline", b"x" * 33 + b"\n"]):
                path = root / f"bad{i}.jsonl"
                path.write_bytes(value)
                with self.assertRaises(ValueError):shard_issue_report(path, 32)
                self.assertEqual(path.read_bytes(), value)


if __name__ == "__main__":unittest.main()

import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from file_vault import apply, restore, scan


class VaultTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        (self.root / "a.txt").write_bytes(b"same content")
        (self.root / "nested").mkdir()
        (self.root / "nested" / "b.txt").write_bytes(b"same content")
        (self.root / "unique.txt").write_bytes(b"different!!!")

    def tearDown(self):
        self.tmp.cleanup()

    def test_scan_quarantine_and_restore_preserve_bytes(self):
        plan = scan(self.root)
        self.assertEqual(len(plan["groups"]), 1)
        self.assertEqual(plan["reclaimable_bytes"], 12)
        self.assertTrue((self.root / "nested" / "b.txt").exists())
        manifest = apply(plan)
        self.assertTrue((self.root / "a.txt").exists())
        self.assertFalse((self.root / "nested" / "b.txt").exists())
        self.assertEqual(scan(self.root)["groups"], [])
        self.assertEqual(restore(manifest), 1)
        self.assertEqual((self.root / "nested" / "b.txt").read_bytes(), b"same content")
        self.assertEqual(restore(manifest), 0)

    def test_changed_file_rejects_entire_plan(self):
        plan = scan(self.root)
        (self.root / "nested" / "b.txt").write_bytes(b"new contents")
        with self.assertRaises(ValueError):
            apply(plan)
        self.assertFalse((self.root / ".file-vault").exists())
        self.assertTrue((self.root / "a.txt").exists())

    def test_restore_never_overwrites_new_file(self):
        manifest = apply(scan(self.root))
        target = self.root / "nested" / "b.txt"
        target.write_bytes(b"new data")
        with self.assertRaises(ValueError):
            restore(manifest)
        self.assertEqual(target.read_bytes(), b"new data")
        self.assertEqual((manifest.parent / "files" / "000000").read_bytes(), b"same content")

    def test_plan_cannot_escape_root_or_remove_kept_copy(self):
        plan = scan(self.root)
        for name in ("../outside.txt", str(self.root / "a.txt"), "a.txt"):
            changed = copy.deepcopy(plan)
            changed["groups"][0]["duplicates"] = [name]
            with self.assertRaises(ValueError):
                apply(changed)

    def test_interrupted_journal_is_recoverable(self):
        manifest_path = apply(scan(self.root))
        manifest = json.loads(manifest_path.read_text())
        manifest["state"] = "interrupted"
        manifest_path.write_text(json.dumps(manifest))
        self.assertEqual(restore(manifest_path), 1)

    def test_cli_requires_confirmation_before_moving(self):
        script = str(Path(__file__).resolve().parents[1] / "file_vault.py")
        plan = self.root / "review.plan.json"
        scanned = subprocess.run([sys.executable, script, "scan", str(self.root), "--output", str(plan)], capture_output=True, text=True)
        self.assertEqual(scanned.returncode, 0, scanned.stdout)
        denied = subprocess.run([sys.executable, script, "apply", str(plan)], capture_output=True, text=True)
        self.assertEqual(denied.returncode, 2)
        self.assertTrue((self.root / "nested" / "b.txt").exists())


if __name__ == "__main__":
    unittest.main()

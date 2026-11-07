import hashlib
import importlib.util
import io
import json
import os
import pathlib
import tarfile
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("restore", pathlib.Path(__file__).with_name("restore.py"))
restore = importlib.util.module_from_spec(spec)
spec.loader.exec_module(restore)


class RestoreExtraction(unittest.TestCase):
    def archive(self, extra=None):
        out = io.BytesIO()
        content = b"persistent-data"
        manifest = {"schema": "shuttle.application-backup/v1", "files": [
            {"path": "volumes/data/file", "size": len(content), "sha256": hashlib.sha256(content).hexdigest()}]}
        with tarfile.open(fileobj=out, mode="w") as tar:
            directory = tarfile.TarInfo("volumes/data")
            directory.type = tarfile.DIRTYPE
            directory.mode, directory.uid, directory.gid = 0o751, os.getuid(), os.getgid()
            tar.addfile(directory)
            f = tarfile.TarInfo("volumes/data/file")
            f.size, f.mode, f.uid, f.gid = len(content), 0o640, os.getuid(), os.getgid()
            tar.addfile(f, io.BytesIO(content))
            if extra:
                tar.addfile(extra)
            data = json.dumps(manifest).encode()
            f = tarfile.TarInfo("manifest.json")
            f.size, f.uid, f.gid = len(data), os.getuid(), os.getgid()
            tar.addfile(f, io.BytesIO(data))
        out.seek(0)
        return out

    def test_volume_directory_permissions_survive(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            restore.extract(self.archive(), root)
            self.assertEqual((root / "volumes/data").stat().st_mode & 0o777, 0o751)
            self.assertEqual((root / "volumes/data/file").stat().st_mode & 0o777, 0o640)
            self.assertEqual((root / "volumes/data").stat().st_uid, os.getuid())

    def test_links_paths_and_duplicates_are_refused(self):
        for name, kind in [("../escape", tarfile.REGTYPE), ("volumes/link", tarfile.SYMTYPE), ("volumes/data/file", tarfile.REGTYPE)]:
            extra = tarfile.TarInfo(name)
            extra.type, extra.linkname = kind, "/etc/shadow" if kind == tarfile.SYMTYPE else ""
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                with self.assertRaises(RuntimeError):
                    restore.extract(self.archive(extra), pathlib.Path(tmp))


if __name__ == "__main__":
    unittest.main()

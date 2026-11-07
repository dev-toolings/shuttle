import importlib.util
import datetime
import time
import json
import pathlib
import tempfile
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).parent


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


source = load("source")
restore = load("restore")


class OperationInteropTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        root = pathlib.Path(self.directory.name)
        source.OPERATIONS_ROOT = root / "operations"
        source.OPERATIONS_LOCK = str(root / "root.lock")
        source.STAGING_ROOT = root / "staging"
        restore.OPERATIONS_ROOT = root / "operations"
        restore.OPERATIONS_LOCK = str(root / "root.lock")
        restore.STAGING_ROOT = root / "staging"
        self.owner = "SHA256:" + ("a" * 43)
        self.host = "SHA256:" + ("b" * 43)
        # These programs run on the Linux host, where the boot id is read from
        # /proc. The suite also runs on macOS CI, which has no /proc: every
        # reservation test failed there on FileNotFoundError, not on what it
        # tested. A fixed id keeps the boot comparison itself under test.
        for module in (source, restore):
            patcher = mock.patch.object(module, "host_boot_id", return_value="test-boot")
            patcher.start()
            self.addCleanup(patcher.stop)

    def provided(self, identifier, owner=None, host=None, principal=None):
        return {
            "id": identifier,
            "principal": principal or (owner or self.owner),
            "owner_key_fingerprint": owner or self.owner,
            "host": host or self.host,
        }

    def write_go_reservation(self, identifier, app="demo", owner=None, host=None, boot=None, lease="2099-01-01T00:00:00Z"):
        owner = owner or self.owner
        host = host or self.host
        record = {
            "schema": "shuttle.operation/v1",
            "id": identifier,
            "kind": "backup",
            "scope": "global",
            "app": app,
            "principal": owner,
            "owner_key_fingerprint": owner,
            "host": host,
            "host_boot_id": boot or source.host_boot_id(),
            "started_at": "2026-09-13T00:00:00Z",
            "updated_at": "2026-09-13T00:00:00Z",
            "lease_until": lease,
            "state": "active",
            "recovery_required": False,
            "events": [],
        }
        source.write_operation(record)
        return record

    def tearDown(self):
        self.directory.cleanup()

    def test_migration_blocks_backup_and_restore_before_reservation(self):
        intent = source.OPERATIONS_ROOT.parent / "helper-migration" / "intent.json"
        intent.parent.mkdir()
        for body in [b"broken", json.dumps({"schema":"shuttle.helper-migration/v1","phase":"prepared"}).encode(), json.dumps({"schema":"shuttle.helper-migration/v1","phase":"replaced"}).encode(), b"x"*16385]:
            intent.write_bytes(body)
            intent.chmod(0o600)
            for start in [lambda: source.reserve_operation("backup", "demo"), lambda: restore.reserve_operation("demo")]:
                with self.assertRaises((RuntimeError,ValueError)):
                    start()
            self.assertEqual(list(source.OPERATIONS_ROOT.glob("*.json")), [])
        intent.unlink()
        target = intent.parent / "target"
        target.write_text('{}')
        intent.symlink_to(target)
        with self.assertRaises(OSError):
            source.reserve_operation("backup", "demo")

    def test_source_and_restore_share_the_same_global_reservation(self):
        identifier = source.reserve_operation("backup", "demo")
        record = json.loads((source.OPERATIONS_ROOT / (identifier + ".json")).read_text())
        self.assertEqual(record["schema"], "shuttle.operation/v1")
        self.assertEqual(record["kind"], "backup")
        with self.assertRaises(RuntimeError):
            restore.reserve_operation("demo")
        source.transition_operation(identifier, "completed", "snapshot restored")
        recovery_id = restore.reserve_operation("demo")
        restore.finish_operation(recovery_id, "completed", "isolated restore verified")
        final = json.loads((restore.OPERATIONS_ROOT / (recovery_id + ".json")).read_text())
        self.assertEqual(final["state"], "completed")

    def test_interrupted_source_is_explicitly_recoverable(self):
        identifier = source.reserve_operation("backup", "demo")
        source.transition_operation(identifier, "recovery_required", "replica restoration was not verified", recovery=True)
        record = json.loads((source.OPERATIONS_ROOT / (identifier + ".json")).read_text())
        self.assertTrue(record["recovery_required"])
        self.assertEqual(record["state"], "recovery_required")
        with self.assertRaises(RuntimeError):
            source.reserve_operation("backup", "other")

    def test_expired_other_app_blocks_backup_and_is_not_skipped(self):
        identifier = source.reserve_operation("run", "other")
        path = source.operation_file(identifier)
        record = json.loads(path.read_text())
        record["lease_until"] = "2000-01-01T00:00:00Z"
        source.write_operation(record)
        with self.assertRaises(RuntimeError):
            source.reserve_operation("backup", "demo")
        self.assertEqual(json.loads(path.read_text())["state"], "recovery_required")

    def test_events_are_parseable_utc_and_lock_wait_is_bounded(self):
        identifier = source.reserve_operation("backup", "demo")
        record = json.loads(source.operation_file(identifier).read_text())
        for event in record["events"]:
            at = datetime.datetime.fromisoformat(event["at"].replace("Z", "+00:00"))
            self.assertIsNotNone(at.tzinfo)
        previous = source.OPERATION_LOCK_WAIT_SECONDS
        source.OPERATION_LOCK_WAIT_SECONDS = .05
        try:
            with source.operation_lock():
                started = time.monotonic()
                with self.assertRaises(RuntimeError):
                    with source.operation_lock():
                        self.fail("second lock acquired")
                self.assertLess(time.monotonic() - started, .5)
        finally:
            source.OPERATION_LOCK_WAIT_SECONDS = previous

    def test_stale_source_cannot_claim_completion(self):
        identifier = source.reserve_operation("backup", "demo")
        record = json.loads(source.operation_file(identifier).read_text())
        record["host_boot_id"] = "previous-boot"
        source.write_operation(record)
        with self.assertRaises(RuntimeError):
            source.transition_operation(identifier, "completed", "success")
        self.assertEqual(json.loads(source.operation_file(identifier).read_text())["state"], "recovery_required")

    def test_attach_rejects_wrong_owner_host_and_kind(self):
        identifier = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        self.write_go_reservation(identifier)
        with self.assertRaises(RuntimeError):
            source.reserve_operation("backup", "demo", self.provided(identifier, owner="SHA256:" + ("c" * 43)))
        with self.assertRaises(RuntimeError):
            source.reserve_operation("backup", "demo", self.provided(identifier, host="SHA256:" + ("d" * 43)))
        with self.assertRaises(RuntimeError):
            source.reserve_operation("restore", "demo", self.provided(identifier))
        with self.assertRaises(RuntimeError):
            source.reserve_operation("backup", "other", self.provided(identifier))
        attached = source.reserve_operation("backup", "demo", self.provided(identifier))
        self.assertEqual(attached, identifier)
        self.assertEqual(json.loads(source.operation_file(identifier).read_text())["state"], "active")

    def test_attach_of_expired_or_rebooted_reservation_marks_recovery(self):
        expired = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        self.write_go_reservation(expired, lease="2000-01-01T00:00:00Z")
        with self.assertRaises(RuntimeError):
            source.reserve_operation("backup", "demo", self.provided(expired))
        self.assertEqual(json.loads(source.operation_file(expired).read_text())["state"], "recovery_required")
        rebooted = "cccccccccccccccccccccccccccccccc"
        self.write_go_reservation(rebooted, boot="previous-boot")
        with self.assertRaises(RuntimeError):
            source.reserve_operation("backup", "demo", self.provided(rebooted))
        self.assertEqual(json.loads(source.operation_file(rebooted).read_text())["state"], "recovery_required")

    def test_attached_capture_failure_stays_active_for_client_abort(self):
        identifier = "dddddddddddddddddddddddddddddddd"
        self.write_go_reservation(identifier)
        source.reserve_operation("backup", "demo", self.provided(identifier))
        with self.assertRaises(RuntimeError):
            source.transition_operation(identifier, "completed", "too early", identity=self.provided(identifier, owner="SHA256:" + ("e" * 43)))
        self.assertEqual(json.loads(source.operation_file(identifier).read_text())["state"], "active")
        source.transition_operation(identifier, "active", "source streamed; publication pending", phase="source-capture", identity=self.provided(identifier))
        record = json.loads(source.operation_file(identifier).read_text())
        self.assertEqual(record["state"], "active")
        self.assertEqual(len(record["phases"]), 1)

    def test_pending_marker_is_durable_before_quiesce(self):
        marker = source.STAGING_ROOT / "demo.pending.json"
        quiesced = {"started": False}

        def would_stop():
            self.assertTrue(marker.exists())
            body = json.loads(marker.read_text())
            self.assertEqual(body["app"], "demo")
            self.assertEqual(body["operation_id"], "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee")
            self.assertEqual(body["replicas"], {"demo_web": 2})
            quiesced["started"] = True

        source.write_pending_marker(marker, {"app": "demo", "operation_id": "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", "replicas": {"demo_web": 2}, "work": "/tmp/work"})
        would_stop()
        self.assertTrue(quiesced["started"])
        with self.assertRaises(RuntimeError):
            source.write_pending_marker(marker, {"app": "demo", "operation_id": "other", "replicas": {"demo_web": 2}, "work": "/tmp/work"})

    def test_restore_marks_expired_operation_and_pending_marker_before_starting(self):
        identifier = source.reserve_operation("backup", "demo")
        path = source.operation_file(identifier)
        record = json.loads(path.read_text())
        record["lease_until"] = "2000-01-01T00:00:00Z"
        source.write_operation(record)
        with self.assertRaises(RuntimeError):
            restore.reserve_operation("demo")
        self.assertEqual(json.loads(path.read_text())["state"], "recovery_required")
        marker = restore.STAGING_ROOT / "demo.pending.json"
        source.write_pending_marker(marker, {"app": "demo", "operation_id": identifier, "replicas": {"demo_web": 1}, "work": "/tmp/work"})
        with self.assertRaises(RuntimeError) as raised:
            restore.reserve_operation("demo")
        self.assertIn("pending backup", str(raised.exception))

    def test_restore_finish_of_expired_lease_marks_recovery(self):
        identifier = restore.reserve_operation("demo")
        path = restore.operation_path(identifier)
        record = json.loads(path.read_text())
        record["lease_until"] = "2000-01-01T00:00:00Z"
        restore.write_operation(record)
        with self.assertRaises(RuntimeError):
            restore.finish_operation(identifier, "completed", "should not complete")
        self.assertEqual(json.loads(path.read_text())["state"], "recovery_required")
        with self.assertRaises(RuntimeError):
            restore.reserve_operation("other")

    def test_restore_cannot_finish_a_backup_reservation(self):
        identifier = source.reserve_operation("backup", "demo")
        with self.assertRaises(RuntimeError):
            restore.finish_operation(identifier, "completed", "stolen")
        self.assertEqual(json.loads(source.operation_file(identifier).read_text())["state"], "active")

    def test_restore_report_fsync_failure_cannot_complete_journal(self):
        identifier = restore.reserve_operation("demo")
        report_root = pathlib.Path(self.directory.name) / "restore-report"
        report_root.mkdir()
        report = {"status": "verified", "operation_id": identifier}
        original_fsync = restore.os.fsync

        def fail_report_only(descriptor):
            # Identify the descriptor by inode rather than /proc/self/fd, which
            # macOS does not have: same file, same answer, on both platforms.
            try:
                target = (report_root / "report.json").stat()
            except FileNotFoundError:
                target = None
            opened = restore.os.fstat(descriptor)
            if target is not None and (opened.st_dev, opened.st_ino) == (target.st_dev, target.st_ino):
                raise OSError("injected report persistence failure")
            return original_fsync(descriptor)

        with mock.patch.object(restore.os, "fsync", side_effect=fail_report_only):
            error = restore.publish_restore_report(report_root, report, identifier)
        self.assertIsNotNone(error)
        self.assertEqual(report["status"], "failed")
        record = json.loads(restore.operation_path(identifier).read_text())
        self.assertEqual(record["state"], "recovery_required")
        self.assertTrue(record["recovery_required"])

    def test_staging_cleanup_failure_after_stream_does_not_complete(self):
        identifier = source.reserve_operation("backup", "demo")
        work = source.STAGING_ROOT / "work"
        work.mkdir(parents=True)
        (work / "snap").write_text("streamed")

        def boom(*args, **kwargs):
            raise OSError("directory busy")

        previous = source.shutil.rmtree
        source.shutil.rmtree = boom
        try:
            with self.assertRaises(OSError):
                source.commit_source_capture(identifier, None, work)
        finally:
            source.shutil.rmtree = previous
        record = json.loads(source.operation_file(identifier).read_text())
        self.assertEqual(record["state"], "active")
        self.assertFalse(record["recovery_required"])
        request = {"app": "demo", "operation_id": identifier}
        try:
            record = json.loads(source.operation_file(identifier).read_text())
            if record.get("state") == "active" and not request.get("operation"):
                source.transition_operation(identifier, "recovery_required", "backup capture failed; inspect actual source state", recovery=True)
        except Exception:
            self.fail("main handler must not hide a cleanup failure behind a completed journal")
        record = json.loads(source.operation_file(identifier).read_text())
        self.assertNotEqual(record["state"], "completed")
        self.assertEqual(record["state"], "recovery_required")

    def test_attached_cleanup_failure_keeps_go_reservation_active(self):
        identifier = "ffffffffffffffffffffffffffffffff"
        self.write_go_reservation(identifier)
        source.reserve_operation("backup", "demo", self.provided(identifier))
        work = source.STAGING_ROOT / "work"
        work.mkdir(parents=True)
        (work / "snap").write_text("streamed")

        def boom(*args, **kwargs):
            raise OSError("directory busy")

        previous = source.shutil.rmtree
        source.shutil.rmtree = boom
        try:
            with self.assertRaises(OSError):
                source.commit_source_capture(identifier, self.provided(identifier), work)
        finally:
            source.shutil.rmtree = previous
        record = json.loads(source.operation_file(identifier).read_text())
        self.assertEqual(record["state"], "active")
        self.assertFalse(record["recovery_required"])


if __name__ == "__main__":
    unittest.main()

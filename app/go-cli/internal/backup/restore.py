# Restore only into a newly created native PostgreSQL cluster and fresh volumes.
# No live database, service, volume or SSH configuration is replaced.
import base64
import fcntl
import hashlib
import json
import os
import pathlib
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import uuid
import datetime
from contextlib import contextmanager


OPERATIONS_ROOT = pathlib.Path(os.environ.get("SHUTTLE_OPERATIONS_ROOT", "/var/lib/shuttle/operations"))
OPERATIONS_LOCK = os.environ.get("SHUTTLE_ROOT_LOCK", "/run/shuttle-root.lock")
STAGING_ROOT = pathlib.Path(os.environ.get("SHUTTLE_BACKUP_STAGING", "/var/lib/shuttle/backup-staging"))
OPERATION_LOCK_WAIT_SECONDS = 30.0


@contextmanager
def operation_lock():
    descriptor = os.open(OPERATIONS_LOCK, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    lock = os.fdopen(descriptor, "r+")
    deadline = time.monotonic() + OPERATION_LOCK_WAIT_SECONDS
    try:
        while True:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise RuntimeError("Shuttle operation lock remained busy for 30 seconds")
                time.sleep(0.05)
        yield lock
    finally:
        fcntl.flock(lock, fcntl.LOCK_UN)
        lock.close()


def refuse_pending_helper_migration():
    # Called under the shared operation flock before admitting a writer.
    path = OPERATIONS_ROOT.parent / "helper-migration" / "intent.json"
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077 or info.st_size > 16384:
            raise RuntimeError("unsafe helper migration intent")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            body = stream.read(16385)
        if len(body) > 16384:
            raise RuntimeError("oversized helper migration intent")
        intent = json.loads(body)
        if intent.get("schema") != "shuttle.helper-migration/v1" or intent.get("phase") != "completed":
            raise RuntimeError("helper migration must be finalized before backup or restore")
        if not re.fullmatch(r"[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}", intent.get("id", "")) or not re.fullmatch(r"sha256:[a-f0-9]{64}", intent.get("candidate_sha256", "")):
            raise RuntimeError("invalid helper migration completion")
    finally:
        os.close(descriptor)


def operation_timestamp(timestamp=None):
    return datetime.datetime.fromtimestamp(time.time() if timestamp is None else timestamp, datetime.timezone.utc).isoformat().replace("+00:00", "Z")


def operation_expired(record):
    try:
        lease = datetime.datetime.fromisoformat(record["lease_until"].replace("Z", "+00:00"))
        return lease.tzinfo is None or lease.timestamp() <= time.time() or record.get("host_boot_id") != host_boot_id()
    except (KeyError, ValueError, TypeError):
        return True


def host_boot_id():
    return pathlib.Path("/proc/sys/kernel/random/boot_id").read_text().strip()


def operation_path(identifier):
    if not re.fullmatch(r"(?:[a-f0-9]{32}|[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})", identifier):
        raise RuntimeError("invalid operation id")
    return OPERATIONS_ROOT / (identifier + ".json")


def write_operation(record):
    OPERATIONS_ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".operation-", suffix=".tmp", dir=OPERATIONS_ROOT)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write((json.dumps(record, indent=2, sort_keys=True) + "\n").encode())
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, operation_path(record["id"]))
        directory = os.open(OPERATIONS_ROOT, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def operation_event(record, kind, recovery=False):
    record.setdefault("events", []).append({"at": operation_timestamp(), "kind": kind, "state": record["state"], "recovery_required": recovery})
    record["events"] = record["events"][-128:]


def mark_stale(record):
    record["state"] = "recovery_required"
    record["recovery_required"] = True
    record["lease_until"] = ""
    record["result"] = "operation lease expired or host boot changed; executor fence is not proven"
    record["updated_at"] = operation_timestamp()
    operation_event(record, "stale", recovery=True)
    return record


def reserve_operation(app):
    identifier = uuid.uuid4().hex
    now = time.time()
    stamp = operation_timestamp()
    with operation_lock():
        refuse_pending_helper_migration()
        OPERATIONS_ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
        for marker in sorted(STAGING_ROOT.glob("*.pending.json")):
            raise RuntimeError("a pending backup requires recovery before restore: " + str(marker))
        for path in OPERATIONS_ROOT.glob("*.json"):
            try:
                active = json.loads(path.read_text())
            except Exception as error:
                raise RuntimeError("invalid Shuttle operation journal: " + str(path)) from error
            if active.get("state") == "active" and operation_expired(active):
                write_operation(mark_stale(active))
            if active.get("state") in ("active", "recovery_required") or active.get("recovery_required"):
                raise RuntimeError("operation %s is active for %s; recovery is required before this restore starts" % (active.get("id"), active.get("kind")))
        record = {"schema": "shuttle.operation/v1", "id": identifier, "kind": "restore", "scope": "global", "app": app, "principal": "restore-python", "host_boot_id": host_boot_id(), "started_at": stamp, "updated_at": stamp, "lease_until": operation_timestamp(now + 35 * 60), "state": "active", "recovery_required": False, "events": []}
        operation_event(record, "reserved")
        write_operation(record)
    return identifier


def finish_operation(identifier, state, result, recovery=False):
    with operation_lock():
        path = operation_path(identifier)
        if not path.exists():
            raise RuntimeError("restore operation journal disappeared")
        record = json.loads(path.read_text())
        if record.get("id") != identifier or record.get("kind") != "restore" or record.get("principal") != "restore-python" or record.get("state") != "active" or record.get("recovery_required"):
            raise RuntimeError("restore does not own an active reservation")
        if record.get("host_boot_id") != host_boot_id() and not recovery:
            write_operation(mark_stale(record))
            raise RuntimeError("restore lease or boot expired; recovery required")
        if operation_expired(record) and not recovery:
            write_operation(mark_stale(record))
            raise RuntimeError("restore lease or boot expired; recovery required")
        record.update(state=state, recovery_required=recovery, result=result[:512], lease_until="", updated_at=operation_timestamp())
        operation_event(record, state, recovery)
        write_operation(record)


def run(args, stdin=None):
    result = subprocess.run(args, stdin=stdin, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=1800)
    if result.returncode:
        raise RuntimeError("%s failed (exit %s); isolated recovery files retained" %
                           (pathlib.Path(args[0]).name, result.returncode))
    return result.stdout


def file_hash(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def allowed(name):
    p = pathlib.PurePosixPath(name)
    return (not p.is_absolute() and ".." not in p.parts and str(p) == name
            and not any(c in name for c in "\\\r\n\x00")
            and (name in ("manifest.json", "config.json")
                 or any(name.startswith(prefix) for prefix in ("postgres/", "volumes/", "state/", "images/"))))


def extract(stream, root):
    seen = set()
    with tarfile.open(fileobj=stream, mode="r|") as archive:
        for member in archive:
            name = member.name.rstrip("/")
            if not allowed(name) or name in seen or not (member.isfile() or member.isdir()):
                raise RuntimeError("unsafe or duplicate archive entry")
            seen.add(name)
            if len(seen) > 100000:
                raise RuntimeError("archive exceeds 100000 entries")
            dest = root / name
            if member.isdir():
                dest.mkdir(parents=True, exist_ok=True)
                os.chmod(dest, member.mode & 0o777)
                os.chown(dest, member.uid, member.gid)
                continue
            dest.parent.mkdir(parents=True, exist_ok=True)
            with open(dest, "xb") as out:
                shutil.copyfileobj(archive.extractfile(member), out)
            os.chmod(dest, member.mode & 0o777)
            os.chown(dest, member.uid, member.gid)
    manifest = json.loads((root / "manifest.json").read_text())
    if manifest["schema"] != "shuttle.application-backup/v1":
        raise RuntimeError("unsupported backup schema")
    expected = {}
    for item in manifest["files"]:
        if item["path"] in expected or not allowed(item["path"]):
            raise RuntimeError("invalid manifest inventory")
        expected[item["path"]] = item
    actual = {p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file() and p.relative_to(root).as_posix() != "manifest.json"}
    if actual != set(expected):
        raise RuntimeError("archive inventory differs from manifest")
    for name, item in expected.items():
        p = root / name
        if p.stat().st_size != item["size"] or file_hash(p) != item["sha256"]:
            raise RuntimeError("restored file does not match manifest: " + name)
    return manifest


def publish_restore_report(root, report, operation_id):
    failure = None
    try:
        with open(root / "report.json", "w") as output:
            output.write(json.dumps(report, indent=2))
            output.flush()
            os.fsync(output.fileno())
        directory = os.open(root, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except Exception as error:
        failure = error
        report["status"] = "failed"
        report["cleanup"] = ((report["cleanup"] + "; ") if report.get("cleanup") else "") + "restore report could not be persisted: " + str(error)
    if operation_id:
        try:
            if report["status"] == "verified":
                finish_operation(operation_id, "completed", "isolated native restore verified; no live application switched")
            else:
                finish_operation(operation_id, "recovery_required", "isolated restore or cleanup failed; recovery files retained", recovery=True)
        except Exception as error:
            failure = error if failure is None else failure
            report["status"] = "failed"
            report["journal"] = str(error)
    return failure


def main():
    if os.geteuid() != 0:
        raise RuntimeError("restore requires the SSH administrator with sudo -n")
    os.umask(0o077)
    request = json.loads(base64.b64decode(sys.argv[1]))
    app = request.get("app", "")
    if not re.fullmatch(r"[a-z][a-z0-9-]{0,62}", app):
        raise RuntimeError("restore requires its verified application identity")
    operation_id = reserve_operation(app)
    identifier = uuid.uuid4().hex[:16]
    root = pathlib.Path("/var/lib/shuttle/recovery") / identifier
    root.mkdir(mode=0o700, parents=True)
    report = {"schema": "shuttle.restore-report/v1", "id": identifier, "status": "failed", "directory": str(root)}
    cluster = None
    cluster_created = False
    version = None
    cleanup_error = None
    try:
        payload = root / "payload"
        payload.mkdir()
        manifest = extract(sys.stdin.buffer, payload)
        version = manifest["postgres"]
        if version not in (16, 17, 18) or not pathlib.Path("/usr/lib/postgresql/%s/bin/pg_restore" % version).is_file():
            raise RuntimeError("target must have the matching native PostgreSQL major installed")
        for name in manifest["databases"]:
            if not re.fullmatch(r"[a-z_][a-z0-9_]{0,62}", name) or name in ("postgres", "template0", "template1"):
                raise RuntimeError("invalid application database in backup")
        if manifest["app"] != app:
            raise RuntimeError("archive application differs from the reserved restore")
        cluster = "shuttle_restore_" + identifier
        system_user = "shuttle_rec_" + identifier
        bootstrap = system_user
        run(["useradd", "--system", "--user-group", "--no-create-home", "--home-dir", "/nonexistent", "--shell", "/usr/sbin/nologin", system_user])
        report["system_user"] = system_user
        socket = pathlib.Path("/var/lib/postgresql") / (cluster + "_socket")
        socket.mkdir(mode=0o700)
        # A dedicated OS identity owns the native recovery cluster. Restored
        # SQL therefore cannot read another cluster through the postgres Unix
        # account. Only this account and root can reach its private socket.
        import pwd
        pguser = pwd.getpwnam(system_user)
        os.chown(socket, pguser.pw_uid, pguser.pw_gid)
        run(["pg_createcluster", str(version), cluster, "--start-conf=manual", "--user=" + system_user,
             "--pgoption=ssl=off", "--pgoption=external_pid_file=" + str(socket / "server.pid"),
             "--socketdir=" + str(socket), "--pgoption=listen_addresses=",
             "--", "--username=" + bootstrap, "--auth-local=trust", "--auth-host=scram-sha-256"])
        cluster_created = True
        # pg_createcluster omits an empty --pgoption value. Write PostgreSQL's
        # literal empty string as the final setting, then prove it after start.
        conf = pathlib.Path("/etc/postgresql") / str(version) / cluster / "postgresql.conf"
        with open(conf, "a") as f:
            f.write("\nlisten_addresses = ''\n")
        report.update(cluster=cluster, postgres=version)
        # Debian's stock unit expects the postgres account's shared PID path.
        # The isolated owner uses its private socket directory instead.
        unit_dir = pathlib.Path("/etc/systemd/system") / ("postgresql@%s-%s.service.d" % (version, cluster))
        unit_dir.mkdir(parents=True)
        (unit_dir / "10-shuttle-recovery.conf").write_text("[Service]\nPIDFile=%s\n" % (socket / "server.pid"))
        run(["systemctl", "daemon-reload"])
        run(["pg_ctlcluster", str(version), cluster, "start"])
        port = run(["pg_conftool", str(version), cluster, "show", "port"]).decode().strip().split("=")[-1].strip()
        def pg(command, *args, stdin=None):
            return run(["/usr/lib/postgresql/%s/bin/%s" % (version, command),
                        "-h", str(socket), "-p", port, "-U", bootstrap, *args], stdin=stdin)
        if pg("psql", "-XAt", "-d", "template1", "-c", "SHOW listen_addresses").strip():
            raise RuntimeError("recovery cluster unexpectedly listens on TCP")
        with open(payload / "postgres/roles.sql", "rb") as f:
            pg("psql", "-X", "-v", "ON_ERROR_STOP=1", "-d", "template1", stdin=f)
        for name in manifest["databases"]:
            pg("pg_restore", "--exit-on-error", "--create", "--dbname=template1", str(payload / ("postgres/" + name + ".dump")))
        counts = json.loads((payload / "postgres/counts.json").read_text())
        checked = 0
        for database in manifest["databases"]:
            for schema, table, expected in counts[database]:
                quote = lambda value: '"' + value.replace('"', '""') + '"'
                query = "SELECT count(*) FROM %s.%s" % (quote(schema), quote(table))
                actual = int(pg("psql", "-XAt", "-v", "ON_ERROR_STOP=1", "-d", database, "-c", query))
                if actual != expected:
                    raise RuntimeError("restored table count differs: %s.%s.%s" % (database, schema, table))
                checked += 1
        volume_map = {}
        for original in manifest["volumes"]:
            if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}", original):
                raise RuntimeError("invalid volume in backup")
            name = "shuttle-recovery-" + identifier + "-" + original
            run(["docker", "volume", "create", "--label", "dev.shuttle.recovery=" + identifier, name])
            info = json.loads(run(["docker", "volume", "inspect", name]))[0]
            target = pathlib.Path(info["Mountpoint"])
            source = payload / "volumes" / original
            # tar extraction retained numeric ownership. cp -a preserves those
            # permissions in the new volume, without touching the source volume.
            run(["cp", "-a", str(source) + "/.", str(target)])
            # A matching RDB hash was not enough: losing directory ownership
            # made Redis unable to enter /data despite intact file contents.
            for original_path in [source, *source.rglob("*")]:
                restored_path = target / original_path.relative_to(source)
                before, after = original_path.stat(), restored_path.stat()
                if (before.st_mode & 0o777, before.st_uid, before.st_gid) != (after.st_mode & 0o777, after.st_uid, after.st_gid):
                    raise RuntimeError("restored volume ownership or permissions differ")
                if original_path.is_file() and file_hash(original_path) != file_hash(restored_path):
                    raise RuntimeError("restored volume content differs")
            volume_map[original] = name
        image_map = {}
        references = json.loads((payload / "images/references.json").read_text())
        with open(payload / "images/images.tar", "rb") as f:
            run(["docker", "image", "load", "--quiet"], stdin=f)
        for image in references:
            if not re.fullmatch(r"sha256:[0-9a-f]{64}", image["id"]) or not re.fullmatch(r"[a-zA-Z0-9_.-]{1,128}", image["service"]):
                raise RuntimeError("invalid restored image identity")
            loaded = json.loads(run(["docker", "image", "inspect", image["id"]]))[0]
            if loaded["Id"] != image["id"]:
                raise RuntimeError("restored image ID does not match the source")
            reference = "shuttle-recovery/" + identifier + "/" + image["service"] + ":restored"
            run(["docker", "image", "tag", image["id"], reference])
            image_map[image["service"]] = reference
        report.update(status="verified", app=manifest["app"], postgres=version,
                      cluster=cluster, socket=str(socket), port=int(port),
                      # The docs send the operator to this report for the start
                      # command: the VM drill of 2026-11-07 had to deduce it.
                      start_command="pg_ctlcluster %s %s start" % (version, cluster),
                      bootstrap_user=bootstrap, databases=manifest["databases"],
                      tables_verified=checked, volumes=volume_map, images=image_map,
                      activation="isolated; no live application switched")
    finally:
        # Leave the verified cluster stopped so a drill consumes no persistent
        # RAM. pg_ctlcluster <major> <cluster> start is the explicit next step.
        if cluster_created:
            stopped = subprocess.run(["pg_ctlcluster", str(version), cluster, "stop"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=60)
            if stopped.returncode != 0:
                report["status"] = "failed"
                report["cleanup"] = "isolated PostgreSQL cluster stop failed"
                cleanup_error = RuntimeError(report["cleanup"])
        report["operation_id"] = operation_id
        publication_error = publish_restore_report(root, report, operation_id)
        if cleanup_error is None:
            cleanup_error = publication_error
        print(json.dumps(report), flush=True)
    if report["status"] != "verified":
        raise RuntimeError("isolated restore did not pass verification")
    if cleanup_error is not None:
        raise RuntimeError("isolated restore cleanup failed: " + str(cleanup_error))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)

# Executed only through the explicitly selected SSH administrator account.
# PostgreSQL always uses the host's native binaries and its system cluster.
import base64
import fcntl
import hashlib
import json
import os
import pathlib
import re
import shutil
import signal
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
FINGERPRINT = re.compile(r"^SHA256:[A-Za-z0-9+/]{43}$")


def host_boot_id():
    return pathlib.Path("/proc/sys/kernel/random/boot_id").read_text().strip()


def operation_file(identifier):
    if not re.fullmatch(r"(?:[a-f0-9]{32}|[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})", identifier):
        raise RuntimeError("invalid operation id")
    return OPERATIONS_ROOT / (identifier + ".json")


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


def write_operation(record):
    OPERATIONS_ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
    destination = operation_file(record["id"])
    fd, temporary = tempfile.mkstemp(prefix=".operation-", suffix=".tmp", dir=OPERATIONS_ROOT)
    try:
        os.fchmod(fd, 0o600)
        payload = (json.dumps(record, indent=2, sort_keys=True) + "\n").encode()
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, destination)
        directory = os.open(OPERATIONS_ROOT, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def operation_event(record, kind, phase="", recovery=False):
    record.setdefault("events", []).append({"at": operation_timestamp(), "kind": kind, "state": record["state"], "phase": phase, "recovery_required": recovery})
    record["events"] = record["events"][-128:]


def mark_stale(record):
    record["state"] = "recovery_required"
    record["recovery_required"] = True
    record["lease_until"] = ""
    record["result"] = "operation lease expired or host boot changed; executor fence is not proven"
    record["updated_at"] = operation_timestamp()
    operation_event(record, "stale", recovery=True)
    return record


def provided_identity(provided):
    if not isinstance(provided, dict):
        raise RuntimeError("backup source does not own a live compatible reservation")
    identifier = provided.get("id") or ""
    owner = provided.get("owner_key_fingerprint") or ""
    host = provided.get("host") or ""
    principal = provided.get("principal") or owner
    if not identifier or not owner or not host or not principal:
        raise RuntimeError("backup source does not own a live compatible reservation")
    if FINGERPRINT.match(owner) is None or FINGERPRINT.match(host) is None or FINGERPRINT.match(principal) is None:
        raise RuntimeError("backup source reservation identity is not a host or owner fingerprint")
    return identifier, principal, owner, host


def reservation_identity_matches(record, kind, app, principal, owner, host):
    return (record.get("schema") == "shuttle.operation/v1"
            and record.get("kind") == kind
            and record.get("app") == app
            and record.get("principal") == principal
            and record.get("owner_key_fingerprint") == owner
            and record.get("host") == host)


def write_pending_marker(marker, payload):
    marker.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        with open(marker, "x") as pending:
            pending.write(json.dumps(payload, sort_keys=True))
            pending.flush()
            os.fsync(pending.fileno())
    except FileExistsError as error:
        raise RuntimeError("previous backup requires recovery; inspect " + str(marker)) from error
    directory = os.open(marker.parent, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def attach_provided_operation(kind, app, provided):
    identifier, principal, owner, host = provided_identity(provided)
    path = operation_file(identifier)
    try:
        record = json.loads(path.read_text())
    except FileNotFoundError as error:
        raise RuntimeError("backup source does not own a live compatible reservation") from error
    except Exception as error:
        raise RuntimeError("invalid Shuttle operation journal: " + str(path)) from error
    if record.get("id") != identifier or not reservation_identity_matches(record, kind, app, principal, owner, host):
        raise RuntimeError("backup source does not own a live compatible reservation")
    if record.get("state") != "active" or record.get("recovery_required"):
        raise RuntimeError("backup source does not own a live compatible reservation")
    if operation_expired(record):
        write_operation(mark_stale(record))
        raise RuntimeError("backup source reservation lease or host boot changed; recovery is required")
    return identifier


def refuse_blocking_operation(active):
    target = active.get("app") or "VPS"
    raise RuntimeError("operation %s is active for %s (target %s); recovery is required before this backup starts" % (active.get("id"), active.get("kind"), target))


def reserve_operation(kind, app, provided=None):
    identifier = uuid.uuid4().hex
    now = time.time()
    boot = host_boot_id()
    with operation_lock():
        refuse_pending_helper_migration()
        OPERATIONS_ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
        if provided:
            return attach_provided_operation(kind, app, provided)
        for path in OPERATIONS_ROOT.glob("*.json"):
            try:
                active = json.loads(path.read_text())
            except Exception as error:
                raise RuntimeError("invalid Shuttle operation journal: " + str(path)) from error
            if active.get("state") not in ("active", "recovery_required"):
                continue
            if active.get("state") == "active" and operation_expired(active):
                write_operation(mark_stale(active))
            if active.get("state") in ("active", "recovery_required") or active.get("recovery_required"):
                refuse_blocking_operation(active)
        stamp = operation_timestamp()
        record = {"schema": "shuttle.operation/v1", "id": identifier, "kind": kind, "scope": "global", "app": app, "principal": "backup-source", "host_boot_id": boot, "started_at": stamp, "updated_at": stamp, "lease_until": operation_timestamp(now + 35 * 60), "state": "active", "recovery_required": False, "events": []}
        operation_event(record, "reserved")
        write_operation(record)
    return identifier


def transition_operation(identifier, state, result, recovery=False, phase=None, identity=None):
    if not identifier:
        return
    with operation_lock():
        path = operation_file(identifier)
        if not path.exists():
            raise RuntimeError("operation journal disappeared")
        record = json.loads(path.read_text())
        if identity:
            _, principal, owner, host = provided_identity(identity)
            if record.get("id") != identifier or not reservation_identity_matches(record, record.get("kind"), record.get("app"), principal, owner, host):
                raise RuntimeError("backup source does not own a live compatible reservation")
        if record.get("state") != "active" or record.get("recovery_required"):
            raise RuntimeError("operation is already terminal or requires recovery")
        if operation_expired(record) and not recovery:
            write_operation(mark_stale(record))
            raise RuntimeError("operation lease or host boot changed; recovery is required")
        if phase:
            record.setdefault("phases", []).append({"name": phase, "started_at": record.get("updated_at", ""), "ended_at": operation_timestamp(), "result": result})
        record["state"] = state
        record["recovery_required"] = recovery
        record["result"] = result[:512]
        record["lease_until"] = operation_timestamp(time.time() + 35 * 60) if state == "active" else ""
        record["updated_at"] = operation_timestamp()
        operation_event(record, state, phase or "", recovery)
        write_operation(record)


def commit_source_capture(operation_id, identity, work):
    # Remove plaintext staging before any success transition. A Go-owned
    # reservation stays active until the client publishes ciphertext; a
    # standalone reservation becomes completed only after this cleanup.
    shutil.rmtree(work)
    transition_operation(operation_id, "active" if identity else "completed", "source snapshot streamed and replicas restored; encrypted archive publication remains pending" if identity else "snapshot streamed and replicas restored", phase="source-capture", identity=identity)


def run(args, stdout=None, timeout=600):
    result = subprocess.run(args, stdout=stdout or subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=timeout)
    if result.returncode:
        raise RuntimeError("%s failed (exit %s); no backup was committed" %
                           (pathlib.Path(args[0]).name, result.returncode))
    return result.stdout if stdout is None else b""


def read_json(args):
    return json.loads(run(args))


def sha_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def secure_copy(src, dest):
    mode = src.lstat().st_mode
    if stat.S_ISLNK(mode) or not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)):
        raise RuntimeError("backup refuses links or special files: " + str(src))
    if stat.S_ISDIR(mode):
        dest.mkdir(parents=True, exist_ok=True)
        for child in src.iterdir():
            secure_copy(child, dest / child.name)
    else:
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(src, dest, follow_symlinks=False)
    os.chown(dest, src.stat().st_uid, src.stat().st_gid)
    os.chmod(dest, stat.S_IMODE(mode) & 0o777)


def pg(version, command, *args, stdout=None):
    return run(["runuser", "-u", "postgres", "--",
                "/usr/lib/postgresql/%s/bin/%s" % (version, command),
                "-h", "/var/run/postgresql", "-p", "5432", *args], stdout=stdout)


def quote_identifier(s):
    return '"' + s.replace('"', '""') + '"'


def table_counts(version, database):
    rows = json.loads(pg(version, "psql", "-XAt", "-d", database, "-c",
        "SELECT coalesce(json_agg(json_build_array(schemaname,tablename)), '[]') "
        "FROM pg_tables WHERE schemaname NOT IN ('pg_catalog','information_schema')"))
    counts = []
    for schema, table in rows:
        query = "SELECT count(*) FROM %s.%s" % (quote_identifier(schema), quote_identifier(table))
        count = int(pg(version, "psql", "-XAt", "-d", database, "-c", query))
        counts.append([schema, table, count])
    return sorted(counts)


def wait_stopped(app):
    deadline = time.monotonic() + 90
    while run(["docker", "ps", "-q", "--filter", "label=com.docker.stack.namespace=" + app]).strip():
        if time.monotonic() > deadline:
            raise RuntimeError("application tasks did not stop; refusing an inconsistent volume snapshot")
        time.sleep(1)


def restore_replicas(services):
    # Restore every requested replica count, including when a scale request
    # reached Docker but its reply or the following snapshot failed.
    errors = []
    for name, replicas in services.items():
        try:
            run(["docker", "service", "scale", "--detach=true", name + "=" + str(replicas)], timeout=60)
        except Exception:
            errors.append(name)
    if errors:
        raise RuntimeError("could not restore service replicas: " + ", ".join(errors))


def wait_ready(services):
    deadline = time.monotonic() + 120
    while True:
        healthy = True
        for name, expected in services.items():
            if expected == 0:
                continue
            ids = run(["docker", "ps", "-q", "--filter", "label=com.docker.swarm.service.name=" + name]).split()
            if len(ids) != expected:
                healthy = False
                break
            for container in ids:
                state = read_json(["docker", "inspect", container.decode()])[0]["State"]
                if not state.get("Running") or state.get("Health", {}).get("Status", "healthy") != "healthy":
                    healthy = False
        if healthy:
            return
        if time.monotonic() >= deadline:
            raise RuntimeError("replica counts were restored but application health is not verified")
        time.sleep(1)


def main(request):
    if request.get("dry_run"):
        return capture(request)
    app = request.get("app", "")
    if not re.fullmatch(r"[a-z][a-z0-9-]{0,62}", app):
        raise RuntimeError("invalid backup application")
    operation_id = reserve_operation("backup", app, request.get("operation"))
    request["operation_id"] = operation_id
    try:
        return capture(request)
    except BaseException:
        # A Go-owned reservation stays active after a clean capture failure so
        # the client can abort after ciphertext publication is known not to
        # have happened. Replica-restore failure already moved the journal to
        # recovery_required inside capture(). Standalone captures must not be
        # left looking live.
        try:
            record = json.loads(operation_file(operation_id).read_text())
            if record.get("state") == "active" and not request.get("operation"):
                # Never rewrite a completed journal. Cleanup failure is raised
                # before the success transition, so a standalone capture that
                # still looks live here did not finish.
                transition_operation(operation_id, "recovery_required", "backup capture failed; inspect actual source state", recovery=True)
        except Exception:
            pass
        raise


def capture(request):
    if os.geteuid() != 0:
        raise RuntimeError("backup requires the configured administrator with sudo -n")
    os.umask(0o077)
    app = request["app"]
    if not re.fullmatch(r"[a-z][a-z0-9-]{0,62}", app):
        raise RuntimeError("invalid application name")
    version = request["postgres"]
    if version not in (16, 17, 18):
        raise RuntimeError("only native PostgreSQL 16, 17 and 18 are supported")
    if read_json(["docker", "info", "--format", "{{json .Swarm}}"])["Nodes"] != 1:
        raise RuntimeError("backup requires a single-node Swarm")
    actual = pg(version, "psql", "-XAt", "-d", "postgres", "-c", "SHOW server_version_num").strip()
    if int(actual) // 10000 != version:
        raise RuntimeError("native PostgreSQL major differs from configuration")
    for name in request["databases"]:
        if not re.fullmatch(r"[a-z_][a-z0-9_]{0,62}", name) or name in ("postgres", "template0", "template1"):
            raise RuntimeError("invalid application database")
    service_ids = run(["docker", "service", "ls", "-q", "--filter", "label=com.docker.stack.namespace=" + app]).split()
    if not service_ids:
        raise RuntimeError("application has no deployed Swarm services")
    specs = read_json(["docker", "service", "inspect", *[s.decode() for s in service_ids]])
    replicas = {}
    available_volumes = set()
    for service in specs:
        spec = service["Spec"]
        if "Replicated" not in spec["Mode"]:
            raise RuntimeError("global services cannot be quiesced by this backup contract")
        replicas[spec["Name"]] = spec["Mode"]["Replicated"]["Replicas"]
        for mount in spec["TaskTemplate"]["ContainerSpec"].get("Mounts", []):
            if mount["Type"] == "volume":
                available_volumes.add(mount["Source"])
            elif mount["Type"] == "bind":
                raise RuntimeError("bind-mounted application data requires an explicit recovery design")
    volumes = request["volumes"] or []
    if set(volumes) != available_volumes:
        raise RuntimeError("backup volumes must explicitly cover the deployed volumes: " + ", ".join(sorted(available_volumes)))
    mounts = {}
    for name in volumes:
        if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}", name):
            raise RuntimeError("invalid volume name")
        volume = read_json(["docker", "volume", "inspect", name])[0]
        if volume["Driver"] != "local" or volume.get("Options"):
            raise RuntimeError("only ordinary local Docker volumes are supported")
        # Never stop another application's writers to make this backup work.
        users = run(["docker", "ps", "-q", "--filter", "volume=" + name]).split()
        for container in users:
            info = read_json(["docker", "inspect", container.decode()])[0]
            if info["Config"].get("Labels", {}).get("com.docker.stack.namespace") != app:
                raise RuntimeError("volume is shared with another running application: " + name)
        mounts[name] = pathlib.Path(volume["Mountpoint"])
    if request.get("dry_run"):
        print(json.dumps({"app": app, "postgres": version, "databases": request["databases"], "volumes": volumes, "replicas_to_restore": replicas, "mode": "read-only preflight"}))
        return
    captured_secrets = {}
    for service in specs:
        spec = service["Spec"]
        declared = spec["TaskTemplate"]["ContainerSpec"].get("Secrets", [])
        if not declared:
            continue
        containers = run(["docker", "ps", "-q", "--filter", "label=com.docker.swarm.service.name=" + spec["Name"]]).split()
        if not containers:
            raise RuntimeError("cannot capture mounted secrets from inactive service " + spec["Name"])
        info = read_json(["docker", "inspect", containers[0].decode()])[0]
        pid = info["State"]["Pid"]
        for secret in declared:
            name = secret.get("File", {}).get("Name", secret["SecretName"])
            if not re.fullmatch(r"[a-zA-Z0-9_.-]{1,128}", name) or name in (".", ".."):
                raise RuntimeError("unsupported secret mount target")
            with open("/proc/%d/root/run/secrets/%s" % (pid, name), "rb") as f:
                value = f.read(65537)
            if len(value) > 65536:
                raise RuntimeError("mounted secret exceeds recovery limit")
            captured_secrets[secret["SecretName"]] = base64.b64encode(value).decode()
    images = []
    for service in specs:
        reference = service["Spec"]["TaskTemplate"]["ContainerSpec"]["Image"]
        info = read_json(["docker", "image", "inspect", reference])[0]
        images.append({"service": service["Spec"]["Name"], "reference": reference,
                       "id": info["Id"], "size": info["Size"]})
    estimated = sum(image["size"] for image in images)
    for mount in mounts.values():
        estimated += int(run(["du", "-sb", str(mount)]).split()[0])
    for name in request["databases"]:
        estimated += int(pg(version, "psql", "-XAt", "-d", name, "-c", "SELECT pg_database_size(current_database())"))
    disk = shutil.disk_usage("/var/lib/shuttle")
    if disk.free - estimated * 2 < disk.total // 5:
        raise RuntimeError("insufficient snapshot headroom while preserving 20 percent free disk")
    root = STAGING_ROOT
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    marker = root / (app + ".pending.json")
    if marker.exists():
        raise RuntimeError("previous backup requires recovery; inspect " + str(marker))
    other_pending = sorted(root.glob("*.pending.json"))
    if other_pending:
        raise RuntimeError("a pending backup requires recovery; inspect " + ", ".join(str(path) for path in other_pending))
    operation_id = request["operation_id"]
    identity = request.get("operation")
    work = pathlib.Path(tempfile.mkdtemp(prefix=app + "-", dir=root))
    quiesced = False
    terminal = False
    try:
        (work / "images").mkdir()
        (work / "images/references.json").write_text(json.dumps(images))
        # Saving by content ID avoids exporting mutable production tags. A
        # restore imports these IDs under its own isolated names.
        with open(work / "images/images.tar", "wb") as f:
            run(["docker", "image", "save", *sorted({image["id"] for image in images})], stdout=f)
        # The pending marker is the recovery identity. It has to be durable
        # before any replica count changes: a crash after scale-to-zero with
        # no marker leaves the application stopped and unrecoverable by the
        # helper, which refuses a marker whose operation_id does not match.
        write_pending_marker(marker, {"app": app, "operation_id": operation_id, "replicas": replicas, "work": str(work)})
        quiesced = True
        restore_replicas(dict.fromkeys(replicas, 0))
        wait_stopped(app)
        print("Application stopped for a consistent database/volume snapshot", file=sys.stderr, flush=True)
        (work / "postgres").mkdir()
        manifest = {"schema": "shuttle.application-backup/v1", "app": app,
                    "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "postgres": version, "databases": request["databases"], "volumes": volumes, "files": []}
        with open(work / "postgres/roles.sql", "wb") as f:
            pg(version, "pg_dumpall", "--roles-only", stdout=f)
        counts = {}
        for name in request["databases"]:
            with open(work / ("postgres/" + name + ".dump"), "wb") as f:
                pg(version, "pg_dump", "--format=custom", "--create", "--no-tablespaces", "--lock-wait-timeout=10000", "--dbname=" + name, stdout=f)
            counts[name] = table_counts(version, name)
        (work / "postgres/counts.json").write_text(json.dumps(counts))
        (work / "config.json").write_text(json.dumps(request["config"], indent=2))
        secure_copy(pathlib.Path("/var/lib/shuttle/apps") / app, work / "state/application")
        (work / "state/swarm-secrets.json").write_text(json.dumps(captured_secrets))
        for config_file in ("postgresql.conf", "pg_hba.conf", "pg_ident.conf", "pg_ctl.conf", "start.conf", "conf.d"):
            original = pathlib.Path("/etc/postgresql") / str(version) / "main" / config_file
            if original.exists():
                secure_copy(original, work / "state/postgresql" / config_file)
        secret_dir = pathlib.Path("/var/lib/shuttle/secrets") / app
        if secret_dir.exists():
            secure_copy(secret_dir, work / "state/infrastructure-secrets")
        for name, mount in mounts.items():
            secure_copy(mount, work / "volumes" / name)
        # Application writers can restart once the stable local snapshot exists.
        restore_replicas(replicas)
        wait_ready(replicas)
        quiesced = False
        marker.unlink()
        print("Application replica counts restored; encrypting the snapshot off-host", file=sys.stderr, flush=True)
        for p in sorted(work.rglob("*")):
            if p.is_file():
                manifest["files"].append({"path": p.relative_to(work).as_posix(), "size": p.stat().st_size, "sha256": sha_file(p)})
        (work / "manifest.json").write_text(json.dumps(manifest))
        with tarfile.open(fileobj=sys.stdout.buffer, mode="w|") as archive:
            for p in sorted(work.rglob("*")):
                if p.relative_to(work).as_posix() not in ("postgres", "volumes", "state", "images"):
                    archive.add(p, arcname=p.relative_to(work).as_posix(), recursive=False)
        # Staging must be gone before the journal claims source-capture success.
        # Completing first, then ignoring rmtree, returned 0 with leftover
        # plaintext and let main() rewrite a completed standalone record.
        commit_source_capture(operation_id, identity, work)
        terminal = True
    finally:
        restore_error = None
        cleanup_error = None
        journal_error = None
        if quiesced:
            try:
                restore_replicas(replicas)
                wait_ready(replicas)
            except Exception as error:
                restore_error = error
            if restore_error is None:
                try:
                    marker.unlink(missing_ok=True)
                except Exception as error:
                    cleanup_error = error
        if restore_error is None and work.exists():
            try:
                shutil.rmtree(work)
            except Exception as error:
                cleanup_error = error if cleanup_error is None else cleanup_error
        if restore_error is not None:
            try:
                transition_operation(operation_id, "recovery_required", "service restoration failed: " + str(restore_error), recovery=True, identity=identity)
            except Exception as error:
                journal_error = error
        elif not terminal and not identity:
            try:
                transition_operation(operation_id, "failed", "backup did not complete; service state was observed after cleanup", identity=identity)
            except Exception as error:
                journal_error = error
        if cleanup_error is not None:
            print("backup staging cleanup failed: %s" % cleanup_error, file=sys.stderr, flush=True)
        if restore_error is not None:
            if journal_error is not None:
                raise restore_error from journal_error
            raise restore_error
        if journal_error is not None:
            raise journal_error
        if cleanup_error is not None:
            raise cleanup_error


def interrupted(signum, frame):
    raise RuntimeError("backup interrupted; restoring the original service replica counts")


if __name__ == "__main__":
    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP, signal.SIGALRM):
        signal.signal(sig, interrupted)
    signal.alarm(1800)
    try:
        main(json.load(sys.stdin))
    except Exception as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)

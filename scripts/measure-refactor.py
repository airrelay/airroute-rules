#!/usr/bin/env python3
"""Measure one *offline* controller build against an isolated SQLite backup.

Only aggregates/digests are retained. This is a local end-to-end CLI benchmark,
not a production or HTTP-latency claim. Reuse the same frozen --root inputs for
before/after runs, and never pass an active controller's data directory.
"""
import argparse
from contextlib import closing
import ctypes
import hashlib
import json
import os
from pathlib import Path
import platform
import resource
import sqlite3
import subprocess
import time


class DarwinRusageV2(ctypes.Structure):
    # macOS SDK sys/resource.h, rusage_info_v2 (flavor 2).
    _fields_ = [("uuid", ctypes.c_uint8 * 16)] + [(name, ctypes.c_uint64) for name in (
        "user_time", "system_time", "pkg_idle_wkups", "interrupt_wkups", "pageins",
        "wired_size", "resident_size", "phys_footprint", "proc_start_abstime",
        "proc_exit_abstime", "child_user_time", "child_system_time", "child_pkg_idle_wkups",
        "child_interrupt_wkups", "child_pageins", "child_elapsed_abstime",
        "diskio_bytesread", "diskio_byteswritten",
    )]


def disk_usage(pid):
    if platform.system() == "Darwin":
        try:
            info = DarwinRusageV2()
            libproc = ctypes.CDLL("/usr/lib/libproc.dylib")
            if libproc.proc_pid_rusage(pid, 2, ctypes.byref(info)) == 0:
                return info.diskio_bytesread, info.diskio_byteswritten
        except (OSError, AttributeError):
            pass
    return None


def file_size(path):
    # SQLite creates/removes WAL between exists() and stat(), including normal
    # close/checkpoint. Treat an absent sample as zero rather than abandoning
    # the monitor while the measured child continues running.
    try:
        return path.stat().st_size
    except FileNotFoundError:
        return 0


def connect(path, quiescent=False):
    # Completed SQLite backups can retain WAL mode without a -shm file. Older
    # system SQLite cannot open those read-only unless explicitly immutable.
    # Never use immutable for the live build monitor or a source with a WAL.
    immutable = quiescent and not Path(str(path) + "-wal").exists()
    suffix = "?mode=ro&immutable=1" if immutable else "?mode=ro"
    return sqlite3.connect(path.resolve().as_uri() + suffix, uri=True, timeout=0.05)


def snapshot(path):
    if not path.exists():
        return {}
    with closing(connect(path, quiescent=True)) as conn:
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        result = {}
        for table in ("cases", "case_ranges", "build_case_sources", "jobs", "facts", "discovery_domains", "work_requests", "decisions", "gp_remote"):
            if table not in tables:
                continue
            columns = conn.execute('PRAGMA table_info("' + table + '")').fetchall()
            primary = [row[1] for row in sorted(columns, key=lambda row: row[5]) if row[5]]
            names = [row[1] for row in columns]
            rows = {}
            for row in conn.execute('SELECT * FROM "' + table + '"'):
                key = tuple(row[names.index(name)] for name in primary) if primary else row
                body = json.dumps(row, separators=(",", ":"), default=str).encode()
                rows[key] = hashlib.sha256(body).digest()
            result[table] = rows
        return result


def changes(before, after):
    result = {}
    for table in before.keys() | after.keys():
        old, new = before.get(table, {}), after.get(table, {})
        result[table] = {
            "before": len(old), "after": len(new),
            "inserted": len(new.keys() - old.keys()),
            "deleted": len(old.keys() - new.keys()),
            "changed_rows": sum(old[key] != new[key] for key in old.keys() & new.keys()),
        }
    return result


def public_outputs(database, data):
    """Cardinality context only, outside measured child time/IO."""
    if not database.exists():
        return None
    with closing(connect(database, quiescent=True)) as conn:
        row = conn.execute("SELECT value FROM meta WHERE key='current-release'").fetchone()
    if not row:
        return None
    directory = data / "releases" / row[0]
    if not directory.is_dir():
        return {"release": row[0], "directory_missing": True}
    files = [p for p in directory.rglob("*") if p.is_file()]
    csv = []
    for path in files:
        if path.suffix == ".csv":
            with path.open("rb") as stream:
                lines = sum(1 for _ in stream)
            csv.append({"path": str(path.relative_to(directory)), "bytes": path.stat().st_size, "lines_including_header": lines})
    return {"release": row[0], "files": len(files), "bytes": sum(p.stat().st_size for p in files), "csv": csv}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--data", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--seed-db", type=Path)
    parser.add_argument("--label", default="offline-build")
    parser.add_argument("--command-json", help="Optional JSON argv for the existing full-pipeline opt-in fixture; no shell is invoked")
    parser.add_argument("--start-marker", type=Path, help="Full-pipeline fixture ready file; measure only after setup and release it with <file>.go")
    parser.add_argument("--sample-writer-lock", action="store_true", help="Probe BEGIN IMMEDIATE/ROLLBACK every 50ms on the isolated database; adds small contention")
    args = parser.parse_args()
    args.data = args.data.resolve()
    args.root = args.root.resolve()
    args.data.mkdir(parents=True, exist_ok=True)
    os.chmod(args.data, 0o700)
    database = args.data / "control.sqlite3"
    if args.seed_db:
        if database.exists():
            parser.error("--seed-db requires a new data directory; existing data is never overwritten")
        with closing(connect(args.seed_db, quiescent=True)) as source, closing(sqlite3.connect(database)) as dest:
            source.backup(dest)
    if args.start_marker:
        args.start_marker = args.start_marker.resolve()
        if args.start_marker.exists() or Path(str(args.start_marker) + ".go").exists():
            parser.error("ready/go files must not already exist")
    before = {} if args.start_marker else snapshot(database)
    args.output = args.output.resolve()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    command = json.loads(args.command_json) if args.command_json else [str(args.binary.resolve()), "--root", str(args.root), "--data", str(args.data), "build", "--offline"]
    if not isinstance(command, list) or not command or not all(isinstance(item, str) for item in command):
        parser.error("--command-json must be a nonempty JSON string array")
    wal_path = Path(str(database) + "-wal")
    initial_wal_bytes = file_size(wal_path)
    cpu_before = resource.getrusage(resource.RUSAGE_CHILDREN)
    phases, first_stage, peak_wal, queries, disk = [], None, 0, [], None
    writer, writer_samples, writer_busy_samples, writer_errors, busy_start, busy_windows = None, 0, 0, 0, None, []
    if args.sample_writer_lock and database.exists() and not args.start_marker:
        writer = sqlite3.connect(database, timeout=0, isolation_level=None)
    started = time.monotonic()
    process_started = started
    started_unix = int(time.time())
    measuring, disk_baseline, setup_wait_seconds = not args.start_marker, None, 0.0
    with args.output.with_suffix(".stdout.log").open("wb") as stdout, args.output.with_suffix(".stderr.log").open("wb") as stderr:
        proc = subprocess.Popen(command, stdout=stdout, stderr=stderr)
        while proc.poll() is None:
            if not measuring:
                if not args.start_marker.exists():
                    time.sleep(0.02)
                    continue
                # The fixture is quiescent until .go, so row/IO baselines do
                # not include artificial stale-projection setup or seeding.
                before = snapshot(database)
                disk_baseline = disk_usage(proc.pid)
                initial_wal_bytes = file_size(wal_path)
                if args.sample_writer_lock:
                    writer = sqlite3.connect(database, timeout=0, isolation_level=None)
                started, started_unix = time.monotonic(), int(time.time())
                setup_wait_seconds = started - process_started
                measuring = True
                Path(str(args.start_marker) + ".go").write_text("go\n")
            disk = disk_usage(proc.pid) or disk
            wal = Path(str(database) + "-wal")
            peak_wal = max(peak_wal, file_size(wal))
            if database.exists():
                if writer is not None:
                    writer_samples += 1
                    busy = False
                    try:
                        writer.execute("BEGIN IMMEDIATE")
                        writer.execute("ROLLBACK")
                    except sqlite3.OperationalError as error:
                        if "locked" in str(error).lower():
                            busy, writer_busy_samples = True, writer_busy_samples + 1
                        else:
                            writer_errors += 1
                    at = time.monotonic() - started
                    if busy and busy_start is None:
                        busy_start = at
                    elif not busy and busy_start is not None:
                        busy_windows.append({"start_seconds": busy_start, "end_seconds": at})
                        busy_start = None
                try:
                    query_start = time.monotonic()
                    with closing(connect(database)) as conn:
                        row = conn.execute("SELECT p.build_id,p.snapshot FROM build_progress p JOIN builds b ON b.id=p.build_id WHERE b.started>=? ORDER BY b.started DESC,b.rowid DESC LIMIT 1", (started_unix,)).fetchone()
                    queries.append(time.monotonic() - query_start)
                    if row:
                        progress = json.loads(row[1])
                        stage = (row[0], progress["stage"])
                        if stage != first_stage:
                            first_stage = stage
                            phases.append({"stage": progress["stage"], "label": progress["label"], "at_seconds": time.monotonic() - started})
                except (sqlite3.OperationalError, json.JSONDecodeError, KeyError):
                    pass
            time.sleep(0.05)
        code = proc.wait()
    elapsed = time.monotonic() - started
    if busy_start is not None:
        busy_windows.append({"start_seconds": busy_start, "end_seconds": elapsed})
    if writer is not None:
        writer.close()
    cpu_after = resource.getrusage(resource.RUSAGE_CHILDREN)
    after = snapshot(database)
    for index, phase in enumerate(phases):
        phase["observed_seconds"] = (phases[index + 1]["at_seconds"] if index + 1 < len(phases) else elapsed) - phase["at_seconds"]
    queries.sort()
    report = {
        "label": args.label, "command": command, "exit_code": code,
        "binary_sha256": hashlib.sha256(args.binary.read_bytes()).hexdigest(),
        "config_sha256": hashlib.sha256(json.dumps({str(p.relative_to(args.root)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted((args.root / "config").rglob("*")) if p.is_file()}, sort_keys=True).encode()).hexdigest(),
        "environment": {"platform": platform.platform(), "machine": platform.machine(), "cpu_count": os.cpu_count(), "python_sqlite": sqlite3.sqlite_version},
        "elapsed_seconds": elapsed,
        "setup_wait_seconds": setup_wait_seconds,
        "start_marker_observed": measuring if args.start_marker else None,
        "measurement_epoch": "after isolated fixture setup" if args.start_marker else "process start",
        "cpu_user_seconds": cpu_after.ru_utime - cpu_before.ru_utime,
        "cpu_system_seconds": cpu_after.ru_stime - cpu_before.ru_stime,
        "child_peak_rss_bytes": cpu_after.ru_maxrss * (1 if platform.system() == "Darwin" else 1024),
        "child_peak_rss_scope": "whole child including initial migration/setup; native RUSAGE_CHILDREN maximum",
        "io_output_blocks": cpu_after.ru_oublock - cpu_before.ru_oublock,
        "sampled_disk_read_bytes_including_setup": disk[0] if disk else None,
        "sampled_disk_written_bytes_including_setup": disk[1] if disk else None,
        "sampled_disk_read_bytes": max(0,disk[0] - (disk_baseline[0] if disk_baseline else 0)) if disk else None,
        "sampled_disk_written_bytes": max(0,disk[1] - (disk_baseline[1] if disk_baseline else 0)) if disk else None,
        "peak_wal_bytes": peak_wal, "phase_observations": phases,
        "initial_wal_bytes": initial_wal_bytes,
        "final_wal_bytes": file_size(wal_path),
        "monitor_read_p95_seconds": queries[min(len(queries) - 1, int(len(queries) * 0.95))] if queries else None,
        "table_changes": changes(before, after),
        "public_outputs": public_outputs(database, args.data),
        "writer_availability_probe": {"enabled": args.sample_writer_lock, "samples": writer_samples, "busy_samples": writer_busy_samples, "errors": writer_errors, "sampled_busy_windows": busy_windows},
        "limitations": ["WAL high-water size is not total bytes written (checkpoint reuse).", "Sampled process disk IO includes all file output, not only SQLite, and may miss the final 50ms.", "Child CPU counters cover the whole process, including setup; marker-scoped wall/disk measurements exclude setup.", "Row digests detect stored changes, not same-value UPDATE statements.", "Progress reads are sampled every 50ms; phase durations are approximate.", "Monitor read latency is not HTTP/list latency; queue/list fixtures are measured separately.", "When enabled, the writer availability probe adds contention and can change checkpoint timing; sampled busy windows are not exact lock durations."],
    }
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    print(json.dumps({"report": str(args.output), "exit_code": code, "elapsed_seconds": elapsed, "peak_wal_bytes": peak_wal, "table_changes": report["table_changes"]}, ensure_ascii=False))
    raise SystemExit(code)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Measure an isolated, network-disabled Linux acceptance container.

Prepare frozen inputs and synthetic jobs in a separate container and measure in
one fresh cgroup. Controller, fake QUIC nodes, HTTP/append load, optional writer
probe and sampler all share the exact memory/CPU/I/O budget. No real DNS,
traceroute or provider measurement is performed by this fixture.
"""
import argparse
from contextlib import closing
import hashlib
import json
import math
import os
from pathlib import Path
import signal
import sqlite3
import subprocess
import threading
import time
import urllib.request

TOKEN = "isolated-public-admin-fixture-not-a-real-credential"
CG = Path("/sys/fs/cgroup")


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def counters(text):
    return {parts[0]: int(parts[1]) for line in (text or "").splitlines()
            if len(parts := line.split()) == 2 and parts[1].isdigit()}


def block_io(text):
    return {parts[0]: {key: int(value) for item in parts[1:]
                      for key, value in [item.split("=", 1)]}
            for line in (text or "").splitlines() if (parts := line.split())}


def difference(before, after):
    return {key: after.get(key, 0) - before.get(key, 0) for key in before.keys() | after.keys()}


def cgroup():
    result = {}
    for name in ("memory.current", "memory.peak", "memory.max", "memory.stat", "memory.swap.current", "memory.swap.max", "memory.events", "cpu.stat", "io.stat", "pids.current"):
        try:
            value = (CG / name).read_text().strip()
            result[name] = int(value) if value.isdigit() else value
        except OSError:
            result[name] = None
    processes = []
    for pid in (CG / "cgroup.procs").read_text().split():
        try:
            status = dict(line.split(":", 1) for line in Path(f"/proc/{pid}/status").read_text().splitlines() if ":" in line)
            io = dict(line.split(":", 1) for line in Path(f"/proc/{pid}/io").read_text().splitlines())
            processes.append({"pid": int(pid), "name": status["Name"].strip(),
                              **{key: int(status.get(field, "0 kB").split()[0]) for key, field in [("rss_kib", "VmRSS"), ("hwm_kib", "VmHWM"), ("anon_kib", "RssAnon"), ("file_kib", "RssFile")]},
                              "io": {key: int(value) for key, value in io.items()}})
        except (OSError, ValueError, KeyError):
            pass
    result["processes"] = processes
    return result


def database(path):
    with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=0.05)) as conn:
        conn.execute("BEGIN")
        return {
            "results": conn.execute("SELECT count(*),coalesce(sum(accepted),0) FROM results").fetchone(),
            "jobs": dict(conn.execute("SELECT status,count(*) FROM jobs GROUP BY status")),
            "unique_result_jobs": conn.execute("SELECT count(DISTINCT job_id) FROM results WHERE accepted=1").fetchone()[0],
            "qualified_results": conn.execute("SELECT count(*) FROM results WHERE qualified=1").fetchone()[0],
            "accepted_qualified_unique_rounds": conn.execute("SELECT count(*) FROM (SELECT job_id,round_seq FROM results WHERE accepted=1 AND qualified=1 GROUP BY job_id,round_seq)").fetchone()[0],
            "historical_results": conn.execute("SELECT count(*) FROM results WHERE accepted=0").fetchone()[0],
            "gp_remote": conn.execute("SELECT count(*) FROM gp_remote").fetchone()[0],
            "gp_tests": conn.execute("SELECT coalesce(sum(tests),0) FROM gp_test_usage").fetchone()[0],
            "replan_pending": conn.execute("SELECT EXISTS(SELECT 1 FROM replan_cases)").fetchone()[0],
            "pending_markers": dict(conn.execute("SELECT key,value FROM meta WHERE key IN ('build-sync-pending','export-pending')")),
            "current_release": conn.execute("SELECT value FROM meta WHERE key='current-release'").fetchone(),
        }


def request(path, payload=None, timeout=5, metadata=None):
    body = None if payload is None else json.dumps(payload).encode()
    req = urllib.request.Request("http://127.0.0.1:8787" + path, data=body, headers={"Authorization": "Bearer " + TOKEN, "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as response:
        if metadata is not None:
            metadata["status"] = response.status
        return json.load(response)


def distribution(values):
    values = sorted(values)
    return {"n": len(values), "p50_ms": values[(len(values) - 1) // 2] if values else None,
            "p95_ms": values[math.ceil(len(values) * .95) - 1] if values else None,
            "max_ms": max(values) if values else None}


def checked_memory_limit(requested):
    effective = int((CG / "memory.max").read_text().strip())
    page_size = os.sysconf("SC_PAGE_SIZE")
    if not 0 < effective <= requested or requested - effective >= page_size:
        raise RuntimeError(f"memory.max {effective} must not exceed requested {requested} and may round down by less than one page ({page_size})")
    return effective, page_size


def phase_delta(phase, sampled_peak):
    begin, end = phase["begin"], phase["end"]
    a, b = begin["cgroup"], end["cgroup"]
    elapsed = end["seconds"] - begin["seconds"]
    cpu = difference(counters(a["cpu.stat"]), counters(b["cpu.stat"]))
    io_a, io_b = block_io(a["io.stat"]), block_io(b["io.stat"])
    rounds = end["database"]["accepted_qualified_unique_rounds"] - begin["database"]["accepted_qualified_unique_rounds"]
    previous = {p["pid"]: p for p in a["processes"]}
    surviving = {p["pid"]: difference(previous[p["pid"]]["io"], p["io"]) for p in b["processes"] if p["pid"] in previous}
    return {"seconds": elapsed, "cpu_stat_delta": cpu,
            "cpu_percent_of_one_core": 100 * cpu.get("usage_usec", 0) / (elapsed * 1e6) if elapsed else None,
            "accepted_qualified_unique_rounds_delta": rounds,
            "cpu_seconds_per_new_accepted_qualified_round": cpu.get("usage_usec", 0) / 1e6 / rounds if rounds > 0 else None,
            "block_io_delta_by_device": {device: difference(io_a.get(device, {}), io_b.get(device, {})) for device in io_a.keys() | io_b.keys()},
            "proc_io_delta_surviving_pids": surviving,
            "proc_io_new_pids_end_counters": {p["pid"]: p["io"] for p in b["processes"] if p["pid"] not in previous},
            "proc_io_missing_end_pids": sorted(previous.keys() - {p["pid"] for p in b["processes"]}),
            "proc_io_scope": "surviving process deltas plus new process end counters; exited process I/O can be absent, cgroup block I/O covers the whole phase",
            "sampled_memory_current_peak_bytes": max(sampled_peak or 0, a.get("memory.current") or 0, b.get("memory.current") or 0),
            "memory_events_delta": difference(counters(a["memory.events"]), counters(b["memory.events"]))}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("binary", "fixture", "root", "data", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--timeout", type=float, default=600)
    parser.add_argument("--build-count", type=int, default=1, help="Consecutive builds in the same controller process; nodes drain only after all rounds")
    parser.add_argument("--memory-bytes", type=int, default=2000000000, help="Exact cgroup bytes; decimal 2GB is distinct from the old 2GiB runs")
    parser.add_argument("--idle-seconds", type=float, default=15)
    parser.add_argument("--post-seconds", type=float, default=20)
    parser.add_argument("--runtime-only", action="store_true", help="Never request a build; measure only the prepared queue and optional arriving targets")
    parser.add_argument("--duration", type=float, default=60, help="Seconds of the runtime-only phase")
    parser.add_argument("--append-rate", type=float, default=0, help="Scheduled unique synthetic observation submissions per second; report missed client slots")
    parser.add_argument("--append-kind", choices=("dns", "trace"), default="dns", help="Match the prepared node capabilities; DNS uses append-NNNNNN.invalid, trace uses synthetic public IPs")
    parser.add_argument("--fixture-nodes", type=int, default=3)
    parser.add_argument("--fixture-capacity", type=int, default=20)
    parser.add_argument("--writer-probe", action="store_true", help="Perturbs the same cgroup: attempt BEGIN IMMEDIATE then immediate ROLLBACK every 50ms")
    parser.add_argument("--no-fixture", action="store_true", help="Freeze observations for zero/small/full input-change builds")
    args = parser.parse_args()
    if (any(not math.isfinite(v) for v in (args.timeout, args.idle_seconds, args.post_seconds, args.duration, args.append_rate))
            or args.timeout <= 0 or min(args.idle_seconds, args.post_seconds, args.append_rate) < 0
            or args.duration <= 0 or args.memory_bytes <= 0 or args.build_count < 1 or args.fixture_nodes not in range(1, 4) or not 1 <= args.fixture_capacity <= 1000):
        parser.error("invalid duration, append rate, build count, node count or capacity")
    if args.no_fixture and args.append_rate:
        parser.error("--no-fixture freezes observations and cannot append targets")
    if args.runtime_only and args.build_count != 1:
        parser.error("--build-count requires build mode")
    for name in ("binary", "fixture", "root", "data", "output"):
        setattr(args, name, getattr(args, name).resolve())
    args.output.mkdir(exist_ok=True, parents=True)
    effective_memory, page_size = checked_memory_limit(args.memory_bytes)
    assert (CG / "memory.swap.max").read_text().strip() == "0"
    assert set(os.listdir("/sys/class/net")) == {"lo"}, "requires --network none"
    started = time.monotonic()
    state = {"phase": "startup", "progress": None}
    stop, load_stop, append_stop, probe_stop = (threading.Event() for _ in range(4))
    api, appends, probes, phases, phase_peaks, monitor_errors = [], [], [], [], {}, []
    loaders, node_logs, nodes, fixture_logs = [], [], [], []
    appender = probe = None
    db_path = args.data / "control.sqlite3"
    result = {"scope": "native Linux whole cgroup: controller, fake QUIC nodes, real HTTP load, sampler and optional append/writer probe; no swap or external network",
              "memory_budget_bytes": args.memory_bytes, "script_sha256": sha256(Path(__file__)),
              "memory_budget_requested_bytes": args.memory_bytes, "memory_budget_effective_bytes": effective_memory, "memory_page_size_bytes": page_size,
              "binary_sha256": sha256(args.binary), "fixture_sha256": sha256(args.fixture),
              "runtime_only": args.runtime_only, "append_rate_requested": args.append_rate, "append_kind": args.append_kind,
              "build_count_requested": args.build_count, "rounds": [],
              "writer_probe_perturbation": args.writer_probe, "observations_frozen": args.no_fixture,
              "setup_excluded": True, "setup_contract": "caller used a separate preparation container and a fresh measurement cgroup",
              "fixture_nodes_requested": 0 if args.no_fixture else args.fixture_nodes,
              "fixture_capacity_each": args.fixture_capacity, "start_cgroup": cgroup(),
              "coverage": {"synthetic_success_receipts": not args.no_fixture, "real_dns_or_provider": False,
                           "short_ttl_or_reconnect_retransmit": "not implied; requires a separately identified fixture mode"}}

    def snapshot():
        return {"seconds": time.monotonic() - started, "cgroup": cgroup(), "database": database(db_path)}

    def phase(name):
        boundary = snapshot()
        if phases and "end" not in phases[-1]:
            phases[-1]["end"] = boundary
        state["phase"] = name
        state["progress"] = None
        phases.append({"name": name, "begin": boundary})

    def sample():
        try:
            with (args.output / "samples.jsonl").open("w") as log:
                while not stop.wait(.1):
                    name = state["phase"]
                    reading = cgroup()
                    phase_peaks[name] = max(phase_peaks.get(name, 0), reading.get("memory.current") or 0)
                    log.write(json.dumps({"seconds": time.monotonic() - started, "phase": name, "progress": state["progress"], **reading}, separators=(",", ":")) + "\n")
                    log.flush()
        except Exception as error:
            monitor_errors.append(str(error))

    def timed_request(path, payload=None):
        begin, name = time.monotonic(), state["phase"]
        row = {"phase": name, "path": path, "started_seconds": begin - started}
        try:
            value = request(path, payload, metadata=row)
            row["ok"] = True
            return value
        except Exception as error:
            row.update(ok=False, status=getattr(error, "code", None), error=f"{type(error).__name__}: {error}")
        finally:
            row["elapsed_ms"] = (time.monotonic() - begin) * 1000
            api.append(row)

    def http_load(path):
        while not load_stop.is_set():
            begin = time.monotonic()
            timed_request(path)
            load_stop.wait(max(0, 1 - (time.monotonic() - begin)))

    def append_load():
        next_at, sequence = time.monotonic(), 0
        period = 1 / args.append_rate
        while not append_stop.wait(max(0, next_at - time.monotonic())):
            begin = time.monotonic()
            missed = max(0, int((begin - next_at) / period))
            sequence += missed + 1
            target = (f"append-{sequence:06}.invalid" if args.append_kind == "dns" else
                      f"11.{20 + sequence // (254 * 254)}.{sequence // 254 % 254}.{sequence % 254 + 1}")
            value = timed_request("/api/observations", {"target": target, "regions": ["us"], "reason": "isolated synthetic arriving observation; no packets sent", "refresh": False})
            appends.append({"target": target, "ok": value is not None, "started_seconds": begin - started, "missed_schedule_slots": missed})
            next_at += (missed + 1) * period

    def writer_probe():
        try:
            with sqlite3.connect(db_path.as_uri() + "?mode=rw", uri=True, timeout=0, isolation_level=None) as conn:
                conn.execute("PRAGMA busy_timeout=0")
                while not probe_stop.is_set():
                    begin, name = time.monotonic(), state["phase"]
                    row = {"phase": name, "started_seconds": begin - started}
                    try:
                        conn.execute("BEGIN IMMEDIATE")
                        row["ok"] = True
                    except sqlite3.Error as error:
                        code = getattr(error, "sqlite_errorcode", None)
                        # sqlite_errorcode was added in Python 3.11; older
                        # acceptance images still expose SQLite's exact message.
                        busy = ((code & 255) in (5, 6) if code is not None else
                                isinstance(error, sqlite3.OperationalError) and str(error) in ("database is locked", "database table is locked"))
                        row.update(ok=False, busy=busy, error=str(error))
                    finally:
                        if conn.in_transaction:
                            conn.execute("ROLLBACK")
                    row["elapsed_ms"] = (time.monotonic() - begin) * 1000
                    probes.append(row)
                    probe_stop.wait(max(0, .05 - (time.monotonic() - begin)))
        except Exception as error:
            monitor_errors.append("writer probe: " + str(error))

    environment = {**os.environ, "AIRROUTE_ADMIN_TOKEN": TOKEN, "RUST_LOG": "airroute_rules=info"}
    phase("startup")
    logs = (args.output / "controller.log").open("w")
    controller = subprocess.Popen([str(args.binary), "--root", str(args.root), "--data", str(args.data), "serve", "--offline", "--bind", "127.0.0.1:8787", "--quic-bind", "127.0.0.1:8788", "--interval-hours", "0"], env=environment, stdout=logs, stderr=subprocess.STDOUT)
    result["controller_pid"] = controller.pid
    sampler = threading.Thread(target=sample, daemon=True)
    sampler.start()

    def alive():
        if controller.poll() is not None:
            raise RuntimeError(f"controller exited: {controller.returncode}")
        for node in nodes:
            if node.poll() is not None:
                raise RuntimeError(f"synthetic node exited: {node.returncode}")

    def observe(seconds):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            alive()
            time.sleep(min(.1, max(0, deadline - time.monotonic())))

    try:
        deadline = time.monotonic() + 60
        while True:
            alive()
            try:
                request("/healthz")
                break
            except Exception:
                if time.monotonic() > deadline:
                    raise
                time.sleep(.1)
        result["startup_seconds"] = time.monotonic() - started
        phase("idle_no_connected_executor")
        for path in ("/api/task-items?limit=25", "/api/task-summary", "/api/nodes"):
            loader = threading.Thread(target=http_load, args=(path,), daemon=True)
            loader.start()
            loaders.append(loader)
        if args.writer_probe:
            probe = threading.Thread(target=writer_probe, daemon=True)
            probe.start()
        observe(args.idle_seconds)
        phase("fixture_connecting")
        if not args.no_fixture:
            ids = ["isolated-native-fixture" + (f"-{i}" if i else "") for i in range(args.fixture_nodes)]
            for i, node_id in enumerate(ids):
                path = args.output / ("fixture.jsonl" if i == 0 else f"fixture-{i}.jsonl")
                fixture_logs.append(path)
                node_log = path.open("w")
                node_logs.append(node_log)
                env = {**environment, "AIRROUTE_FIXTURE_NODE_ID": node_id, "AIRROUTE_FIXTURE_CAPACITY": str(args.fixture_capacity)}
                nodes.append(subprocess.Popen([str(args.fixture), "run", str(args.data)], env=env, stdout=node_log, stderr=subprocess.STDOUT))
            deadline = time.monotonic() + 10
            while not set(ids).issubset({n["id"] for n in request("/api/nodes") if n["connected"]}):
                alive()
                if time.monotonic() >= deadline:
                    raise TimeoutError("synthetic nodes did not all connect")
                time.sleep(.1)
        def build_phase(name, number):
            phase(f"round_{number}:{name}" if args.build_count > 1 else name)
            phases[-1]["round"] = number

        if args.runtime_only:
            phase("runtime_measurements")
        else:
            build_phase("build_fixed_observations" if args.no_fixture else "build_and_measurements", 1)
        result["counts_before_build"] = phases[-1]["begin"]["database"]
        if args.append_rate:
            appender = threading.Thread(target=append_load, daemon=True)
            appender.start()
        if args.runtime_only:
            observe(args.duration)
        else:
            for number in range(1, args.build_count + 1):
                if number > 1:
                    build_phase("build_fixed_observations" if args.no_fixture else "build_and_measurements", number)
                round_result = {"round": number, "controller_pid": controller.pid, "status": "running", "counts_before": phases[-1]["begin"]["database"],
                                "build_seconds": None, "sync_seconds": None, "whole_build_and_sync_seconds": None}
                result["rounds"].append(round_result)
                build_started = time.monotonic()
                try:
                    alive()
                    build_ids = {row["id"] for row in request("/api/builds?compact=true")}
                    request("/api/builds", {})
                    while time.monotonic() - build_started < args.timeout:
                        alive()
                        rows = request("/api/builds?compact=true", timeout=10)
                        build = next((row for row in rows if row["id"] not in build_ids), None)
                        if build:
                            state["progress"] = build.get("progress")
                            round_result["build"] = build
                            if build["status"] in ("complete", "failed", "deferred"):
                                break
                        time.sleep(.5)
                    else:
                        raise TimeoutError("whole build deadline")
                    round_result["build_seconds"] = time.monotonic() - build_started
                    result.update(build=build, build_seconds=round_result["build_seconds"])
                    if build["status"] != "complete":
                        raise RuntimeError("build did not complete")
                    build_phase("background_sync_and_measurements", number)
                    sync_started = time.monotonic()
                    while time.monotonic() - build_started < args.timeout:
                        alive()
                        counts = database(db_path)
                        if not counts["pending_markers"] and not counts["replan_pending"]:
                            break
                        time.sleep(.25)
                    else:
                        raise TimeoutError("manifest/replan drain deadline")
                    round_result.update(sync_seconds=time.monotonic() - sync_started, whole_build_and_sync_seconds=time.monotonic() - build_started)
                    result["whole_build_and_sync_seconds"] = round_result["whole_build_and_sync_seconds"]
                    # Refresh the compact summary after synchronization; never
                    # deserialize the wide private geography candidate here.
                    final_build = next(row for row in request("/api/builds?compact=true") if row["id"] == build["id"])
                    round_result.update(build=final_build, summary=final_build.get("summary"))
                    result["build"] = final_build
                    build_phase("post_build_measurements", number)
                    observe(args.post_seconds)
                    round_result["counts_after"] = database(db_path)
                    if args.no_fixture:
                        for key in ("results", "gp_tests", "gp_remote"):
                            if round_result["counts_before"][key] != round_result["counts_after"][key]:
                                raise RuntimeError(f"frozen observations changed in round {number}: {key}")
                    round_result["status"] = "complete"
                except Exception as error:
                    round_result.update(status="failed", error=str(error))
                    raise
                finally:
                    round_result["elapsed_seconds"] = time.monotonic() - build_started
                    if "counts_after" not in round_result:
                        try:
                            round_result["counts_after"] = database(db_path)
                        except Exception as error:
                            round_result["counts_after_error"] = str(error)
        append_stop.set()
        if appender:
            appender.join(timeout=6)
            if appender.is_alive():
                raise RuntimeError("append request did not finish")
        result["counts_after"] = database(db_path)
        phase("fixture_drain_after_measurement")
        for node in nodes:
            node.send_signal(signal.SIGUSR1)
        for node in nodes:
            node.wait(timeout=30)
            if node.returncode:
                raise RuntimeError(f"synthetic fixture failed to drain: {node.returncode}")
        deadline = time.monotonic() + 30
        while nodes and time.monotonic() < deadline:
            counts = database(db_path)
            if not counts["replan_pending"] and not counts["pending_markers"]:
                break
            if controller.poll() is not None:
                raise RuntimeError("controller exited while draining")
            time.sleep(.25)
        result["baseline_counts_after_drain"] = database(db_path)
        if result["baseline_counts_after_drain"]["jobs"].get("leased", 0):
            raise RuntimeError("fixture left an executing lease; baseline cannot be reused")
        if nodes and (counts["replan_pending"] or counts["pending_markers"]):
            raise RuntimeError("fixture baseline still has pending synchronization")
        if args.no_fixture:
            for key in ("results", "gp_tests", "gp_remote"):
                if result["counts_before_build"][key] != result["counts_after"][key]:
                    raise RuntimeError(f"frozen observations changed: {key}")
        result["status"] = "complete"
    except Exception as error:
        result.update(status="failed", error=str(error))
    finally:
        load_stop.set()
        append_stop.set()
        probe_stop.set()
        for thread in loaders + [t for t in (appender, probe) if t is not None]:
            thread.join(timeout=6)
            if thread.is_alive():
                result.update(status="failed", error=result.get("error", "measurement load did not stop"))
        try:
            phase("stopping")
            phases[-1]["end"] = phases[-1]["begin"]
        except Exception as error:
            result.setdefault("boundary_errors", []).append(str(error))
            result.update(status="failed", error=result.get("error", "final boundary snapshot failed"))
        result["end_before_shutdown_cgroup"] = cgroup()
        stop.set()
        for child in nodes + [controller]:
            if child.poll() is None:
                child.send_signal(signal.SIGINT)
                try:
                    child.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait()
        sampler.join(timeout=2)
        logs.close()
        for log in node_logs:
            log.close()
        result.update(controller_exit=controller.returncode, fixture_exits=[n.returncode for n in nodes], elapsed_seconds=time.monotonic() - started, final_cgroup=cgroup())
        result["phases"] = [{**p, "delta": phase_delta(p, phase_peaks.get(p["name"]))} for p in phases if "end" in p]
        for round_result in result["rounds"]:
            round_result["phases"] = [p for p in result["phases"] if p.get("round") == round_result["round"]]
        summaries = {}
        for row in api:
            key = row["phase"] + ":" + row["path"]
            summaries.setdefault(key, []).append(row)
        durations = {p["name"]: p["end"]["seconds"] - p["begin"]["seconds"] for p in phases if "end" in p}
        result["http"] = {key: {"requests": len(rows), "errors": sum(not r["ok"] for r in rows),
                               "error_rate": sum(not r["ok"] for r in rows) / len(rows),
                               "status_counts": {str(status): sum(r.get("status") == status for r in rows) for status in {r.get("status") for r in rows}},
                               "success_ms": distribution([r["elapsed_ms"] for r in rows if r["ok"]]),
                               "all_outcomes_ms": distribution([r["elapsed_ms"] for r in rows]),
                               "actual_rps": len(rows) / durations[rows[0]["phase"]] if durations.get(rows[0]["phase"], 0) > 0 else None} for key, rows in summaries.items()}
        result["http_errors"] = [r for r in api if not r["ok"]]
        result["append"] = {"attempted": len(appends), "succeeded": sum(r["ok"] for r in appends), "missed_schedule_slots": sum(r["missed_schedule_slots"] for r in appends)}
        result["writer_probe"] = {"enabled": args.writer_probe, "period_seconds": .05, "holds_lock_during_sleep": False,
                                  "attempts": len(probes), "busy": sum(r.get("busy", False) for r in probes),
                                  "busy_rate": sum(r.get("busy", False) for r in probes) / len(probes) if probes else None,
                                  "errors": sum(not r["ok"] and not r.get("busy", False) for r in probes),
                                  "attempt_ms": distribution([r["elapsed_ms"] for r in probes])}
        result["writer_probe"]["by_phase"] = {name: {"attempts": len(rows), "busy": sum(r.get("busy", False) for r in rows),
                                                    "attempt_ms": distribution([r["elapsed_ms"] for r in rows])}
                                              for name in {r["phase"] for r in probes}
                                              for rows in [[r for r in probes if r["phase"] == name]]}
        result["monitor_errors"] = monitor_errors
        events = difference(counters(result["start_cgroup"]["memory.events"]), counters(result["final_cgroup"]["memory.events"]))
        result["memory_events_delta"] = events
        if events.get("oom_kill", 0):
            result.update(status="failed", error="cgroup OOM kill observed")
        elif result["http_errors"] or monitor_errors or result["writer_probe"]["errors"]:
            result.update(status="failed", error=result.get("error", "HTTP or monitoring errors observed"))
        for filename, rows in (("http.jsonl", api), ("append.jsonl", appends), ("writer-probe.jsonl", probes)):
            (args.output / filename).write_text("".join(json.dumps(r, separators=(",", ":")) + "\n" for r in rows))
        receipts = []
        for path in fixture_logs:
            for line in path.read_text().splitlines():
                try:
                    row = json.loads(line)
                    if "receipt_ms" in row:
                        receipts.append(row)
                except json.JSONDecodeError:
                    pass
        result["synthetic_receipts"] = {"n": len(receipts), "dispositions": {name: sum(r["disposition"] == name for r in receipts) for name in sorted({r["disposition"] for r in receipts})}, "ack_ms": distribution([r["receipt_ms"] for r in receipts]), "time_since_last_fixture_finished_ms": distribution([r["dispatch_gap_ms"] for r in receipts if "dispatch_gap_ms" in r])}
        (args.output / "result.json").write_text(json.dumps(result, indent=2) + "\n")
        work = [{"phase": p["name"], "cpu_seconds": p["delta"]["cpu_stat_delta"].get("usage_usec", 0) / 1e6,
                 "new_accepted_qualified_rounds": p["delta"]["accepted_qualified_unique_rounds_delta"],
                 "cpu_seconds_per_round": p["delta"]["cpu_seconds_per_new_accepted_qualified_round"]}
                for p in result["phases"] if p["name"].split(":")[-1] in ("runtime_measurements", "build_fixed_observations", "build_and_measurements", "background_sync_and_measurements", "post_build_measurements")]
        print(json.dumps({"status": result["status"], "error": result.get("error"), "elapsed_seconds": result["elapsed_seconds"], "memory_budget_bytes": args.memory_bytes, "memory_budget_requested_bytes": args.memory_bytes, "memory_budget_effective_bytes": effective_memory, "memory_page_size_bytes": page_size, "cgroup_peak": result["final_cgroup"]["memory.peak"], "work": work, "http_errors": len(result["http_errors"]), "writer_probe_busy": result["writer_probe"]["busy"], "result": str(args.output / "result.json")}))
    return 0 if result["status"] == "complete" else 1


if __name__ == "__main__":
    raise SystemExit(main())

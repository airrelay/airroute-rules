from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import time

from .pipeline import build, write_json
from .validation import validate_candidate


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description="Passive, reproducible AirRoute data production")
    commands = root.add_subparsers(dest="command", required=True)
    acquire = commands.add_parser("snapshot", help="download existing public materials; never probe targets")
    acquire.add_argument("--config", type=Path, default=Path("config/sources.json"))
    acquire.add_argument("--output", type=Path, required=True)
    acquire.add_argument("--fixture-dir", type=Path)
    acquire.add_argument("--offline", action="store_true")
    acquire.add_argument("--source", action="append", dest="source_ids", help="select source IDs for a bounded acquisition")
    candidate = commands.add_parser("build", help="compute using only a fixed local snapshot")
    candidate.add_argument("--snapshot", type=Path, required=True)
    candidate.add_argument("--output", type=Path, required=True)
    candidate.add_argument("--config-dir", type=Path, default=Path("config"))
    candidate.add_argument("--baseline", type=Path)
    candidate.add_argument("--report", type=Path)
    validate = commands.add_parser("validate")
    validate.add_argument("candidate", type=Path)
    validate.add_argument("--baseline", type=Path)
    validate.add_argument("--quality", type=Path, default=Path("config/quality.json"))
    compare = commands.add_parser("compare", help="compare actual predicate languages and IP address coverage")
    compare.add_argument("--before", type=Path, required=True)
    compare.add_argument("--after", type=Path, required=True)
    compare.add_argument("--report", type=Path, required=True)
    publish = commands.add_parser("publish")
    publish.add_argument("--candidate", type=Path, required=True)
    publish.add_argument("--repo", type=Path, default=Path("."))
    publish.add_argument("--source-sha", required=True)
    publish.add_argument("--sequence", type=int, required=True, help="monotonically increasing publication run number")
    publish.add_argument("--attempt", type=int, default=1)
    publish.add_argument("--remote", default="origin")
    publish.add_argument("--branch", default="release")
    rollback = commands.add_parser("rollback")
    rollback.add_argument("--version", required=True)
    rollback.add_argument("--repo", type=Path, default=Path("."))
    rollback.add_argument("--source-sha", required=True)
    rollback.add_argument("--sequence", type=int, required=True)
    rollback.add_argument("--attempt", type=int, default=1)
    rollback.add_argument("--remote", default="origin")
    rollback.add_argument("--branch", default="release")
    return root


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    started = time.monotonic()
    try:
        if args.command == "snapshot":
            from .acquire import acquire_sources
            snapshot = acquire_sources(args.config, args.output, allow_network=not args.offline,
                                       fixture_dir=args.fixture_dir, source_ids=args.source_ids)
            result = {"snapshot": str(args.output / "snapshot.json"),
                      "sources": [{"id": s["id"], "status": s["status"]} for s in snapshot["sources"]]}
        elif args.command == "build":
            metrics = {}
            manifest = build(args.snapshot, args.output, args.config_dir, baseline=args.baseline, metrics=metrics)
            result = {"data_version": manifest["data_version"], "summary": manifest["summary"]}
            if args.report:
                write_json(args.report, {**result, "elapsed_seconds": round(time.monotonic() - started, 3), "stages": metrics})
        elif args.command == "validate":
            policy = json.loads(args.quality.read_text()) if args.quality.exists() else {}
            result = validate_candidate(args.candidate, baseline=args.baseline, quality=policy)
        elif args.command == "publish":
            from .publish import publish
            result = publish(args.candidate, args.repo, args.source_sha, sequence=args.sequence, attempt=args.attempt,
                             remote=args.remote, branch=args.branch)
        elif args.command == "compare":
            from .coverage import compare_directories
            report = compare_directories(args.before, args.after)
            write_json(args.report, report)
            result = {"report": str(args.report), "before": report["before_version"], "after": report["after_version"]}
        else:
            from .publish import rollback
            result = rollback(args.repo, args.version, args.source_sha, sequence=args.sequence, attempt=args.attempt,
                              remote=args.remote, branch=args.branch)
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
        return 0
    except (ValueError, OSError, KeyError, RuntimeError) as error:
        print(f"{args.command} failed: {error}", file=sys.stderr)
        return 1

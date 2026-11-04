from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import time
import traceback

from .pipeline import build, build_domain_candidate, write_json
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
    acquire.add_argument('--record-dir', type=Path)
    candidate = commands.add_parser("build", help="compute using only a fixed local snapshot")
    candidate.add_argument("--snapshot", type=Path, required=True)
    candidate.add_argument("--output", type=Path, required=True)
    candidate.add_argument("--config-dir", type=Path, default=Path("config"))
    candidate.add_argument("--baseline", type=Path)
    candidate.add_argument("--report", type=Path)
    candidate.add_argument('--record-dir', type=Path)
    domains = commands.add_parser("build-domains", help="refresh domains/special data, reusing verified regional IP lists and special/asn.ardb")
    domains.add_argument("--snapshot", type=Path, required=True)
    domains.add_argument("--output", type=Path, required=True)
    domains.add_argument("--config-dir", type=Path, default=Path("config"))
    domains.add_argument("--baseline", type=Path, required=True)
    domains.add_argument("--report", type=Path)
    domains.add_argument('--record-dir', type=Path)
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
    publish.add_argument("--remote", required=True, help="explicit configured data Git remote, e.g. products")
    publish.add_argument("--branch", default="main")
    publish.add_argument("--source-remote", help="source fence remote; defaults to the publication remote")
    publish.add_argument("--source-branch", default="main")
    publish.add_argument("--replace-legacy-head", help="explicitly replace this exact target SHA only when no release manifest exists")
    publish.add_argument('--record-dir', type=Path)
    pack = commands.add_parser('record-pack', help='package bounded diagnostics; never publishes data')
    pack.add_argument('--record-dir', type=Path, required=True)
    pack.add_argument('--output', type=Path, required=True)
    status = commands.add_parser('record-status', help='record publication/skipped workflow outcome separately from build outcome')
    status.add_argument('--record-dir', type=Path, required=True)
    status.add_argument('--status', required=True)
    status.add_argument('--reason', default='')
    status.add_argument('--workflow-status')
    status.add_argument('--preserve-publication', action='store_true')
    explain = commands.add_parser('explain', help='read-only bounded trace lookup')
    explain.add_argument('--record-dir', type=Path, required=True)
    choice = explain.add_mutually_exclusive_group(required=True)
    choice.add_argument('--domain'); choice.add_argument('--ip'); choice.add_argument('--asn'); choice.add_argument('--product')
    explain.add_argument('--limit', type=int, default=100); explain.add_argument('--offset', type=int, default=0)
    rollback = commands.add_parser("rollback")
    rollback.add_argument("--version", required=True)
    rollback.add_argument("--repo", type=Path, default=Path("."))
    rollback.add_argument("--source-sha", required=True)
    rollback.add_argument("--sequence", type=int, required=True)
    rollback.add_argument("--attempt", type=int, default=1)
    rollback.add_argument("--remote", required=True)
    rollback.add_argument("--branch", default="main")
    rollback.add_argument("--source-remote", help="source fence remote; defaults to the publication remote")
    rollback.add_argument("--source-branch", default="main")
    return root


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    started = time.monotonic()
    from .record import clean, open_record, collect
    trace = None
    status = 'failed'
    failure = None
    metrics = {}
    if args.command in {'snapshot', 'build', 'build-domains', 'publish'}:
        default = (args.output.parent / (args.output.name + '-record')) if hasattr(args, 'output') else args.repo / '.build/publication-record'
        trace = open_record(args.record_dir or default, args.command)
        if trace is not None: trace.stage(args.command, 'started')
    try:
        if args.command == "snapshot":
            from .acquire import acquire_sources
            snapshot = acquire_sources(args.config, args.output, allow_network=not args.offline,
                                       fixture_dir=args.fixture_dir, source_ids=args.source_ids, trace=trace)
            result = {"snapshot": str(args.output / "snapshot.json"),
                      "sources": [{"id": s["id"], "status": s["status"]} for s in snapshot["sources"]]}
        elif args.command in {"build", "build-domains"}:
            if trace is not None:
                try: trace.inputs(json.loads(args.snapshot.read_text()), args.config_dir)
                except (ValueError, OSError): pass
            builder = build_domain_candidate if args.command == "build-domains" else build
            manifest = builder(args.snapshot, args.output, args.config_dir, baseline=args.baseline, metrics=metrics, trace=trace)
            result = {"data_version": manifest["data_version"], "summary": manifest["summary"]}
            if args.report:
                write_json(args.report, {**result, "elapsed_seconds": round(time.monotonic() - started, 3), "stages": metrics})
        elif args.command == "validate":
            policy = json.loads(args.quality.read_text()) if args.quality.exists() else {}
            result = validate_candidate(args.candidate, baseline=args.baseline, quality=policy)
        elif args.command == "publish":
            from .publish import publish
            result = publish(args.candidate, args.repo, args.source_sha, sequence=args.sequence, attempt=args.attempt,
                             remote=args.remote, branch=args.branch, source_remote=args.source_remote, source_branch=args.source_branch,
                             replace_legacy_head=args.replace_legacy_head, trace=trace)
            if trace is not None:
                trace.state['publication'] = {**result, 'target_branch': args.branch, 'source_commit': args.source_sha}
        elif args.command == 'record-pack':
            from .record import pack
            result = pack(args.record_dir, args.output)
        elif args.command == 'record-status':
            from .record import set_status
            set_status(args.record_dir, args.status, args.reason, args.workflow_status, args.preserve_publication)
            result = {'status': args.status}
        elif args.command == 'explain':
            from .explain import explain
            result = explain(args.record_dir, domain=args.domain, ip=args.ip, asn=args.asn, product=args.product, limit=args.limit, offset=args.offset)
        elif args.command == "compare":
            from .coverage import compare_directories
            report = compare_directories(args.before, args.after)
            write_json(args.report, report)
            result = {"report": str(args.report), "before": report["before_version"], "after": report["after_version"]}
        else:
            from .publish import rollback
            result = rollback(args.repo, args.version, args.source_sha, sequence=args.sequence, attempt=args.attempt,
                              remote=args.remote, branch=args.branch, source_remote=args.source_remote, source_branch=args.source_branch)
        print(json.dumps(clean(result), ensure_ascii=False, sort_keys=True))
        status = 'success'
        return 0
    except Exception as error:
        failure = {'error_type': type(error).__name__, 'error': clean(str(error)),
                   'error_frames': [{'file': Path(frame.filename).name, 'line': frame.lineno, 'function': frame.name}
                                    for frame in traceback.extract_tb(error.__traceback__)]}
        print(f"{args.command} failed: {clean(str(error))}", file=sys.stderr)
        return 1
    finally:
        if trace is not None:
            try:
                if args.command in {'build', 'build-domains'}:
                    collect(trace, args.output, args.baseline)
                    if status != 'success': trace.state['publication'] = {'status': 'skipped', 'reason': 'build-not-validated'}
                    # Retain legacy --report on failure too, without masking it.
                    if args.report:
                        try: write_json(args.report, clean({**(result if status=='success' else {}), 'status': status, **(failure or {}), 'stages': metrics,
                            'candidate': trace.state.get('candidate'), 'elapsed_seconds': round(time.monotonic()-started,3)}))
                        except OSError: pass
                if args.command == 'publish' and status != 'success':
                    trace.state['publication'] = {'status': 'failed-or-unconfirmed', **(failure or {})}
                    # Existing durable journal is the authority for uncertain pushes.
                    trace.state['publication']['recovery'] = 'preserve the exact pending journal; never infer remote success from candidate files'
                if args.command in {'build','build-domains'}:
                    trace.state['evidence_complete'] = bool(trace.state.get('candidate')) and not trace.state['diagnostic_errors']
                trace.finish(('acquisition-'+status) if args.command=='snapshot' else status, **(failure or {}))
                trace.close()
            except Exception:
                print('warning: build diagnostic finalization incomplete; original operation status retained', file=sys.stderr)

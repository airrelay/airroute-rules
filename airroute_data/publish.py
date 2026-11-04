"""Atomic, non-force publication, with a separately fenced source repository.

The public data files and their manifest enter one Git commit. A durable
local journal names the exact commit before push, so an interrupted push is
reconciled by identity/ancestry instead of regenerating an old candidate.
"""
from __future__ import annotations

import contextlib
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import tempfile
from typing import Any

MAX_ARTIFACT_BYTES = 95 * 1024 * 1024  # Headroom below GitHub's 100 MiB Git blob cap.


class PublicationError(RuntimeError):
    pass


class PublicationUncertain(PublicationError):
    """The caller must preserve the publication workspace and retry reconciliation."""


def _git(repo: Path, *args: str, allow_failure: bool = False) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env.update(GIT_TERMINAL_PROMPT="0", GIT_AUTHOR_NAME="AirRoute data bot",
               GIT_AUTHOR_EMAIL="data-bot@users.noreply.github.com",
               GIT_COMMITTER_NAME="AirRoute data bot",
               GIT_COMMITTER_EMAIL="data-bot@users.noreply.github.com")
    try:
        result = subprocess.run(["git", "-C", str(repo), *args], text=True,
                                capture_output=True, env=env, timeout=180)
    except subprocess.TimeoutExpired as exc:
        raise PublicationUncertain("Git transport timed out; retained exact commit for reconciliation") from exc
    if result.returncode and not allow_failure:
        # Do not copy URLs, credentials, HTTP headers or remote output into logs.
        raise PublicationError("Git operation failed: " + args[0])
    return result


def _json_write(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8") as output:
        json.dump(value, output, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
        output.write("\n")
        output.flush()
        os.fsync(output.fileno())
    os.replace(temporary, path)


def _digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def _version(value: Any) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", value):
        raise PublicationError("Invalid data version")
    return value


def _publication_order(sequence: Any, attempt: Any) -> tuple[int, int]:
    if any(isinstance(v, bool) or not isinstance(v, int) or not 1 <= v <= (1 << 63) - 1
           for v in (sequence, attempt)):
        raise PublicationError("Publication sequence and attempt must be positive integers")
    return sequence, attempt


def _same_data(left: dict, right: dict) -> bool:
    return {k: v for k, v in left.items() if k != "publication"} == {
        k: v for k, v in right.items() if k != "publication"}


def _public_manifest(manifest: dict) -> dict:
    """Publish a closed inventory; diagnostics remain in the build artifact."""
    files = []
    for record in manifest["files"]:
        name = record["path"]
        is_rule = bool(re.fullmatch(r"(region|category|provider|special)/[a-z0-9][a-z0-9-]*\.list", name))
        if name.endswith((".list", ".ardb")) and not (is_rule or name == "special/asn.ardb"):
            raise PublicationError("Unexpected rule/database publication path: " + name)
        if is_rule or name in {"special/asn.ardb", "regions.json", "ATTRIBUTION.md"}:
            files.append(dict(record))
    return {**{k: v for k, v in manifest.items() if k not in {"publication", "layout"}},
            "files": files, "layout": "flat-v1"}


def _read_release(worker: Path) -> tuple[dict, Path]:
    """Read the flat layout, or the former pointer once during migration."""
    if (worker / "manifest.json").exists():
        path = worker / "manifest.json"
        if path.is_symlink():
            raise PublicationError("Release manifest is a symlink")
        manifest = json.loads(path.read_text())
        if manifest.get("layout") != "flat-v1":
            raise PublicationError("Unsupported release layout")
        return manifest, worker
    current = worker / "current.json"
    if current.is_symlink():
        raise PublicationError("Release pointer is a symlink")
    pointer = json.loads(current.read_text())
    version = _version(pointer.get("data_version"))
    relative = "versions/" + version + "/manifest.json"
    if pointer.get("manifest") != relative:
        raise PublicationError("Unsafe previous release pointer")
    path = worker / relative
    if any(p.is_symlink() for p in (path, path.parent, path.parent.parent)):
        raise PublicationError("Previous release contains a symlink")
    if _digest(path) != pointer.get("manifest_sha256"):
        raise PublicationError("Previous release manifest digest mismatch")
    manifest = json.loads(path.read_text())
    if manifest.get("data_version") != version:
        raise PublicationError("Previous release version mismatch")
    return {**manifest, "publication": pointer["publication"]}, path.parent


def _replace_release(worker: Path, candidate: Path, manifest: dict) -> None:
    # This is an isolated publisher checkout, never the user's source tree.
    # Remove all old tracked/untracked payload, including obsolete reports.
    for path in worker.iterdir():
        if path.name == ".git":
            continue
        if path.is_dir() and not path.is_symlink():
            shutil.rmtree(path)
        else:
            path.unlink()
    for record in manifest["files"]:
        target = worker / record["path"]
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(candidate / record["path"], target)
    _json_write(worker / "manifest.json", manifest)


def _check_order(previous: dict, incoming: tuple[int, int]) -> None:
    previous_order = previous.get("publication", {})
    if incoming <= _publication_order(previous_order.get("sequence"), previous_order.get("attempt")):
        raise PublicationError("An equal or newer publication already exists; refusing a late candidate")


def validate_candidate(candidate: Path) -> dict:
    """Validate the exact inventory, not an unbounded directory copy."""
    candidate = Path(candidate)
    manifest_path = candidate / "manifest.json"
    if manifest_path.is_symlink() or not manifest_path.is_file():
        raise PublicationError("Candidate manifest is missing or is a symlink")
    if manifest_path.stat().st_size > MAX_ARTIFACT_BYTES:
        raise PublicationError("Artifact exceeds 95 MiB publication limit: manifest.json")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("schema") != 1 or manifest.get("format_version") != 1:
        raise PublicationError("Unsupported publication manifest")
    _version(manifest.get("data_version", manifest.get("version")))
    files = manifest.get("files")
    if not isinstance(files, list) or not files:
        raise PublicationError("Candidate has no files")
    inventory = {"manifest.json"}
    checked = []
    for record in files:
        name = record.get("path")
        if not isinstance(name, str):
            raise PublicationError("Invalid candidate file path")
        relative = PurePosixPath(name)
        if (relative.is_absolute() or ".." in relative.parts or "\\" in name
                or str(relative) != name or name in inventory or name.startswith(".")
                or any(p.startswith(".") for p in relative.parts)):
            raise PublicationError("Unsafe or duplicate candidate file path")
        inventory.add(name)
        path = candidate / name
        if any(parent.is_symlink() for parent in [path, *path.parents] if parent != candidate.parent):
            raise PublicationError("Candidate file symlink is forbidden")
        if not path.is_file():
            raise PublicationError("Candidate file length mismatch: " + name)
        size = path.stat().st_size
        if size > MAX_ARTIFACT_BYTES:
            raise PublicationError("Artifact exceeds 95 MiB publication limit: " + name)
        if size != record.get("bytes"):
            raise PublicationError("Candidate file length mismatch: " + name)
        checked.append((path, record))
    actual = {str(p.relative_to(candidate)) for p in candidate.rglob("*") if p.is_file() or p.is_symlink()}
    if actual != inventory:
        raise PublicationError("Candidate contains unlisted files")
    # Reject all oversized/missing/unlisted files before reading any large
    # payload or touching Git. Limits apply to reports as well as Geo/ASN.
    for path, record in checked:
        if _digest(path) != record.get("sha256"):
            raise PublicationError("Candidate file checksum mismatch: " + record["path"])
    return manifest


def _semantic_validation(candidate: Path) -> None:
    from .validation import validate_candidate as validate_data
    try:
        validate_data(candidate)
    except (ValueError, KeyError, OSError) as exc:
        raise PublicationError("Candidate failed AirRoute data validation: " + str(exc)) from exc


def prepare_baseline(repo: Path, output: Path, *, remote: str = "origin", branch: str = "release") -> bool:
    """Read only the previous public manifest for coverage comparison."""
    repo, output = Path(repo).resolve(), Path(output)
    tracking = "refs/remotes/airroute/baseline"
    try:
        if _remote_sha(repo, remote, branch) is None:
            return False
        _git(repo, "fetch", "--no-tags", remote, "+refs/heads/" + branch + ":" + tracking)
    except PublicationUncertain:
        # The historical comparison is optional. Source acquisition and actual
        # publication retain their own strict transport/error boundaries.
        return False
    except PublicationError as error:
        if str(error) != "Git operation failed: fetch":
            raise
        return False
    flat = _git(repo, "show", tracking + ":manifest.json", allow_failure=True)
    if flat.returncode == 0:
        raw = flat.stdout.encode("utf-8")
        if json.loads(raw).get("layout") != "flat-v1":
            raise PublicationError("Unsupported release layout")
    else:
        pointer_result = _git(repo, "show", tracking + ":current.json", allow_failure=True)
        if pointer_result.returncode:
            # An existing target can still predate the producer manifest.
            # Comparison is optional; do not invent a different-repository base.
            return False
        pointer = json.loads(pointer_result.stdout)
        version = _version(pointer.get("data_version"))
        path = "versions/" + version + "/manifest.json"
        if pointer.get("manifest") != path:
            raise PublicationError("Previous release has an unsafe manifest pointer")
        raw = _git(repo, "show", tracking + ":" + path).stdout.encode("utf-8")
        if hashlib.sha256(raw).hexdigest() != pointer.get("manifest_sha256"):
            raise PublicationError("Previous release manifest digest mismatch")
        if json.loads(raw).get("data_version") != version:
            raise PublicationError("Previous release version mismatch")
    output.mkdir(parents=True, exist_ok=True)
    (output / "manifest.json").write_bytes(raw)
    # Comparisons explain semantic changes; they never gate on previous counts.
    # Retain actual previous predicates, not vendor archives or reports.
    previous = json.loads(raw)
    prefix = "" if flat.returncode == 0 else path.rsplit("/", 1)[0] + "/"
    from .validation import safe_file
    for record in previous["files"]:
        if record["path"].endswith(".list"):
            target = safe_file(output, record["path"])
            data = _git(repo, "show", tracking + ":" + prefix + record["path"]).stdout.encode("utf-8")
            if len(data) != record["bytes"] or hashlib.sha256(data).hexdigest() != record["sha256"]:
                raise PublicationError("Previous product checksum mismatch")
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
    return True


def _remote_sha(repo: Path, remote: str, branch: str) -> str | None:
    _git(repo, "check-ref-format", "refs/heads/" + branch)
    result = _git(repo, "ls-remote", "--exit-code", remote, "refs/heads/" + branch, allow_failure=True)
    if result.returncode == 2:
        return None
    if result.returncode:
        raise PublicationUncertain("Cannot read remote branch; publication remains unresolved")
    lines = result.stdout.splitlines()
    if len(lines) != 1 or not re.fullmatch(r"[0-9a-f]{40,64}\s+refs/heads/" + re.escape(branch), lines[0]):
        raise PublicationError("Malformed remote ref response")
    return lines[0].split()[0]


def _fetch(worker: Path, branch: str) -> str:
    # Forced update is local tracking only, never a force push.
    _git(worker, "fetch", "--no-tags", "origin", "+refs/heads/" + branch + ":refs/remotes/origin/" + branch)
    return _git(worker, "rev-parse", "refs/remotes/origin/" + branch).stdout.strip()


def _credential_config(repo: Path, worker: Path) -> None:
    # checkout's scoped HTTP header is not inherited by a new worktree. Copy it
    # into a private, short-lived local config; never print it or add it to Git.
    result = _git(repo, "config", "--get-regexp", r"^http\..*\.extraheader$", allow_failure=True)
    if result.returncode not in (0, 1):
        raise PublicationError("Cannot read scoped Git transport configuration")
    for line in result.stdout.splitlines():
        key, value = line.split(" ", 1)
        _git(worker, "config", "--local", key, value)


def _state_root(repo: Path, remote: str, branch: str) -> Path:
    git_dir = Path(_git(repo, "rev-parse", "--absolute-git-dir").stdout.strip())
    key = hashlib.sha256((remote + "\0" + branch).encode()).hexdigest()[:16]
    return git_dir / "airroute-publish" / key


@contextlib.contextmanager
def _lock(root: Path):
    # Advisory lock is process scoped and released after crashes. Actions and
    # supported local execution run on Linux/macOS; no daemon or database.
    import fcntl
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    with (root / "lock").open("a") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        yield


def _finish(root: Path, state: dict, status: str, remote_sha: str | None) -> dict:
    result = {"status": status, "version": state["version"], "commit": state["commit"],
              "remote_commit": remote_sha, "source_sha": state["source_sha"],
              "publication": state["publication"]}
    _json_write(root / "last.json", result)
    (root / "pending.json").unlink(missing_ok=True)
    if (root / "work").exists():
        shutil.rmtree(root / "work")
    return result


def _reconcile(repo: Path, remote: str, branch: str, root: Path, state: dict) -> dict | None:
    observed = _remote_sha(repo, remote, branch)
    if observed == state["commit"]:
        return _finish(root, state, "published", observed)
    if observed and observed != state["base_commit"]:
        worker = root / "work"
        _fetch(worker, branch)
        ancestor = _git(worker, "merge-base", "--is-ancestor", state["commit"], observed, allow_failure=True)
        if ancestor.returncode == 0:
            return _finish(root, state, "published", observed)
        if ancestor.returncode != 1:
            raise PublicationUncertain("Unable to reconcile the recorded publication commit")
        return _finish(root, state, "superseded", observed)
    return None


def _push_recorded(repo: Path, remote: str, branch: str, source_branch: str,
                   root: Path, state: dict, trace=None) -> dict:
    if trace is not None: trace.stage('publication-reconcile', 'started', commit=state['commit'], target_branch=branch)
    reconciled = _reconcile(repo, remote, branch, root, state)
    if reconciled:
        if trace is not None: trace.stage('publication-reconcile', reconciled['status'], commit=state['commit'], remote_commit=reconciled.get('remote_commit'))
        return reconciled
    # Retry the recorded attempt against its original source fence, even if a
    # caller now supplies a different source remote. Old journals predate the
    # split and used the publication remote for both responsibilities.
    latest = _remote_sha(repo, state.get("source_remote", remote), state.get("source_branch", source_branch))
    if latest != state["source_sha"]:
        return _finish(root, state, "superseded", state["base_commit"])
    worker = root / "work"
    _credential_config(repo, worker)
    state["status"] = "pushing"
    _json_write(root / "pending.json", state)
    if trace is not None: trace.stage('publication-push', 'started', commit=state['commit'], base_commit=state['base_commit'])
    try:
        _git(worker, "push", "origin", state["commit"] + ":refs/heads/" + branch, allow_failure=True)
    except PublicationUncertain:
        pass
    # Even a reported success is independently read back. On timeout/rejection
    # retain the original commit and working copy; never rebase/recreate it.
    reconciled = _reconcile(repo, remote, branch, root, state)
    if reconciled:
        if trace is not None: trace.stage('publication-push', reconciled['status'], commit=state['commit'], remote_commit=reconciled.get('remote_commit'))
        return reconciled
    if trace is not None: trace.stage('publication-push', 'unconfirmed', commit=state['commit'], journal='pending.json')
    raise PublicationUncertain("Remote has not confirmed the recorded commit; retry the same candidate")


def publish(candidate: Path, repo: Path, source_sha: str, *, sequence: int, attempt: int = 1,
            remote: str = "origin",
            branch: str = "release", source_branch: str = "main", source_remote: str | None = None,
            replace_legacy_head: str | None = None, trace=None) -> dict:
    candidate, repo = Path(candidate).resolve(), Path(repo).resolve()
    order = _publication_order(sequence, attempt)
    source_remote = remote if source_remote is None else source_remote
    if replace_legacy_head is not None and not re.fullmatch(r"[0-9a-f]{40,64}", replace_legacy_head):
        raise PublicationError("Legacy replacement requires the exact expected target commit SHA")
    if trace is not None: trace.stage('publication-validation', 'started', source_commit=source_sha, target_branch=branch)
    manifest = validate_candidate(candidate)
    if trace is not None:
        trace.state['source_commit'] = source_sha
        trace.state['sources'] = manifest.get('source_snapshot', [])
        trace.manifest(manifest)
        trace.stage('publication-validation', 'passed', data_version=manifest.get('data_version'))
    version = _version(manifest.get("data_version", manifest.get("version")))
    manifest_sha = _digest(candidate / "manifest.json")
    root = _state_root(repo, remote, branch)
    with _lock(root):
        pending = root / "pending.json"
        if pending.exists():
            state = json.loads(pending.read_text())
            resolved = _reconcile(repo, remote, branch, root, state)
            if not resolved:
                if state["manifest_sha256"] != manifest_sha or state["source_sha"] != source_sha:
                    # An obsolete source can be discarded only after readback
                    # proves the remote has not advanced to its commit.
                    if _remote_sha(repo, state.get("source_remote", remote), state.get("source_branch", source_branch)) != state["source_sha"]:
                        _finish(root, state, "superseded", _remote_sha(repo, remote, branch))
                    else:
                        raise PublicationUncertain("Another candidate has an unresolved publication; reconcile it first")
                else:
                    return _push_recorded(repo, remote, branch, source_branch, root, state, trace=trace)
            elif resolved["version"] == version and resolved["status"] == "published":
                return resolved
        if _remote_sha(repo, source_remote, source_branch) != source_sha:
            raise PublicationError("Source main advanced; refusing an obsolete build")
        worker = root / "work"
        if worker.exists():
            shutil.rmtree(worker)
        worker.mkdir()
        _git(worker, "init", "--quiet")
        url = _git(repo, "remote", "get-url", remote).stdout.strip()
        _git(worker, "remote", "add", "origin", url)
        _credential_config(repo, worker)
        base = _remote_sha(repo, remote, branch)
        if trace is not None: trace.stage('publication-fetch', 'started', target_base_commit=base, source_commit=source_sha)
        if base:
            fetched = _fetch(worker, branch)
            if fetched != base:
                raise PublicationError("Release changed during preparation; retry a fresh build")
            _git(worker, "checkout", "--quiet", "--detach", base)
        else:
            _git(worker, "checkout", "--quiet", "--orphan", "candidate")
        public = _public_manifest(manifest)
        public["publication"] = {"sequence": sequence, "attempt": attempt, "source_sha": source_sha}
        previous = None
        if base:
            has_layout = any((worker / name).exists() or (worker / name).is_symlink()
                             for name in ("manifest.json", "current.json"))
            if has_layout:
                previous, _ = _read_release(worker)
            elif replace_legacy_head != base:
                raise PublicationError("Target has no AirRoute manifest; explicit matching legacy head is required")
            # An explicitly named legacy commit stays in Git history. Only the
            # checked-out payload changes; the normal forward push is retained.
        # Revalidate structural/semantic contracts, never historical quantities.
        # The fetched baseline is retained for publication ordering only.
        if trace is not None: trace.stage('publication-semantic-validation', 'started')
        _semantic_validation(candidate)
        if trace is not None: trace.stage('publication-semantic-validation', 'passed', target_base_commit=base)
        if previous is not None:
            # Historical private reports are not published identity. Preserve
            # all historical client files for collision detection, including
            # retired paths; only the incoming tree uses today's whitelist.
            old_public = {**previous, "layout": "flat-v1", "files": [
                record for record in previous["files"]
                if record["path"].endswith((".list", ".ardb")) or
                record["path"] in {"regions.json", "ATTRIBUTION.md"}]}
            if (old_public["data_version"] == version and
                    not _same_data(old_public, public)):
                raise PublicationError("Immutable data version collision")
            expected_paths = {r["path"] for r in public["files"]} | {"manifest.json"}
            actual_paths = {p.relative_to(worker).as_posix() for p in worker.rglob("*")
                            if ".git" not in p.relative_to(worker).parts and (p.is_file() or p.is_symlink())}
            if (previous.get("layout") == "flat-v1" and _same_data(previous, public)
                    and actual_paths == expected_paths):
                for record in public["files"]:
                    path = worker / record["path"]
                    if (any(p.is_symlink() for p in (path, path.parent)) or
                            path.stat().st_size != record["bytes"] or _digest(path) != record["sha256"]):
                        raise PublicationError("Existing release file checksum mismatch")
                shutil.rmtree(worker)
                return {"status": "unchanged", "version": version, "commit": base,
                        "remote_commit": base, "publication": previous["publication"]}
            _check_order(previous, order)
        _replace_release(worker, candidate, public)
        _git(worker, "add", "--all")
        _git(worker, "commit", "--quiet", "-m", "Publish AirRoute data " + version)
        commit = _git(worker, "rev-parse", "HEAD").stdout.strip()
        state = {"schema": 1, "version": version, "manifest_sha256": manifest_sha,
                 "source_sha": source_sha, "base_commit": base, "commit": commit,
                 "source_remote": source_remote, "source_branch": source_branch,
                 "status": "prepared", "publication": public["publication"]}
        _json_write(pending, state)
        if trace is not None: trace.stage('publication-prepared', 'completed', commit=commit, base_commit=base, data_version=version)
        return _push_recorded(repo, remote, branch, source_branch, root, state, trace=trace)


def rollback(repo: Path, version: str, source_sha: str, *, sequence: int, attempt: int = 1,
             remote: str = "origin",
             branch: str = "release", source_branch: str = "main", source_remote: str | None = None) -> dict:
    """Restore historical data as a normal forward flat-layout commit."""
    repo = Path(repo).resolve()
    order = _publication_order(sequence, attempt)
    source_remote = remote if source_remote is None else source_remote
    version = _version(version)
    root = _state_root(repo, remote, branch)
    with _lock(root):
        if (root / "pending.json").exists():
            raise PublicationUncertain("Reconcile the pending publication before rollback")
        if _remote_sha(repo, source_remote, source_branch) != source_sha:
            raise PublicationError("Source main advanced; refusing stale rollback")
        worker = root / "work"
        if worker.exists():
            shutil.rmtree(worker)
        worker.mkdir()
        _git(worker, "init", "--quiet")
        _git(worker, "remote", "add", "origin", _git(repo, "remote", "get-url", remote).stdout.strip())
        _credential_config(repo, worker)
        base = _fetch(worker, branch)
        _git(worker, "checkout", "--quiet", "--detach", base)
        previous, _ = _read_release(worker)
        if previous["data_version"] == version:
            shutil.rmtree(worker)
            return {"status": "unchanged", "version": version, "commit": base,
                    "remote_commit": base, "publication": previous["publication"]}
        _check_order(previous, order)
        # Versions live in Git history, never duplicated in the release tree.
        # Inspect metadata without repeatedly checking out large payloads.
        target = None
        for commit in _git(worker, "rev-list", base).stdout.splitlines():
            result = _git(worker, "show", commit + ":manifest.json", allow_failure=True)
            if result.returncode == 0:
                historical = json.loads(result.stdout)
                if historical.get("data_version") == version:
                    target = commit
                    break
            else:
                result = _git(worker, "show", commit + ":versions/" + version + "/manifest.json", allow_failure=True)
                if result.returncode == 0:
                    target = commit
                    break
        if target is None:
            raise PublicationError("Requested version is absent from release history")
        _git(worker, "checkout", "--quiet", "--detach", target)
        historical, directory = _read_release(worker)
        if historical["data_version"] != version:
            # Old layout commits may retain the requested version alongside a
            # different current pointer. Read only its explicitly named folder.
            directory = worker / "versions" / version
            if directory.is_symlink() or directory.parent.is_symlink():
                raise PublicationError("Historical release contains a symlink")
            historical = json.loads((directory / "manifest.json").read_text())
        public = _public_manifest(historical)
        public["publication"] = {"sequence": sequence, "attempt": attempt, "source_sha": source_sha}
        with tempfile.TemporaryDirectory(dir=root) as temporary:
            staged = Path(temporary)
            for record in public["files"]:
                path = staged / record["path"]
                path.parent.mkdir(parents=True, exist_ok=True)
                source = directory / record["path"]
                if any(p.is_symlink() for p in (source, source.parent)):
                    raise PublicationError("Historical release contains a symlink")
                shutil.copyfile(source, path)
            _json_write(staged / "manifest.json", public)
            validate_candidate(staged)
            _semantic_validation(staged)
            _git(worker, "checkout", "--quiet", "--detach", base)
            _replace_release(worker, staged, public)
        _git(worker, "add", "--all")
        _git(worker, "commit", "--quiet", "-m", "Roll back AirRoute data to " + version)
        state = {"schema": 1, "version": version, "manifest_sha256": _digest(worker / "manifest.json"),
                 "source_sha": source_sha, "base_commit": base,
                 "source_remote": source_remote, "source_branch": source_branch,
                 "commit": _git(worker, "rev-parse", "HEAD").stdout.strip(), "status": "prepared",
                 "publication": public["publication"]}
        _json_write(root / "pending.json", state)
        return _push_recorded(repo, remote, branch, source_branch, root, state)

"""Atomic, non-force publication to a branch of the source repository.

The complete candidate and the current pointer enter one Git commit. A durable
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
from typing import Any


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
    return all(left.get(key) == right.get(key) for key in
               ("data_version", "manifest", "manifest_sha256"))


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
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("schema") != 1 or manifest.get("format_version") != 1:
        raise PublicationError("Unsupported publication manifest")
    _version(manifest.get("data_version", manifest.get("version")))
    files = manifest.get("files")
    if not isinstance(files, list) or not files:
        raise PublicationError("Candidate has no files")
    inventory = {"manifest.json"}
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
        if not path.is_file() or path.stat().st_size != record.get("bytes"):
            raise PublicationError("Candidate file length mismatch: " + name)
        if _digest(path) != record.get("sha256"):
            raise PublicationError("Candidate file checksum mismatch: " + name)
    actual = {str(p.relative_to(candidate)) for p in candidate.rglob("*") if p.is_file() or p.is_symlink()}
    if actual != inventory:
        raise PublicationError("Candidate contains unlisted files")
    return manifest


def _semantic_validation(candidate: Path, repo: Path, baseline: Path | None = None) -> None:
    from .validation import validate_candidate as validate_data
    policy_path = repo / "config" / "quality.json"
    policy = json.loads(policy_path.read_text()) if policy_path.exists() else None
    try:
        validate_data(candidate, baseline=baseline, quality=policy)
    except (ValueError, KeyError, OSError) as exc:
        raise PublicationError("Candidate failed AirRoute data validation: " + str(exc)) from exc


def prepare_baseline(repo: Path, output: Path, *, remote: str = "origin", branch: str = "release") -> bool:
    """Read only the previous public manifest for coverage comparison."""
    repo, output = Path(repo).resolve(), Path(output)
    if _remote_sha(repo, remote, branch) is None:
        return False
    tracking = "refs/remotes/airroute/baseline"
    _git(repo, "fetch", "--no-tags", remote, "+refs/heads/" + branch + ":" + tracking)
    pointer = json.loads(_git(repo, "show", tracking + ":current.json").stdout)
    version = _version(pointer.get("data_version"))
    path = "versions/" + version + "/manifest.json"
    if pointer.get("manifest") != path:
        raise PublicationError("Previous release has an unsafe manifest pointer")
    raw = _git(repo, "show", tracking + ":" + path).stdout.encode("utf-8")
    if hashlib.sha256(raw).hexdigest() != pointer.get("manifest_sha256"):
        raise PublicationError("Previous release manifest digest mismatch")
    previous = json.loads(raw)
    if previous.get("data_version") != version:
        raise PublicationError("Previous release version mismatch")
    output.mkdir(parents=True, exist_ok=True)
    (output / "manifest.json").write_bytes(raw)
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
                   root: Path, state: dict) -> dict:
    reconciled = _reconcile(repo, remote, branch, root, state)
    if reconciled:
        return reconciled
    latest = _remote_sha(repo, remote, source_branch)
    if latest != state["source_sha"]:
        return _finish(root, state, "superseded", state["base_commit"])
    worker = root / "work"
    _credential_config(repo, worker)
    state["status"] = "pushing"
    _json_write(root / "pending.json", state)
    try:
        _git(worker, "push", "origin", state["commit"] + ":refs/heads/" + branch, allow_failure=True)
    except PublicationUncertain:
        pass
    # Even a reported success is independently read back. On timeout/rejection
    # retain the original commit and working copy; never rebase/recreate it.
    reconciled = _reconcile(repo, remote, branch, root, state)
    if reconciled:
        return reconciled
    raise PublicationUncertain("Remote has not confirmed the recorded commit; retry the same candidate")


def publish(candidate: Path, repo: Path, source_sha: str, *, sequence: int, attempt: int = 1,
            remote: str = "origin",
            branch: str = "release", source_branch: str = "main") -> dict:
    candidate, repo = Path(candidate).resolve(), Path(repo).resolve()
    order = _publication_order(sequence, attempt)
    manifest = validate_candidate(candidate)
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
                    if _remote_sha(repo, remote, source_branch) != state["source_sha"]:
                        _finish(root, state, "superseded", _remote_sha(repo, remote, branch))
                    else:
                        raise PublicationUncertain("Another candidate has an unresolved publication; reconcile it first")
                else:
                    return _push_recorded(repo, remote, branch, source_branch, root, state)
            elif resolved["version"] == version and resolved["status"] == "published":
                return resolved
        if _remote_sha(repo, remote, source_branch) != source_sha:
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
        if base:
            fetched = _fetch(worker, branch)
            if fetched != base:
                raise PublicationError("Release changed during preparation; retry a fresh build")
            _git(worker, "checkout", "--quiet", "--detach", base)
        else:
            _git(worker, "checkout", "--quiet", "--orphan", "candidate")
        pointer = {"schema": 1, "data_version": version,
                   "manifest": "versions/" + version + "/manifest.json",
                   "manifest_sha256": manifest_sha,
                   "publication": {"sequence": sequence, "attempt": attempt, "source_sha": source_sha}}
        current = worker / "current.json"
        version_dir = worker / "versions" / version
        if (worker / "versions").is_symlink() or current.is_symlink() or version_dir.is_symlink():
            raise PublicationError("Release layout contains a symlink")
        baseline = None
        if current.exists():
            old_pointer = json.loads(current.read_text())
            old_version = _version(old_pointer.get("data_version"))
            old_dir = worker / "versions" / old_version
            if old_dir.is_symlink() or (old_dir / "manifest.json").is_symlink():
                raise PublicationError("Previous release contains a symlink")
            if old_pointer.get("manifest") != "versions/" + old_version + "/manifest.json":
                raise PublicationError("Unsafe previous release pointer")
            if _digest(old_dir / "manifest.json") != old_pointer.get("manifest_sha256"):
                raise PublicationError("Previous release manifest digest mismatch")
            baseline = old_dir
        # The inventory above fences pending recovery by exact hashes. A new
        # candidate receives one complete semantic check here, with the freshly
        # fetched baseline; doing it before fetching as well duplicates all
        # binary/list decoding without adding a trust boundary.
        _semantic_validation(candidate, repo, baseline)
        if version_dir.exists():
            if not (version_dir / "manifest.json").is_file() or _digest(version_dir / "manifest.json") != manifest_sha:
                raise PublicationError("Immutable version collision")
            validate_candidate(version_dir)
        else:
            version_dir.parent.mkdir(exist_ok=True)
            shutil.copytree(candidate, version_dir)
        if current.exists():
            previous = json.loads(current.read_text())
            if _same_data(previous, pointer):
                shutil.rmtree(worker)
                return {"status": "unchanged", "version": version, "commit": base,
                        "remote_commit": base, "publication": previous["publication"]}
            _check_order(previous, order)
        _json_write(current, pointer)
        (worker / "README.md").write_text(
            "# AirRoute generated data\n\nRead current.json once, then fetch its immutable version directory. "
            "Verify manifest and file SHA-256 values before use. Source code is on main.\n", encoding="utf-8")
        _git(worker, "add", "--", "current.json", "README.md", "versions/" + version)
        _git(worker, "commit", "--quiet", "-m", "Publish AirRoute data " + version)
        commit = _git(worker, "rev-parse", "HEAD").stdout.strip()
        state = {"schema": 1, "version": version, "manifest_sha256": manifest_sha,
                 "source_sha": source_sha, "base_commit": base, "commit": commit,
                 "status": "prepared", "publication": pointer["publication"]}
        _json_write(pending, state)
        return _push_recorded(repo, remote, branch, source_branch, root, state)


def rollback(repo: Path, version: str, source_sha: str, *, sequence: int, attempt: int = 1,
             remote: str = "origin",
             branch: str = "release", source_branch: str = "main") -> dict:
    """Make a normal forward commit that points to an existing immutable version."""
    repo = Path(repo).resolve()
    order = _publication_order(sequence, attempt)
    version = _version(version)
    root = _state_root(repo, remote, branch)
    with _lock(root):
        if (root / "pending.json").exists():
            raise PublicationUncertain("Reconcile the pending publication before rollback")
        if _remote_sha(repo, remote, source_branch) != source_sha:
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
        version_dir = worker / "versions" / version
        if (worker / "versions").is_symlink() or (worker / "current.json").is_symlink() or version_dir.is_symlink():
            raise PublicationError("Release layout contains a symlink")
        manifest = validate_candidate(version_dir)
        _semantic_validation(version_dir, repo)
        if manifest.get("data_version", manifest.get("version")) != version:
            raise PublicationError("Version directory does not match its manifest")
        manifest_sha = _digest(version_dir / "manifest.json")
        pointer = {"schema": 1, "data_version": version,
                   "manifest": "versions/" + version + "/manifest.json", "manifest_sha256": manifest_sha,
                   "publication": {"sequence": sequence, "attempt": attempt, "source_sha": source_sha}}
        previous = json.loads((worker / "current.json").read_text())
        if _same_data(previous, pointer):
            shutil.rmtree(worker)
            return {"status": "unchanged", "version": version, "commit": base,
                    "remote_commit": base, "publication": previous["publication"]}
        _check_order(previous, order)
        _json_write(worker / "current.json", pointer)
        _git(worker, "add", "--", "current.json")
        _git(worker, "commit", "--quiet", "-m", "Roll back AirRoute data to " + version)
        state = {"schema": 1, "version": version, "manifest_sha256": manifest_sha,
                 "source_sha": source_sha, "base_commit": base,
                 "commit": _git(worker, "rev-parse", "HEAD").stdout.strip(), "status": "prepared",
                 "publication": pointer["publication"]}
        _json_write(root / "pending.json", state)
        return _push_recorded(repo, remote, branch, source_branch, root, state)

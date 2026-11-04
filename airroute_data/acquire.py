"""Fixed public dataset snapshots, never target measurements (stdlib only)."""
from __future__ import annotations

import base64
import bz2
import datetime as dt
import gzip
import hashlib
import html
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import tarfile
from typing import Any, Iterable
import urllib.error
import urllib.parse
import urllib.request
import zipfile

CHUNK = 1024 * 1024
DEFAULT_LIMIT = 1536 * 1024 * 1024
EXTRACT_LIMIT = 8 * 1024 * 1024 * 1024
USER_AGENT = "AirRoute-data-builder/2 (+https://github.com/airrelay/airroute-rules)"


class AcquisitionError(ValueError):
    """Safe error text without request URLs or environment credential values."""


def _origin(url):
    value = urllib.parse.urlsplit(url)
    return value.scheme, value.hostname, value.port


class SafeRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if urllib.parse.urlsplit(newurl).scheme != "https":
            raise AcquisitionError("download redirected to a non-HTTPS endpoint")
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new is not None and _origin(req.full_url) != _origin(newurl):
            for key in list(new.headers):
                if key.lower() in {"authorization", "cookie", "proxy-authorization"}:
                    del new.headers[key]
        return new


def _safe_url(url):
    p = urllib.parse.urlsplit(url)
    return urllib.parse.urlunsplit((p.scheme, p.hostname or "", p.path, "", ""))


def _expand(value, now):
    value = value.replace("{YYYY-MM}", now.strftime("%Y-%m")).replace("{YYYY.MM}", now.strftime("%Y.%m"))
    def replace(match):
        env_value = os.environ.get(match.group(1))
        if not env_value:
            raise AcquisitionError("required environment credential is absent")
        return urllib.parse.quote(env_value, safe="")
    return re.sub(r"\{env:([A-Z][A-Z0-9_]*)\}", replace, value)


def _request(url, headers=None):
    if urllib.parse.urlsplit(url).scheme != "https":
        raise AcquisitionError("only HTTPS dataset downloads are allowed")
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, **(headers or {})})
    try:
        return urllib.request.build_opener(SafeRedirect()).open(req, timeout=90)
    except urllib.error.HTTPError as exc:
        raise AcquisitionError(f"HTTP {exc.code}") from None
    except AcquisitionError:
        raise
    except Exception:
        raise AcquisitionError("dataset connection or transfer failed") from None


def _stream_copy(source, target, limit):
    digest = hashlib.sha256(); size = 0
    while True:
        block = source.read(CHUNK)
        if not block:
            break
        size += len(block)
        if size > limit:
            raise AcquisitionError("dataset exceeds configured byte limit")
        digest.update(block); target.write(block)
    return digest.hexdigest(), size


def _download(url, target, headers, limit):
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_name(target.name + ".part")
    try:
        with _request(url, headers) as response, tmp.open("wb") as output:
            declared_length = response.headers.get("Content-Length")
            if declared_length is not None:
                if not str(declared_length).isdecimal() or int(declared_length) > limit:
                    raise AcquisitionError("invalid or oversized dataset Content-Length")
                declared_length = int(declared_length)
            digest, size = _stream_copy(response, output, limit)
            if declared_length is not None and size != declared_length:
                raise AcquisitionError("dataset transfer length mismatch")
            metadata = {"url": _safe_url(url), "sha256": digest, "bytes": size,
                        "etag": response.headers.get("ETag", ""),
                        "last_modified": response.headers.get("Last-Modified", "")}
        tmp.replace(target)
        return metadata
    except AcquisitionError:
        raise
    except Exception:
        raise AcquisitionError("dataset transfer failed") from None
    finally:
        tmp.unlink(missing_ok=True)


def _unpack_source(archive, output, source, *, compression, strip_root=False):
    """Report archive failures without exposing a provider's response body."""
    try:
        return unpack(archive, output, compression=compression, strip_root=strip_root)
    except (zipfile.BadZipFile, gzip.BadGzipFile, tarfile.ReadError, EOFError) as error:
        # IP2Location documents textual permission/quota errors returned by its
        # download endpoint. Classify only these fixed markers, never log text.
        if source.get("format") == "ip2location-db1-csv" and compression == "zip":
            with Path(archive).open("rb") as stream:
                prefix = stream.read(8192).lower()
            if not prefix.startswith(b"pk"):
                if any(marker in prefix for marker in (b"5 times", b"download limit", b"download quota", b"quota exceeded")):
                    raise AcquisitionError("provider download quota exceeded; response is not a ZIP archive") from None
                if b"no permission" in prefix or b"nopermission" in prefix:
                    raise AcquisitionError("provider rejected download permission; response is not a ZIP archive") from None
        raise AcquisitionError("archive preparation failed (" + type(error).__name__ + ")") from None


def _member_path(name):
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts or "\\" in name or not path.parts:
        raise AcquisitionError("unsafe archive member path")
    return path


def unpack(archive, output, *, compression, strip_root=False,
           max_bytes=EXTRACT_LIMIT, max_files=100000):
    """Bounded streaming extraction; reject links, special files and traversal."""
    archive, output = Path(archive), Path(output)
    output.mkdir(parents=True, exist_ok=True)
    total = 0; count = 0
    def write(name, stream):
        nonlocal total, count
        relative = _member_path(name)
        if strip_root:
            relative = PurePosixPath(*relative.parts[1:])
        if not relative.parts or str(relative) == ".":
            return
        count += 1
        if count > max_files:
            raise AcquisitionError("archive has too many members")
        destination = output.joinpath(*relative.parts)
        destination.parent.mkdir(parents=True, exist_ok=True)
        with destination.open("xb") as target:
            _, size = _stream_copy(stream, target, max_bytes - total)
        total += size
    if compression == "zip":
        with zipfile.ZipFile(archive) as bundle:
            for member in bundle.infolist():
                _member_path(member.filename)
                if member.is_dir():
                    continue
                if (member.external_attr >> 16) & 0o170000 == 0o120000:
                    raise AcquisitionError("archive links are forbidden")
                if member.file_size > max_bytes - total:
                    raise AcquisitionError("archive exceeds expanded byte limit")
                with bundle.open(member) as stream:
                    write(member.filename, stream)
    elif compression in {"tar.gz", "tgz", "tar"}:
        with tarfile.open(archive, mode="r|*") as bundle:
            for member in bundle:
                _member_path(member.name)
                if member.isdir():
                    continue
                if not member.isfile():
                    raise AcquisitionError("archive special files and links are forbidden")
                if member.size > max_bytes - total:
                    raise AcquisitionError("archive exceeds expanded byte limit")
                stream = bundle.extractfile(member)
                if stream is None:
                    raise AcquisitionError("archive member is unreadable")
                with stream:
                    write(member.name, stream)
    elif compression in {"gzip", "bzip2"}:
        filename = archive.name.removesuffix(".gz").removesuffix(".bz2")
        with (gzip.open if compression == "gzip" else bz2.open)(archive, "rb") as stream:
            write(filename, stream)
    else:
        raise AcquisitionError("unsupported source compression")
    return output


def tree_digest(path, on_file=None):
    """Hash member names and content, independent of filesystem timestamps."""
    path = Path(path)
    if not path.exists() or path.is_symlink():
        raise AcquisitionError("fixed input is absent or a symlink")
    digest = hashlib.sha256(); total = 0
    if path.is_dir() and any(p.is_symlink() for p in path.rglob("*")):
        raise AcquisitionError("input symlinks are forbidden")
    files = [path] if path.is_file() else sorted(p for p in path.rglob("*") if p.is_file())
    for item in files:
        relative = item.name if path.is_file() else item.relative_to(path).as_posix()
        data_digest = hashlib.sha256(); size = 0
        with item.open("rb") as source:
            while block := source.read(CHUNK):
                data_digest.update(block); size += len(block)
        total += size
        digest.update(relative.encode()); digest.update(b"\0")
        digest.update(str(size).encode()); digest.update(b"\0"); digest.update(data_digest.digest())
        if on_file is not None: on_file(relative, size, data_digest.hexdigest())
    return digest.hexdigest(), total


def _github_commit(repo, ref, cache):
    if re.fullmatch(r"[0-9a-f]{40}", ref):
        return ref
    key = repo, ref
    if key not in cache:
        url = f"https://api.github.com/repos/{repo}/commits/{urllib.parse.quote(ref, safe='')}"
        headers = {"Accept": "application/vnd.github+json"}
        if os.environ.get("GITHUB_TOKEN"):
            headers["Authorization"] = "Bearer " + os.environ["GITHUB_TOKEN"]
        with _request(url, headers) as response:
            data = response.read(1024 * 1024 + 1)
        if len(data) > 1024 * 1024:
            raise AcquisitionError("GitHub commit metadata exceeds limit")
        try:
            sha = json.loads(data)["sha"]
        except Exception:
            raise AcquisitionError("invalid GitHub commit metadata") from None
        if not re.fullmatch(r"[0-9a-f]{40}", sha):
            raise AcquisitionError("invalid GitHub commit identity")
        cache[key] = sha
    return cache[key]


def _get_source(source, directory, now, commits):
    directory.mkdir(parents=True)
    headers = {}
    auth = source.get("auth", {})
    if "basic" in auth:
        values = [os.environ.get(key, "") for key in auth["basic"]]
        if not all(values):
            raise AcquisitionError("required environment credential is absent")
        headers["Authorization"] = "Basic " + base64.b64encode(":".join(values).encode()).decode()
    if source.get("github_api_token"):
        if _origin(source.get("url", "")) != ("https", "api.github.com", None):
            raise AcquisitionError("optional GitHub authentication requires its exact API origin")
        if token := os.environ.get("GITHUB_TOKEN"):
            headers["Authorization"] = "Bearer " + token
    if source.get("user_agent_env"):
        value = os.environ.get(source["user_agent_env"])
        if not value:
            raise AcquisitionError("identifying User-Agent environment variable is absent")
        headers["User-Agent"] = value
    transport = source.get("transport", "http")
    records = []; content = directory / "content"
    limit = source.get("max_download_bytes", DEFAULT_LIMIT)
    if transport.startswith("github"):
        repo, ref = source["repo"], source.get("ref", "main")
        if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo):
            raise AcquisitionError("invalid GitHub repository name")
        version = _github_commit(repo, ref, commits)
        if transport == "github_archive":
            url = f"https://codeload.github.com/{repo}/tar.gz/{version}"
            archive = directory / "download.tar.gz"
            records.append(_download(url, archive, headers, limit))
            _unpack_source(archive, content, source, compression="tar.gz", strip_root=True)
        else:
            paths = source.get("paths", [source.get("file")]); content.mkdir()
            for raw in paths:
                if not isinstance(raw, str):
                    raise AcquisitionError("GitHub file path is absent")
                relative = _member_path(raw)
                url = f"https://raw.githubusercontent.com/{repo}/{version}/{urllib.parse.quote(raw, safe='/')}"
                target = content.joinpath(*relative.parts)
                record = _download(url, target, headers, limit)
                with target.open("rb") as file:
                    prefix = file.read(160)
                if prefix.startswith(b"version https://git-lfs.github.com/spec/"):
                    url = f"https://media.githubusercontent.com/media/{repo}/{version}/{urllib.parse.quote(raw, safe='/')}"
                    record = _download(url, target, headers, limit)
                records.append(record)
            if source.get("compression"):
                if len(paths) != 1:
                    raise AcquisitionError("compressed GitHub source must select one archive")
                archive = content.joinpath(*_member_path(paths[0]).parts)
                _unpack_source(archive, directory / "expanded", source, compression=source["compression"])
                content = directory / "expanded"
            elif len(paths) == 1:
                content = content.joinpath(*_member_path(paths[0]).parts)
    else:
        urls = source.get("files", [{"url": source.get("url"), "name": source.get("filename", "input")}])
        content.mkdir()
        for ordinal, item in enumerate(urls):
            url = _expand(item["url"], now)
            if transport == "directory_latest":
                with _request(url, headers) as response:
                    index = response.read(4 * 1024 * 1024 + 1)
                if len(index) > 4 * 1024 * 1024:
                    raise AcquisitionError("dataset index exceeds limit")
                matches = sorted(set(re.findall(source["filename_regex"], index.decode("utf-8"))))
                if not matches:
                    raise AcquisitionError("no snapshot file in official index")
                url = urllib.parse.urljoin(url, html.unescape(matches[-1]))
            target = content.joinpath(*_member_path(item["name"]).parts)
            records.append(_download(url, target, headers, limit))
            compression = item.get("compression", source.get("compression"))
            if compression:
                # IPv4/IPv6 vendor ZIPs can both contain LICENSE/README. Keep
                # each archive isolated while exposing one recursive input root.
                subtree = f"{ordinal:03d}-{target.stem}" if len(urls) > 1 else ""
                _unpack_source(target, directory / "expanded" / subtree, source, compression=compression)
        if any(i.get("compression", source.get("compression")) for i in urls):
            content = directory / "expanded"
        elif len(urls) == 1:
            content = content / urls[0]["name"]
        version = source.get("version") or records[0].get("last_modified") or records[0]["sha256"]
    if source.get("payload_glob") and content.is_dir():
        candidates = sorted(content.rglob(source["payload_glob"]))
        if len(candidates) != 1 or not candidates[0].is_file():
            raise AcquisitionError("source must contain exactly one matching payload")
        content = candidates[0]
    checksum, size = tree_digest(content)
    return {"path": content, "sha256": checksum, "bytes": size, "version": version, "downloads": records}


def acquire_sources(config_path, output_dir, *, allow_network=True, fixture_dir=None,
                    now=None, source_ids: Iterable[str] | None = None, trace=None) -> dict[str, Any]:
    """Freeze participating inputs; fail at the first preparation failure.

    The partial snapshot records the original failure for diagnostics only and
    can never be consumed as a complete build input.
    """
    config_path, output_dir = Path(config_path), Path(output_dir)
    if output_dir.exists() and any(output_dir.iterdir()):
        raise AcquisitionError("snapshot output must be a new empty directory")
    config = json.loads(config_path.read_text())
    if config.get("schema") != 1 or not isinstance(config.get("sources"), list):
        raise AcquisitionError("unsupported source registry")
    sources = config["sources"]; ids = [s["id"] for s in sources]
    if len(set(ids)) != len(ids) or any(not re.fullmatch(r"[a-z0-9][a-z0-9_-]*", i) for i in ids):
        raise AcquisitionError("source identifiers must be safe and unique")
    requested = set(source_ids) if source_ids is not None else None
    if requested is not None and requested - set(ids):
        raise AcquisitionError("unknown requested source identifier")
    now = now or dt.datetime.now(dt.timezone.utc)
    timestamp = now.astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z")
    output_dir.mkdir(parents=True, exist_ok=True)
    result = {"schema": 1, "created_at": timestamp, "sources": []}; commits = {}
    def persist():
        output_dir.joinpath("snapshot.json").write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
        if trace is not None: trace.inputs(result, config_path.parent)

    def fail(entry):
        result["status"] = "failed"
        try:
            persist()
        except Exception:
            # A diagnostic write failure must not replace the source failure.
            pass
        raise AcquisitionError(f"{entry['id']}: {entry['status']}: {entry.get('error', 'required environment credential is absent')}")

    for source in sources:
        entry = {k: v for k, v in source.items() if k not in {"auth", "url", "files"}}
        entry["fetched_at"] = timestamp
        entry["source_url"] = source.get("documentation", source.get("homepage", ""))
        if requested is not None and source["id"] not in requested:
            entry["status"] = "not-selected"
        elif not source.get("enabled", True):
            entry["status"] = "disabled"
        else:
            entry["status"] = "pending"
        if entry["status"] != "pending":
            if trace is not None: trace.source_event(source['id'], 'acquisition', entry['status'])
            result["sources"].append(entry); continue
        missing = [key for key in source.get("requires_env", []) if not os.environ.get(key)]
        if missing and fixture_dir is None:
            entry.update(status="missing-credentials", missing_env=missing)
            if trace is not None: trace.source_event(source['id'], 'acquisition', 'missing-credentials', missing_env=missing)
            result["sources"].append(entry)
            fail(entry)
        directory = output_dir / "sources" / source["id"]
        try:
            if fixture_dir is not None:
                local = Path(fixture_dir) / source.get("fixture", source["id"])
                if not local.exists() or local.is_symlink():
                    raise AcquisitionError("fixture source is absent or a symlink")
                directory.mkdir(parents=True); content = directory / "content"
                if local.is_dir():
                    if any(p.is_symlink() for p in local.rglob("*")):
                        raise AcquisitionError("fixture source symlink is forbidden")
                    shutil.copytree(local, content)
                else:
                    shutil.copyfile(local, content)
                digest, size = tree_digest(content)
                data = {"path": content, "sha256": digest, "bytes": size, "version": "fixture-" + digest, "downloads": []}
            elif allow_network:
                data = _get_source(source, directory, now, commits)
            else:
                raise AcquisitionError("network acquisition is disabled")
            data["path"] = data["path"].relative_to(output_dir).as_posix()
            if not data["bytes"]:
                raise AcquisitionError("input payload is empty")
            entry.update(data, status="available")
        except Exception as exc:
            if directory.exists():
                shutil.rmtree(directory)
            entry.update(status="unavailable", error_type=type(exc).__name__, error=str(exc) if isinstance(exc, AcquisitionError) else "invalid or unreadable source payload (" + type(exc).__name__ + ")")
        result["sources"].append(entry)
        if trace is not None:
            missing_fields = []
            if fixture_dir is None:
                if source.get('transport','http').startswith('github'):
                    if not source.get('repo'):missing_fields.append('repo')
                    if source.get('transport')!='github_archive' and not source.get('paths') and not source.get('file'):missing_fields.append('paths/file')
                elif not source.get('url') and not source.get('files'):missing_fields.append('url/files')
            diagnostic_status = 'downloaded' if entry['status']=='available' else 'missing-configuration' if missing_fields else 'download-failed'
            trace.source_event(source['id'], 'acquisition', diagnostic_status,
                               bytes=entry.get('bytes'), sha256=entry.get('sha256'), error=entry.get('error'), error_type=entry.get('error_type'), missing_fields=missing_fields)
        if entry["status"] != "available":
            fail(entry)
        persist()
    result["status"] = "complete"
    persist()
    return result


def verify_snapshot(snapshot_dir, trace=None):
    snapshot_dir = Path(snapshot_dir).resolve()
    result = json.loads((snapshot_dir / "snapshot.json").read_text())
    if result.get("schema") != 1:
        raise AcquisitionError("unsupported input snapshot")
    if result.get("status") == "failed":
        raise AcquisitionError("input snapshot preparation failed; partial inputs cannot build")
    for source in result["sources"]:
        if source["status"] in {"disabled", "not-selected"}:
            continue
        if source["status"] != "available":
            raise AcquisitionError(f"{source['id']}: participating source is not available ({source['status']})")
        path = snapshot_dir.joinpath(*_member_path(source["path"]).parts)
        if not path.resolve().is_relative_to(snapshot_dir):
            raise AcquisitionError("snapshot path escapes input root")
        callback = (lambda name, size, digest: trace.source_event(source['id'], 'input-file', 'hashed', file=name, bytes=size, sha256=digest)) if trace is not None else None
        digest, size = tree_digest(path, on_file=callback)
        if digest != source["sha256"] or size != source["bytes"]:
            raise AcquisitionError("fixed input checksum mismatch")
    return result

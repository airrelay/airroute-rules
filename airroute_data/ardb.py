"""AirRoute ARDB v1 production writer and strict, allocation-bounded verifier.

Only CIDR records live in these files. Provenance and registry identity belong to
an immutable release manifest. Production emits only special/asn.ardb (kind 2).
The generic kind-1 codec remains solely for historical wire-contract goldens;
it is not a generated, retained, validated or published Geo product.
"""
from __future__ import annotations

import hashlib
import ipaddress
import os
from pathlib import Path
import stat
import struct
import tempfile
from typing import Iterable, Mapping, Optional, Union

MAGIC = b"ARDBv001"
FORMAT_VERSION = 1
HEADER_BYTES = 64
DIRECTORY_ENTRY_BYTES = 28
MAX_GROUPS = 1_048_576  # Same directory admission bound as the Core reader.
MAX_PREFIXES_PER_GROUP = 1_048_576
UINT32_MAX = (1 << 32) - 1
UINT64_MAX = (1 << 64) - 1
_HEADER = struct.Struct("<8sHBBIQQ32s")
_DIRECTORY = struct.Struct("<IQIQI")


class FormatError(ValueError):
    """An invalid or unsupported immutable IP data file."""


def _kind(value: Union[str, int]) -> int:
    if isinstance(value, str):
        value = {"geo": 1, "asn": 2}.get(value.lower(), 0)
    if isinstance(value, bool) or not isinstance(value, int) or value not in (1, 2):
        raise FormatError("kind must be geo (1) or asn (2)")
    return value


def _group_id(value: int, kind: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= UINT32_MAX:
        raise FormatError("group ID must be a positive u32")
    return value


def normalize_prefixes(values: Iterable) -> list:
    """Losslessly normalize and collapse each address family independently."""
    families = {4: [], 6: []}
    for value in values:
        try:
            network = ipaddress.ip_network(value, strict=False)
        except (TypeError, ValueError) as error:
            raise FormatError("invalid IP network") from error
        families[network.version].append(network)
    result = []
    for version in (4, 6):
        result.extend(ipaddress.collapse_addresses(families[version]))
    if len(result) > MAX_PREFIXES_PER_GROUP:
        raise FormatError("group exceeds Core's requested-prefix limit")
    return result


def _registry_ids(values: Optional[Iterable[int]]) -> Optional[set]:
    if values is None:
        return None
    return {_group_id(value, 1) for value in values}


def write_database(path, kind, groups: Mapping[int, Iterable], *, allowed_geo_ids=None) -> dict:
    """Write one canonical, uncompressed database, atomically replacing *path*.

    Passing the release registry's IDs is required at the publishing boundary for
    Geo. Empty groups are retained, with both family offset/count pairs set to 0.
    No payload block is shared between groups, even for a MOAS duplicate prefix.
    """
    kind = _kind(kind)
    allowed = _registry_ids(allowed_geo_ids)
    if len(groups) > MAX_GROUPS:
        raise FormatError("directory group limit")
    normalized = {}
    for group, prefixes in groups.items():
        group = _group_id(group, kind)
        if kind == 1 and allowed is not None and group not in allowed:
            raise FormatError("unknown Geo group ID")
        normalized[group] = normalize_prefixes(prefixes)
    directory_size = HEADER_BYTES + DIRECTORY_ENTRY_BYTES * len(normalized)
    offset = directory_size
    entries = []
    for group in sorted(normalized):
        v4 = [net for net in normalized[group] if net.version == 4]
        v6 = [net for net in normalized[group] if net.version == 6]
        off4 = offset if v4 else 0
        offset += len(v4) * 5
        off6 = offset if v6 else 0
        offset += len(v6) * 17
        if offset > UINT64_MAX:
            raise FormatError("file length overflows u64")
        entries.append((group, off4, len(v4), off6, len(v6)))
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix="." + path.name + ".", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(_HEADER.pack(MAGIC, FORMAT_VERSION, kind, 0, len(entries), HEADER_BYTES, directory_size, bytes(32)))
            for entry in entries:
                stream.write(_DIRECTORY.pack(*entry))
            for group, *_ in entries:
                for net in normalized[group]:
                    stream.write(net.network_address.packed)
                    stream.write(bytes((net.prefixlen,)))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return database_metadata(path, kind)


def database_metadata(path, kind) -> dict:
    kind = _kind(kind)
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        while True:
            block = stream.read(1024 * 1024)
            if not block:
                break
            digest.update(block)
    return {"format_version": FORMAT_VERSION, "kind": "geo" if kind == 1 else "asn", "bytes": Path(path).stat().st_size, "sha256": digest.hexdigest()}


def read_database(path, expected_kind, *, allowed_geo_ids=None) -> dict:
    """Validate every directory/prefix and return canonical CIDR strings by group.

    Reads one group at a time and bounds both directory and per-group allocation.
    A caller must validate the release manifest's hash and registry version first.
    """
    expected_kind = _kind(expected_kind)
    allowed = _registry_ids(allowed_geo_ids)
    path = Path(path)
    if not stat.S_ISREG(path.lstat().st_mode):
        raise FormatError("not a regular file")
    size = path.stat().st_size
    with path.open("rb") as stream:
        header = stream.read(HEADER_BYTES)
        if len(header) != HEADER_BYTES:
            raise FormatError("missing 64-byte header")
        magic, version, kind, reserved, count, directory, data, reserved_tail = _HEADER.unpack(header)
        if magic != MAGIC:
            raise FormatError("invalid magic")
        if version != FORMAT_VERSION:
            raise FormatError("unsupported format version")
        if kind != expected_kind:
            raise FormatError("file type mismatch")
        if reserved or any(reserved_tail):
            raise FormatError("nonzero reserved header fields")
        if count > MAX_GROUPS:
            raise FormatError("directory group limit")
        if directory != HEADER_BYTES or data != HEADER_BYTES + DIRECTORY_ENTRY_BYTES * count:
            raise FormatError("directory or data offset mismatch")
        if data > size:
            raise FormatError("truncated directory")
        entries, ranges = [], []
        previous = 0
        for _ in range(count):
            record = stream.read(DIRECTORY_ENTRY_BYTES)
            if len(record) != DIRECTORY_ENTRY_BYTES:
                raise FormatError("truncated directory")
            entry = _DIRECTORY.unpack(record)
            group, off4, count4, off6, count6 = entry
            _group_id(group, kind)
            if group <= previous:
                raise FormatError("group IDs not unique and ascending")
            if kind == 1 and allowed is not None and group not in allowed:
                raise FormatError("unknown Geo group ID")
            previous = group
            if count4 + count6 > MAX_PREFIXES_PER_GROUP:
                raise FormatError("group exceeds Core's requested-prefix limit")
            for offset, number, width in ((off4, count4, 5), (off6, count6, 17)):
                if not number:
                    if offset:
                        raise FormatError("empty address family has nonzero offset")
                    continue
                end = offset + number * width
                if offset < data or end > UINT64_MAX or end > size:
                    raise FormatError("payload offset overflow, overlap with directory, or truncation")
                ranges.append((offset, end))
            entries.append(entry)
        end = data
        for start, stop in sorted(ranges):
            # Publisher canonical layout has no aliases, gaps, or unreferenced bytes.
            if start != end:
                raise FormatError("overlapping payloads or unreferenced data")
            end = stop
        if end != size:
            raise FormatError("unreferenced trailing bytes")
        result = {}
        for group, off4, count4, off6, count6 in entries:
            prefixes = []
            for offset, number, width, bits in ((off4, count4, 5, 32), (off6, count6, 17, 128)):
                if not number:
                    continue
                stream.seek(offset)
                previous_prefix = None
                for _ in range(number):
                    record = stream.read(width)
                    if len(record) != width:
                        raise FormatError("truncated prefix")
                    length = record[-1]
                    address = int.from_bytes(record[:-1], "big")
                    if length > bits or address & ((1 << (bits - length)) - 1):
                        raise FormatError("noncanonical network address or invalid prefix length")
                    nettype = ipaddress.IPv4Network if bits == 32 else ipaddress.IPv6Network
                    prefix = nettype((address, length))
                    sort_key = (address, length)
                    if previous_prefix is not None and sort_key <= previous_prefix:
                        raise FormatError("group prefixes not unique and sorted")
                    previous_prefix = sort_key
                    prefixes.append(prefix)
            if normalize_prefixes(prefixes) != prefixes:
                raise FormatError("group prefixes contain losslessly mergeable ranges")
            result[group] = [str(prefix) for prefix in prefixes]
    return result


def read_group(path, expected_kind, group_id, *, allowed_geo_ids=None) -> list:
    groups = read_database(path, expected_kind, allowed_geo_ids=allowed_geo_ids)
    if group_id not in groups:
        raise FormatError("requested group is not present")
    return groups[group_id]

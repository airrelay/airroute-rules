import datetime as dt
import gzip
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest import mock
import urllib.request
import zipfile

from airroute_data.acquire import (AcquisitionError, SafeRedirect, _download,
    _get_source, _github_commit, acquire_sources, tree_digest, unpack, verify_snapshot)


class Response(io.BytesIO):
    headers = {"ETag": '"fixed"', "Last-Modified": "Mon, 02 Nov 2026 00:00:00 GMT"}


class AcquisitionTests(unittest.TestCase):
    def test_optional_github_meta_auth_is_origin_scoped_and_not_persisted(self):
        with tempfile.TemporaryDirectory() as directory:
            source = {"url": "https://api.github.com/meta", "filename": "meta.json", "github_api_token": True}
            with mock.patch.dict(os.environ, {"GITHUB_TOKEN": "fixture-only-value"}):
                with mock.patch("airroute_data.acquire._request", return_value=Response(b'{}')) as request:
                    entry = _get_source(source, Path(directory)/"good", dt.datetime.now(dt.timezone.utc), {})
                    self.assertEqual(request.call_args.args[1]["Authorization"], "Bearer fixture-only-value")
                    self.assertNotIn("fixture-only-value", json.dumps(entry, default=str))
                with mock.patch("airroute_data.acquire._request") as request:
                    with self.assertRaisesRegex(AcquisitionError, "exact API origin"):
                        _get_source({**source, "url": "https://other.invalid/meta"}, Path(directory)/"bad", dt.datetime.now(dt.timezone.utc), {})
                    request.assert_not_called()

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def config(self, sources):
        p = self.root / "sources.json"
        p.write_text(json.dumps({"schema": 1, "sources": sources}))
        return p

    def test_fixture_freezes_and_verifies_bytes(self):
        fixtures = self.root / "fixtures"; fixtures.mkdir()
        (fixtures / "one").write_text("network,country_code\n1.0.0.0/24,CN\n")
        config = self.config([{"id": "one", "format": "iplocate-country-csv", "role": "country", "lineage": "one"}])
        snapshot = self.root / "snapshot"
        result = acquire_sources(config, snapshot, fixture_dir=fixtures)
        self.assertEqual(result["sources"][0]["status"], "available")
        self.assertEqual(verify_snapshot(snapshot), result)
        (fixtures / "one").write_text("changed original")
        self.assertEqual(verify_snapshot(snapshot), result)
        (snapshot / result["sources"][0]["path"]).write_text("changed fixed input")
        with self.assertRaisesRegex(AcquisitionError, "checksum"):
            verify_snapshot(snapshot)

    def test_refuses_refresh_of_existing_snapshot(self):
        config = self.config([])
        output = self.root / "snapshot"
        acquire_sources(config, output, allow_network=False)
        with self.assertRaisesRegex(AcquisitionError, "empty"):
            acquire_sources(config, output, allow_network=False)

    def test_absent_credentials_and_disabled_and_selected_independently(self):
        config = self.config([{"id": "private", "requires_env": ["AIRROUTE_TEST_MISSING_KEY"]},
                              {"id": "disabled", "enabled": False}, {"id": "not-chosen"}])
        with mock.patch.dict(os.environ, {}, clear=True), mock.patch("airroute_data.acquire._request") as req:
            with self.assertRaisesRegex(AcquisitionError, "private: missing-credentials"):
                acquire_sources(config, self.root / "snapshot", source_ids=["private", "disabled"])
            result = json.loads((self.root / "snapshot/snapshot.json").read_text())
        self.assertEqual([s["status"] for s in result["sources"]], ["missing-credentials"])
        self.assertEqual(result["status"], "failed")
        with self.assertRaisesRegex(AcquisitionError, "partial inputs"):
            verify_snapshot(self.root / "snapshot")
        req.assert_not_called()

    def test_errors_do_not_serialize_provider_exception_or_url_query(self):
        config = self.config([{"id": "one", "url": "https://example.com/input?test=private-provider-message"}])
        with mock.patch("airroute_data.acquire._get_source", side_effect=RuntimeError("private-provider-message")):
            with self.assertRaisesRegex(AcquisitionError, "one: unavailable"):
                acquire_sources(config, self.root / "snapshot")
        result = json.loads((self.root / "snapshot/snapshot.json").read_text())
        self.assertEqual(result["sources"][0]["status"], "unavailable")
        self.assertNotIn("private-provider-message", json.dumps(result))

    def test_disabled_and_unselected_inputs_are_not_failures(self):
        config = self.config([{"id": "disabled", "enabled": False}, {"id": "unused"}])
        result = acquire_sources(config, self.root / "snapshot", source_ids=["disabled"])
        self.assertEqual([s["status"] for s in result["sources"]], ["disabled", "not-selected"])
        self.assertEqual(verify_snapshot(self.root / "snapshot")["status"], "complete")

    def test_first_failed_participating_source_stops_and_preserves_record(self):
        config = self.config([{"id": "first"}, {"id": "later"}])
        with mock.patch("airroute_data.acquire._get_source", side_effect=AcquisitionError("HTTP 503")) as get:
            with self.assertRaisesRegex(AcquisitionError, "first: unavailable: HTTP 503"):
                acquire_sources(config, self.root / "snapshot")
        self.assertEqual(get.call_count, 1)
        record = json.loads((self.root / "snapshot/snapshot.json").read_text())
        self.assertEqual(record["status"], "failed")
        self.assertEqual(record["sources"][0]["error"], "HTTP 503")

    def test_download_streaming_and_sanitized_origin(self):
        with mock.patch("airroute_data.acquire._request", return_value=Response(b"fixed input")):
            entry = _download("https://example.com/file?edition=country", self.root / "file", {}, 100)
        self.assertEqual(entry["url"], "https://example.com/file")
        self.assertEqual((self.root / "file").read_bytes(), b"fixed input")
        with mock.patch("airroute_data.acquire._request", return_value=Response(b"too large")):
            with self.assertRaises(AcquisitionError):
                _download("https://example.com/file", self.root / "large", {}, 3)
        self.assertFalse((self.root / "large.part").exists())
        self.assertFalse((self.root / "large").exists())

    def test_short_transfer_does_not_freeze_partial_content(self):
        response = Response(b"partial")
        response.headers = {"Content-Length": "100"}
        with mock.patch("airroute_data.acquire._request", return_value=response):
            with self.assertRaisesRegex(AcquisitionError, "transfer length mismatch"):
                _download("https://vendor.invalid/data", self.root / "truncated", {}, 200)
        self.assertFalse((self.root / "truncated").exists())
        self.assertFalse((self.root / "truncated.part").exists())

    def test_redirect_drops_credentials_across_origin_and_rejects_downgrade(self):
        req = urllib.request.Request("https://vendor.example/input", headers={"Authorization": "Basic fixture", "Cookie": "fixture", "User-Agent": "test"})
        redirect = SafeRedirect()
        new = redirect.redirect_request(req, None, 302, "found", {}, "https://storage.example/fixed")
        self.assertNotIn("Authorization", new.headers)
        self.assertNotIn("Cookie", new.headers)
        same = redirect.redirect_request(req, None, 302, "found", {}, "https://vendor.example/new")
        self.assertIn("Authorization", same.headers)
        with self.assertRaises(AcquisitionError):
            redirect.redirect_request(req, None, 302, "found", {}, "http://vendor.example/new")

    def test_zip_rejects_traversal_links_and_expansion(self):
        archive = self.root / "input.zip"
        with zipfile.ZipFile(archive, "w") as z:
            z.writestr("../outside", "invalid")
        with self.assertRaises(AcquisitionError):
            unpack(archive, self.root / "traversal", compression="zip")
        self.assertFalse((self.root / "outside").exists())
        with zipfile.ZipFile(archive, "w") as z:
            item = zipfile.ZipInfo("link"); item.external_attr = 0o120777 << 16
            z.writestr(item, "/etc/passwd")
        with self.assertRaises(AcquisitionError):
            unpack(archive, self.root / "link", compression="zip")
        with zipfile.ZipFile(archive, "w") as z:
            z.writestr("big", "123456")
        with self.assertRaises(AcquisitionError):
            unpack(archive, self.root / "big", compression="zip", max_bytes=5)

    def test_tar_rejects_links_and_strips_github_root(self):
        archive = self.root / "repo.tar.gz"
        with tarfile.open(archive, "w:gz") as t:
            item = tarfile.TarInfo("repo/data/a"); item.size = 3
            t.addfile(item, io.BytesIO(b"one"))
        unpack(archive, self.root / "good", compression="tar.gz", strip_root=True)
        self.assertEqual((self.root / "good/data/a").read_text(), "one")
        with tarfile.open(archive, "w:gz") as t:
            item = tarfile.TarInfo("repo/link"); item.type = tarfile.SYMTYPE; item.linkname = "/etc"
            t.addfile(item)
        with self.assertRaises(AcquisitionError):
            unpack(archive, self.root / "bad", compression="tar.gz")

    def test_hash_ignores_mtime_but_includes_names_and_content(self):
        directory = self.root / "data"; directory.mkdir()
        (directory / "b").write_text("b"); (directory / "a").write_text("a")
        before = tree_digest(directory)
        os.utime(directory / "a", (1, 1))
        self.assertEqual(tree_digest(directory), before)
        (directory / "a").rename(directory / "c")
        self.assertNotEqual(tree_digest(directory), before)

    def test_compressed_http_payload_and_monthly_version_are_fixed(self):
        source = {"url": "https://db.example/db-{YYYY-MM}.csv.gz", "filename": "db.csv.gz", "compression": "gzip"}
        now = dt.datetime(2026, 11, 3, tzinfo=dt.timezone.utc)
        with mock.patch("airroute_data.acquire._request", return_value=Response(gzip.compress(b"1.0.0.0,1.0.0.255,CN\n"))) as req:
            result = _get_source(source, self.root / "source", now, {})
        self.assertEqual(req.call_args.args[0], "https://db.example/db-2026-11.csv.gz")
        self.assertEqual((result["path"] / "db.csv").read_text(), "1.0.0.0,1.0.0.255,CN\n")
        self.assertEqual(result["version"], Response.headers["Last-Modified"])

    def test_dual_stack_vendor_zips_keep_shared_license_in_separate_subtrees(self):
        def bundle(filename, data):
            output = io.BytesIO()
            with zipfile.ZipFile(output, "w") as archive:
                archive.writestr("LICENSE", "shared vendor license")
                archive.writestr(filename, data)
            return output.getvalue()
        payloads = [bundle("IP2LOCATION-LITE-DB1.CSV", '"16843008","16843263","CN","China"\n'),
                    bundle("IP2LOCATION-LITE-DB1.IPV6.CSV", '"42540766411282592856903984951653826560","42540766411282592856903984951653826815","RU","Russia"\n')]
        # Negative control: the previous shared extraction shape rejects LICENSE
        # on ZIP2, even though its data payload is otherwise valid and distinct.
        archives = [self.root / "v4.zip", self.root / "v6.zip"]
        for path, data in zip(archives, payloads):
            path.write_bytes(data)
        unpack(archives[0], self.root / "shared", compression="zip")
        with self.assertRaises(FileExistsError):
            unpack(archives[1], self.root / "shared", compression="zip")

        source = {"id": "ip2location", "format": "ip2location-db1-csv", "role": "country",
                  "lineage": "ip2location-lite", "address_families": [4, 6], "transport": "http_files", "files": [
                      {"url": "https://vendor.example/v4", "name": "DB1LITE.zip", "compression": "zip"},
                      {"url": "https://vendor.example/v6", "name": "DB1LITEIPV6.zip", "compression": "zip"}]}
        with mock.patch("airroute_data.acquire._request", side_effect=[Response(data) for data in payloads]):
            snapshot = acquire_sources(self.config([source]), self.root / "snapshot")
        entry = snapshot["sources"][0]
        self.assertEqual(entry["status"], "available")
        fixed = self.root / "snapshot" / entry["path"]
        self.assertEqual(len(list(fixed.rglob("LICENSE"))), 2)
        self.assertEqual(len(list(fixed.rglob("*.CSV"))), 2)
        self.assertEqual(verify_snapshot(self.root / "snapshot"), snapshot)
        # The common parent preserves the parser's recursive dual-stack contract.
        from airroute_data.geo import parse_source
        records = list(parse_source(entry["format"], fixed, entry))
        self.assertEqual(sorted(record.version for record in records), [4, 6])
        self.assertEqual({record.country for record in records}, {"CN", "RU"})

    def test_ipinfo_gzip_glob_selects_actual_csv_file(self):
        source = {"url": "https://vendor.example/ipinfo.csv.gz", "filename": "ipinfo-lite.csv.gz",
                  "compression": "gzip", "payload_glob": "*.csv"}
        now = dt.datetime(2026, 11, 3, tzinfo=dt.timezone.utc)
        with mock.patch("airroute_data.acquire._request", return_value=Response(gzip.compress(b"network,country_code\n1.1.1.0/24,CN\n"))):
            entry = _get_source(source, self.root / "source", now, {})
        self.assertTrue(entry["path"].is_file())
        self.assertEqual(entry["path"].name, "ipinfo-lite.csv")

    def test_branch_resolves_once_and_immutable_sha_never_calls_api(self):
        sha = "a" * 40; cache = {}
        with mock.patch("airroute_data.acquire._request", return_value=Response(json.dumps({"sha": sha}).encode())) as req:
            self.assertEqual(_github_commit("owner/repo", "main", cache), sha)
            self.assertEqual(_github_commit("owner/repo", "main", cache), sha)
            self.assertEqual(_github_commit("owner/repo", sha, cache), sha)
        self.assertEqual(req.call_count, 1)

    def test_duplicate_ids_and_unknown_selection_rejected(self):
        config = self.config([{"id": "duplicate"}, {"id": "duplicate"}])
        with self.assertRaises(AcquisitionError):
            acquire_sources(config, self.root / "dup")
        config = self.config([{"id": "one"}])
        with self.assertRaises(AcquisitionError):
            acquire_sources(config, self.root / "unknown", source_ids=["unknown"])

    def test_fixture_symlink_rejected(self):
        fixtures = self.root / "fixtures"; fixtures.mkdir()
        (fixtures / "real").write_text("content")
        (fixtures / "one").symlink_to(fixtures / "real")
        with self.assertRaisesRegex(AcquisitionError, "one: unavailable"):
            acquire_sources(self.config([{"id": "one"}]), self.root / "snapshot", fixture_dir=fixtures)
        result = json.loads((self.root / "snapshot/snapshot.json").read_text())
        self.assertEqual(result["sources"][0]["status"], "unavailable")


if __name__ == "__main__":
    unittest.main()

"""Real local Git transport tests. No GitHub, provider or production requests."""
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from airroute_data import publish as module


def git(repo, *args):
    return subprocess.check_output(["git", "-C", str(repo), *args], text=True,
                                   stderr=subprocess.DEVNULL).strip()


class PublicationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.remote = self.root / "remote.git"
        self.source = self.root / "source"
        self.source.mkdir()
        git(self.root, "init", "--bare", "--quiet", str(self.remote))
        git(self.source, "init", "--quiet", "-b", "main")
        git(self.source, "config", "user.name", "Fixture")
        git(self.source, "config", "user.email", "fixture@example.invalid")
        (self.source / "README.md").write_text("fixture\n")
        git(self.source, "add", "README.md")
        git(self.source, "commit", "--quiet", "-m", "source")
        git(self.source, "remote", "add", "origin", str(self.remote))
        git(self.source, "push", "--quiet", "origin", "main")
        self.sha = git(self.source, "rev-parse", "HEAD")
        self.sequence = 0

    def publish(self, candidate, repo, source_sha, **kwargs):
        self.sequence += 1
        kwargs.setdefault("sequence", self.sequence)
        return module.publish(candidate, repo, source_sha, **kwargs)

    def tearDown(self):
        self.temp.cleanup()

    def candidate(self, version="a1", value=b"fixture-data"):
        path = self.root / ("candidate-" + version)
        path.mkdir(exist_ok=True)
        from airroute_data.ardb import write_database
        write_database(path / "geo.ardb", "geo", {1: ["192.0.2.0/24"]}, allowed_geo_ids=[1])
        write_database(path / "asn.ardb", "asn", {64500: ["192.0.2.0/24"]})
        (path / "regions.json").write_text(json.dumps({"version": "fixture", "regions": [
            {"id": 1, "key": "cn", "countries": ["CN"]}]}))
        (path / "region").mkdir(exist_ok=True)
        domain = hashlib.sha256(value).hexdigest()[:16] + ".example"
        (path / "region" / "cn.list").write_text("DOMAIN-SUFFIX," + domain + "\nIP-CIDR,192.0.2.0/24\n")
        files = []
        for name in ["geo.ardb", "asn.ardb", "regions.json", "region/cn.list"]:
            data = (path / name).read_bytes()
            files.append({"path": name, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()})
        manifest = {"schema": 1, "format_version": 1, "data_version": version, "version": version,
                    "geo_registry_version": "fixture", "files": files,
                    "summary": {"country_lineages": 2, "geo_prefixes": 1, "asn_prefixes": 1,
                                "domain_rules": 1, "geo_v4_addresses": 256, "geo_v6_addresses": 0}}
        (path / "manifest.json").write_text(json.dumps(manifest, sort_keys=True))
        return path

    def current(self):
        return json.loads(git(self.remote, "show", "release:manifest.json"))

    def add_file(self, candidate, name, content):
        path = candidate / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        manifest = json.loads((candidate / "manifest.json").read_text())
        manifest["files"].append({"path": name, "bytes": len(content),
                                  "sha256": hashlib.sha256(content).hexdigest()})
        (candidate / "manifest.json").write_text(json.dumps(manifest))

    def legacy_release(self, candidate):
        """A real pre-change tree, including diagnostics and stale files."""
        import shutil
        worker = self.root / "legacy"
        worker.mkdir()
        git(worker, "init", "--quiet", "-b", "release")
        git(worker, "config", "user.name", "Fixture")
        git(worker, "config", "user.email", "fixture@example.invalid")
        version = json.loads((candidate / "manifest.json").read_text())["data_version"]
        shutil.copytree(candidate, worker / "versions" / version)
        raw = (candidate / "manifest.json").read_bytes()
        (worker / "current.json").write_text(json.dumps({
            "data_version": version, "manifest": "versions/" + version + "/manifest.json",
            "manifest_sha256": hashlib.sha256(raw).hexdigest(),
            "publication": {"sequence": 1, "attempt": 1, "source_sha": self.sha}}))
        (worker / "README.md").write_text("old instructions")
        (worker / "stale-file").write_text("must disappear")
        git(worker, "add", "--all")
        git(worker, "commit", "--quiet", "-m", "old layout")
        git(worker, "remote", "add", "origin", str(self.remote))
        git(worker, "push", "--quiet", "origin", "release")
        return git(worker, "rev-parse", "HEAD")

    def test_release_inventory_excludes_reports_readme_and_scratch(self):
        candidate = self.candidate()
        self.add_file(candidate, "reports/internal.json", b'{"audit":true}\n')
        self.add_file(candidate, "README.md", b"build-only instructions\n")
        self.add_file(candidate, "scratch/debug.log", b"diagnostic\n")
        self.add_file(candidate, "ATTRIBUTION.md", b"upstream license\n")
        self.publish(candidate, self.source, self.sha)
        paths = set(git(self.remote, "ls-tree", "-r", "--name-only", "release").splitlines())
        self.assertEqual(paths, {"geo.ardb", "asn.ardb", "regions.json", "manifest.json",
                                 "ATTRIBUTION.md", "region/cn.list"})
        self.assertEqual(self.current()["layout"], "flat-v1")
        self.assertEqual({f["path"] for f in self.current()["files"]}, paths - {"manifest.json"})

    def test_legacy_layout_migrates_same_data_and_preserves_git_history(self):
        candidate = self.candidate()
        self.add_file(candidate, "reports/internal.json", b"{}\n")
        old = self.legacy_release(candidate)
        baseline = self.root / "legacy-baseline"
        self.assertTrue(module.prepare_baseline(self.source, baseline))
        result = self.publish(candidate, self.source, self.sha, sequence=2)
        self.assertEqual(result["status"], "published")
        self.assertEqual(git(self.remote, "rev-parse", "release~1"), old)
        paths = git(self.remote, "ls-tree", "-r", "--name-only", "release").splitlines()
        self.assertFalse(any(p.startswith(("versions/", "reports/")) for p in paths))
        self.assertNotIn("current.json", paths)
        self.assertNotIn("stale-file", paths)
        self.assertEqual(self.publish(candidate, self.source, self.sha, sequence=3)["status"], "unchanged")

    def test_next_version_deletes_removed_products(self):
        first = self.candidate()
        self.add_file(first, "category/obsolete.list", b"# no longer offered\n")
        self.publish(first, self.source, self.sha)
        self.publish(self.candidate("a2"), self.source, self.sha)
        self.assertNotIn("category/obsolete.list", git(self.remote, "ls-tree", "-r", "--name-only", "release"))

    def test_unexpected_rule_or_database_directory_is_rejected(self):
        for index, name in enumerate(("scratch/rogue.list", "test.ardb", "region/NONCANONICAL.list")):
            candidate = self.candidate("bad" + str(index))
            self.add_file(candidate, name, b"# fixture\n")
            with self.assertRaisesRegex(module.PublicationError, "Unexpected rule/database"):
                self.publish(candidate, self.source, self.sha)

    def test_rollback_old_layout_version_restores_only_public_data(self):
        first = self.candidate()
        self.add_file(first, "reports/internal.json", b"{}\n")
        self.legacy_release(first)
        self.publish(self.candidate("a2"), self.source, self.sha, sequence=2)
        result = module.rollback(self.source, "a1", self.sha, sequence=3)
        self.assertEqual(result["status"], "published")
        self.assertEqual(self.current()["data_version"], "a1")
        paths = git(self.remote, "ls-tree", "-r", "--name-only", "release")
        self.assertNotIn("versions/", paths)
        self.assertNotIn("reports/", paths)

    def test_unknown_rollback_version_keeps_current_release(self):
        first = self.publish(self.candidate(), self.source, self.sha)
        with self.assertRaisesRegex(module.PublicationError, "absent"):
            module.rollback(self.source, "absent", self.sha, sequence=2)
        self.assertEqual(git(self.remote, "rev-parse", "release"), first["commit"])

    def test_initial_publication_then_no_change(self):
        candidate = self.candidate()
        first = self.publish(candidate, self.source, self.sha)
        self.assertEqual(first["status"], "published")
        self.assertEqual(first["commit"], git(self.remote, "rev-parse", "release"))
        self.assertEqual(self.current()["data_version"], "a1")
        second = self.publish(candidate, self.source, self.sha)
        self.assertEqual(second["status"], "unchanged")
        self.assertEqual(first["commit"], second["commit"])
        self.assertEqual(self.current()["publication"], first["publication"])
        self.assertEqual(git(self.source, "rev-parse", "HEAD"), self.sha)
        self.assertEqual(git(self.source, "status", "--porcelain"), "")

    def test_second_version_and_forward_rollback_preserve_both(self):
        one = self.publish(self.candidate(), self.source, self.sha)
        two = self.publish(self.candidate("a2", b"second"), self.source, self.sha)
        self.assertEqual(self.current()["data_version"], "a2")
        rolled = module.rollback(self.source, "a1", self.sha, sequence=3)
        self.assertEqual(rolled["status"], "published")
        self.assertEqual(self.current()["data_version"], "a1")
        self.assertEqual(json.loads(git(self.remote, "show", two["commit"] + ":manifest.json"))["data_version"], "a2")
        self.assertEqual(git(self.remote, "rev-parse", "release~1"), two["commit"])
        self.assertEqual(git(self.remote, "rev-parse", "release~2"), one["commit"])

    def test_modified_and_unlisted_candidate_never_publish(self):
        candidate = self.candidate()
        (candidate / "geo.ardb").write_bytes(b"changed")
        with self.assertRaises(module.PublicationError):
            self.publish(candidate, self.source, self.sha)
        candidate = self.candidate(value=b"fixture-data")
        (candidate / "secret.env").write_text("not a secret fixture")
        with self.assertRaises(module.PublicationError):
            self.publish(candidate, self.source, self.sha)

    def test_path_traversal_symlink_and_immutable_collision_rejected(self):
        candidate = self.candidate()
        manifest = json.loads((candidate / "manifest.json").read_text())
        manifest["files"][0]["path"] = "../outside"
        (candidate / "manifest.json").write_text(json.dumps(manifest))
        with self.assertRaises(module.PublicationError): module.validate_candidate(candidate)
        candidate = self.candidate()
        (candidate / "geo.ardb").unlink()
        (candidate / "geo.ardb").symlink_to(self.source / "README.md")
        with self.assertRaises(module.PublicationError): module.validate_candidate(candidate)
        (candidate / "geo.ardb").unlink()
        candidate = self.candidate()
        self.publish(candidate, self.source, self.sha)
        self.candidate(value=b"different")
        with self.assertRaisesRegex(module.PublicationError, "collision"):
            self.publish(candidate, self.source, self.sha)

    def test_stale_main_cannot_publish(self):
        (self.source / "next").write_text("new source")
        git(self.source, "add", "next")
        git(self.source, "commit", "--quiet", "-m", "new main")
        git(self.source, "push", "--quiet", "origin", "main")
        with self.assertRaisesRegex(module.PublicationError, "obsolete"):
            self.publish(self.candidate(), self.source, self.sha)

    def test_real_remote_rejection_keeps_previous_release_and_pending_identity(self):
        first = self.publish(self.candidate(), self.source, self.sha)
        hook = self.remote / "hooks" / "pre-receive"
        hook.write_text("#!/bin/sh\nexit 1\n")
        hook.chmod(0o700)
        with self.assertRaises(module.PublicationUncertain):
            self.publish(self.candidate("a2"), self.source, self.sha)
        root = module._state_root(self.source, "origin", "release")
        state = json.loads((root / "pending.json").read_text())
        original_commit = state["commit"]
        self.assertEqual(git(self.remote, "rev-parse", "release"), first["commit"])
        hook.unlink()
        retried = self.publish(self.candidate("a2"), self.source, self.sha)
        self.assertEqual(retried["commit"], original_commit)
        self.assertFalse((root / "pending.json").exists())

    def test_push_succeeded_response_timeout_reconciles_exact_sha(self):
        original = module._git
        pushes = []
        def lose_response(repo, *args, **kwargs):
            result = original(repo, *args, **kwargs)
            if args[0] == "push":
                pushes.append(args)
                raise module.PublicationUncertain("injected loss after real successful local push")
            return result
        with patch.object(module, "_git", side_effect=lose_response):
            result = self.publish(self.candidate(), self.source, self.sha)
        self.assertEqual(result["status"], "published")
        self.assertEqual(len(pushes), 1)
        self.assertEqual(result["commit"], git(self.remote, "rev-parse", "release"))

    def test_ref_race_does_not_force_old_version_over_new_commit(self):
        self.publish(self.candidate(), self.source, self.sha)
        original = module._git
        competed = []
        def competing_update(repo, *args, **kwargs):
            if args[0] == "push" and not competed:
                competed.append(True)
                other = self.root / "competitor"
                git(self.root, "clone", "--quiet", "-b", "release", str(self.remote), str(other))
                git(other, "config", "user.name", "Competitor")
                git(other, "config", "user.email", "competitor@example.invalid")
                (other / "newer").write_text("separate release writer")
                git(other, "add", "newer")
                git(other, "commit", "--quiet", "-m", "newer release")
                git(other, "push", "--quiet", "origin", "release")
            return original(repo, *args, **kwargs)
        with patch.object(module, "_git", side_effect=competing_update):
            result = self.publish(self.candidate("a2"), self.source, self.sha)
        self.assertEqual(result["status"], "superseded")
        self.assertEqual(git(self.remote, "show", "release:newer"), "separate release writer")
        self.assertEqual(self.current()["data_version"], "a1")

    def test_pending_unknown_cannot_be_bypassed_by_another_candidate(self):
        self.publish(self.candidate(), self.source, self.sha)
        hook = self.remote / "hooks" / "pre-receive"
        hook.write_text("#!/bin/sh\nexit 1\n"); hook.chmod(0o700)
        with self.assertRaises(module.PublicationUncertain):
            self.publish(self.candidate("a2"), self.source, self.sha)
        with self.assertRaisesRegex(module.PublicationUncertain, "unresolved"):
            self.publish(self.candidate("a3"), self.source, self.sha)

    def test_previous_manifest_baseline_is_verified_and_not_raw_sources(self):
        output = self.root / "previous"
        self.assertFalse(module.prepare_baseline(self.source, output))
        self.assertFalse(output.exists())
        self.publish(self.candidate(), self.source, self.sha)
        self.assertTrue(module.prepare_baseline(self.source, output))
        self.assertEqual({p.relative_to(output).as_posix() for p in output.rglob("*") if p.is_file()}, {"manifest.json", "region/cn.list"})
        self.assertEqual(json.loads((output / "manifest.json").read_text())["data_version"], "a1")

    def test_scoped_checkout_credentials_copy_without_log_or_artifact(self):
        # checkout v6 uses a conditional include pointing outside .git/config.
        credentials = self.root / "checkout-auth.config"
        credentials.write_text('[http "https://github.invalid/"]\nextraheader = fixture-only\n')
        git(self.source, "config", "includeIf.gitdir:" + str((self.source / ".git").resolve()) + ".path", str(credentials))
        worker = self.root / "auth-worker"
        worker.mkdir(); git(worker, "init", "--quiet")
        module._credential_config(self.source, worker)
        self.assertEqual(git(worker, "config", "--get", "http.https://github.invalid/.extraheader"), "fixture-only")

    def test_direct_publish_validates_semantics_even_when_hashes_are_consistent(self):
        candidate = self.candidate()
        path = candidate / "region" / "cn.list"
        path.write_text("USER-AGENT,unsupported\nIP-CIDR,192.0.2.0/24\n")
        manifest = json.loads((candidate / "manifest.json").read_text())
        for record in manifest["files"]:
            if record["path"] == "region/cn.list":
                record.update(bytes=path.stat().st_size, sha256=hashlib.sha256(path.read_bytes()).hexdigest())
        (candidate / "manifest.json").write_text(json.dumps(manifest))
        with self.assertRaisesRegex(module.PublicationError, "validation"):
            self.publish(candidate, self.source, self.sha)

    def test_late_old_candidate_on_same_main_cannot_overwrite_newer_publication(self):
        older = self.candidate("a1", b"old inputs")
        newer = self.candidate("a2", b"new inputs")
        latest = self.publish(newer, self.source, self.sha, sequence=12)
        with self.assertRaisesRegex(module.PublicationError, "late candidate"):
            self.publish(older, self.source, self.sha, sequence=11)
        self.assertEqual(self.current()["data_version"], "a2")
        self.assertEqual(git(self.remote, "rev-parse", "release"), latest["commit"])

    def test_sequence_attempt_pair_and_explicit_rollback_order(self):
        self.publish(self.candidate("a1"), self.source, self.sha, sequence=7, attempt=2)
        with self.assertRaisesRegex(module.PublicationError, "late candidate"):
            self.publish(self.candidate("a2"), self.source, self.sha, sequence=7, attempt=1)
        self.publish(self.candidate("a2"), self.source, self.sha, sequence=7, attempt=3)
        with self.assertRaisesRegex(module.PublicationError, "late candidate"):
            module.rollback(self.source, "a1", self.sha, sequence=7, attempt=3)
        result = module.rollback(self.source, "a1", self.sha, sequence=8)
        self.assertEqual(result["status"], "published")
        self.assertEqual(self.current()["publication"]["sequence"], 8)

    def test_invalid_sequence_rejected_without_remote_write(self):
        for sequence, attempt in [(0, 1), (-1, 1), (True, 1), (1, 0), (1, "2")]:
            with self.assertRaisesRegex(module.PublicationError, "positive integers"):
                self.publish(self.candidate(), self.source, self.sha, sequence=sequence, attempt=attempt)

    def test_new_publication_validates_semantics_once_against_fresh_baseline(self):
        original = module._semantic_validation
        with patch.object(module, "_semantic_validation", wraps=original) as validate:
            self.publish(self.candidate("a1"), self.source, self.sha)
        self.assertEqual(validate.call_count, 1)
        self.assertIsNone(validate.call_args.args[2])
        with patch.object(module, "_semantic_validation", wraps=original) as validate:
            self.publish(self.candidate("a2"), self.source, self.sha)
        self.assertEqual(validate.call_count, 1)
        self.assertEqual(validate.call_args.args[2].name, "work")

    def test_fenced_pending_retry_reuses_prior_semantic_validation(self):
        self.publish(self.candidate("a1"), self.source, self.sha)
        hook = self.remote / "hooks" / "pre-receive"
        hook.write_text("#!/bin/sh\nexit 1\n"); hook.chmod(0o700)
        candidate = self.candidate("a2")
        with self.assertRaises(module.PublicationUncertain):
            self.publish(candidate, self.source, self.sha)
        hook.unlink()
        with patch.object(module, "_semantic_validation", side_effect=AssertionError("should reuse fenced check")):
            result = self.publish(candidate, self.source, self.sha)
        self.assertEqual(result["status"], "published")

    def test_semantic_failure_on_new_candidate_never_calls_push(self):
        first = self.publish(self.candidate("a1"), self.source, self.sha)
        original = module._git
        pushes = []
        def count_push(repo, *args, **kwargs):
            if args[0] == "push":
                pushes.append(args)
            return original(repo, *args, **kwargs)
        with patch.object(module, "_git", side_effect=count_push):
            with patch.object(module, "_semantic_validation", side_effect=module.PublicationError("invalid data")):
                with self.assertRaisesRegex(module.PublicationError, "invalid data"):
                    self.publish(self.candidate("a2"), self.source, self.sha)
        self.assertEqual(pushes, [])
        self.assertEqual(git(self.remote, "rev-parse", "release"), first["commit"])

    def test_oversized_artifact_fails_before_hashing_or_git(self):
        candidate = self.candidate()
        report = candidate / "oversized-report.jsonl"
        size = module.MAX_ARTIFACT_BYTES + 1
        with report.open("wb") as stream:
            stream.truncate(size)  # Sparse fixture; no 95 MiB allocation or download.
        manifest_path = candidate / "manifest.json"
        manifest = json.loads(manifest_path.read_text())
        # The oversized file is last, so a one-pass hash loop would still waste
        # work on earlier files. The entire size inventory must run first.
        manifest["files"].append({"path": report.name, "bytes": size, "sha256": "0" * 64})
        manifest_path.write_text(json.dumps(manifest))
        with patch.object(module, "_digest", side_effect=AssertionError("must not hash")):
            with patch.object(module, "_git", side_effect=AssertionError("must not access Git")):
                with self.assertRaisesRegex(module.PublicationError, "95 MiB publication limit"):
                    self.publish(candidate, self.source, self.sha)

    def test_oversized_manifest_fails_before_read_or_git(self):
        candidate = self.candidate()
        with (candidate / "manifest.json").open("r+b") as stream:
            stream.truncate(module.MAX_ARTIFACT_BYTES + 1)
        with patch.object(module, "_digest", side_effect=AssertionError("must not hash")):
            with patch.object(module, "_git", side_effect=AssertionError("must not access Git")):
                with self.assertRaisesRegex(module.PublicationError, "95 MiB publication limit: manifest.json"):
                    self.publish(candidate, self.source, self.sha)


if __name__ == "__main__":
    unittest.main()

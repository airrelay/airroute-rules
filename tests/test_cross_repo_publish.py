"""Actual isolated Git transports: distinct source and generated-data remotes."""
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from airroute_data import publish as module
from airroute_data.cli import parser


class CrossRepositoryPublicationTests(unittest.TestCase):
    def setUp(self):
        # Reuse the small valid ARDB/list fixture and existing local source repo.
        from test_publish import PublicationTests, git
        self.fixture = PublicationTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.tearDown)
        self.git = git
        self.repo, self.root = self.fixture.source, self.fixture.root
        self.target = self.root / 'products.git'
        git(self.root, 'init', '--bare', '--quiet', str(self.target))
        git(self.repo, 'remote', 'add', 'products', str(self.target))
        self.sha = self.fixture.sha

    def publish(self, candidate=None, **kwargs):
        return module.publish(candidate or self.fixture.candidate(), self.repo,
            kwargs.pop('source_sha', self.sha), sequence=kwargs.pop('sequence', 1),
            remote='products', branch='main', source_remote=kwargs.pop('source_remote', 'origin'), **kwargs)

    def advance_source(self):
        path = self.repo / 'README.md'
        path.write_text(path.read_text() + 'new source\n')
        self.git(self.repo, 'add', 'README.md')
        self.git(self.repo, 'commit', '--quiet', '-m', 'advance source')
        self.git(self.repo, 'push', '--quiet', 'origin', 'main')
        return self.git(self.repo, 'rev-parse', 'HEAD')

    def reject_pushes(self):
        hook = self.target / 'hooks/pre-receive'
        hook.write_text('#!/bin/sh\nexit 1\n')
        hook.chmod(0o755)
        return hook

    def test_distinct_empty_target_can_publish_main_with_ordinary_push(self):
        real_git = module._git
        pushes = []
        def observe(repo, *args, **kwargs):
            if args[0] == 'push': pushes.append(args)
            return real_git(repo, *args, **kwargs)
        with patch.object(module, '_git', side_effect=observe):
            result = self.publish()
        self.assertEqual(result['status'], 'published')
        self.assertEqual(self.git(self.target, 'rev-parse', 'main'), result['commit'])
        self.assertEqual(self.git(self.fixture.remote, 'rev-parse', 'main'), self.sha)
        manifest = json.loads(self.git(self.target, 'show', 'main:manifest.json'))
        self.assertEqual(manifest['publication']['source_sha'], self.sha)
        self.assertEqual(pushes, [('push', 'origin', result['commit'] + ':refs/heads/main')])

    def test_target_need_not_contain_source_branch(self):
        self.git(self.repo, 'push', '--quiet', 'origin', 'HEAD:refs/heads/source-only')
        first = self.publish(source_branch='source-only')
        second = self.publish(self.fixture.candidate('a2'), sequence=2, source_branch='source-only')
        self.assertEqual(first['status'], 'published')
        self.assertEqual(second['status'], 'published')
        self.assertEqual(self.git(self.target, 'for-each-ref', '--format=%(refname)', 'refs/heads'), 'refs/heads/main')

    def test_source_advance_before_preparation_rejects_old_candidate(self):
        self.advance_source()
        with self.assertRaisesRegex(module.PublicationError, 'obsolete build'):
            self.publish()
        self.assertEqual(self.git(self.target, 'for-each-ref', '--format=%(refname)'), '')

    def test_source_advance_after_validation_fences_actual_push(self):
        real_validation = module._semantic_validation
        def change_after_validation(*args, **kwargs):
            real_validation(*args, **kwargs)
            self.advance_source()
        with patch.object(module, '_semantic_validation', side_effect=change_after_validation):
            result = self.publish()
        self.assertEqual(result['status'], 'superseded')
        self.assertEqual(self.git(self.target, 'for-each-ref', '--format=%(refname)'), '')

    def test_rejected_pending_retry_uses_recorded_source_remote_and_commit(self):
        hook = self.reject_pushes()
        candidate = self.fixture.candidate()
        with self.assertRaises(module.PublicationUncertain): self.publish(candidate)
        root = module._state_root(self.repo, 'products', 'main')
        state = json.loads((root / 'pending.json').read_text())
        self.assertEqual(state['source_remote'], 'origin')
        self.assertEqual(state['source_branch'], 'main')
        hook.unlink()
        # A changed invocation must not reinterpret an existing attempt's fence.
        result = self.publish(candidate, source_remote='products')
        self.assertEqual(result['status'], 'published')
        self.assertEqual(result['commit'], state['commit'])
        self.assertFalse((root / 'pending.json').exists())

    def test_pending_new_candidate_checks_old_attempt_source_not_target(self):
        self.publish()
        hook = self.reject_pushes()
        with self.assertRaises(module.PublicationUncertain):
            self.publish(self.fixture.candidate('a2'), sequence=2)
        hook.unlink()
        latest = self.advance_source()
        result = self.publish(self.fixture.candidate('a3'), source_sha=latest, sequence=3)
        self.assertEqual(result['status'], 'published')
        self.assertEqual(result['source_sha'], latest)
        self.assertEqual(json.loads(self.git(self.target, 'show', 'main:manifest.json'))['data_version'], 'a3')

    def test_new_candidate_cannot_discard_pending_when_original_source_is_current(self):
        self.publish()
        self.reject_pushes()
        with self.assertRaises(module.PublicationUncertain):
            self.publish(self.fixture.candidate('a2'), sequence=2)
        root = module._state_root(self.repo, 'products', 'main')
        before = (root / 'pending.json').read_bytes()
        with self.assertRaisesRegex(module.PublicationUncertain, 'Another candidate'):
            self.publish(self.fixture.candidate('a3'), sequence=3)
        self.assertEqual((root / 'pending.json').read_bytes(), before)

    def test_retry_cannot_send_stale_source_after_rejected_push(self):
        hook = self.reject_pushes()
        candidate = self.fixture.candidate()
        with self.assertRaises(module.PublicationUncertain): self.publish(candidate)
        hook.unlink()
        self.advance_source()
        result = self.publish(candidate, source_remote='products')
        self.assertEqual(result['status'], 'superseded')
        self.assertEqual(self.git(self.target, 'for-each-ref', '--format=%(refname)'), '')

    def test_cross_repository_rollback_is_forward_and_fenced_at_source(self):
        first = self.publish()
        second = self.publish(self.fixture.candidate('a2'), sequence=2)
        result = module.rollback(self.repo, 'a1', self.sha, sequence=3,
            remote='products', branch='main', source_remote='origin')
        self.assertEqual(result['status'], 'published')
        self.assertNotEqual(result['commit'], first['commit'])
        self.assertEqual(self.git(self.target, 'rev-parse', 'main^'), second['commit'])
        self.advance_source()
        with self.assertRaisesRegex(module.PublicationError, 'stale rollback'):
            module.rollback(self.repo, 'a2', self.sha, sequence=4,
                remote='products', branch='main', source_remote='origin')

    def test_cli_separates_source_and_target_and_keeps_single_repo_default(self):
        base = ['publish', '--candidate', 'candidate', '--source-sha', self.sha, '--sequence', '1']
        original = parser().parse_args(base)
        self.assertIsNone(original.source_remote)
        self.assertEqual(original.remote, 'origin')
        split = parser().parse_args(base + ['--remote', 'products', '--branch', 'main', '--source-remote', 'origin'])
        self.assertEqual((split.source_remote, split.source_branch, split.remote, split.branch),
                         ('origin', 'main', 'products', 'main'))

    def legacy_head(self):
        self.git(self.repo, 'push', '--quiet', 'products', 'HEAD:refs/heads/main')
        return self.git(self.target, 'rev-parse', 'main')

    def test_legacy_target_requires_explicit_exact_head_and_preserves_history(self):
        old = self.legacy_head()
        for expected in (None, '0' * 40):
            with self.subTest(expected=expected), self.assertRaisesRegex(module.PublicationError, 'explicit matching legacy head'):
                self.publish(replace_legacy_head=expected)
            self.assertEqual(self.git(self.target, 'rev-parse', 'main'), old)
        result = self.publish(replace_legacy_head=old)
        self.assertEqual(result['status'], 'published')
        self.assertEqual(self.git(self.target, 'rev-parse', 'main^'), old)
        self.assertNotIn('README.md', self.git(self.target, 'ls-tree', '-r', '--name-only', 'main').splitlines())
        self.assertIn('README.md', self.git(self.target, 'ls-tree', '-r', '--name-only', old).splitlines())

    def test_legacy_flag_cannot_bypass_existing_flat_release_order(self):
        first = self.publish(sequence=10)
        with self.assertRaisesRegex(module.PublicationError, 'equal or newer publication'):
            self.publish(self.fixture.candidate('a2'), sequence=9, replace_legacy_head=first['commit'])
        result = self.publish(self.fixture.candidate('a2'), sequence=11, replace_legacy_head='0' * 40)
        self.assertEqual(result['status'], 'published')


if __name__ == '__main__':
    unittest.main()

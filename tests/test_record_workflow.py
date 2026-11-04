"""Static guards for diagnostics, without credentials or live publication."""
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class RecordWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.workflow = (ROOT / '.github/workflows/build.yml').read_text()

    def test_acquisition_build_and_publication_have_separate_record_plumbing(self):
        self.assertIn('snapshot --output .build/snapshot --record-dir .build/record', self.workflow)
        self.assertIn('--report .build/build-report.json --record-dir .build/record', self.workflow)
        self.assertIn('--record-dir .build/publication-record', self.workflow)
        self.assertIn('--remote products --branch main --source-remote origin', self.workflow)
        self.assertIn('token: ${{ secrets.RULES_PUBLISH_TOKEN }}', self.workflow)

    def test_diagnostic_steps_run_after_failure_without_hiding_original(self):
        steps = [part for part in self.workflow.split('      - name: ')
                 if any(name in part.splitlines()[0] for name in (
                     'Record workflow outcome', 'Package bounded build diagnostics',
                     'Keep successful or failed build records', 'Record publication job outcome',
                     'Package publication diagnostics', 'Keep publication outcome'))]
        self.assertEqual(len(steps), 6)
        for step in steps:
            with self.subTest(step=step.splitlines()[0]):
                self.assertIn('if: always()', step)
                self.assertIn('continue-on-error: true', step)
        # Build and publish themselves must still fail normally.
        generate = self.workflow.split('      - name: Build and validate the complete candidate')[1].split('      - uses:')[0]
        self.assertNotIn('continue-on-error', generate)
        self.assertNotIn('|| true', generate)
        publish = self.workflow.split('      - name: Revalidate downloaded data and publish one atomic release commit')[1].split('      - name:')[0]
        self.assertNotIn('continue-on-error', publish)

    def test_diagnostics_are_retained_separately_and_no_raw_source_upload(self):
        self.assertIn('name: build-record-${{ github.run_id }}-${{ github.run_attempt }}', self.workflow)
        self.assertIn('path: .build/diagnostics/', self.workflow)
        self.assertIn('name: publication-record-${{ github.run_id }}-${{ github.run_attempt }}', self.workflow)
        self.assertGreaterEqual(self.workflow.count('retention-days: 7'), 3)
        self.assertIn('retention-days: 1', self.workflow)
        self.assertNotIn('path: .build/snapshot/', self.workflow)
        self.assertIn('--record-dir .build/record --workflow-status "$WORKFLOW_STATE" --status skipped', self.workflow)
        status_calls = [line for line in self.workflow.splitlines() if 'python -m airroute_data record-status ' in line]
        self.assertTrue(status_calls)
        self.assertTrue(all('--workflow-status "$WORKFLOW_STATE"' in line for line in status_calls))
        publication_status = self.workflow.split('      - name: Record publication job outcome')[1].split('      - name:')[0]
        self.assertIn('--preserve-publication', publication_status)
        self.assertIn('--status "$fallback"', publication_status)
        self.assertNotIn('if [ "$PUBLISH_OUTCOME" != success ]', publication_status)

    def test_no_new_network_or_quality_bypass(self):
        self.assertNotIn('minimum_retained_fraction', self.workflow)
        self.assertNotIn('--skip-validation', self.workflow)
        self.assertNotIn('--force', self.workflow)
        publish = self.workflow.split('\n  publish:\n')[1]
        self.assertIn('needs: build', publish)
        self.assertIn("if: github.event_name == 'schedule' || inputs.publish", publish)


if __name__ == '__main__':
    unittest.main()

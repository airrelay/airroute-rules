"""Basic publication engineering checks with frozen synthetic inputs."""
import copy
import json
import unittest
import test_pipeline as fixture_module
from airroute_data.ardb import read_database,write_database
from airroute_data.coverage import profiles
from airroute_data.validation import file_digest,validate_candidate,parse_list


class IntegrationReviewTests(unittest.TestCase):
    def setUp(self):
        self.fixture=fixture_module.PipelineTests();self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)

    def rebind(self,target,manifest):
        for rec in manifest['files']:
            path=target/rec['path'];rec.update(bytes=path.stat().st_size,sha256=file_digest(path))
        manifest['product_coverage']=profiles({p.relative_to(target).as_posix()[:-5]:parse_list(p) for p in target.rglob('*.list')})
        (target/'manifest.json').write_text(json.dumps(manifest))

    def test_summary_coverage_is_verified_against_regional_list_bytes(self):
        target,manifest=self.fixture.run_build()
        for key in ('geo_v4_addresses','geo_v6_addresses'):
            with self.subTest(key=key):
                forged=copy.deepcopy(manifest);forged['summary'][key]=10**50
                (target/'manifest.json').write_text(json.dumps(forged))
                with self.assertRaisesRegex(ValueError,'summary|coverage'):validate_candidate(target)

    def test_region_overlap_fails_even_after_hashes_and_summary_are_updated(self):
        target,manifest=self.fixture.run_build()
        path=target/'region/cn-ip.list';path.write_text(path.read_text()+'IP-CIDR,2.2.2.0/24\n')
        manifest['summary']['geo_prefixes']+=1;manifest['summary']['geo_v4_addresses']+=256
        self.rebind(target,manifest)
        with self.assertRaisesRegex(ValueError,'overlapping regional'):validate_candidate(target)

    def test_asn_ipv6_loss_is_detected_even_when_counts_and_hashes_match(self):
        target,manifest=self.fixture.run_build();path=target/'special/asn.ardb'
        groups=read_database(path,'asn');groups={asn:[p for p in rows if ':' not in p] for asn,rows in groups.items()}
        groups={asn:rows for asn,rows in groups.items() if rows};write_database(path,'asn',groups)
        manifest['summary']['asn_groups']=len(groups);manifest['summary']['asn_prefixes']=sum(map(len,groups.values()))
        self.rebind(target,manifest)
        with self.assertRaisesRegex(ValueError,'lost an address family'):validate_candidate(target)


if __name__=='__main__':unittest.main()

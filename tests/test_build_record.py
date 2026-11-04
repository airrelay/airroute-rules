import contextlib
import gzip
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import test_pipeline as fixture_module
import test_cross_repo_publish as publication_fixtures
from airroute_data.acquire import acquire_sources
from airroute_data.cli import main
from airroute_data.explain import explain
from airroute_data.geo import CountryRecord, fuse_country, parse_source
from airroute_data.pipeline import build, build_domain_candidate
from airroute_data.record import BuildRecord, clean, collect, pack, set_status
from airroute_data.routing import RoutingRecord, fuse_routes


class BuildRecordTests(unittest.TestCase):
    def fixture(self):
        fixture = fixture_module.PipelineTests('test_full_pipeline_reproducible_geo_list_moas_cn_exclusion')
        fixture.setUp(); self.addCleanup(fixture.doCleanups)
        return fixture

    def test_full_trace_does_not_change_candidate_bytes_and_explains_coverage(self):
        f = self.fixture()
        baseline, first = f.run_build()
        record = BuildRecord(f.root/'record')
        try:
            second = build(f.snapshot/'snapshot.json', f.root/'traced', f.config, trace=record)
            collect(record, f.root/'traced', baseline)
            record.finish('success')
            self.assertFalse(record.broken, record.state['diagnostic_errors'])
        finally: record.close()
        self.assertEqual(first, second)
        for row in first['files']:
            self.assertEqual((baseline/row['path']).read_bytes(), (f.root/'traced'/row['path']).read_bytes())
        domain = explain(f.root/'record', domain='only.mainland.example')
        self.assertTrue(any(row.get('covering_predicate')=='DOMAIN-SUFFIX,mainland.example' for row in domain['events']['records']))
        self.assertTrue(any(row['product']=='region/cn-domain' for row in domain['final_matching_rules']['records']))
        ip = explain(f.root/'record', ip='1.1.1.200')
        self.assertEqual(ip['geo_issue']['records'][0]['status'],'primary-selected')
        self.assertTrue(ip['recorded_geo_decision']['recorded_conflicts'])
        self.assertFalse(ip['recorded_geo_decision']['unknown_reasons'])
        self.assertEqual(ip['source_selection']['selected_source'],'country-a')
        self.assertEqual({r['country'] for r in ip['geo_input']['records']},{'AU','SG'})
        self.assertTrue(all(r['original_fields_recorded'] for r in ip['geo_input']['records']))
        self.assertEqual({r['raw_fields']['country_code'] for r in ip['geo_input']['records']},{'AU','SG'})
        asn = explain(f.root/'record', asn=2)
        self.assertEqual(asn['inputs']['records'][0]['details']['asns'],[2])
        self.assertTrue(asn['output_prefixes']['records'])
        summary = json.loads((f.root/'record/summary.json').read_text())
        self.assertTrue(summary['source_processing'])
        self.assertTrue(summary['bgp']['regions'])
        self.assertTrue((f.root/'record/comparison.json').exists())
        overview=(f.root/'record/overview.md').read_text()
        self.assertIn(first['data_version'],overview)
        self.assertIn('未核实发布状态的比较基线',overview)

    def test_quality_failure_preserves_original_error_comparison_and_full_index(self):
        f=self.fixture(); baseline,_=f.run_build()
        output=f.root/'rejected'; directory=f.root/'record'
        errors=io.StringIO()
        with patch('airroute_data.pipeline.validate_candidate',side_effect=ValueError('invalid ASN directory boundary')), contextlib.redirect_stderr(errors),contextlib.redirect_stdout(io.StringIO()):
            code=main(['build','--snapshot',str(f.snapshot/'snapshot.json'),'--output',str(output),
                       '--config-dir',str(f.config),'--baseline',str(baseline),'--record-dir',str(directory),'--report',str(f.root/'build.json')])
        self.assertEqual(code,1)
        self.assertIn('invalid ASN directory boundary',errors.getvalue())
        summary=json.loads((directory/'summary.json').read_text())
        self.assertEqual(summary['status'],'failed');self.assertEqual(summary['publication']['status'],'skipped')
        self.assertIn('invalid ASN directory boundary',summary['error'])
        self.assertTrue((directory/'comparison.json').is_file())
        self.assertTrue(explain(directory, ip='1.1.1.200')['geo_issue']['records'])
        self.assertEqual(json.loads((f.root/'build.json').read_text())['status'],'failed')
        set_status(directory,'skipped','build failed')
        self.assertEqual(json.loads((directory/'summary.json').read_text())['status'],'failed')

    def test_missing_disabled_failed_empty_and_malformed_inputs_are_distinct(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); conf=root/'sources.json'
            conf.write_text(json.dumps({'schema':1,'sources':[
                {'id':'disabled','enabled':False},
                {'id':'credentials','requires_env':['AIRROUTE_RECORD_TEST_NONEXISTENT_SECRET']},
                {'id':'offline','transport':'http','url':'https://example.invalid/data'}]}))
            record=BuildRecord(root/'record')
            try:
                snapshot=acquire_sources(conf,root/'snapshot',allow_network=False,trace=record)
                self.assertEqual([r['status'] for r in snapshot['sources']],['disabled','missing-credentials','unavailable'])
                empty=root/'empty.csv';empty.write_text('network,country_code\n')
                self.assertEqual(list(parse_source('country-csv',empty,{'id':'empty'},trace=record)),[])
                bad=root/'bad.csv';bad.write_text('network,country_code\n2400::/32,CN\nnot-an-ip,US\n')
                with self.assertRaises(ValueError): list(parse_source('country-csv',bad,{'id':'bad'},trace=record))
                record.finish('failed')
                rows=record.connection.execute('SELECT source,status,details FROM source_event').fetchall()
                self.assertIn(('empty','empty'),[(s,status) for s,status,data in rows])
                stats=next(json.loads(d) for s,status,d in rows if s=='bad' and status=='failed')
                self.assertEqual(stats['records_parsed'],1);self.assertGreater(stats['records_read'],stats['records_parsed'])
            finally:record.close()

    def test_wide_ipv6_observed_bgp_is_not_derived_asn_or_quarantined_default(self):
        with tempfile.TemporaryDirectory() as tmp:
            record=BuildRecord(tmp)
            try:
                fuse_country([CountryRecord.network('2400::/32','CN','a'),CountryRecord.network('2400::/32','US','b')],
                             Path(__file__).resolve().parents[1]/'config/regions.json',source_order=['a','b'],trace=record)
                fuse_routes([RoutingRecord.network('2400:0:1::/48',[1],'observed'),
                             RoutingRecord.network('2400::/32',[2],'derived',raw_prefix_claim=False),
                             RoutingRecord.network('::/0',[3],'bad-default')],trace=record)
                record.finish('success');self.assertFalse(record.broken,record.state['diagnostic_errors'])
                state=record.state['bgp']['issues']['ipv6/primary-selected']
                self.assertEqual(state['observed_bgp_addresses'],2**80)
                self.assertEqual(state['not_observed_bgp_addresses'],2**96-2**80)
                self.assertEqual(state['interval_cidr_sum'],1)
                self.assertEqual(record.state['bgp']['default_forwarding_observations'],{'6':1})
                sample=next(r for r in record.state['largest_conflict_or_unknown_ranges_sample'] if r['status']=='primary-selected')
                self.assertEqual(sample['observed_bgp_addresses'],2**80)
            finally:record.close()

    def test_references_are_redacted_in_config_errors_urls_and_pack(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); record=BuildRecord(root/'record');reference='$TEST_SECRET'
            try:
                config=root/'config';config.mkdir()
                (config/'source.json').write_text(json.dumps({'auth':reference,'url':'https://'+reference+'@example.org/data?token='+reference,'token':reference}))
                record.inputs({'sources':[]},config)
                record.stage('test','failed',error='Authorization: '+reference)
                record.finish('failed')
            finally:record.close()
            for p in (root/'record').rglob('*'):
                if p.suffix in {'.json','.md'}:self.assertNotIn(reference,p.read_text())
            index=pack(root/'record',root/'packed');self.assertTrue(index['complete'])
            self.assertEqual(gzip.decompress((root/'packed/trace.sqlite3.gz').read_bytes()),(root/'record/trace.sqlite3').read_bytes())
            tiny=pack(root/'record',root/'tiny',max_bytes=1)
            self.assertFalse(tiny['complete']);self.assertTrue(tiny['excluded'])
            self.assertFalse(tiny['evidence_complete'])
            self.assertTrue(all(item['compressed_bytes'] > 0 for item in tiny['excluded']))
            self.assertEqual(index['budget_bytes'],1024*1024*1024)

    def test_diagnostic_error_does_not_mask_build_failure_or_success(self):
        f=self.fixture(); impossible=f.root/'not-a-directory';impossible.write_text('keep')
        with contextlib.redirect_stdout(io.StringIO()),contextlib.redirect_stderr(io.StringIO()):
            result=main(['build','--snapshot',str(f.snapshot/'snapshot.json'),'--output',str(f.root/'candidate'),
                         '--config-dir',str(f.config),'--record-dir',str(impossible)])
        self.assertEqual(result,0);self.assertEqual(impossible.read_text(),'keep')

    def test_redaction_reads_credentials_once_for_nested_object(self):
        payload = {'rows': [{'country': 'CN', 'note': 'example-secret'} for _ in range(100)],
                   'url': 'https://user:pass@example.org/data?token=secret', 'token': 'never-persist'}
        with patch('airroute_data.record.os.environ.get', side_effect=lambda key: 'example-secret' if key=='GH_TOKEN' else None) as get:
            result = clean(payload)
        self.assertEqual(get.call_count, 6)
        self.assertEqual(result['rows'][0]['note'], '[redacted]')
        self.assertEqual(result['url'], 'https://example.org/data')
        self.assertEqual(result['token'], '[redacted]')

    def test_special_asn_observation_is_not_compiled_as_public_membership(self):
        with tempfile.TemporaryDirectory() as tmp:
            record=BuildRecord(tmp)
            try:
                routed=fuse_routes([RoutingRecord.network('1.0.0.0/24',[1,64512],'rib')],trace=record)
                record.route_outputs(routed['groups']);record.finish('success')
            finally:record.close()
            result=explain(tmp,ip='1.0.0.1')
            self.assertEqual(result['route_input']['records'][0]['details']['asns'],[1,64512])
            self.assertEqual(result['asn_point_selection']['expected_asns_from_recorded_inputs'],[1])
            self.assertEqual(result['asn_point_selection']['stored_asns'],[1])

    def test_upstream_resolution_modifier_removal_is_audited(self):
        from airroute_data.domains import build_domains
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);source=root/'source.list'
            source.write_text('IP-CIDR,1.0.0.0/24,no-resolve\nIP-ASN,132203,no-resolve\n')
            record=BuildRecord(root/'record')
            try:
                groups,_=build_domains([{'id':'upstream','path':str(source),'format':'surge','status':'available'}],
                    {'schema':1,'groups':[{'id':'region/cn-domain','selectors':[]},
                    {'id':'provider/test','selectors':[{'source':'upstream'}]}]},trace=record)
                self.assertEqual(set(groups['provider/test']),{'IP-CIDR,1.0.0.0/24','IP-ASN,132203'})
                record.product_outputs(groups,{})
                record.finish('success');self.assertFalse(record.broken,record.state['diagnostic_errors'])
            finally:record.close()
            result=explain(root/'record',ip='1.0.0.1')
            conversion=[r for r in result['rule_events']['records'] if r.get('reason')=='upstream-resolution-modifier-removed']
            self.assertEqual(conversion[0]['removed_modifiers'],['no-resolve'])
            asn=explain(root/'record',asn=132203)
            self.assertEqual(asn['rule_references']['records'][0]['value'],'132203')
            self.assertNotIn('no-resolve',','.join(asn['rule_references']['records'][0].values()))

    def test_index_lookup_is_bounded_and_ipv6_exact(self):
        with tempfile.TemporaryDirectory() as tmp:
            record=BuildRecord(tmp)
            try:
                for i in range(500):record.geo_input(CountryRecord.network(f'2400::{i:x}/128','CN','test'))
                record.finish('success')
            finally:record.close()
            result=explain(tmp,ip='2400::1ff',limit=5)
            self.assertEqual(result['geo_input']['records'],[])
            result=explain(tmp,ip='2400::1f3',limit=5)
            self.assertEqual(len(result['geo_input']['records']),1)
            broad=explain(tmp,ip='2400::/112',limit=5)
            self.assertTrue(broad['geo_input']['has_more']);self.assertEqual(len(broad['geo_input']['records']),5)

    def test_geo_decision_is_independent_of_asn_page_limit(self):
        with tempfile.TemporaryDirectory() as tmp:
            record=BuildRecord(tmp)
            try:
                record.route_outputs({123:['2400::/32']})
                record.product_outputs({'region/cn-ip':['IP-CIDR6,2400::/32']},{})
                record.finish('success')
            finally:record.close()
            result=explain(tmp,ip='2400::1',limit=1)
            self.assertTrue(result['output_ip']['has_more'])
            self.assertEqual(result['recorded_geo_decision']['regions'],['region/cn-ip'])

    def test_interrupted_build_never_inherits_acquisition_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            record=BuildRecord(tmp);record.finish('acquisition-success');record.close()
            record=BuildRecord(tmp);record.stage('build','started');record.stage('geo','started');record.close()
            set_status(tmp,'skipped','generation was interrupted',workflow_status='failure')
            summary=json.loads((Path(tmp)/'summary.json').read_text())
            self.assertEqual(summary['status'],'interrupted')
            self.assertEqual(summary['workflow_status'],'failure')

    def test_confirmed_and_unconfirmed_publication_identity_is_retained(self):
        f=publication_fixtures.CrossRepositoryPublicationTests('test_distinct_empty_target_can_publish_main_with_ordinary_push')
        f.setUp();self.addCleanup(f.doCleanups)
        candidate=f.fixture.candidate()
        common=['publish','--repo',str(f.repo),'--source-sha',f.sha,'--remote','products','--branch','main','--source-remote','origin']
        directory=f.root/'publication-record'
        with contextlib.redirect_stdout(io.StringIO()),contextlib.redirect_stderr(io.StringIO()):
            code=main(common+['--candidate',str(candidate),'--sequence','1','--record-dir',str(directory)])
        self.assertEqual(code,0)
        summary=json.loads((directory/'summary.json').read_text())
        self.assertEqual(summary['publication']['status'],'published')
        self.assertEqual(summary['publication']['commit'],f.git(f.target,'rev-parse','main'))
        self.assertTrue(any(s['name']=='publication-push' and s['status']=='published' for s in summary['stages']))
        published_files=f.git(f.target,'ls-tree','-r','--name-only','main')
        self.assertNotIn('trace.sqlite3',published_files)
        f.reject_pushes()
        other=f.fixture.candidate('a2');rejected=f.root/'rejected-publication-record'
        errors=io.StringIO()
        with contextlib.redirect_stdout(io.StringIO()),contextlib.redirect_stderr(errors):
            code=main(common+['--candidate',str(other),'--sequence','2','--record-dir',str(rejected)])
        self.assertEqual(code,1);self.assertIn('not confirmed',errors.getvalue())
        value=json.loads((rejected/'summary.json').read_text())
        self.assertEqual(value['publication']['status'],'failed-or-unconfirmed')
        prepared=next(s for s in value['stages'] if s['name']=='publication-prepared')
        self.assertTrue(prepared['commit'])
        set_status(directory,'failed','post-publication artifact failure',workflow_status='failure',preserve_publication=True)
        self.assertEqual(json.loads((directory/'summary.json').read_text())['publication']['status'],'published')

    def test_lan_ip_exclusions_and_unsupported_mentions_can_be_traced(self):
        with tempfile.TemporaryDirectory() as tmp:
            record=BuildRecord(tmp)
            try:
                record.domain_event({'group':'special/lan','source':'config','predicate':'IP-CIDR,10.0.0.0/8',
                                     'stage':'purpose','status':'accept','reason':'RFC1918'})
                record.domain_event({'group':'special/lan','source':'community','predicate':'IP-CIDR,198.18.0.0/15',
                                     'stage':'scope','status':'excluded','reason':'not a LAN purpose'})
                record.domain_event({'group':'provider/test','source':'community','predicate':'UNSUPPORTED,AND example.org',
                                     'stage':'parse','status':'excluded','reason':'cannot express AND'})
                record.finish('success')
            finally:record.close()
            lan=explain(tmp,ip='10.1.2.3')['rule_events']['records']
            self.assertEqual(lan[0]['reason'],'RFC1918')
            fake=explain(tmp,ip='198.18.1.2')['rule_events']['records']
            self.assertEqual(fake[0]['status'],'excluded')
            self.assertEqual(explain(tmp,domain='example.org')['unparsed_text_mentions'][0]['reason'],'cannot express AND')

    def test_registration_input_is_visible_but_never_a_location_vote(self):
        with tempfile.TemporaryDirectory() as tmp:
            record=BuildRecord(tmp)
            try:
                fuse_country([CountryRecord.network('1.0.0.0/24','CN','registration',semantics='registration'),
                              CountryRecord.network('1.0.0.0/24','CN','location')],
                             Path(__file__).resolve().parents[1]/'config/regions.json',source_order=['registration','location'],trace=record)
                record.finish('success')
            finally:record.close()
            result=explain(tmp,ip='1.0.0.1')
            self.assertEqual(result['recorded_geo_decision']['unknown_reasons'],[])
            self.assertEqual([r['source'] for r in result['selected_source_records']],['location'])

    def test_large_summary_stays_readable_in_downloaded_package(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);record=BuildRecord(root/'record')
            record.state['fixture_padding']='x'*(1024*1024+10)
            record.finish('success');record.close()
            index=pack(root/'record',root/'downloaded')
            self.assertTrue(index['complete']);self.assertTrue((root/'downloaded/summary.json').exists())
            (root/'downloaded/trace.sqlite3').write_bytes(gzip.decompress((root/'downloaded/trace.sqlite3.gz').read_bytes()))
            self.assertEqual(explain(root/'downloaded',domain='example.org')['build_status'],'success')

    def test_asn_longest_match_reason_is_reconstructed_without_fragment_log(self):
        with tempfile.TemporaryDirectory() as tmp:
            record=BuildRecord(tmp)
            try:
                routed=fuse_routes([RoutingRecord.network('1.0.0.0/24',[9],'a','view-one'),
                                    RoutingRecord.network('1.0.0.0/25',[1],'a','view-one'),
                                    RoutingRecord.network('1.0.0.0/24',[2],'b','view-two')],trace=record)
                record.route_outputs(routed['groups']);record.finish('success')
            finally:record.close()
            selected=explain(tmp,ip='1.0.0.1',limit=1)['asn_point_selection']
            self.assertEqual(selected['expected_asns_from_recorded_inputs'],[1,2])
            self.assertEqual(selected['stored_asns'],[1,2])
            self.assertTrue(selected['input_complete'])

    def test_domain_only_record_keeps_retained_asn_query_without_new_observations(self):
        f=self.fixture();baseline,_=f.run_build();record=BuildRecord(f.root/'record')
        try:
            build_domain_candidate(f.snapshot/'snapshot.json',f.root/'refreshed',f.config,baseline=baseline,trace=record)
            record.finish('success');self.assertFalse(record.broken,record.state['diagnostic_errors'])
            self.assertFalse(record.state['bgp']['applicable'])
        finally:record.close()
        result=explain(f.root/'record',asn=2)
        self.assertEqual(result['generation_context']['mode'],'domains-only')
        retained=result['generation_context']['retained_ip_base']
        self.assertIn('region/cn-ip.list',retained['files'])
        self.assertNotIn('geo.ardb',retained['files'])
        self.assertIn('source_acquisition',retained)
        self.assertTrue(result['output_prefixes']['records']);self.assertFalse(result['inputs']['records'])
        point=explain(f.root/'record',ip='1.0.1.1')
        self.assertFalse(point['asn_point_selection']['applicable'])


if __name__=='__main__':unittest.main()

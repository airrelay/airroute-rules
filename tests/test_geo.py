import ipaddress
import json
from pathlib import Path
import tempfile
import unittest

from airroute_data.geo import CountryRecord, bounds, fuse_country, load_registry, load_geo_policy, parse_source

REGISTRY = Path(__file__).resolve().parents[1] / 'config/regions.json'


class GeoTests(unittest.TestCase):
    def setUp(self):
        from airroute_data.address_space import AddressEligibility
        from test_address_space import sources
        self.directory=tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.inputs=sources(Path(self.directory.name))
        self.eligibility=AddressEligibility.from_sources(self.inputs)

    def fusion(self, rows, **kw):
        rows = list(rows)
        order = kw.pop('source_order', tuple(sorted({r.source for r in rows if r.semantics == 'country-estimate'})) or ('a',))
        eligibility=kw.pop('eligibility', self.eligibility)
        return fuse_country(rows, REGISTRY, source_order=order, eligibility=eligibility, **kw)

    def test_registry_is_exclusive_russia_is_own_group(self):
        registry=load_registry(REGISTRY)
        self.assertEqual([r['id'] for r in registry['regions']], list(range(1,17)))
        self.assertEqual([r['key'] for r in registry['regions'] if 'RU' in r['countries']], ['ru'])
        broken=json.loads(REGISTRY.read_text()); broken['regions'][0]['countries'].append('RU')
        with self.assertRaises(ValueError):load_registry(broken)

    def test_crossed_boundaries_keep_primary_and_report_dissent(self):
        rows=[CountryRecord.network('1.0.0.0/24','CN','a'),
              CountryRecord.network('1.0.0.0/25','CN','b'),
              CountryRecord.network('1.0.0.128/26','US','b'),
              CountryRecord.network('1.0.0.192/26',None,'b')]
        result=self.fusion(rows)
        self.assertEqual(result['groups'], {1:['1.0.0.0/24']})
        self.assertEqual(result['report']['coverage']['ipv4']['region-disagreement'],64)
        self.assertNotIn('insufficient-lineages', result['report']['coverage']['ipv4'])
        self.assertEqual(result['report']['special']['cn']['ipv4_assigned_addresses'],256)
        self.assertGreater(result['report']['coverage']['ipv4']['missing-all-sources'],0)

    def test_mirror_lineage_is_recorded_without_votes(self):
        rows=[CountryRecord.network('1.0.0.0/24','CN','upstream','family'),
              CountryRecord.network('1.0.0.0/24','CN','mirror','family')]
        result=self.fusion(rows)
        self.assertEqual(result['groups'],{1:['1.0.0.0/24']})
        self.assertEqual(result['report']['usable_lineages'],['family'])
        self.assertNotIn('minimum_lineages',result['report'])

    def test_same_macroregion_country_disagreement_not_lost(self):
        result=self.fusion([CountryRecord.network('1.0.0.0/24','DE','a'),
                            CountryRecord.network('1.0.0.0/24','IT','b')])
        self.assertEqual(result['groups'],{10:['1.0.0.0/24']})
        self.assertTrue(result['issues'][0]['country_disagreement'])

    def test_more_specific_primary_and_fixed_order_ignore_lineage_voting(self):
        result=self.fusion([CountryRecord.network('1.0.0.0/24','US','a'),
                            CountryRecord.network('1.0.0.0/25','CN','a'),
                            CountryRecord.network('1.0.0.0/24','CN','b')])
        self.assertEqual(result['groups'],{1:['1.0.0.0/25'],11:['1.0.0.128/25']})
        result=self.fusion([CountryRecord.network('1.0.0.0/24','US','a','same'),
                            CountryRecord.network('1.0.0.0/24','CN','b','same'),
                            CountryRecord.network('1.0.0.0/24','CN','c','other')])
        self.assertEqual(result['groups'],{11:['1.0.0.0/24']})

    def test_crossing_intervals_are_not_false_more_specific(self):
        base=int(ipaddress.IPv4Address('1.0.0.0'))
        result=self.fusion([CountryRecord(4,base,base+199,'CN','a','a'),
                            CountryRecord(4,base+100,base+249,'US','a','a'),
                            CountryRecord(4,base,base+255,'CN','b','b')])
        self.assertEqual(result['report']['coverage']['ipv4']['assigned'],256)
        self.assertEqual(result['report']['coverage']['ipv4']['region-disagreement'],150)
        self.assertEqual(result['report']['source_address_support']['b']['ipv4_selected_addresses'],106)

    def test_ipv6_end_sentinel_and_special_space(self):
        rows=[CountryRecord.network('2400::/32','RU','a'),CountryRecord.network('2400::/32','RU','b'),
              CountryRecord.network('10.0.0.0/8','CN','a'),CountryRecord.network('10.0.0.0/8','CN','b'),
              CountryRecord.network('ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128','CN','a')]
        result=self.fusion(rows)
        self.assertEqual(result['groups'],{9:['2400::/32']})
        self.assertEqual(result['report']['excluded_by_geo_eligibility_addresses_sum_per_source']['ipv4'],2*2**24)

    def test_auxiliary_registration_never_votes(self):
        result=self.fusion([CountryRecord.network('1.0.0.0/24','CN','a'),
                            CountryRecord.network('1.0.0.0/24','CN','rir',semantics='registration')])
        self.assertEqual(result['groups'],{1:['1.0.0.0/24']})
        self.assertEqual(result['report']['segments']['auxiliary_rows_ignored'],1)

    def test_iana_documentation_and_benchmark_never_acquire_geography(self):
        from airroute_data.address_space import AddressEligibility
        source=next(row for row in self.inputs if row['id']=='iana-special-v6')
        path=Path(source['path'])
        with path.open('a') as stream:
            stream.write('3fff::/20,Documentation,False,False,False\n2001:2::/48,Benchmark,False,False,False\n')
        from airroute_data.acquire import tree_digest
        source['sha256']=tree_digest(path)[0]
        eligibility=AddressEligibility.from_sources(self.inputs)
        for prefix in ('3fff::/20', '2001:2::/48'):
            with self.subTest(prefix=prefix):
                result = self.fusion([CountryRecord.network(prefix, 'CN', 'a'),
                                      CountryRecord.network(prefix, 'CN', 'b')], eligibility=eligibility)
                self.assertFalse(result['groups'])

    def test_empty_data_reports_contract_gaps_not_overseas(self):
        with tempfile.TemporaryDirectory() as d:
            result=self.fusion([],details_path=Path(d)/'issues.jsonl')
            issues=[json.loads(x) for x in (Path(d)/'issues.jsonl').read_text().splitlines()]
        self.assertFalse(result['groups'])
        self.assertTrue(issues)
        self.assertTrue(all(r['status']=='missing-all-sources' for r in issues))
        self.assertEqual(result['report']['usable_sources'],[])

    def test_deterministic_reordered_records_and_full_details(self):
        rows=[CountryRecord.network('1.0.0.0/24','CN','a'),CountryRecord.network('1.0.0.0/24','US','b')]
        self.assertEqual(self.fusion(rows),self.fusion(list(reversed(rows))))

    def test_configured_source_order_is_required_and_validated(self):
        policy=load_geo_policy(REGISTRY.parent/'geo-policy.json')
        self.assertEqual(policy['primary_source'],'iplocate')
        self.assertEqual(policy['source_order'][0],'iplocate')
        for broken in ({'schema':1,'primary_source':'a','source_order':[]},
                       {'schema':1,'primary_source':'b','source_order':['a','b']},
                       {'schema':1,'primary_source':'a','source_order':['a','a']}):
            with self.assertRaises(ValueError):load_geo_policy(broken)
        with self.assertRaisesRegex(ValueError,'configured order'):
            self.fusion([CountryRecord.network('1.0.0.0/24','CN','extra')],source_order=['primary'])

    def test_missing_primary_estimate_fills_in_configured_order_even_ipv6_only(self):
        rows=[CountryRecord.network('2400::/32',None,'primary'),
              CountryRecord.network('2400::/33','RU','second'),
              CountryRecord.network('2400::/32','CN','third')]
        result=self.fusion(rows,source_order=['primary','second','third'])
        self.assertEqual(result['groups'],{1:['2400:0:8000::/33'],9:['2400::/33']})
        support=result['report']['source_address_support']
        self.assertEqual(support['second']['ipv6_selected_addresses'],2**95)
        self.assertEqual(support['third']['ipv6_selected_addresses'],2**95)
        self.assertEqual(result['report']['source_valid_country_rows']['second'],{'ipv6':1})
        self.assertTrue(all(x['selected_source'] in ('second','third') for x in result['issues'] if x['region_id']))

    def test_ipv6_wide_primary_dissent_and_nested_hole_have_exact_boundaries(self):
        rows=[CountryRecord.network('2808::/13','CH','primary'),
              CountryRecord.network('2808::/64','UY','primary'),
              CountryRecord.network('2808::/13','US','backup')]
        result=self.fusion(rows,source_order=['primary','backup'])
        total=sum(ipaddress.ip_network(n).num_addresses for group in result['groups'].values() for n in group)
        self.assertEqual(total,2**115)
        self.assertIn('2808::/64',result['groups'][13])
        self.assertEqual(result['report']['source_address_support']['primary']['ipv6_selected_addresses'],2**115)
        self.assertEqual(result['report']['coverage']['ipv6']['region-disagreement'],2**115)
        self.assertTrue(all(x['selected_source']=='primary' for x in result['issues'] if x['region_id']))
        # A narrower unknown estimate masks its own broader value, allowing the
        # configured backup to fill only that hole rather than recoloring /13.
        rows[1]=CountryRecord.network('2808::/64',None,'primary')
        hole=self.fusion(rows,source_order=['primary','backup'])
        self.assertEqual(hole['groups'][11],['2808::/64'])
        self.assertEqual(hole['report']['source_address_support']['backup']['ipv6_selected_addresses'],2**64)

    def test_missing_primary_address_does_not_require_two_sources(self):
        result=self.fusion([CountryRecord.network('1.0.0.0/24','CN','backup')],source_order=['primary','backup'])
        self.assertEqual(result['groups'],{1:['1.0.0.0/24']})
        self.assertEqual(result['report']['coverage']['ipv4']['fallback-selected'],256)

    def test_official_country_formats_and_registration_not_fallback(self):
        with tempfile.TemporaryDirectory() as directory:
            d=Path(directory)
            (d/'GeoLite2-Country-Locations-en.csv').write_text('geoname_id,country_iso_code\n1,CN\n2,US\n')
            (d/'GeoLite2-Country-Blocks-IPv4.csv').write_text('network,geoname_id,registered_country_geoname_id\n1.0.0.0/24,,1\n1.0.1.0/24,2,1\n')
            rows=list(parse_source('maxmind-country-csv',d,{'id':'maxmind'}))
            self.assertIsNone(rows[0].country);self.assertEqual(rows[1].country,'US')
            (d/'dbip.csv').write_text('1.0.0.0,1.0.0.255,CN\n')
            self.assertEqual(list(parse_source('dbip-country-csv',d/'dbip.csv',{'id':'dbip'}))[0].country,'CN')
            (d/'ipinfo.csv').write_text('network,country,country_code,asn\n1.0.0.0/24,China,CN,AS1\n')
            self.assertEqual(list(parse_source('ipinfo-lite-csv',d/'ipinfo.csv',{'id':'ipinfo'}))[0].country,'CN')
            (d/'ip2.csv').write_text('"336637624282308039039419983084188827648","336637624282308039039419983084188827903","RU","Russia"\n')
            row=list(parse_source('ip2location-db1-csv',d/'ip2.csv',{'id':'ip2','ip_version':6}))[0]
            self.assertEqual(row.version,6)
            (d/'iplocate.csv').write_text('network,continent_code,country_code,country_name\n1.0.0.0/24,AS,CN,China\n')
            self.assertEqual(list(parse_source('iplocate-country-csv',d/'iplocate.csv',{'id':'iplocate'}))[0].country,'CN')

    def test_malformed_country_source_fails_instead_of_silent_drop(self):
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory)/'bad.csv';p.write_text('network,registered_country\n1.0.0.0/24,CN\n')
            with self.assertRaises(ValueError):list(parse_source('country-csv',p,{'id':'bad'}))
        with self.assertRaises(ValueError):bounds('1.0.0.255','1.0.0.0')
        with self.assertRaises(ValueError):bounds('1.0.0.1/24')

    def test_same_source_ambiguity_is_about_macroregion_not_duplicates_or_country_names(self):
        duplicate=self.fusion([CountryRecord.network('1.0.0.0/24','CN','a'),CountryRecord.network('1.0.0.0/24','CN','a')])
        self.assertEqual(duplicate['groups'],{1:['1.0.0.0/24']})
        same_region=self.fusion([CountryRecord.network('1.0.0.0/24','DE','a'),CountryRecord.network('1.0.0.0/24','IT','a')])
        self.assertEqual(same_region['groups'],{10:['1.0.0.0/24']})
        detail=next(row for row in same_region['issues'] if row.get('sources'))
        self.assertIsNone(detail['selected_country'])
        self.assertTrue(detail['country_disagreement']);self.assertFalse(detail['region_disagreement'])
        ambiguous=self.fusion([CountryRecord.network('1.0.0.0/24','CN','a'),CountryRecord.network('1.0.0.0/24','US','a'),
                               CountryRecord.network('1.0.0.0/24','RU','b')],source_order=['a','b'])
        self.assertEqual(ambiguous['groups'],{9:['1.0.0.0/24']})
        self.assertEqual(ambiguous['report']['source_address_support']['b']['ipv4_selected_addresses'],256)

    def test_frozen_iana_geo_mask_replaces_legacy_aggregate_and_reports_unknown_holes(self):
        from airroute_data.address_space import AddressEligibility
        from test_address_space import sources
        with tempfile.TemporaryDirectory() as tmp:
            eligibility = AddressEligibility.from_sources(sources(Path(tmp)))
            result = self.fusion([CountryRecord.network("4000::/32", "CN", "a"),
                                  CountryRecord.network("3000::/16", "US", "a"),
                                  CountryRecord.network("192.0.0.9/32", "US", "a")], eligibility=eligibility)
        self.assertEqual(result['groups'], {1:['4000::/32']})
        self.assertEqual(result['report']['address_eligibility']['policy'],'frozen-IANA-allocation-and-special-purpose-boundaries')
        self.assertEqual(result['report']['coverage']['ipv6']['assigned'],2**96)
        self.assertEqual(result['report']['coverage']['ipv6']['unknown'],eligibility.report['geo']['6']['addresses']-2**96)
        self.assertEqual(result['report']['coverage']['ipv4']['unknown'],eligibility.report['geo']['4']['addresses'])

    def test_dbip_ipv6_comparison_does_not_fill_unallocated_or_primary_gaps(self):
        from airroute_data.address_space import AddressEligibility
        from test_address_space import sources
        with tempfile.TemporaryDirectory() as tmp:
            eligibility = AddressEligibility.from_sources(sources(Path(tmp)))
            rows=[CountryRecord.network('1.0.0.0/24','CN','primary'),
                  CountryRecord.network('::/0','US','dbip'),
                  CountryRecord.network('2400::/32','RU','backup')]
            result=self.fusion(rows,source_order=['primary','dbip','backup'],eligibility=eligibility,
                               comparison_only_address_families={'dbip':[6]})
        self.assertEqual(result['groups'],{1:['1.0.0.0/24'],9:['2400::/32']})
        support=result['report']['source_address_support']['dbip']
        self.assertNotIn('ipv6_selected_addresses',support)
        self.assertGreater(support['ipv6_comparison_only_addresses'],0)
        self.assertGreater(result['report']['coverage']['ipv6']['comparison-only-evidence'],0)
        self.assertEqual(result['report']['source_rows']['dbip'],1)
        self.assertTrue(all(item['comparison_only_sources']==['dbip'] for item in result['issues'] if item.get('sources')))
        v4=self.fusion([CountryRecord.network('1.0.0.0/24',None,'primary'),CountryRecord.network('1.0.0.0/24','US','dbip')],
                       source_order=['primary','dbip'],comparison_only_address_families={'dbip':[6]})
        self.assertEqual(v4['groups'],{11:['1.0.0.0/24']})

    def test_declared_geo_families_are_enforced_for_every_text_parser(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            header='network,country_code\n'
            for fmt in ('country-csv','iplocate-country-csv','ipinfo-lite-csv','dbip-country-csv'):
                path=root/'input.csv'
                path.write_text('1.0.0.0,1.0.0.255,CN\n' if fmt=='dbip-country-csv' else header+'1.0.0.0/24,CN\n')
                with self.subTest(format=fmt),self.assertRaisesRegex(ValueError,'declared families'):
                    list(parse_source(fmt,path,{'id':'country','role':'country','address_families':[4,6]}))
            path=root/'only6.csv';path.write_text(header+'2400::/32,RU\n')
            self.assertEqual(list(parse_source('country-csv',path,{'id':'v6-backup','role':'country','address_families':[6]}))[0].version,6)
            with self.assertRaisesRegex(ValueError,'outside address_families'):
                list(parse_source('country-csv',path,{'id':'v4','role':'country','address_families':[4]}))
            with self.assertRaisesRegex(ValueError,'contract missing'):
                list(parse_source('country-csv',path,{'id':'missing','role':'country'}))
            path.write_text(header+'2400::/32,ZZ\n')
            with self.assertRaisesRegex(ValueError,'no valid country'):
                list(parse_source('country-csv',path,{'id':'empty-country','role':'country','address_families':[6]}))

    def test_maxmind_requires_both_declared_blocks_and_matching_row_family(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);source={'id':'maxmind','role':'country','address_families':[4,6]}
            (root/'GeoLite2-Country-Locations-en.csv').write_text('geoname_id,country_iso_code\n1,CN\n')
            (root/'GeoLite2-Country-Blocks-IPv4.csv').write_text('network,geoname_id\n1.0.0.0/24,1\n')
            v6=root/'GeoLite2-Country-Blocks-IPv6.csv'
            with self.assertRaisesRegex(ValueError,'Blocks file'):
                list(parse_source('maxmind',root,source))
            v6.write_text('network,geoname_id\n')
            with self.assertRaisesRegex(ValueError,'declared families'):
                list(parse_source('maxmind',root,source))
            v6.write_text('network,geoname_id\n1.0.1.0/24,1\n')
            with self.assertRaisesRegex(ValueError,'differs from file family'):
                list(parse_source('maxmind',root,source))
            v6.write_text('network,geoname_id\n2400::/32,1\n')
            self.assertEqual([row.version for row in parse_source('maxmind',root,source)],[4,6])

    def test_numeric_country_ranges_use_declared_family_not_integer_magnitude(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);path=root/'range.csv';path.write_text('start_ip,end_ip,country_code\n1,255,CN\n')
            row=list(parse_source('country-csv',path,{'id':'small-v6','address_families':[6]}))[0]
            self.assertEqual((row.version,row.start,row.end),(6,1,255))
            with self.assertRaisesRegex(ValueError,'unambiguous'):
                list(parse_source('country-csv',path,{'id':'ambiguous','address_families':[4,6]}))
            path.write_text('"1","255","CN","China"\n')
            row=list(parse_source('ip2location',path,{'id':'v6-only','address_families':[6]}))[0]
            self.assertEqual(row.version,6)
            with self.assertRaisesRegex(ValueError,'family-specific'):
                list(parse_source('ip2location',path,{'id':'both','address_families':[4,6]}))
            directory=root/'bundle';directory.mkdir()
            (directory/'IP2LOCATION-LITE-DB1.CSV').write_text('"16777216","16777471","CN","China"\n')
            (directory/'IP2LOCATION-LITE-DB1.IPV6.CSV').write_text('"1","255","CN","China"\n')
            # A common IPv4 file has no IPV4 token: explicitly named DB1.CSV
            # remains supported when paired with its named IPv6 sibling.
            self.assertEqual({row.version for row in parse_source('ip2location',directory,{'id':'both','address_families':[4,6]})},{4,6})


if __name__=='__main__':unittest.main()

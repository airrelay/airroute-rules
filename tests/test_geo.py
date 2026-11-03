import ipaddress
import json
from pathlib import Path
import tempfile
import unittest

from airroute_data.geo import CountryRecord, bounds, fuse_country, load_registry, parse_source

REGISTRY = Path(__file__).resolve().parents[1] / 'config/regions.json'


class GeoTests(unittest.TestCase):
    def fusion(self, rows, **kw):
        return fuse_country(rows, REGISTRY, **kw)

    def test_registry_is_exclusive_russia_is_own_group(self):
        registry=load_registry(REGISTRY)
        self.assertEqual([r['id'] for r in registry['regions']], list(range(1,17)))
        self.assertEqual([r['key'] for r in registry['regions'] if 'RU' in r['countries']], ['ru'])
        broken=json.loads(REGISTRY.read_text()); broken['regions'][0]['countries'].append('RU')
        with self.assertRaises(ValueError):load_registry(broken)

    def test_crossed_boundaries_consensus_conflict_and_missing(self):
        rows=[CountryRecord.network('1.0.0.0/24','CN','a'),
              CountryRecord.network('1.0.0.0/25','CN','b'),
              CountryRecord.network('1.0.0.128/26','US','b'),
              CountryRecord.network('1.0.0.192/26',None,'b')]
        result=self.fusion(rows)
        self.assertEqual(result['groups'], {1:['1.0.0.0/25']})
        self.assertEqual(result['report']['coverage']['ipv4']['conflicting-regions'],64)
        self.assertEqual(result['report']['coverage']['ipv4']['insufficient-lineages'],64)
        self.assertEqual(result['report']['special']['cn']['ipv4_unresolved_addresses'],128)
        self.assertGreater(result['report']['coverage']['ipv4']['missing-all-sources'],0)

    def test_mirror_cannot_supply_second_vote(self):
        rows=[CountryRecord.network('1.0.0.0/24','CN','upstream','family'),
              CountryRecord.network('1.0.0.0/24','CN','mirror','family')]
        result=self.fusion(rows)
        self.assertEqual(result['groups'],{})
        self.assertEqual(result['report']['usable_lineages'],['family'])

    def test_same_macroregion_country_disagreement_not_lost(self):
        result=self.fusion([CountryRecord.network('1.0.0.0/24','DE','a'),
                            CountryRecord.network('1.0.0.0/24','IT','b')])
        self.assertEqual(result['groups'],{10:['1.0.0.0/24']})
        self.assertTrue(result['issues'][0]['country_disagreement'])

    def test_more_specific_same_source_and_lineage_internal_conflict(self):
        result=self.fusion([CountryRecord.network('1.0.0.0/24','US','a'),
                            CountryRecord.network('1.0.0.0/25','CN','a'),
                            CountryRecord.network('1.0.0.0/24','CN','b')])
        self.assertEqual(result['groups'],{1:['1.0.0.0/25']})
        result=self.fusion([CountryRecord.network('1.0.0.0/24','US','a','same'),
                            CountryRecord.network('1.0.0.0/24','CN','b','same'),
                            CountryRecord.network('1.0.0.0/24','CN','c','other')])
        self.assertFalse(result['groups'])

    def test_crossing_intervals_are_not_false_more_specific(self):
        base=int(ipaddress.IPv4Address('1.0.0.0'))
        result=self.fusion([CountryRecord(4,base,base+199,'CN','a','a'),
                            CountryRecord(4,base+100,base+249,'US','a','a'),
                            CountryRecord(4,base,base+255,'CN','b','b')])
        self.assertEqual(result['report']['coverage']['ipv4']['assigned'],100)
        self.assertEqual(result['report']['coverage']['ipv4']['conflicting-regions'],150)

    def test_ipv6_end_sentinel_and_special_space(self):
        rows=[CountryRecord.network('2400::/32','RU','a'),CountryRecord.network('2400::/32','RU','b'),
              CountryRecord.network('10.0.0.0/8','CN','a'),CountryRecord.network('10.0.0.0/8','CN','b'),
              CountryRecord.network('ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128','CN','a')]
        result=self.fusion(rows)
        self.assertEqual(result['groups'],{9:['2400::/32']})
        self.assertEqual(result['report']['filtered_special_addresses_sum_per_source']['ipv4'],2*2**24)

    def test_auxiliary_registration_never_votes(self):
        result=self.fusion([CountryRecord.network('1.0.0.0/24','CN','a'),
                            CountryRecord.network('1.0.0.0/24','CN','rir',semantics='registration')])
        self.assertFalse(result['groups'])
        self.assertEqual(result['report']['segments']['auxiliary_rows_ignored'],1)

    def test_iana_documentation_and_benchmark_never_acquire_geography(self):
        for prefix in ('3fff::/20', '2001:2::/48'):
            with self.subTest(prefix=prefix):
                result = self.fusion([CountryRecord.network(prefix, 'CN', 'a'),
                                      CountryRecord.network(prefix, 'CN', 'b')])
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


if __name__=='__main__':unittest.main()

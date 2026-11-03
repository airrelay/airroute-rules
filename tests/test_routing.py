import ipaddress
import json
from pathlib import Path
import struct
import tempfile
import unittest

from airroute_data.geo import load_registry
from airroute_data.routing import (AuxiliaryRecord, RoutingRecord, audit_auxiliary,
                                  fuse_routes, parse_mrt, parse_source)


def mrt_record(subtype,payload,kind=13):
    return struct.pack('!IHHI',1,kind,subtype,len(payload))+payload


def peer_index():
    # Two-octet peer ASN deliberately: RIB AS_PATH must still use four octets.
    peer=b'\x00'+ipaddress.IPv4Address('8.8.8.8').packed+ipaddress.IPv4Address('8.8.4.4').packed+struct.pack('!H',64500)
    return mrt_record(1,b'\0'*4+struct.pack('!HH',0,1)+peer)


def rib(prefix,asns,*,asset=False,addpath=False):
    net=ipaddress.ip_network(prefix); length=(net.prefixlen+7)//8
    aspath=bytes([1 if asset else 2,len(asns)])+b''.join(struct.pack('!I',a) for a in asns)
    attrs=bytes([0x40,2,len(aspath)])+aspath
    entry=struct.pack('!HI',0,1)+(struct.pack('!I',123) if addpath else b'')+struct.pack('!H',len(attrs))+attrs
    payload=struct.pack('!I',1)+bytes([net.prefixlen])+net.network_address.packed[:length]+struct.pack('!H',1)+entry
    subtype=(8 if addpath else 2) if net.version==4 else (10 if addpath else 4)
    return mrt_record(subtype,payload)


class RoutingTests(unittest.TestCase):
    def test_longest_prefix_origin_union_across_views(self):
        rows=[RoutingRecord.network('1.0.0.0/24',[10],'ris','peer-a'),
              RoutingRecord.network('1.0.0.128/25',[20,30],'ris','peer-a'),
              RoutingRecord.network('1.0.0.0/24',[40],'rv','peer-b')]
        result=fuse_routes(rows)
        self.assertEqual(result['groups'],{10:['1.0.0.0/25'],20:['1.0.0.128/25'],30:['1.0.0.128/25'],40:['1.0.0.0/24']})
        self.assertEqual(result['report']['coverage']['ipv4_multi_origin_addresses'],256)

    def test_withdrawn_or_absent_not_carried_forward(self):
        before=fuse_routes([RoutingRecord.network('1.0.0.0/24',[10],'one')])
        after=fuse_routes([])
        self.assertTrue(before['groups']);self.assertEqual(after['groups'],{})

    def test_default_route_is_not_universal_asn_ownership(self):
        result=fuse_routes([RoutingRecord.network('0.0.0.0/0',[174],'ris'),
                            RoutingRecord.network('::/0',[1299],'ris6'),
                            RoutingRecord.network('1.0.0.0/24',[13335],'ris')])
        self.assertEqual(result['groups'],{13335:['1.0.0.0/24']})
        self.assertEqual(result['report']['coverage']['ipv4_default_routes_ignored'],1)
        self.assertEqual(result['report']['coverage']['ipv6_default_routes_ignored'],1)

    def test_real_ris_superaggregates_quarantined_but_broad_allocations_retained(self):
        records=[RoutingRecord.network('2000::/3',[24785],'ris','ris6',peer_count=1),
                 RoutingRecord.network('2000::/6',[29632],'ris','ris6',peer_count=3),
                 RoutingRecord.network('2410::/17',[10],'ris','ris6'),
                 RoutingRecord.network('2003::/19',[20],'ris','ris6'),
                 RoutingRecord.network('2002::/16',[6939],'ris','ris6')]
        result=fuse_routes(records)
        self.assertEqual(set(result['groups']),{10,20,6939})
        policy=result['report']['ownership_admission']
        self.assertEqual(policy['quarantined_claim_rows'],2)
        self.assertEqual([(r['prefix'],r['asns'],r['peer_count']) for r in policy['claim_details']],
                         [('2000::/3',[24785],1),('2000::/6',[29632],3)])
        self.assertFalse(policy['claim_details_truncated'])
        self.assertNotIn('3000::/5',result['routed_prefixes'])

    def test_asn_admission_floor_configurable_v4_and_interval_guard(self):
        broad=RoutingRecord.network('8.0.0.0/7',[10],'ris')
        narrow=RoutingRecord.network('8.0.0.0/8',[20],'other')
        result=fuse_routes([broad,narrow])
        self.assertEqual(set(result['groups']),{20})
        self.assertEqual(result['report']['ownership_admission']['minimum_prefix_lengths'],{'ipv4':8,'ipv6':12})
        result=fuse_routes([broad],minimum_prefix_lengths={4:7})
        self.assertEqual(result['groups'],{10:['8.0.0.0/7']})
        with self.assertRaises(ValueError):fuse_routes([],minimum_prefix_lengths={6:129})

    def test_derived_iptoasn_range_not_misread_as_single_bgp_superprefix(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'iptoasn.tsv'
            p.write_text('29.121.1.0\t30.255.255.255\t749\tUS\tProvider-coalesced range\n')
            rows=list(parse_source('iptoasn-tsv',p,{'id':'iptoasn'}))
            self.assertIsNone(rows[0].origin_prefix_length)
            result=fuse_routes(rows)
            self.assertEqual(result['report']['ownership_admission']['quarantined_claim_rows'],0)
            networks=[ipaddress.ip_network(prefix) for prefix in result['groups'][749]]
            self.assertEqual(sum(net.num_addresses for net in networks),25_624_320)
            self.assertEqual(networks[0].network_address,ipaddress.ip_address('29.121.1.0'))
            self.assertEqual(networks[-1].broadcast_address,ipaddress.ip_address('30.255.255.255'))
            p.write_text('network,asn\n8.0.0.0/7,10\n')
            derived=list(parse_source('iplocate-asn-csv',p,{'id':'iplocate-asn'}))
            self.assertIsNone(derived[0].origin_prefix_length)
            self.assertIn(10,fuse_routes(derived)['groups'])
            p.write_text('{"prefix":"8.0.0.0/7","asn":10}\n')
            original=list(parse_source('bgp-tools-jsonl',p,{'id':'bgptools'}))
            self.assertEqual(original[0].origin_prefix_length,7)
            self.assertFalse(fuse_routes(original)['groups'])

    def test_ipv6_dualstack_and_cross_asn_duplicate_retained(self):
        result=fuse_routes([RoutingRecord.network('2400::/32',[10,20],'ris'),
                            RoutingRecord.network('1.0.0.0/24',[10,20],'ris')])
        self.assertEqual(result['groups'][10],result['groups'][20])
        self.assertEqual(result['groups'][10],['1.0.0.0/24','2400::/32'])

    def test_actual_rib_aspath4_for_peer_asn2_asset_and_addpath(self):
        data=peer_index()+rib('1.0.0.0/24',[64500,202662])+rib('2400::/32',[212271,3257],asset=True,addpath=True)
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'rib.mrt';p.write_bytes(data)
            rows=list(parse_mrt(p,'routeviews','rv'))
        self.assertEqual(rows[0].asns,(202662,))
        self.assertEqual(rows[1].asns,(3257,212271))
        self.assertEqual(rows[0].collector,'rv/AS64500@8.8.4.4')

    def test_bad_mrt_truncation_update_unknown_peer_fail(self):
        bad=[peer_index()+rib('1.0.0.0/24',[10])[:-1],mrt_record(1,b'',kind=16),rib('1.0.0.0/24',[10])]
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'bad'
            for blob in bad:
                p.write_bytes(blob)
                with self.assertRaises(ValueError):list(parse_mrt(p,'bad'))

    def test_official_ris_and_iptoasn_and_auxiliary_formats(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'source'
            p.write_text('% Prefix table\n10\t1.0.0.0/24\t5\n{20,30}\t2400::/32\t7\n')
            rows=list(parse_source('ris-whois',p,{'id':'ris'}))
            self.assertEqual(rows[1].asns,(20,30))
            self.assertEqual([row.peer_count for row in rows],[5,7])
            p.write_text('1.0.0.0\t1.0.0.255\t10\tUS\tOrg\n1.0.1.0\t1.0.1.255\t0\tZZ\tNot routed\n')
            self.assertEqual(len(list(parse_source('iptoasn-tsv',p,{'id':'iptoa'}))),1)
            p.write_text('apnic|CN|ipv4|1.0.0.0|256|20260101|allocated\napnic|RU|ipv6|2400::|32|20260101|allocated\n')
            rows=list(parse_source('rir-delegated',p,{'id':'rir'}))
            self.assertEqual(rows[0].kind,'registration');self.assertEqual(rows[1].version,6)
            self.assertFalse(fuse_routes(rows)['groups'])
            p.write_text('# RFC8805\n1.0.0.0/24,CN,CN-BJ,Beijing,\n')
            rows=list(parse_source('geofeed-csv',p,{'id':'feed'}))
            self.assertEqual(rows[0].kind,'operator-geofeed')

    def test_surge_cidr_reference_never_mines_nested_or_domain_rules(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'ChinaMax.list'
            p.write_text('DOMAIN-SUFFIX,cn.example\nIP-CIDR,1.0.0.0/24,no-resolve\n'
                         'IP-CIDR6,2400::/32\nIP6-CIDR,2600::/32,DIRECT\n'
                         'AND,((DOMAIN-SUFFIX,x.example),(IP-CIDR,2.0.0.0/8))\n'
                         'NOT,((IP-CIDR,3.0.0.0/8))\nIP-ASN,202662\n')
            rows=list(parse_source('surge-cidr-reference',p,{'id':'bm-chinamax','lineage':'blackmatrix','country':'CN'}))
        self.assertEqual(len(rows),3)
        self.assertTrue(all(row.kind=='route-list' and row.status=='rule-reference-only' for row in rows))
        self.assertEqual([row.version for row in rows],[4,6,6])
        self.assertFalse(fuse_routes(rows)['groups'])

    def test_routed_union_and_auxiliary_bgp_region_comparison(self):
        routes=fuse_routes([RoutingRecord.network('1.0.0.0/25',[10,20],'ris'),
                            RoutingRecord.network('1.0.0.128/25',[30],'ris'),
                            RoutingRecord.network('2400::/32',[30],'ris')])
        self.assertEqual(routes['routed_prefixes'],['1.0.0.0/24','2400::/32'])
        registry=load_registry(Path(__file__).resolve().parents[1]/'config/regions.json')
        report=audit_auxiliary([],{1:['1.0.0.0/25'],9:['1.0.0.128/26']},registry,
                               routing_prefixes=routes['routed_prefixes'])
        stats=report['sources']['bgp-visible']
        self.assertEqual(stats['ipv4_candidate_addresses'],256)
        self.assertEqual(stats['ipv4_region_cn_addresses'],128)
        self.assertEqual(stats['ipv4_region_ru_addresses'],64)
        self.assertEqual(stats['ipv4_unknown_addresses'],64)
        self.assertEqual(report['input_rows']['bgp-visible'],2)
        self.assertEqual(report['lineage']['bgp-visible'],'current-routing-snapshots-union')

    def test_auxiliary_compared_not_unioned(self):
        registry=load_registry(Path(__file__).resolve().parents[1]/'config/regions.json')
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'cn.txt';p.write_text('1.0.0.0/24\n1.0.0.0/24\n1.0.1.0/24\n')
            report=audit_auxiliary([{'id':'cn','format':'cidr-list','path':str(p),'lineage':'cn-parent'}],
                                   {1:['1.0.0.0/25'],11:['1.0.0.128/25']},registry)
        stats=report['sources']['cn']
        self.assertEqual(stats['ipv4_candidate_addresses'],512)
        self.assertEqual(stats['ipv4_region_cn_addresses'],128)
        self.assertEqual(stats['ipv4_region_us_addresses'],128)
        self.assertEqual(stats['ipv4_unknown_addresses'],256)
        self.assertEqual(report['input_rows']['cn'],3)

    def test_grouped_peer_views_preserve_each_peers_longest_prefix(self):
        from dataclasses import replace
        rows = [RoutingRecord.network('1.0.0.0/24', [10], 'rib', views=['a', 'b']),
                RoutingRecord.network('1.0.0.0/25', [20], 'rib', views=['a'])]
        expanded = [replace(r, collector=view, views=()) for r in rows for view in r.views]
        grouped = fuse_routes(rows)
        self.assertEqual(grouped['groups'], fuse_routes(expanded)['groups'])
        self.assertIn('1.0.0.0/24', grouped['groups'][10])
        self.assertEqual(grouped['groups'][20], ['1.0.0.0/25'])
        self.assertEqual(grouped['report']['source_rows']['rib'], 3)
        self.assertEqual(grouped['report']['sort_record_rows']['rib'], 2)

    def test_grouped_peer_views_equivalent_to_expanded_overlapping_moas(self):
        import random
        from dataclasses import replace
        for seed in range(10):
            rng = random.Random(seed)
            rows = [RoutingRecord.network(f'1.0.{rng.randrange(4)}.0/{rng.choice([24,25,26])}',
                      rng.sample(range(10, 16), rng.randint(1, 3)), 'rib',
                      views=rng.sample(['a', 'b', 'c', 'd'], rng.randint(1, 4))) for _ in range(30)]
            expanded = [replace(r, collector=view, views=()) for r in rows for view in r.views]
            one, two = fuse_routes(rows), fuse_routes(expanded)
            self.assertEqual(one['groups'], two['groups'])
            self.assertEqual(one['routed_prefixes'], two['routed_prefixes'])

    def test_rir_country_subsets_are_not_replaced_by_last_source_row(self):
        registry=load_registry(Path(__file__).resolve().parents[1]/'config/regions.json')
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'rir.txt'
            path.write_text('ripencc|CN|ipv4|1.0.0.0|128|20260101|allocated\n'
                            'ripencc|RU|ipv4|1.0.0.128|128|20260101|allocated\n')
            report=audit_auxiliary([{'id':'rir','format':'rir-delegated','path':str(path)}],
                                  {1:['1.0.0.0/25'],9:['1.0.0.128/25']},registry)
        country=report['cn_ru_by_declared_country']['rir']
        self.assertEqual(country['CN']['ipv4_region_cn_addresses'],128)
        self.assertEqual(country['RU']['ipv4_region_ru_addresses'],128)
        self.assertNotIn('ipv4_region_cn_addresses',country['RU'])


if __name__=='__main__':unittest.main()

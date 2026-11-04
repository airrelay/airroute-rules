import ipaddress
from dataclasses import replace
import json
from pathlib import Path
import struct
import tempfile
import unittest

from airroute_data.geo import load_registry
from airroute_data.routing import (AuxiliaryRecord, RoutingRecord, audit_auxiliary,
                                  fuse_routes as _fuse_routes, fuse_asn, parse_mrt, parse_source)


class FixtureEligibility:
    def asn_intervals(self, family, start, end):
        yield start, end


def fuse_routes(records, **kwargs):
    return _fuse_routes(records, eligibility=kwargs.pop("eligibility", FixtureEligibility()), **kwargs)


def mrt_record(subtype,payload,kind=13):
    return struct.pack('!IHHI',1,kind,subtype,len(payload))+payload


def peer_index(view=b''):
    # Two-octet peer ASN deliberately: RIB AS_PATH must still use four octets.
    peer=b'\x00'+ipaddress.IPv4Address('8.8.8.8').packed+ipaddress.IPv4Address('8.8.4.4').packed+struct.pack('!H',64500)
    return mrt_record(1,b'\0'*4+struct.pack('!H',len(view))+view+struct.pack('!H',1)+peer)


def rib(prefix,asns,*,asset=False,addpath=False,peer=0):
    net=ipaddress.ip_network(prefix); length=(net.prefixlen+7)//8
    aspath=bytes([1 if asset else 2,len(asns)])+b''.join(struct.pack('!I',a) for a in asns)
    attrs=bytes([0x40,2,len(aspath)])+aspath
    entry=struct.pack('!HI',peer,1)+(struct.pack('!I',123) if addpath else b'')+struct.pack('!H',len(attrs))+attrs
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
        self.assertEqual(result['report']['coverage']['ipv4_default_forwarding_observations'],1)
        self.assertEqual(result['report']['coverage']['ipv6_default_forwarding_observations'],1)

    def test_observed_wide_prefixes_are_retained_without_ownership_claim(self):
        records=[RoutingRecord.network('2000::/3',[24785],'ris','ris6',peer_count=1),
                 RoutingRecord.network('2000::/6',[29632],'ris','ris6',peer_count=3),
                 RoutingRecord.network('2410::/17',[10],'ris','ris6'),
                 RoutingRecord.network('8.0.0.0/7',[20],'other')]
        result=fuse_routes(records)
        self.assertEqual(set(result['groups']),{10,20,24785,29632})
        self.assertTrue(any(ipaddress.ip_address('3000::') in ipaddress.ip_network(n) for n in result['groups'][24785]))
        self.assertTrue(any(ipaddress.ip_address('2100::') in ipaddress.ip_network(n) for n in result['groups'][29632]))
        self.assertEqual(result['groups'][20],['8.0.0.0/7'])
        self.assertEqual(result['report']['input_families'],[4,6])
        self.assertEqual(result['report']['original_prefix_lengths']['ipv6/3'],1)
        self.assertIn('not proof of ownership',result['report']['wide_prefix_policy'])
        self.assertNotIn('ownership_admission',result['report'])

    def test_ris_aggregate_rows_never_invent_a_shared_peer(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'ris.txt'
            p.write_text('10 1.0.0.0/24 2\n20 1.0.0.128/25 1\n')
            rows=list(parse_source('ris-whois',p,{'id':'ris'}))
        result=fuse_routes(rows)
        self.assertEqual(result['groups'],{10:['1.0.0.0/24'],20:['1.0.0.128/25']})
        self.assertNotEqual(rows[0].views,rows[1].views)
        self.assertEqual(result['report']['collector_views'],[])
        self.assertEqual(result['report']['aggregate_claim_rows'],{'ris':2})

    def test_iana_nonpublic_asns_remain_observations_not_global_membership(self):
        class Trace:
            def __init__(self):self.rows=[]
            def route_input(self,*args):self.rows.append(args)
        trace=Trace()
        result=fuse_routes([RoutingRecord.network('1.0.0.0/24',[0,112,23456,64496,64512,4200000000,4294967295,13335],'sample'),
                            RoutingRecord.network('2400::/32',[64512],'sample')],trace=trace)
        self.assertEqual(set(result['groups']),{112,13335})
        self.assertEqual(result['report']['input_families'],[4])
        self.assertEqual(trace.rows[0][0].asns,(0,112,13335,23456,64496,64512,4200000000,4294967295))
        self.assertEqual(trace.rows[0][0].compiled_asns,(112,13335))
        self.assertEqual(trace.rows[1][1],'observed-only')
        self.assertIn('registry',result['report']['special_asns'])

    def test_derived_iptoasn_range_not_misread_as_single_bgp_superprefix(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'iptoasn.tsv'
            p.write_text('29.121.1.0\t30.255.255.255\t749\tUS\tProvider-coalesced range\n')
            rows=list(parse_source('iptoasn-tsv',p,{'id':'iptoasn'}))
            self.assertIsNone(rows[0].origin_prefix_length)
            result=fuse_routes(rows)
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
            self.assertEqual(fuse_routes(original)['groups'],{10:['8.0.0.0/7']})

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
        self.assertEqual(rows[0].collector,'routeviews/rv/view:0.0.0.0:/AS64500@8.8.4.4#8.8.8.8')

    def test_mrt_keeps_different_peer_bgp_ids_and_sources_separate(self):
        address=ipaddress.IPv4Address('8.8.4.4').packed
        peers=b''.join(b'\x00'+ipaddress.IPv4Address(bgp).packed+address+struct.pack('!H',64500)
                       for bgp in ('8.8.8.8','8.8.8.9'))
        data=mrt_record(1,b'\0'*4+struct.pack('!HH',0,2)+peers)
        data+=rib('1.0.0.0/24',[10],peer=0)+rib('1.0.0.128/25',[20],peer=1)
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'rib.mrt';p.write_bytes(data)
            rows=list(parse_mrt(p,'first-source','same-collector'))
            other=list(parse_mrt(p,'second-source','same-collector'))
        result=fuse_routes(rows)
        self.assertEqual(result['groups'],{10:['1.0.0.0/24'],20:['1.0.0.128/25']})
        self.assertNotEqual(rows[0].views,rows[1].views)
        self.assertNotEqual(rows[0].views,other[0].views)

    def test_mrt_peer_index_named_views_do_not_mask_each_other(self):
        data=peer_index(b'view-a')+rib('1.0.0.0/24',[10])
        data+=peer_index(b'view-b')+rib('1.0.0.128/25',[20])
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'rib.mrt';p.write_bytes(data)
            rows=list(parse_mrt(p,'rib','collector'))
        self.assertNotEqual(rows[0].views,rows[1].views)
        self.assertEqual(fuse_routes(rows)['groups'],{10:['1.0.0.0/24'],20:['1.0.0.128/25']})

    def test_declared_ipv6_source_cannot_silently_parse_ipv4(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'wrong-family.txt';p.write_text('10 1.0.0.0/24 1\n')
            with self.assertRaisesRegex(ValueError,'address family'):
                list(parse_source('ris-whois',p,{'id':'ris-v6','ip_version':6}))

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
            self.assertEqual([r.asns for r in parse_source('iptoasn-tsv',p,{'id':'iptoa'})],[(10,),(0,)])
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




class FormalAsnTests(unittest.TestCase):
    SOURCE = {'id':'maxmind-asn','role':'asn','address_families':[4,6]}

    def bundle(self, root, *, v4=None, v6=None, header=None):
        import csv
        header = header or ['network','autonomous_system_number','autonomous_system_organization','future_field']
        for family, rows in ((4,v4 if v4 is not None else [['1.0.0.0/24','13335','Example, Inc.','new']]),
                             (6,v6 if v6 is not None else [['2400::/32','3257',None,'extra']])):
            with (root/f'GeoLite2-ASN-Blocks-IPv{family}.csv').open('w',newline='') as stream:
                writer=csv.writer(stream);writer.writerow(header);writer.writerows(rows)

    def formal(self, prefix, values):
        from dataclasses import replace
        row=RoutingRecord.network(prefix,values,'maxmind-asn',raw_prefix_claim=False)
        return replace(row,semantics='asn-provider-prefix')

    def test_official_csv_named_fields_allow_org_commas_null_and_extra_columns(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);self.bundle(root)
            rows=list(parse_source('maxmind-asn-csv',root,self.SOURCE))
        self.assertEqual([r.asns for r in rows],[(13335,),(3257,)])
        self.assertTrue(all(r.semantics=='asn-provider-prefix' and r.origin_prefix_length is None for r in rows))
        result=fuse_asn(rows,eligibility=FixtureEligibility())
        self.assertEqual(result['groups'],{3257:['2400::/32'],13335:['1.0.0.0/24']})
        self.assertEqual(result['report']['expected_families'],[4,6])

    def test_required_dual_blocks_missing_empty_or_wrong_family_fails(self):
        for problem in ('missing-v6','empty-v6','wrong-v6','header-missing-asn'):
            with self.subTest(problem=problem),tempfile.TemporaryDirectory() as directory:
                root=Path(directory)
                if problem=='header-missing-asn':
                    self.bundle(root,header=['network','wrong','org','extra'])
                else:self.bundle(root,v6=[] if problem=='empty-v6' else [['1.0.0.0/24','3257','','']] if problem=='wrong-v6' else None)
                if problem=='missing-v6':(root/'GeoLite2-ASN-Blocks-IPv6.csv').unlink()
                with self.assertRaises(ValueError):list(parse_source('maxmind-asn-csv',root,self.SOURCE))

    def test_formal_family_contract_rejects_missing_empty_duplicate_bool_and_string(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);self.bundle(root)
            for value in (None,[],[4],[6],[4,4,6],[True,6],['4',6],'4,6'):
                source=dict(self.SOURCE)
                if value is None:source.pop('address_families')
                else:source['address_families']=value
                with self.subTest(value=value),self.assertRaises(ValueError):
                    list(parse_source('maxmind-asn-csv',root,source))

    def test_deep_unknown_and_special_children_shadow_before_asn_filter(self):
        rows=[self.formal('1.0.0.0/24',[10]),self.formal('1.0.0.0/25',[0]),
              self.formal('1.0.0.0/26',[20]),self.formal('1.0.0.0/27',[64512]),
              self.formal('1.0.0.128/26',[]),self.formal('2400::/120',[30]),
              self.formal('2400::/121',[64512]),self.formal('2400::/122',[40]),
              self.formal('2400::/123',[])]
        result=fuse_asn(rows,eligibility=FixtureEligibility())
        self.assertEqual(result['groups'],{10:['1.0.0.192/26'],20:['1.0.0.32/27'],
                                           30:['2400::80/121'],40:['2400::20/123']})
        self.assertEqual(result['report']['parsed_input_families'],[4,6])
        self.assertGreater(result['report']['coverage']['ipv6_unknown_or_special_asn_addresses'],0)

    def test_equal_specific_asn_sets_retained_and_no_bgp_can_fill_formal(self):
        rows=[self.formal('1.0.0.0/24',[10]),self.formal('1.0.0.0/24',[20]),self.formal('2400::/32',[30])]
        result=fuse_asn(rows,eligibility=FixtureEligibility())
        self.assertEqual(result['groups'][10],result['groups'][20])
        with self.assertRaisesRegex(ValueError,'only the configured ASN provider'):
            fuse_asn(rows+[RoutingRecord.network('1.0.1.0/24',[99],'bgp')],eligibility=FixtureEligibility())
        with self.assertRaisesRegex(ValueError,'exactly one provider'):
            fuse_asn(rows+[replace(self.formal('2.0.0.0/24',[10]),source='other')],eligibility=FixtureEligibility())

    def test_mrt_ignores_unused_nlri_padding_for_v4_and_v6(self):
        from airroute_data.routing import _prefix
        v4,offset=_prefix(bytes([25,1,0,0,0xff]),0,4)
        self.assertEqual((v4,offset),('1.0.0.128/25',5))
        v6,offset=_prefix(bytes([33])+bytes.fromhex('24000000ff'),0,6)
        self.assertEqual((v6,offset),('2400:0:8000::/33',6))
        for bad in (bytes([33,1]),bytes([129])+bytes(17)):
            with self.assertRaises(ValueError):_prefix(bad,0,4 if bad[0]==33 else 6)

    def test_comparison_unknown_child_masks_only_same_peer_and_raw_bgp_stays_visible(self):
        rows=[RoutingRecord.network('1.0.0.0/24',[10],'bgp','peer-a'),
              RoutingRecord.network('1.0.0.0/25',[64512],'bgp','peer-a')]
        result=fuse_routes(rows)
        self.assertEqual(result['groups'],{10:['1.0.0.128/25']})
        self.assertEqual(result['observed_prefixes'],['1.0.0.0/24'])
        derived=RoutingRecord(4,int(ipaddress.ip_address('2.0.0.0')),int(ipaddress.ip_address('2.0.0.255')),(20,),'iptoasn')
        result=fuse_routes(rows+[derived])
        self.assertEqual(result['observed_prefixes'],['1.0.0.0/24'])
        self.assertIn('2.0.0.0/24',result['routed_prefixes'])


    def test_formal_asn_uses_iana_asn_reachable_exceptions_not_geo_filter(self):
        from airroute_data.address_space import AddressEligibility
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            contents={
                'iana-alloc-v4':'Prefix,Designation,Status\n192/8,IANA,LEGACY\n',
                'iana-alloc-v6':'Prefix,Designation,Status\n2000::/3,IANA,ALLOCATED\n',
                'iana-special-v4':'Address Block,Name,Globally Reachable,Destination,Forwardable\n192.0.0.0/24,Protocol assignments,False,False,False\n192.0.0.9/32,PCP anycast,True,True,True\n192.0.0.10/32,TURN anycast,True,True,True\n',
                'iana-special-v6':'Address Block,Name,Globally Reachable,Destination,Forwardable\n64:ff9b::/96,Translation,True,True,True\n'}
            sources=[]
            for sid,text in contents.items():
                path=root/(sid+'.csv');path.write_text(text)
                sources.append({'id':sid,'path':str(path),'status':'available'})
            eligibility=AddressEligibility.from_sources(sources)
            self.assertFalse(list(eligibility.geo_intervals(4,int(ipaddress.ip_address('192.0.0.9')),int(ipaddress.ip_address('192.0.0.9')))))
            result=fuse_asn([self.formal('192.0.0.0/24',[10]),self.formal('64:ff9b::/96',[20])],eligibility=eligibility)
            self.assertEqual(result['groups'],{10:['192.0.0.9/32','192.0.0.10/32'],20:['64:ff9b::/96']})


    def test_production_auxiliary_sources_require_each_declared_family_nonempty(self):
        cases=[('rir-delegated','rir','apnic|CN|ipv4|1.0.0.0|256|20260101|allocated\n'),
               ('geofeed-csv','geofeed','1.0.0.0/24,CN,CN-BJ,Beijing,\n'),
               ('china-route-list','cn-reference','1.0.0.0/24\n')]
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'source'
            for format,role,contents in cases:
                path.write_text(contents)
                source={'id':'aux','role':role,'address_families':[4,6]}
                with self.subTest(format=format),self.assertRaisesRegex(ValueError,'no records for a declared address family'):
                    list(parse_source(format,path,source))
                source['address_families']=[4]
                self.assertEqual(len(list(parse_source(format,path,source))),1)
                path.write_text('')
                with self.subTest(empty=format),self.assertRaisesRegex(ValueError,'no records for a declared address family'):
                    list(parse_source(format,path,source))
            path.write_text('not a delegated record\n')
            with self.assertRaisesRegex(ValueError,'no records for a declared address family'):
                list(parse_source('rir-delegated',path,{'id':'rir','role':'rir','address_families':[4,6]}))


if __name__=='__main__':unittest.main()

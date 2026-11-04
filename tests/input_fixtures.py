"""Small frozen source files shared by offline pipeline checks."""
import csv
from pathlib import Path


def write_iana_fixture(root):
    root=Path(root)
    allocation_header=['Prefix','Designation','Status']
    special_header=['Address Block','Name','Globally Reachable','Destination','Forwardable','RFC']
    contents={
        'iana-alloc-v4':(allocation_header,[[prefix,'Synthetic allocated space','ALLOCATED'] for prefix in
            ('001/8','002/8','008/8','192/8','198/8','203/8')]),
        'iana-alloc-v6':(allocation_header,[[prefix,'Synthetic allocated space','ALLOCATED'] for prefix in
            ('2000::/3','4000::/3')]),
        'iana-special-v4':(special_header,[
            ['0.0.0.0/8','This network','False','False','False','RFC 1122'],
            ['10.0.0.0/8','Private-use','False','True','True','RFC 1918'],
            ['100.64.0.0/10','Shared address space','False','True','True','RFC 6598'],
            ['127.0.0.0/8','Loopback','False','True','False','RFC 1122'],
            ['169.254.0.0/16','Link local','False','True','False','RFC 3927'],
            ['172.16.0.0/12','Private-use','False','True','True','RFC 1918'],
            ['192.0.0.0/24','Protocol assignments','False','True','False','RFC 6890'],
            ['192.0.0.9/32','PCP anycast','True','True','True','RFC 7723'],
            ['192.0.0.10/32','TURN anycast','True','True','True','RFC 8155'],
            ['192.0.2.0/24','Documentation','False','True','False','RFC 5737'],
            ['192.168.0.0/16','Private-use','False','True','True','RFC 1918'],
            ['198.18.0.0/15','Benchmarking','False','True','True','RFC 2544'],
            ['198.51.100.0/24','Documentation','False','True','False','RFC 5737'],
            ['203.0.113.0/24','Documentation','False','True','False','RFC 5737'],
            ['224.0.0.0/4','Multicast','False','True','True','RFC 1112'],
            ['240.0.0.0/4','Reserved','False','False','False','RFC 1112'],
            ['255.255.255.255/32','Limited broadcast','False','True','False','RFC 919']]),
        'iana-special-v6':(special_header,[
            ['::/128','Unspecified','False','False','False','RFC 4291'],
            ['::1/128','Loopback','False','True','False','RFC 4291'],
            ['::ffff:0:0/96','IPv4 mapped','False','True','False','RFC 4291'],
            ['64:ff9b::/96','Translation','True','True','True','RFC 6052'],
            ['64:ff9b:1::/48','Local translation','False','True','True','RFC 8215'],
            ['100::/64','Discard-only','False','True','True','RFC 6666'],
            ['2001::/23','Protocol assignments','False','True','True','RFC 2928'],
            ['2001:2::/48','Benchmarking','False','True','True','RFC 5180'],
            ['2001:db8::/32','Documentation','False','True','False','RFC 3849'],
            ['3fff::/20','Documentation','False','True','False','RFC 9637'],
            ['fc00::/7','Unique local','False','True','True','RFC 4193'],
            ['fe80::/10','Link local','False','True','False','RFC 4291'],
            ['ff00::/8','Multicast','False','True','True','RFC 4291']])}
    sources=[]
    for sid,(header,rows) in contents.items():
        path=root/sid
        with path.open('w',newline='') as stream:
            writer=csv.writer(stream);writer.writerow(header);writer.writerows(rows)
        sources.append({'id':sid,'role':'special-reference' if 'special' in sid else 'address-eligibility',
            'format':'iana-special-csv' if 'special' in sid else 'iana-allocation-csv',
            'address_families':[int(sid[-1])],'lineage':'iana','publish_allowed':True,
            'license':'Synthetic IANA-shaped test data'})
    return sources

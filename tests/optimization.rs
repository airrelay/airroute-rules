use airroute_rules::rules::{Rule, optimize, verify_equivalent, verify_ip_equivalent};
use std::collections::BTreeSet;

fn rows(lines: &[&str]) -> BTreeSet<Rule> {
    lines
        .iter()
        .map(|line| {
            let p: Vec<_> = line.split(',').collect();
            Rule::new(p[0], p[1], &p[2..]).unwrap()
        })
        .collect()
}

#[test]
fn borrowed_ip_coverage_accepts_equivalent_splits_without_losing_typed_boundaries() {
    let before = rows(&[
        "IP-CIDR,1.1.1.0/24,no-resolve",
        "IP-CIDR6,::/126,no-resolve",
        "DOMAIN,cn.example",
    ]);
    let split = rows(&[
        "IP-CIDR,1.1.1.0/25,no-resolve",
        "IP-CIDR,1.1.1.128/25,no-resolve",
        "IP-CIDR6,::/127,no-resolve",
        "IP-CIDR6,::2/127,no-resolve",
    ]);
    verify_ip_equivalent(&before, &split).unwrap();
    verify_ip_equivalent(&split, &before).unwrap();
    for invalid in [
        rows(&[
            "IP-CIDR,1.1.1.0/25,no-resolve",
            "IP-CIDR,1.1.1.192/26,no-resolve",
            "IP-CIDR6,::/126,no-resolve",
        ]),
        rows(&["IP-CIDR,1.1.1.0/24", "IP-CIDR6,::/126,no-resolve"]),
        rows(&[
            "SRC-IP-CIDR,1.1.1.0/24,no-resolve",
            "IP-CIDR6,::/126,no-resolve",
        ]),
        rows(&["IP-CIDR6,::/120,no-resolve"]),
    ] {
        assert!(verify_ip_equivalent(&before, &invalid).is_err());
    }
}

#[test]
fn cross_type_coverage_keeps_final_witnesses_and_exact_hostname_semantics() {
    let input = rows(&[
        "DOMAIN-KEYWORD,umeng",
        "DOMAIN-KEYWORD,aaid.umeng",
        "DOMAIN-SUFFIX,umeng.com",
        "DOMAIN,aaid.umeng.com",
        "DOMAIN-SUFFIX,nowe.com",
        r"DOMAIN-REGEX,^ewcdn[0-9]+\.nowe\.com$",
        "DOMAIN,aaa.com",
        "DOMAIN,cc.aaa.com",
        "DOMAIN-SUFFIX,example.com",
        "DOMAIN,badexample.com",
        "DOMAIN-WILDCARD,*.example.com",
        "DOMAIN-SUFFIX,child.example.com",
    ]);
    let expected = rows(&[
        "DOMAIN-KEYWORD,umeng",
        "DOMAIN-SUFFIX,nowe.com",
        "DOMAIN,aaa.com",
        "DOMAIN,cc.aaa.com",
        "DOMAIN-SUFFIX,example.com",
        "DOMAIN,badexample.com",
    ]);
    assert_eq!(optimize(input.clone()).unwrap(), expected);
    verify_equivalent(&input, &expected).unwrap();
    assert_eq!(optimize(expected.clone()).unwrap(), expected);
}

#[test]
fn regex_proof_requires_mandatory_literal_suffix_and_absolute_end() {
    let input = rows(&[
        "DOMAIN-SUFFIX,example.com",
        r"DOMAIN-REGEX,^api[0-9]+\.example\.com$",
        r"DOMAIN-REGEX,^api(---|\.)node[0-9]+\.example\.com$",
        r"DOMAIN-REGEX,.*example\.com$",
        r"DOMAIN-REGEX,^api\.example\.com$|^elsewhere\.net$",
        r"DOMAIN-REGEX,^api\.example\.com$.*",
        r"DOMAIN-REGEX,^api\.example\.com\$",
        r"DOMAIN-REGEX,(?m)^api\.example\.com$",
        r"DOMAIN-REGEX,^api\.example\.com(?:\.evil)?$",
        r"DOMAIN-REGEX,(?i)^api\.example\.com$",
    ]);
    let mut expected = input.clone();
    expected.remove(&Rule::new("DOMAIN-REGEX", r"^api[0-9]+\.example\.com$", &[]).unwrap());
    expected.remove(
        &Rule::new(
            "DOMAIN-REGEX",
            r"^api(---|\.)node[0-9]+\.example\.com$",
            &[],
        )
        .unwrap(),
    );
    assert_eq!(optimize(input).unwrap(), expected);
}

#[test]
fn equivalence_gate_rejects_expansion_dropped_predicates_and_filled_ip_holes() {
    assert!(
        verify_equivalent(
            &rows(&["DOMAIN,aaa.com", "DOMAIN,cc.aaa.com"]),
            &rows(&["DOMAIN-SUFFIX,aaa.com"])
        )
        .is_err()
    );
    assert!(verify_equivalent(&rows(&["DOMAIN,a.com"]), &BTreeSet::new()).is_err());
    assert!(verify_equivalent(&rows(&["PROCESS-NAME,Foo"]), &BTreeSet::new()).is_err());
    assert!(
        verify_equivalent(
            &rows(&[
                "IP-CIDR,102.129.139.0/25,no-resolve",
                "IP-CIDR,102.129.139.224/27,no-resolve"
            ]),
            &rows(&["IP-CIDR,102.129.139.0/24,no-resolve"])
        )
        .is_err()
    );
    assert!(
        verify_equivalent(
            &rows(&["IP-CIDR,1.1.1.0/24,no-resolve"]),
            &rows(&["IP-CIDR,1.1.1.0/24"])
        )
        .is_err()
    );
    assert!(
        verify_equivalent(
            &rows(&["SRC-IP-CIDR,1.1.1.0/24"]),
            &rows(&["IP-CIDR,1.1.1.0/24"])
        )
        .is_err()
    );
}

#[test]
fn ip_compaction_preserves_holes_family_direction_and_modifiers() {
    let input = rows(&[
        "IP-CIDR,102.129.139.0/26,no-resolve",
        "IP-CIDR,102.129.139.64/26,no-resolve",
        "IP-CIDR,102.129.139.224/27,no-resolve",
        "IP-CIDR,102.129.139.0/24",
        "SRC-IP-CIDR,102.129.139.0/25",
        "IP-CIDR6,::/1,no-resolve",
        "IP-CIDR6,8000::/1,no-resolve",
    ]);
    let expected = rows(&[
        "IP-CIDR,102.129.139.0/25,no-resolve",
        "IP-CIDR,102.129.139.224/27,no-resolve",
        "IP-CIDR,102.129.139.0/24",
        "SRC-IP-CIDR,102.129.139.0/25",
        "IP-CIDR6,::/0,no-resolve",
    ]);
    assert_eq!(optimize(input).unwrap(), expected);
}

#[test]
fn wildcard_contract_matches_airroute_root_inclusive_suffix_and_byte_globs() {
    for (pattern, host, expected) in [
        ("*.example.com", "example.com", true),
        ("*.example.com", "a.b.example.com", true),
        ("*.example.com", "badexample.com", false),
        ("api?.example.com", "api1.example.com", true),
        ("api?.example.com", "api12.example.com", false),
        ("api*.example.com", "api.example.com", true),
        ("*", "example.com", true),
        ("api*", "ap", false),
    ] {
        assert_eq!(
            Rule::new("DOMAIN-WILDCARD", pattern, &[])
                .unwrap()
                .domain_match(host),
            expected,
            "{pattern} on {host}"
        );
    }
    assert!(Rule::new("DOMAIN-WILDCARD", "*.api?.example.com", &[]).is_err());
    assert!(Rule::new("DOMAIN", "api?.example.com", &[]).is_err());
    assert!(Rule::new("DOMAIN-SUFFIX", "*.example.com", &[]).is_err());
    assert_eq!(
        Rule::new("DOMAIN-WILDCARD", "API?.例子.com", &[])
            .unwrap()
            .value,
        "api?.xn--fsqu00a.com"
    );
}

#[test]
fn representative_hostname_language_is_unchanged_after_compaction() {
    let input = rows(&[
        "DOMAIN-WILDCARD,*.example.com",
        "DOMAIN-SUFFIX,child.example.com",
        "DOMAIN,child.example.com",
        "DOMAIN-KEYWORD,metrics",
        "DOMAIN-SUFFIX,metrics.net",
        "DOMAIN-WILDCARD,api?.other.com",
        "DOMAIN,api1.other.com",
        r"DOMAIN-REGEX,^node[0-9]+\.example\.com$",
        "DOMAIN,badexample.com",
    ]);
    let output = optimize(input.clone()).unwrap();
    for left in [
        "",
        "child",
        "a.b",
        "api",
        "api1",
        "api12",
        "node42",
        "metrics",
        "badexample",
    ] {
        for root in ["example.com", "other.com", "metrics.net", "elsewhere.net"] {
            let host = if left.is_empty() {
                root.into()
            } else {
                format!("{left}.{root}")
            };
            assert_eq!(
                input.iter().any(|r| r.domain_match(&host)),
                output.iter().any(|r| r.domain_match(&host)),
                "{host}"
            );
        }
    }
}

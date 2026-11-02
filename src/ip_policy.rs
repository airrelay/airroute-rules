//! Address safety is independent of country votes and of the number of agreeing sources.
use crate::{
    read_json,
    rules::{Rule, cidrs, ip_parts, union},
};
use anyhow::{Result, ensure};
use serde::Deserialize;
use std::{collections::BTreeSet, path::Path};
type Range = (u128, u128);
#[derive(Deserialize)]
struct Config {
    non_public: Vec<String>,
    public_exceptions: Vec<String>,
    non_geographic: Vec<String>,
}
pub struct Policy {
    non_public: [Vec<Range>; 2],
    geographic: [Vec<Range>; 2],
}
fn split(values: &[String]) -> Result<[Vec<Range>; 2]> {
    let mut out = [vec![], vec![]];
    for v in values {
        let (f, s, e) = ip_parts(v.parse()?);
        out[usize::from(f == 6)].push((s, e));
    }
    Ok(out.map(union))
}
/// Subtract sorted disjoint ranges without expanding to individual addresses.
pub fn subtract(s: u128, e: u128, denied: &[Range]) -> Vec<Range> {
    let mut out = vec![];
    let mut cursor = s;
    let begin = denied.partition_point(|(_, b)| *b < s);
    for &(a, b) in &denied[begin..] {
        if a > e {
            break;
        }
        if a > cursor {
            out.push((cursor, a - 1));
        }
        if b >= e {
            return out;
        }
        cursor = cursor.max(b + 1);
    }
    if cursor <= e {
        out.push((cursor, e));
    }
    out
}
impl Policy {
    pub fn load(root: &Path) -> Result<Self> {
        let c: Config = read_json(&root.join("config/ip-policy.json"))?;
        let denied = split(&c.non_public)?;
        let exceptions = split(&c.public_exceptions)?;
        let non_public = std::array::from_fn(|i| {
            union(
                denied[i]
                    .iter()
                    .flat_map(|&(s, e)| subtract(s, e, &exceptions[i]))
                    .collect(),
            )
        });
        let mut geographic = split(&c.non_geographic)?;
        for i in 0..2 {
            geographic[i].extend(&non_public[i]);
            geographic[i] = union(std::mem::take(&mut geographic[i]));
        }
        Ok(Self {
            non_public,
            geographic,
        })
    }
    pub fn geographic(&self, f: u8) -> &[Range] {
        &self.geographic[usize::from(f == 6)]
    }
    pub fn sanitize(&self, rows: BTreeSet<Rule>, local: bool) -> Result<BTreeSet<Rule>> {
        if local {
            return Ok(rows);
        }
        let mut out = BTreeSet::new();
        for r in rows {
            if !matches!(r.kind.as_str(), "IP-CIDR" | "IP-CIDR6") {
                out.insert(r);
                continue;
            }
            let net: ipnet::IpNet = r.value.parse()?;
            ensure!(
                net.prefix_len() != 0,
                "default route cannot identify a public service"
            );
            let (f, s, e) = ip_parts(net);
            for (a, b) in subtract(s, e, &self.non_public[usize::from(f == 6)]) {
                for value in cidrs(f, a, b) {
                    out.insert(Rule {
                        kind: r.kind.clone(),
                        value,
                        modifiers: r.modifiers.clone(),
                    });
                }
            }
        }
        Ok(out)
    }
    pub fn validate(&self, r: &Rule, geographical: bool, local: bool) -> Result<()> {
        if local || !matches!(r.kind.as_str(), "IP-CIDR" | "IP-CIDR6") {
            return Ok(());
        }
        let net: ipnet::IpNet = r.value.parse()?;
        let (f, s, e) = ip_parts(net);
        ensure!(net.prefix_len() != 0, "default route in public collection");
        let denied = if geographical {
            self.geographic(f)
        } else {
            &self.non_public[usize::from(f == 6)]
        };
        ensure!(
            subtract(s, e, denied) == [(s, e)],
            "non-public/protocol address in public collection: {}",
            r.value
        );
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn subtraction_preserves_holes_and_maximum_address() {
        assert_eq!(
            subtract(0, u128::MAX, &[(1, 2), (u128::MAX, u128::MAX)]),
            [(0, 0), (3, u128::MAX - 1)]
        );
        assert!(subtract(1, 2, &[(0, u128::MAX)]).is_empty());
        assert_eq!(
            subtract(u128::MAX, u128::MAX, &[]),
            [(u128::MAX, u128::MAX)]
        );
    }
    #[test]
    fn public_service_safety_does_not_remove_explicit_protocol_exceptions_or_lan() {
        let p = Policy::load(Path::new(env!("CARGO_MANIFEST_DIR"))).unwrap();
        for (ip, valid) in [
            ("10.72.25.0/24", false),
            ("2001:2::/48", false),
            ("192.0.0.9/32", true),
            ("192.0.0.8/32", false),
        ] {
            let rule = Rule::new("IP-CIDR", ip, &["no-resolve"]).unwrap();
            assert_eq!(p.validate(&rule, false, false).is_ok(), valid);
            p.validate(&rule, false, true).unwrap();
        }
    }
}

//! Small, deterministic target selections. A candidate address is not an
//! observation, a location fact, or permission to expand its enclosing scope.
use crate::{measure::public_ip, rules::addr_num};
use serde_json::{Value, json};
use std::{cmp::Reverse, net::IpAddr};

fn ranges(family: u8, input: &[(u128, u128)]) -> Vec<(u128, u128)> {
    crate::rules::union(
        input
            .iter()
            .copied()
            .filter(|(s, e)| s <= e && (family == 6 || (family == 4 && *e <= u32::MAX as u128)))
            .collect(),
    )
}

/// The range geometry is the entire identity. Build/source versions, observers,
/// wall clocks and array order cannot rotate the addresses after a restart.
pub fn seed(family: u8, input: &[(u128, u128)]) -> String {
    let normalized = ranges(family, input);
    let mut bytes = Vec::with_capacity(1 + normalized.len() * 32);
    bytes.push(family);
    for (s, e) in normalized {
        bytes.extend_from_slice(&s.to_be_bytes());
        bytes.extend_from_slice(&e.to_be_bytes());
    }
    crate::hash(bytes)
}

fn eligible(family: u8, spans: &[(u128, u128)], ip: IpAddr) -> bool {
    let (f, n) = addr_num(ip);
    f == family && public_ip(ip) && spans.iter().any(|(s, e)| *s <= n && n <= *e)
}

fn fill_spread(
    family: u8,
    spans: &[(u128, u128)],
    chosen: &mut Vec<(IpAddr, Value)>,
    pool: &[(IpAddr, Value)],
    budget: usize,
) {
    let center = spans[0].0 + (spans.last().unwrap().1 - spans[0].0) / 2;
    while chosen.len() < budget {
        let next = pool
            .iter()
            .enumerate()
            .filter(|(_, (ip, _))| {
                eligible(family, spans, *ip) && !chosen.iter().any(|(old, _)| old == ip)
            })
            .max_by_key(|(index, (ip, _))| {
                let n = addr_num(*ip).1;
                let distance = chosen
                    .iter()
                    .map(|(ip, _)| addr_num(*ip).1.abs_diff(n))
                    .min()
                    .unwrap_or(u128::MAX - n.abs_diff(center));
                // Input order only settles duplicate evidence for one address;
                // callers put the freshest endpoint response first.
                (distance, Reverse(n), Reverse(*index))
            });
        let Some((_, candidate)) = next else {
            break;
        };
        chosen.push(candidate.clone());
    }
}

/// Keep existing choices first, prefer real candidates, then fill at most three
/// slots with bounded IPv4-only candidates distributed across the exact scope.
/// Returned `sampled-candidate` metadata deliberately has no observation clock.
pub fn select_targets(
    family: u8,
    input: &[(u128, u128)],
    retained: &[(IpAddr, Value)],
    known: &[(IpAddr, Value)],
    budget: usize,
    allow_ipv4_candidates: bool,
) -> Vec<(IpAddr, Value)> {
    let spans = ranges(family, input);
    let budget = budget.min(3);
    if spans.is_empty() || budget == 0 {
        return vec![];
    }
    let mut chosen = Vec::with_capacity(budget);
    for candidate in retained {
        if chosen.len() == budget {
            break;
        }
        if eligible(family, &spans, candidate.0) && !chosen.iter().any(|(ip, _)| *ip == candidate.0)
        {
            chosen.push(candidate.clone());
        }
    }
    fill_spread(family, &spans, &mut chosen, known, budget);
    if chosen.len() == budget || family != 4 || !allow_ipv4_candidates {
        return chosen;
    }

    // IPv4 bounds make this sum at most 2^32. Never enumerate the subnet; the
    // local arithmetic attempts are bounded even for private/very small ranges.
    let total: u128 = spans.iter().map(|(s, e)| e - s + 1).sum();
    let slots = budget.min(total.min(3) as usize);
    let selection_seed = seed(family, &spans);
    let mut candidates = Vec::with_capacity(slots);
    for slot in 0..slots {
        let first = total * slot as u128 / slots as u128;
        let end = total * (slot + 1) as u128 / slots as u128;
        for attempt in 0..8 {
            let digest = crate::fingerprint(&json!([selection_seed, slot, attempt]));
            let random = u64::from_str_radix(&digest[..16], 16).unwrap();
            let mut rank = first + u128::from(random) % (end - first);
            let mut address = None;
            for (s, e) in &spans {
                let size = e - s + 1;
                if rank < size {
                    address = Some(*s + rank);
                    break;
                }
                rank -= size;
            }
            let ip = IpAddr::V4(std::net::Ipv4Addr::from(address.unwrap() as u32));
            if eligible(family, &spans, ip) {
                candidates.push((
                    ip,
                    json!({"kind":"sampled-candidate","source":"bgp-bounded-v1"}),
                ));
                break;
            }
        }
    }
    fill_spread(family, &spans, &mut chosen, &candidates, budget);
    chosen
}

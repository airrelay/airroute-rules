//! Read producer goldens using the actual client library, never a second guessed parser.
//! Build with the unmodified airroute-ip-data crate as documented in docs/FORMAT.md.
extern crate airroute_ip_data;

use airroute_ip_data::{IpDataFile, IpDataKind};
use std::env;
use std::fs;

fn verify() -> Result<(), String> {
    let args: Vec<_> = env::args().collect();
    if args.len() != 4 {
        return Err("usage: verify-ardb geo|asn FILE COMMA_SEPARATED_EXPECTED_GROUP_IDS|@IDS_FILE".into());
    }
    let kind = match args[1].as_str() {
        "geo" => IpDataKind::Geo,
        "asn" => IpDataKind::Asn,
        _ => return Err("unknown file kind".into()),
    };
    let expected = if let Some(path) = args[3].strip_prefix('@') {
        fs::read_to_string(path).map_err(|e| e.to_string())?
    } else {
        args[3].clone()
    };
    let ids = if expected.trim().is_empty() {
        Vec::new()
    } else {
        expected.trim()
            .split(',')
            .map(|s| s.parse::<u32>().map_err(|_| "bad expected ID".to_string()))
            .collect::<Result<Vec<_>, _>>()?
    };
    if ids.iter().any(|id| *id == 0) || ids.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err("expected IDs must be positive, sorted and unique".into());
    }
    let mut file = IpDataFile::open(&args[2], kind).map_err(|e| e.to_string())?;
    // The client reader deliberately delegates registry validation to installation.
    // This golden-check wrapper supplies the producer registry's expected groups.
    if file.group_count() as usize != ids.len() {
        return Err("unknown or missing group in golden registry".into());
    }
    for id in ids {
        let prefixes = file
            .read_group(id)
            .map_err(|e| e.to_string())?
            .ok_or_else(|| "unknown requested group".to_string())?;
        let records = prefixes
            .iter()
            .map(|p| format!("{}/{}", p.address, p.prefix_len))
            .collect::<Vec<_>>()
            .join(",");
        println!("{id}\t{records}");
    }
    Ok(())
}

fn main() {
    if let Err(error) = verify() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

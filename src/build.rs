use crate::{
    atomic_write, build_delta,
    domains::{DomainPolicy, Psl},
    fingerprint, geo, hash,
    inputs::Inputs,
    progress::Reporter,
    read_json,
    rules::{Dlc, Rule, classical, ip_parts, optimize, verify_ip_equivalent},
    store::Store,
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::{Read, Write},
    path::{Path, PathBuf},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceRef {
    pub source_id: String,
    #[serde(default = "all")]
    pub selection: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemberProjection {
    pub id: String,
    pub domain_value_pattern: String,
}
fn all() -> String {
    "all".into()
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Recipe {
    pub id: String,
    pub name: String,
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub sources: Vec<SourceRef>,
    #[serde(default)]
    pub members: Vec<String>,
    #[serde(default)]
    pub projected_members: Vec<MemberProjection>,
    #[serde(default)]
    pub scope: String,
    #[serde(default)]
    pub geo_region: Option<String>,
    #[serde(default)]
    pub allow_empty: bool,
    #[serde(default)]
    pub exclude_payloads: BTreeSet<String>,
    #[serde(default)]
    pub include_payloads: BTreeSet<String>,
    #[serde(default)]
    pub local_domain_allowlist: BTreeSet<String>,
    #[serde(default)]
    pub local_cidr_allowlist: BTreeSet<String>,
}
#[derive(Deserialize)]
struct Catalogue {
    recipes: Vec<Recipe>,
}
pub fn recipes(root: &Path) -> Result<Vec<Recipe>> {
    let c: Catalogue = read_json(&root.join("config/recipes.json"))?;
    let mut seen = BTreeSet::new();
    let mut region_bindings = BTreeSet::new();
    for r in &c.recipes {
        ensure!(
            r.id.split('/').count() == 2
                && r.id.split('/').all(|s| !s.is_empty()
                    && s.bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')),
            "invalid collection path"
        );
        ensure!(seen.insert(&r.id), "duplicate collection {}", r.id);
        ensure!(
            matches!(
                r.kind.as_str(),
                "region" | "category" | "provider" | "special"
            ) && r.id.starts_with(&format!("{}/", r.kind)),
            "collection category/path mismatch {}",
            r.id
        );
        ensure!(
            !r.name.trim().is_empty() && !r.scope.trim().is_empty(),
            "collection needs a name and explicit scope"
        );
        if r.kind == "region" {
            let binding = r
                .geo_region
                .as_ref()
                .context("public region needs one internal geographic binding")?;
            ensure!(
                region_bindings.insert(binding),
                "duplicate public region binding {binding}; keep intermediate products internal"
            );
        }
    }
    for r in &c.recipes {
        for id in r
            .members
            .iter()
            .chain(r.projected_members.iter().map(|p| &p.id))
        {
            ensure!(seen.contains(id), "unknown collection member {id}");
        }
        for p in &r.projected_members {
            ensure!(
                p.domain_value_pattern.starts_with('^') && p.domain_value_pattern.ends_with('$'),
                "member projections must anchor the complete domain value"
            );
            regex::Regex::new(&p.domain_value_pattern)?;
        }
    }
    Ok(c.recipes)
}

struct Resolver {
    dlc: Dlc,
    data: BTreeMap<String, Vec<u8>>,
    endpoints: Value,
    geo: BTreeMap<String, BTreeSet<Rule>>,
    recipes: BTreeMap<String, Recipe>,
    memo: BTreeMap<String, BTreeSet<Rule>>,
    parsed: BTreeMap<String, BTreeSet<Rule>>,
    policy: DomainPolicy,
    ip_policy: crate::ip_policy::Policy,
}
impl Resolver {
    fn source(&mut self, s: &SourceRef) -> Result<BTreeSet<Rule>> {
        let id = s.source_id.as_str();
        if id == "GEO/regions" {
            return self
                .geo
                .get(&s.selection)
                .cloned()
                .context("unknown region selector");
        }
        if id == "GEO/anycast" {
            return self.geo.get("anycast").cloned().context("missing anycast");
        }
        if let Some(name) = id.strip_prefix("D/") {
            return self.dlc.select(name, &s.selection);
        }
        if let Some(rows) = self.parsed.get(id) {
            return Ok(rows.clone());
        }
        let mut rows = BTreeSet::new();
        if id.starts_with("O/") {
            for row in self.endpoints[id]
                .as_array()
                .context("official endpoints")?
            {
                let mods = row[2]
                    .as_array()
                    .context("endpoint modifiers")?
                    .iter()
                    .map(|x| x.as_str().context("modifier"))
                    .collect::<Result<Vec<_>>>()?;
                rows.insert(Rule::new(
                    row[0].as_str().context("endpoint kind")?,
                    row[1].as_str().context("endpoint value")?,
                    &mods,
                )?);
            }
        } else {
            let text = std::str::from_utf8(
                self.data
                    .get(id)
                    .with_context(|| format!("missing input {id}"))?,
            )?
            .trim_start_matches('\u{feff}');
            if id == "F/accelerated" {
                for line in text
                    .lines()
                    .map(str::trim)
                    .filter(|l| !l.is_empty() && !l.starts_with('#'))
                {
                    let v: Vec<_> = line.split('/').collect();
                    ensure!(
                        v.len() == 3 && v[0] == "server=" && !v[2].is_empty(),
                        "unknown dnsmasq row"
                    );
                    rows.insert(Rule::new("DOMAIN-SUFFIX", v[1], &[])?);
                }
                ensure!(rows.len() > 50000, "domestic accelerated source collapsed");
            } else if id == "B/ChinaMax_Domain" {
                for l in text
                    .lines()
                    .map(str::trim)
                    .filter(|l| !l.is_empty() && !l.starts_with('#'))
                {
                    let (k, v) = if let Some(v) = l.strip_prefix("+.") {
                        ("DOMAIN-SUFFIX", v)
                    } else if let Some(v) = l.strip_prefix('.') {
                        ("DOMAIN-SUFFIX", v)
                    } else if l.contains('*') {
                        ("DOMAIN-WILDCARD", l)
                    } else {
                        ("DOMAIN", l)
                    };
                    rows.insert(Rule::new(k, v, &[])?);
                }
            } else if id.starts_with("G/") {
                anyhow::bail!("network IP source {id} must pass through geographic reconciliation");
            } else {
                rows = classical(text).with_context(|| format!("classical {id}"))?;
            }
        }
        ensure!(!rows.is_empty(), "empty source {id}");
        self.parsed.insert(id.into(), rows.clone());
        Ok(rows)
    }
    fn resolve(&mut self, id: &str, stack: &mut Vec<String>) -> Result<()> {
        ensure!(
            !stack.iter().any(|x| x == id),
            "catalogue cycle {stack:?} -> {id}"
        );
        if self.memo.contains_key(id) {
            return Ok(());
        }
        let r = self
            .recipes
            .get(id)
            .with_context(|| format!("unknown member {id}"))?
            .clone();
        stack.push(id.into());
        let mut rows = BTreeSet::new();
        let mut claims = BTreeMap::<Rule, Vec<String>>::new();
        for source in &r.sources {
            let selected = self.source(source)?;
            // Cleaning only needs to distinguish explicitly reviewed endpoints.
            // Heads/digests retain every source; do not copy every IP predicate
            // and selector into a second, otherwise unused provenance catalogue.
            for row in selected
                .iter()
                .filter(|_| source.source_id.starts_with("O/"))
            {
                claims
                    .entry(row.clone())
                    .or_default()
                    .push(format!("{}#{}", source.source_id, source.selection));
            }
            rows.extend(selected)
        }
        for member in &r.members {
            self.resolve(member, stack)?;
            rows.extend(self.memo[member].iter().cloned());
        }
        for projection in &r.projected_members {
            let pattern = regex::Regex::new(&projection.domain_value_pattern)?;
            self.resolve(&projection.id, stack)?;
            for row in &self.memo[&projection.id] {
                if matches!(row.kind.as_str(), "DOMAIN" | "DOMAIN-SUFFIX")
                    && pattern.is_match(&row.value)
                {
                    rows.insert(row.clone());
                }
            }
        }
        rows = self.policy.clean(rows, &r, &claims)?;
        if id == "special/lan" {
            let mut clean = BTreeSet::new();
            let reversed = [
                "100.51.198.in-addr.arpa",
                "113.0.203.in-addr.arpa",
                "2.0.192.in-addr.arpa",
                "8.b.d.0.1.0.0.2.ip6.arpa",
                "255.255.255.255.in-addr.arpa",
            ];
            for mut row in rows {
                if row.value == "::/127" && row.kind == "IP-CIDR6" {
                    row.value = "::1/128".into();
                }
                if Rule::ip_kind(&row.kind) && !r.local_cidr_allowlist.contains(&row.value) {
                    continue;
                }
                if matches!(row.kind.as_str(), "DOMAIN" | "DOMAIN-SUFFIX")
                    && !r.local_domain_allowlist.contains(&row.value)
                    && !row.value.ends_with(".in-addr.arpa")
                    && !row.value.ends_with(".ip6.arpa")
                {
                    continue;
                }
                if reversed.contains(&row.value.as_str()) {
                    continue;
                }
                clean.insert(row);
            }
            rows = clean;
        }
        // Keep accepted atoms through membership projections and product boundaries.
        // Compaction is an export operation: a covering predicate may still be
        // removed by a later product-boundary decision.
        let rows = self.ip_policy.sanitize(rows, id == "special/lan")?;
        verify_geographic_rows(&r, &rows, &self.geo)?;
        ensure!(!rows.is_empty() || r.allow_empty, "empty target {id}");
        stack.pop();
        self.memo.insert(id.into(), rows);
        // The verified result now lives in memo. Keep its authoritative GEO set
        // only while an unfinished recipe still needs it as input or for its
        // own geographic verification; Anycast remains available throughout.
        for region in r.geo_region.iter().map(String::as_str).chain(
            r.sources
                .iter()
                .filter(|source| source.source_id == "GEO/regions")
                .map(|source| source.selection.as_str()),
        ) {
            if region == "anycast" {
                continue;
            }
            let needed = self.recipes.values().any(|recipe| {
                !self.memo.contains_key(&recipe.id)
                    && (recipe.geo_region.as_deref() == Some(region)
                        || recipe.sources.iter().any(|source| {
                            source.source_id == "GEO/regions" && source.selection == region
                        }))
            });
            if !needed {
                self.geo.remove(region);
            }
        }
        Ok(())
    }
}
// A domain/manual/member source must not reintroduce IPs that reconciliation quarantined.
fn verify_geographic_rows(
    recipe: &Recipe,
    rows: &BTreeSet<Rule>,
    geo: &BTreeMap<String, BTreeSet<Rule>>,
) -> Result<()> {
    let Some(region) = &recipe.geo_region else {
        return Ok(());
    };
    ensure!(
        rows.iter()
            .all(|r| matches!(r.kind.as_str(), "IP-CIDR" | "IP-CIDR6")
                || (recipe.id == "region/cn" && r.kind.starts_with("DOMAIN"))),
        "geographic collection {} contains a condition outside reconciled IPs/domains",
        recipe.id
    );
    let expected = geo.get(region).context("unknown geographic region")?;
    ensure!(
        expected
            .iter()
            .all(|r| matches!(r.kind.as_str(), "IP-CIDR" | "IP-CIDR6")),
        "reconciled geographic source contains a non-geographic predicate"
    );
    verify_ip_equivalent(rows, expected).with_context(|| {
        format!(
            "geographic collection {} bypasses or drops reconciled IP ranges",
            recipe.id
        )
    })?;
    Ok(())
}
pub fn run(root: &Path, data_dir: &Path, offline: bool) -> Result<Value> {
    // One-shot CLI startup keeps file configuration compatibility. A running
    // controller uses run_with_store and never repeats startup migrations.
    let store = Store::open(data_dir)?;
    store.import_legacy(root)?;
    crate::scheduler::configure(root, &store)?;
    crate::publish::initialize(root, &store)?;
    run_with_store(root, data_dir, offline, &store)
}
pub fn run_with_store(root: &Path, data_dir: &Path, offline: bool, store: &Store) -> Result<Value> {
    let lock_path = data_dir.join("build.lock");
    let lock = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(lock_path)?;
    let _guard = crate::FileLock::try_new(lock).context("another build is running")?;
    store.connect()?.execute("UPDATE builds SET status='failed',finished=?,error='previous process ended before committing the build' WHERE status='running'",[crate::now()])?;
    let id = store.start_build()?;
    let progress = Reporter::new(store, &id)?;
    let result = build(root, data_dir, offline, store, &id, &progress);
    progress.finish_timing();
    if result.is_err() {
        let _ = progress.flush();
    }
    if let Err(error) = &result {
        if build_delta::is_stale(error) {
            let mut c = store.connect()?;
            let tx = c.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            tx.execute("UPDATE builds SET status='deferred',finished=?,error=? WHERE id=? AND status='running'",rusqlite::params![crate::now(),format!("{error:#}"),id])?;
            if let Some(p) = crate::progress::snapshot(store, &id) {
                tx.execute("INSERT INTO build_progress VALUES(?,?) ON CONFLICT(build_id) DO UPDATE SET snapshot=excluded.snapshot",rusqlite::params![id,serde_json::to_string(&p)?])?;
            }
            tx.commit()?;
        } else {
            store.fail_build(&id, &format!("{error:#}"))?;
        }
    }
    result
}

fn freeze_config(root: &Path) -> Result<tempfile::TempDir> {
    fn read(root: &Path, current: &Path, out: &mut BTreeMap<PathBuf, Vec<u8>>) -> Result<()> {
        for entry in std::fs::read_dir(current)? {
            let entry = entry?;
            let kind = entry.file_type()?;
            ensure!(
                kind.is_file() || kind.is_dir(),
                "configuration snapshot cannot include special files"
            );
            if kind.is_dir() {
                read(root, &entry.path(), out)?;
            } else {
                out.insert(
                    entry.path().strip_prefix(root)?.into(),
                    std::fs::read(entry.path())?,
                );
            }
        }
        Ok(())
    }
    let mut captured = BTreeMap::new();
    read(root, &root.join("config"), &mut captured)?;
    let mut checked = BTreeMap::new();
    read(root, &root.join("config"), &mut checked)?;
    ensure!(
        captured == checked,
        "configuration changed while taking build snapshot"
    );
    let dir = tempfile::Builder::new()
        .prefix("airroute-build-config-")
        .tempdir()?;
    for (path, bytes) in captured {
        atomic_write(&dir.path().join(path), &bytes)?;
    }
    Ok(dir)
}

pub(crate) fn export_guard(store: &Store) -> Result<crate::FileLock> {
    let path = store
        .path
        .parent()
        .context("database parent")?
        .join("export.lock");
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(path)?;
    Ok(crate::FileLock::blocking(file)?)
}

/// The final rename and version activation share a small file guard. A delayed export cannot replace a newer build.
pub fn export_current(
    store: &Store,
    build: &str,
    release: &str,
    source: &Path,
    destination: &Path,
) -> Result<()> {
    let _guard = export_guard(store)?;
    ensure!(
        store.meta("current-build-id")?.as_deref() == Some(build)
            && store.meta("current-release")?.as_deref() == Some(release),
        "export superseded by a newer build"
    );
    store.set_meta(
        "export-pending",
        &json!({"build_id":build,"release_hash":release}).to_string(),
    )?;
    export(source, destination)?;
    let mut c = store.connect()?;
    let tx = c.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    tx.execute("INSERT INTO meta VALUES('exported-build-id',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",[build])?;
    tx.execute("INSERT INTO meta VALUES('exported-release',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",[release])?;
    tx.execute("DELETE FROM meta WHERE key='export-pending'", [])?;
    tx.commit()?;
    Ok(())
}

/// Reconcile the latest committed build, never re-export the stale version named by an old pending marker.
pub fn recover_export(store: &Store, root: &Path, data: &Path) -> Result<bool> {
    if store.meta("export-pending")?.is_none() {
        return Ok(false);
    }
    let Some(build) = store.meta("current-build-id")? else {
        return Ok(false);
    };
    let Some(release) = store.meta("current-release")? else {
        return Ok(false);
    };
    export_current(
        store,
        &build,
        &release,
        &data.join("releases").join(&release),
        &root.join("dist"),
    )?;
    Ok(true)
}
pub fn recover_abandoned(store: &Store, data: &Path) -> Result<()> {
    // A no-op UPDATE still waits for SQLite's writer. Most periodic checks have
    // no running build, so do not acquire either the build lock or a write lock.
    if !store.connect()?.query_row::<bool, _, _>(
        "SELECT EXISTS(SELECT 1 FROM builds WHERE status='running')",
        [],
        |r| r.get(0),
    )? {
        return Ok(());
    }
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(data.join("build.lock"))?;
    if let Ok(_guard) = crate::FileLock::try_new(file) {
        store.connect()?.execute("UPDATE builds SET status='failed',finished=?,error='previous process ended before committing the build' WHERE status='running'",[crate::now()])?;
    }
    Ok(())
}
fn build(
    root: &Path,
    data_dir: &Path,
    offline: bool,
    store: &Store,
    id: &str,
    progress: &Reporter,
) -> Result<Value> {
    let config = freeze_config(root)?;
    let frozen = config.path();
    let recipes = recipes(frozen)?;
    let base_build_id = store.meta("current-build-id")?;
    let observations = crate::fusion::capture(store)?;
    let mut input = Inputs::new(root, offline)?;
    input.config_root = frozen.into();
    input.progress = Some(progress.clone());
    progress.phase(
        2,
        "读取构建来源",
        if offline {
            "读取已缓存的完整来源快照"
        } else {
            "确认上游版本并获取规则来源"
        },
        None,
        "",
    )?;
    tracing::info!("load immutable source snapshot");
    let (dlc, mut data) = input.rule_inputs(&recipes)?;
    let domain_config: Value = read_json(&frozen.join("config/domains.json"))?;
    let psl_bytes = input.mutable("psl", &domain_config["psl"])?;
    let psl = Psl::parse(std::str::from_utf8(&psl_bytes)?)?;
    progress.advance("域名目录与公共后缀边界已读取")?;
    progress.phase(3, "地区核查", "准备地理、路由与 Anycast 数据", None, "")?;
    let country = data.remove("I/country").context("country input")?;
    let internal = build_delta::InternalBuild::new(data_dir, id)?;
    let geo = geo::reconcile_with_facts_into(
        frozen,
        &mut input,
        &country,
        &data,
        &observations,
        &mut |case| internal.add_case(&case),
    )?;
    drop(country);
    let mut digests: BTreeMap<_, _> = data
        .iter()
        .map(|(id, data)| (id.clone(), hash(data)))
        .collect();
    for (key, text) in &dlc {
        digests.insert(format!("D/{key}"), hash(text));
    }
    let endpoints: Value = read_json(&frozen.join("config/endpoints.json"))?;
    let endpoint_refs: Value = read_json(&frozen.join("config/endpoints.references.json"))?;
    for (key, v) in endpoints.as_object().context("endpoints map")? {
        ensure!(
            endpoint_refs[key]["references"]
                .as_array()
                .is_some_and(|a| !a.is_empty())
                && endpoint_refs[key]["reviewed"].as_str().is_some(),
            "official endpoint facts need source references and review date: {key}"
        );
        digests.insert(key.clone(), fingerprint(v));
    }
    let observation_cutoff = observations.observed_at;
    let observation_summary = observations.summary.clone();
    let mut resolver = Resolver {
        dlc: Dlc::new(dlc),
        data,
        endpoints,
        geo: geo.rules,
        recipes: recipes.iter().cloned().map(|r| (r.id.clone(), r)).collect(),
        memo: BTreeMap::new(),
        parsed: BTreeMap::new(),
        policy: DomainPolicy::with_facts(domain_config, psl, &observations),
        ip_policy: crate::ip_policy::Policy::load(frozen)?,
    };
    drop(observations);
    // Resolve products before aggregates; categories always inherit cleaned members.
    progress.phase(
        4,
        "构建规则集",
        "清洗域名与服务商规则",
        Some(recipes.len()),
        "个规则集",
    )?;
    for r in recipes.iter().filter(|r| r.kind == "provider") {
        resolver.resolve(&r.id, &mut vec![])?;
        progress.advance(format!("已构建 {}", r.id))?;
    }
    progress.work("检查互斥产品的域名边界")?;
    resolver
        .policy
        .resolve_exclusivity(&mut resolver.memo, &resolver.recipes)?;
    for r in recipes.iter().filter(|r| r.kind != "provider") {
        resolver.resolve(&r.id, &mut vec![])?;
        progress.advance(format!("已构建 {}", r.id))?;
    }
    // Resolution is complete. Keep its accepted atoms, not the raw sources and
    // duplicate parsing/GEO caches, while writing and validating the output.
    let mut memo = std::mem::take(&mut resolver.memo);
    let domain_quarantines = resolver.policy.cases.len();
    for case in std::mem::take(&mut resolver.policy.cases).into_values() {
        internal.add_case(&case)?;
    }
    drop(resolver);
    progress.phase(
        5,
        "写入规则文件",
        "生成完整规则目录",
        Some(recipes.len()),
        "个文件",
    )?;
    let releases = data_dir.join("releases");
    std::fs::create_dir_all(&releases)?;
    let stage = tempfile::Builder::new()
        .prefix(".build-")
        .tempdir_in(&releases)?;
    let mut counts = BTreeMap::new();
    let mut compacted = 0;
    let mut digest = Sha256::new();
    let mut cn_domain_rules = 0;
    for r in &recipes {
        let accepted = memo.remove(&r.id).context("missing resolved collection")?;
        let accepted_count = accepted.len();
        // Persist complete accepted domain atoms by borrowing before compaction;
        // neither a second Rule nor a collection String copy needs to survive.
        internal.add_domains(&r.id, &accepted)?;
        let rows = optimize(accepted)?;
        compacted += accepted_count.saturating_sub(rows.len());
        if r.id == "region/cn" {
            cn_domain_rules = rows
                .iter()
                .filter(|rule| rule.kind.starts_with("DOMAIN"))
                .count();
        }
        counts.insert(r.id.clone(), rows.len());
        let path = stage.path().join(format!("{}.list", r.id));
        std::fs::create_dir_all(path.parent().context("collection parent")?)?;
        let mut f = std::io::BufWriter::new(std::fs::File::create(path)?);
        writeln!(f, "# {} — {}", r.id, r.name)?;
        digest.update(r.id.as_bytes());
        digest.update(format!("# {} — {}\n", r.id, r.name).as_bytes());
        for row in &rows {
            let line = row.line();
            writeln!(f, "{line}")?;
            digest.update(line.as_bytes());
            digest.update(b"\n");
        }
        f.flush()?;
        f.get_ref().sync_all()?;
        progress.advance(format!("已写入 {}.list", r.id))?;
    }
    render_index(stage.path(), &recipes, &counts)?;
    update_file_digest(&mut digest, &stage.path().join("README.md"))?;
    write_ip_library(stage.path(), &geo.resolved, &recipes)?;
    let ip_library_ranges = geo.resolved.len();
    drop(geo.resolved);
    digest.update(b"ip-library.csv\n");
    update_file_digest(&mut digest, &stage.path().join("ip-library.csv"))?;
    let release = hex::encode(digest.finalize());
    let release = &release[..24];
    drop(memo);
    let summary = json!({"targets":recipes.len(),"rules":counts.values().sum::<usize>(),"compacted_rules":compacted,"cn_domain_rules":cn_domain_rules,"domain_quarantines":domain_quarantines,"geography":geo.report,"release":release,"source_heads":input.heads,"source_digests":digests,"sources":input.mutable,"counts":counts,"observation_cutoff":observation_cutoff,"observations":observation_summary,"ip_library_ranges":ip_library_ranges});
    // This private candidate is not activated until complete validation passes.
    // Persist it now so complete conflict/domain payloads need not coexist with
    // a second parsed public catalogue during validation.
    progress.work("保存完整内部争议与域名发现清单")?;
    let internal = internal.finish(base_build_id.as_deref(), release, &[], &summary)?;
    progress.phase(
        6,
        "完整验证",
        "逐个验证输出文件与规则语法",
        Some(recipes.len()),
        "个规则集",
    )?;
    let validated = validate_progress(stage.path(), frozen, Some(progress))?;
    ensure!(
        validated["rules"] == summary["rules"]
            && validated["cn_domain_rules"] == summary["cn_domain_rules"],
        "validated rule counts differ from generated output"
    );
    ensure!(
        validated["ip_library_ranges"].as_u64() == Some(ip_library_ranges as u64),
        "IP library does not cover the complete resolved source union"
    );
    let destination = releases.join(release);
    if destination.exists() {
        progress.work("复核已有的相同内容版本")?;
        progress.flush()?;
        validate(&destination, frozen)?;
        verify_release_contents(stage.path(), &destination)?;
    } else {
        std::fs::File::open(stage.path().join("README.md"))?.sync_all()?;
        build_delta::sync_directory(stage.path())?;
        std::fs::rename(stage.path(), &destination)?;
        build_delta::sync_directory(&releases)?;
    }
    progress.phase(
        7,
        "保存并切换版本",
        "激活规则版本并标记后台差异同步",
        None,
        "",
    )?;
    input.commit()?;
    let incremental = build_delta::activate(store, id, release, &summary, &internal)?;
    // Publication failure is independent of a committed, validated local generation.
    if let Err(error) = crate::publish::enqueue_current(store) {
        tracing::warn!(%error,"publication enqueue deferred; background publisher will recover current release");
    }
    // SQLite's release pointer is authoritative; dist is a convenient local final-result export.
    let mut summary = summary;
    if let Err(error) = export_current(store, id, release, &destination, &root.join("dist")) {
        tracing::warn!(%error,"canonical release complete; dist export reconciliation remains pending");
        summary["export_error"] = json!(error.to_string());
    }
    summary["incremental"] = incremental;
    if let Err(error) = atomic_write(
        &data_dir.join("last-build.json"),
        &serde_json::to_vec_pretty(&summary)?,
    ) {
        tracing::warn!(%error,"optional last-build summary write failed; SQLite release remains authoritative");
    }
    tracing::info!(
        release,
        targets = recipes.len(),
        rules = summary["rules"].as_u64(),
        "full build complete"
    );
    Ok(summary)
}
fn public_region_bindings(recipes: &[Recipe]) -> Result<BTreeMap<&str, (&str, &str)>> {
    let mut bindings = BTreeMap::new();
    for recipe in recipes {
        if let Some(internal) = recipe.geo_region.as_deref() {
            let public = recipe
                .id
                .strip_prefix("region/")
                .context("geographic recipe has no public region path")?;
            ensure!(
                bindings
                    .insert(internal, (public, recipe.id.as_str()))
                    .is_none(),
                "duplicate geographic binding"
            );
        }
    }
    Ok(bindings)
}
fn write_ip_library(output: &Path, rows: &[geo::ResolvedRange], recipes: &[Recipe]) -> Result<()> {
    let bindings = public_region_bindings(recipes)?;
    let mut rows = rows
        .iter()
        .map(|r| {
            Ok((
                r.family,
                crate::rules::addr_num(r.start.parse()?).1,
                crate::rules::addr_num(r.end.parse()?).1,
                r,
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    rows.sort_unstable_by_key(|r| (r.0, r.1, r.2));
    let mut csv = csv::Writer::from_path(output.join("ip-library.csv"))?;
    csv.write_record(["family", "start", "end", "region", "anycast"])?;
    for (_, _, _, r) in rows {
        let (public, _) = bindings
            .get(r.region.as_str())
            .context("geographic range lacks a public recipe binding")?;
        csv.serialize((r.family, &r.start, &r.end, public, r.anycast))?;
    }
    csv.flush()?;
    std::fs::File::open(output.join("ip-library.csv"))?.sync_all()?;
    Ok(())
}

fn update_file_digest(digest: &mut Sha256, path: &Path) -> Result<()> {
    let mut file = std::fs::File::open(path)?;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let length = file.read(&mut buffer)?;
        if length == 0 {
            break;
        }
        digest.update(&buffer[..length]);
    }
    Ok(())
}

fn verify_release_contents(candidate: &Path, existing: &Path) -> Result<()> {
    fn digests(root: &Path, current: &Path, out: &mut BTreeMap<PathBuf, String>) -> Result<()> {
        for entry in std::fs::read_dir(current)? {
            let entry = entry?;
            let kind = entry.file_type()?;
            ensure!(kind.is_dir() || kind.is_file(), "nonregular release entry");
            let path = entry.path();
            if kind.is_dir() {
                digests(root, &path, out)?;
            } else {
                let mut digest = Sha256::new();
                update_file_digest(&mut digest, &path)?;
                out.insert(
                    path.strip_prefix(root)?.into(),
                    hex::encode(digest.finalize()),
                );
            }
        }
        Ok(())
    }
    let mut expected = BTreeMap::new();
    let mut actual = BTreeMap::new();
    digests(candidate, candidate, &mut expected)?;
    digests(existing, existing, &mut actual)?;
    ensure!(
        expected == actual,
        "existing immutable release content differs from rebuilt candidate: {}",
        existing.display()
    );
    Ok(())
}
pub fn export(source: &Path, destination: &Path) -> Result<()> {
    ensure!(
        !destination.join(".git").exists(),
        "refusing to replace Git worktree"
    );
    let parent = destination.parent().context("export parent")?;
    let stage = tempfile::Builder::new()
        .prefix(".export-")
        .tempdir_in(parent)?;
    copy_tree(source, stage.path())?;
    let previous = parent.join(format!(".previous-{}", uuid::Uuid::new_v4()));
    let had = destination.exists();
    if had {
        std::fs::rename(destination, &previous)?
    }
    if let Err(e) = std::fs::rename(stage.path(), destination) {
        if had {
            std::fs::rename(previous, destination)?
        }
        return Err(e.into());
    }
    if had {
        std::fs::remove_dir_all(previous)?
    }
    Ok(())
}
fn copy_tree(src: &Path, dst: &Path) -> Result<()> {
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        ensure!(!entry.file_type()?.is_symlink(), "symlink in release");
        let path = dst.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            std::fs::create_dir_all(&path)?;
            copy_tree(&entry.path(), &path)?;
        } else {
            std::fs::copy(entry.path(), path)?;
        }
    }
    Ok(())
}
fn render_index(stage: &Path, recipes: &[Recipe], counts: &BTreeMap<String, usize>) -> Result<()> {
    let mut text="# AirRoute 规则集与 IP 库\n\n所有 `.list` 均为无出口动作的 classical 文本。中国大陆日常直连使用 `region/cn.list`，局域网使用 `special/lan.list`。具体服务域名通常放在分类、厂商总集和地区 IP 前。\n\n[下载 IP 库](ip-library.csv)：CSV 列为 `family,start,end,region,anycast`，IPv4/IPv6 范围起止均为包含端点，地区标识与公开规则路径一致（例如 `region/cn.list` 对应 `cn`），Anycast 标记为 true/false。规则与 IP 库由同一固定输入构建生成，不包含原始来源、观测证据或任务清单。\n\n中国大陆只提供 `region/cn.list`：国内域名优先，统一处理后的大陆 IP 兜底。每次构建都匹配可直接回答事实且范围适用的近期合格观测；没有可用结论时，独立有效地理来源映射为大区后按严格多数选择，无多数采用 IPLocate、DB-IP 主备顺序。有效来源分歧不会直接造成范围缺失。BGP、登记国、ping/traceroute 不能单独证明目标位置，单 IP 证据不推广到整个前缀。全部来源和适用观测均无信息时明确报告覆盖缺口，不伪造归属。\n\n每天固定来源、观测快照和判断规则生成完整产物；新观测在下一次构建使用。仍需补证的问题只在维护侧记录，不阻止有效数据输出，也不提供人工裁决入口。范围明确的 Anycast 保持独立分类，疑似情况不擅自扩大为整个父前缀。\n\n厂商总集可含其托管平台全部租户，云/CDN 集合表达基础设施，不能当作某个应用的专属身份。分类按服务用途和明确官方端点处理，供应商的宽范围例外不自动继承。DNS 观测与 CDN 地址不反推永久服务归属；同一主机上的不同 URL 功能无法只靠域名区分。进程、HTTP、ASN 等条件需要平台相应元数据。\n\n".to_string();
    for (typ, title) in [
        ("region", "国家地区"),
        ("category", "分类服务"),
        ("provider", "服务商与产品"),
        ("special", "特殊用途"),
    ] {
        text += &format!("## {title}\n\n| 规则 | 文件 | 条数 |\n|---|---|---:|\n");
        for r in recipes.iter().filter(|r| r.kind == typ) {
            text += &format!(
                "| {} | [{}]({}.list) | {} |\n",
                r.name.replace('|', "/"),
                r.id,
                r.id,
                counts[&r.id]
            );
        }
        text.push('\n');
    }
    text += "## 来源与许可\n\n域名来自 [v2fly/domain-list-community](https://github.com/v2fly/domain-list-community)（MIT）、[blackmatrix7/ios_rule_script](https://github.com/blackmatrix7/ios_rule_script)（GPL-2.0）、[dnsmasq-china-list](https://github.com/felixonmars/dnsmasq-china-list)（WTFPL）。中国网络辅助分类来自 [gaoyifan/china-operator-ip](https://github.com/gaoyifan/china-operator-ip)（MIT）。地理原料 powered by [IPLocate.io](https://www.iplocate.io)（CC BY-SA 4.0）与 [DB-IP Lite](https://db-ip.com/db/download/ip-to-country-lite)（CC BY 4.0）。数据经过地区映射、确定性选择及等价聚合，相应署名与衍生许可继续适用。\n\nAnycast 参考 [LACeS](https://github.com/ut-dacs/anycast-census)（许可见上游）及 [Cloudflare](https://www.cloudflare.com/ips/) / [Google Public DNS](https://developers.google.com/speed/public-dns/docs/isp) 官方范围。域名边界使用 [Mozilla PSL](https://publicsuffix.org/list/)（MPL-2.0），公网/地理地址边界参考 IANA [IPv4](https://www.iana.org/assignments/iana-ipv4-special-registry/) / [IPv6](https://www.iana.org/assignments/iana-ipv6-special-registry/) 特殊地址注册表。维护侧使用 [RIPE RIS](https://ris.ripe.net/docs/ris-whois/) 与 [geofeed-finder](https://github.com/massimocandela/geofeed-finder) 提示；地区映射参考 [UN M49](https://unstats.un.org/unsd/methodology/m49/overview/)。\n\n明确官方端点参考 [Apple 推送](https://support.apple.com/en-us/101555)、[Microsoft 推送](https://learn.microsoft.com/en-us/windows/apps/develop/notifications/push-notifications/firewall-allowlist-config)、[Microsoft 365](https://learn.microsoft.com/en-us/microsoft-365/enterprise/urls-and-ip-address-ranges)、[Windows Update](https://learn.microsoft.com/en-us/troubleshoot/windows-client/installing-updates-features-roles/windows-update-issues-troubleshooting) 与 [Google 搜索域名调整](https://blog.google/products-and-platforms/products/search/country-code-top-level-domains/)。这些是复核过的端点事实子集，不是完整连通性允许列表。最终目录只含本 README、规则文件与 ip-library.csv，完整配方在源代码仓库。\n";
    std::fs::write(stage.join("README.md"), text)?;
    Ok(())
}
pub fn validate(output: &Path, root: &Path) -> Result<Value> {
    validate_progress(output, root, None)
}

#[derive(Deserialize)]
struct IpLibraryRow {
    family: u8,
    start: String,
    end: String,
    region: String,
    anycast: bool,
}
fn validate_ip_library(
    output: &Path,
    recipes: &[Recipe],
    sets: &BTreeMap<String, BTreeSet<Rule>>,
    policy: &crate::ip_policy::Policy,
) -> Result<usize> {
    let mut reader = csv::Reader::from_path(output.join("ip-library.csv"))?;
    ensure!(
        reader
            .headers()?
            .iter()
            .eq(["family", "start", "end", "region", "anycast"]),
        "invalid IP library columns"
    );
    let bindings = public_region_bindings(recipes)?
        .into_values()
        .collect::<BTreeMap<_, _>>();
    let mut normal = BTreeMap::<(String, u8), Vec<(u128, u128)>>::new();
    let mut anycast = [Vec::new(), Vec::new()];
    for r in sets.get("special/anycast").into_iter().flatten() {
        let (f, s, e) = ip_parts(r.value.parse()?);
        anycast[usize::from(f == 6)].push((s, e));
    }
    anycast = anycast.map(crate::rules::union);
    let (mut previous, mut count) = (None, 0);
    for row in reader.deserialize::<IpLibraryRow>() {
        let row = row?;
        let start: std::net::IpAddr = row.start.parse()?;
        let end: std::net::IpAddr = row.end.parse()?;
        let (f, s) = crate::rules::addr_num(start);
        let (ef, e) = crate::rules::addr_num(end);
        ensure!(
            f == row.family && ef == f && s <= e,
            "invalid IP library range"
        );
        ensure!(
            start.to_string() == row.start && end.to_string() == row.end,
            "noncanonical IP library address"
        );
        ensure!(
            bindings.contains_key(row.region.as_str()),
            "unknown IP library region {}",
            row.region
        );
        ensure!(
            previous.is_none_or(|(pf, pe)| pf < f || (pf == f && pe < s)),
            "IP library ranges overlap or are unsorted"
        );
        ensure!(
            crate::ip_policy::subtract(s, e, policy.geographic(f)) == [(s, e)],
            "IP library contains non-geographic protocol space"
        );
        previous = Some((f, e));
        count += 1;
        if row.anycast {
            ensure!(
                crate::ip_policy::subtract(s, e, &anycast[usize::from(f == 6)]).is_empty(),
                "IP library Anycast range lacks matching Anycast rules"
            );
        } else {
            normal.entry((row.region, f)).or_default().push((s, e));
        }
    }
    ensure!(count > 0, "empty IP library");
    for (region, id) in bindings {
        for family in [4, 6] {
            let expected = sets
                .get(id)
                .into_iter()
                .flatten()
                .filter(|r| Rule::ip_kind(&r.kind))
                .map(|r| r.value.parse().map(ip_parts))
                .collect::<std::result::Result<Vec<_>, _>>()?
                .into_iter()
                .filter(|(f, _, _)| *f == family)
                .map(|(_, s, e)| (s, e))
                .collect();
            let actual = normal.remove(&(region.into(), family)).unwrap_or_default();
            ensure!(
                crate::rules::union(actual) == crate::rules::union(expected),
                "IP library geographic coverage differs from {id} IPv{family}"
            );
        }
    }
    Ok(count)
}
fn validate_progress(output: &Path, root: &Path, progress: Option<&Reporter>) -> Result<Value> {
    let recipes = recipes(root)?;
    let ip_policy = crate::ip_policy::Policy::load(root)?;
    let quality: Value = read_json(&root.join("config/quality.json"))?;
    let domain_config: Value = read_json(&root.join("config/domains.json"))?;
    let mut sets = BTreeMap::new();
    let mut intervals = vec![];
    let mut total = 0;
    fn files(root: &Path, current: &Path, out: &mut BTreeSet<PathBuf>) -> Result<()> {
        for e in std::fs::read_dir(current)? {
            let e = e?;
            ensure!(!e.file_type()?.is_symlink(), "release symlink");
            if e.file_type()?.is_dir() {
                files(root, &e.path(), out)?
            } else {
                out.insert(e.path().strip_prefix(root)?.to_path_buf());
            }
        }
        Ok(())
    }
    let mut actual = BTreeSet::new();
    files(output, output, &mut actual)?;
    let mut expected: BTreeSet<_> = recipes
        .iter()
        .map(|r| PathBuf::from(format!("{}.list", r.id)))
        .collect();
    expected.insert("README.md".into());
    expected.insert("ip-library.csv".into());
    ensure!(
        actual == expected,
        "final directory contains missing or unexpected files"
    );
    for recipe in &recipes {
        let text = std::fs::read_to_string(output.join(format!("{}.list", recipe.id)))?;
        let mut rows = BTreeSet::new();
        let mut cn_ip_started = false;
        for line in text
            .lines()
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
        {
            let p: Vec<_> = line.split(',').collect();
            ensure!(p.len() >= 2, "malformed row");
            let r = Rule::new(p[0], p[1], &p[2..])?;
            if r.kind == "DOMAIN-SUFFIX" && !r.value.contains('.') {
                ensure!(
                    domain_config["namespace_scopes"][&recipe.id]["roots"]
                        .as_array()
                        .is_some_and(|a| a.iter().any(|v| v == &r.value))
                        || (recipe.id == "special/lan"
                            && recipe.local_domain_allowlist.contains(&r.value)),
                    "unapproved top-level domain in {}: {}",
                    recipe.id,
                    r.value
                );
            }
            if r.kind == "DOMAIN-KEYWORD" && recipe.kind != "special" {
                ensure!(
                    domain_config["keyword_allowlist"][&recipe.id]
                        .as_array()
                        .is_some_and(|a| a.iter().any(|v| v == &r.value)),
                    "unapproved unbounded keyword in {}: {}",
                    recipe.id,
                    r.value
                );
            }
            ip_policy.validate(&r, recipe.geo_region.is_some(), recipe.id == "special/lan")?;
            ensure!(r.line() == line, "noncanonical rule {line}");
            ensure!(rows.insert(r.clone()), "duplicate rule");
            if recipe.id == "region/cn" {
                ensure!(
                    !cn_ip_started || !r.kind.starts_with("DOMAIN"),
                    "CN domain rule after IP fallback"
                );
                cn_ip_started |= Rule::ip_kind(&r.kind);
            }
            if recipe.geo_region.is_some() {
                ensure!(
                    matches!(r.kind.as_str(), "IP-CIDR" | "IP-CIDR6")
                        || (recipe.id == "region/cn" && r.kind.starts_with("DOMAIN")),
                    "invalid geographic condition"
                );
            }
            if (recipe.geo_region.is_some() && !r.kind.starts_with("DOMAIN"))
                || recipe.id == "special/anycast"
            {
                ensure!(
                    matches!(r.kind.as_str(), "IP-CIDR" | "IP-CIDR6")
                        && r.modifiers == ["no-resolve"],
                    "invalid geographic rule"
                );
                let (f, s, e) = ip_parts(r.value.parse()?);
                intervals.push((f, s, e, recipe.id.clone()));
            }
        }
        ensure!(
            !rows.is_empty() || recipe.allow_empty,
            "empty {}",
            recipe.id
        );
        ensure!(
            optimize(rows.clone())? == rows,
            "nonminimal final predicates in {}",
            recipe.id
        );
        let minimum = quality["minimum_rules"][&recipe.id]
            .as_u64()
            .context("missing collection quality floor")? as usize;
        ensure!(
            rows.len() >= minimum,
            "collection coverage collapsed {}: {} < {}",
            recipe.id,
            rows.len(),
            minimum
        );
        total += rows.len();
        sets.insert(recipe.id.clone(), rows);
        if let Some(p) = progress {
            p.advance(format!("已验证 {}", recipe.id))?;
        }
    }
    if let Some(p) = progress {
        p.work("检查地区与 Anycast 交集、国内直连覆盖及产品边界")?;
        p.flush()?;
    }
    intervals.sort_unstable();
    for pair in intervals.windows(2) {
        ensure!(
            pair[0].0 != pair[1].0 || pair[0].2 < pair[1].1,
            "geographic / Anycast overlap {} {}",
            pair[0].3,
            pair[1].3
        );
    }
    let cn = &sets["region/cn"];
    let count = cn.iter().filter(|r| r.kind.starts_with("DOMAIN")).count();
    ensure!(count >= 50000, "CN domain coverage collapsed {count}");
    let matches = |id: &str, host: &str| {
        let host = crate::rules::ascii_domain(host).unwrap_or_default();
        sets[id].iter().any(|r| r.domain_match(&host))
    };
    for check in quality["domain_checks"]
        .as_array()
        .context("domain quality examples")?
    {
        let id = check[0].as_str().context("quality collection")?;
        let host = check[1].as_str().context("quality hostname")?;
        let expected = check[2].as_bool().context("quality expectation")?;
        ensure!(sets.contains_key(id), "unknown quality collection {id}");
        ensure!(
            matches(id, host) == expected,
            "semantic boundary regression {id}: {host}, expected {expected}"
        );
    }
    for h in [
        "baidu.com",
        "www.qq.com",
        "www.taobao.com",
        "www.jd.com",
        "www.12306.cn",
        "www.shenzhen.gov.cn",
        "unlisted-mainland-business.cn",
        "example.中国",
    ] {
        ensure!(matches("region/cn", h), "CN missing {h}");
    }
    for h in [
        "google.com",
        "www.google.com",
        "youtube.com",
        "netflix.com",
        "openai.com",
        "chatgpt.com",
        "claude.ai",
        "github.com",
        "apple.com",
        "icloud.com",
        "microsoft.com",
        "unrelated.example.hk",
        "unrelated.example.tw",
    ] {
        ensure!(!matches("region/cn", h), "CN false-direct {h}");
    }
    let ip_match = |host: &str| {
        let ip: std::net::IpAddr = host.parse().expect("test IP");
        sets["special/lan"]
            .iter()
            .filter(|r| matches!(r.kind.as_str(), "IP-CIDR" | "IP-CIDR6"))
            .any(|r| {
                r.value
                    .parse::<ipnet::IpNet>()
                    .is_ok_and(|n| n.contains(&ip))
            })
    };
    for h in ["127.0.0.1", "192.168.1.1", "10.0.0.1", "::1", "fc00::1"] {
        ensure!(ip_match(h), "LAN missing {h}");
    }
    for h in ["198.18.1.1", "192.0.2.1", "::"] {
        ensure!(!ip_match(h), "LAN overbroad {h}");
    }
    for (id, yes, no) in [
        (
            "provider/openai",
            "chatgpt.com",
            "openai.com.attacker.invalid",
        ),
        (
            "provider/netflix",
            "netflix.com",
            "client.us-west-2.amazonaws.com",
        ),
        ("provider/microsoft-copilot", "copilot.com", "chatgpt.com"),
    ] {
        ensure!(
            matches(id, yes) && !matches(id, no),
            "service boundary regression {id}"
        );
    }
    for h in ["chatgpt.com", "claude.ai", "copilot.com"] {
        ensure!(matches("category/ai-overseas", h), "AI missing {h}");
    }
    let ip_ranges = validate_ip_library(output, &recipes, &sets, &ip_policy)?;
    Ok(
        json!({"targets":recipes.len(),"rules":total,"cn_domain_rules":count,"ip_library_ranges":ip_ranges}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn incremental_release_digest_keeps_the_original_exact_byte_framing() {
        let directory = tempfile::tempdir().unwrap();
        let readme = "# rules\n域名与 IP\n".repeat(10_000);
        let csv = "family,start,end,region,anycast\n4,1.1.1.0,1.1.1.255,us,false\n".repeat(5_000);
        std::fs::write(directory.path().join("README.md"), &readme).unwrap();
        std::fs::write(directory.path().join("ip-library.csv"), &csv).unwrap();
        let mut legacy = String::new();
        let mut digest = Sha256::new();
        for (id, name, line) in [
            ("provider/test", "测试", "DOMAIN,exact.example"),
            (
                "region/us",
                "United States",
                "IP-CIDR,1.1.1.0/24,no-resolve",
            ),
        ] {
            let header = format!("# {id} — {name}\n");
            legacy += id;
            legacy += &header;
            legacy += line;
            legacy.push('\n');
            digest.update(id.as_bytes());
            digest.update(header.as_bytes());
            digest.update(line.as_bytes());
            digest.update(b"\n");
        }
        legacy += &readme;
        legacy += "ip-library.csv\n";
        legacy += &csv;
        update_file_digest(&mut digest, &directory.path().join("README.md")).unwrap();
        digest.update(b"ip-library.csv\n");
        update_file_digest(&mut digest, &directory.path().join("ip-library.csv")).unwrap();
        assert_eq!(hex::encode(digest.finalize()), hash(legacy));
    }
    #[test]
    fn ip_library_is_complete_nonoverlapping_and_uses_known_regions() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let policy = crate::ip_policy::Policy::load(root).unwrap();
        let recipes = vec![
            serde_json::from_value(
                json!({"id":"region/cn","name":"China","type":"region","geo_region":"cn-geo"}),
            )
            .unwrap(),
        ];
        let sets = BTreeMap::from([
            (
                "region/cn".into(),
                [Rule::new("IP-CIDR", "1.1.1.0/24", &["no-resolve"]).unwrap()].into(),
            ),
            (
                "special/anycast".into(),
                [Rule::new("IP-CIDR", "2.2.2.0/24", &["no-resolve"]).unwrap()].into(),
            ),
        ]);
        let directory = tempfile::tempdir().unwrap();
        let header = "family,start,end,region,anycast\n";
        let valid = "4,1.1.1.0,1.1.1.255,cn,false\n4,2.2.2.0,2.2.2.255,cn,true\n";
        let internal = vec![
            geo::ResolvedRange {
                family: 4,
                start: "1.1.1.0".into(),
                end: "1.1.1.255".into(),
                region: "cn-geo".into(),
                basis: "fixture",
                anycast: false,
                confidence: "fixture",
                sources: vec![],
            },
            geo::ResolvedRange {
                family: 4,
                start: "2.2.2.0".into(),
                end: "2.2.2.255".into(),
                region: "cn-geo".into(),
                basis: "fixture",
                anycast: true,
                confidence: "fixture",
                sources: vec![],
            },
        ];
        write_ip_library(directory.path(), &internal, &recipes).unwrap();
        let public = std::fs::read_to_string(directory.path().join("ip-library.csv")).unwrap();
        assert_eq!(public, format!("{header}{valid}"));
        assert!(!public.contains("cn-geo"));
        assert_eq!(
            internal[0].region, "cn-geo",
            "export must not mutate internal region bindings"
        );
        assert_eq!(
            validate_ip_library(directory.path(), &recipes, &sets, &policy).unwrap(),
            2
        );
        for invalid in [
            "4,2.2.2.0,2.2.2.255,cn,true\n",
            "4,1.1.1.0,1.1.1.255,cn,false\n4,1.1.1.128,1.1.1.255,cn,false\n",
            "4,1.1.1.0,1.1.1.255,unknown,false\n",
            "4,1.1.1.0,1.1.1.255,cn,false\n4,3.3.3.0,3.3.3.255,cn,true\n",
            "4,1.1.1.0,1.1.1.255,cn-geo,false\n4,2.2.2.0,2.2.2.255,cn-geo,true\n",
        ] {
            std::fs::write(
                directory.path().join("ip-library.csv"),
                format!("{header}{invalid}"),
            )
            .unwrap();
            assert!(validate_ip_library(directory.path(), &recipes, &sets, &policy).is_err());
        }
    }
    #[test]
    fn projections_and_export_see_uncompacted_accepted_atoms() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let psl = format!(
            "// ===END ICANN DOMAINS===\n// ===BEGIN PRIVATE DOMAINS===\n// ===END PRIVATE DOMAINS===\n{}",
            (0..1001).map(|i| format!("test{i}\n")).collect::<String>()
        );
        let provider: Recipe = serde_json::from_value(json!({"id":"provider/test","name":"test","type":"provider","sources":[{"source_id":"O/test"}]})).unwrap();
        let category: Recipe = serde_json::from_value(json!({"id":"category/test","name":"test","type":"category","projected_members":[{"id":"provider/test","domain_value_pattern":"^shop\\.example\\.com$"}]})).unwrap();
        let mut resolver = Resolver {
            dlc: Dlc::new(BTreeMap::new()),
            data: BTreeMap::new(),
            endpoints: json!({"O/test":[["DOMAIN-SUFFIX","example.com",[]],["DOMAIN","shop.example.com",[]]]}),
            geo: BTreeMap::new(),
            recipes: [provider, category]
                .into_iter()
                .map(|r| (r.id.clone(), r))
                .collect(),
            memo: BTreeMap::new(),
            parsed: BTreeMap::new(),
            policy: DomainPolicy::new(json!({}), Psl::parse(&psl).unwrap()),
            ip_policy: crate::ip_policy::Policy::load(root).unwrap(),
        };
        resolver.resolve("provider/test", &mut vec![]).unwrap();
        assert_eq!(
            resolver.memo["provider/test"].len(),
            2,
            "member atoms were prematurely compacted"
        );
        let child = Rule::new("DOMAIN", "shop.example.com", &[]).unwrap();
        resolver.resolve("category/test", &mut vec![]).unwrap();
        assert_eq!(resolver.memo["category/test"], [child.clone()].into());
        let parent = Rule::new("DOMAIN-SUFFIX", "example.com", &[]).unwrap();
        resolver
            .memo
            .get_mut("provider/test")
            .unwrap()
            .remove(&parent);
        assert_eq!(
            optimize(resolver.memo["provider/test"].clone()).unwrap(),
            [child].into()
        );
    }
    #[test]
    fn geographic_source_lifetime_keeps_future_consumers_and_failed_validation() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let psl = format!(
            "// ===END ICANN DOMAINS===\n// ===BEGIN PRIVATE DOMAINS===\n// ===END PRIVATE DOMAINS===\n{}",
            (0..1001).map(|i| format!("test{i}\n")).collect::<String>()
        );
        let region:Recipe=serde_json::from_value(json!({"id":"region/us","name":"US","type":"region","geo_region":"us","sources":[{"source_id":"GEO/regions","selection":"us"}]})).unwrap();
        let source_consumer:Recipe=serde_json::from_value(json!({"id":"category/source","name":"source","type":"category","sources":[{"source_id":"GEO/regions","selection":"us"}]})).unwrap();
        let verifying_consumer:Recipe=serde_json::from_value(json!({"id":"category/verified","name":"verified","type":"category","geo_region":"us","members":["region/us"]})).unwrap();
        let expected: BTreeSet<_> =
            [Rule::new("IP-CIDR", "1.1.1.0/24", &["no-resolve"]).unwrap()].into();
        let make = |recipes: Vec<Recipe>| Resolver {
            dlc: Dlc::new(BTreeMap::new()),
            data: BTreeMap::new(),
            endpoints: json!({}),
            geo: BTreeMap::from([
                ("us".into(), expected.clone()),
                ("anycast".into(), BTreeSet::new()),
            ]),
            recipes: recipes.into_iter().map(|r| (r.id.clone(), r)).collect(),
            memo: BTreeMap::new(),
            parsed: BTreeMap::new(),
            policy: DomainPolicy::new(json!({}), Psl::parse(&psl).unwrap()),
            ip_policy: crate::ip_policy::Policy::load(root).unwrap(),
        };
        let mut resolver = make(vec![region, source_consumer, verifying_consumer]);
        resolver.resolve("region/us", &mut vec![]).unwrap();
        assert!(
            resolver.geo.contains_key("us"),
            "future direct source still needs the authority set"
        );
        resolver.resolve("category/source", &mut vec![]).unwrap();
        assert!(
            resolver.geo.contains_key("us"),
            "future geographic verification still needs the authority set"
        );
        resolver.resolve("category/verified", &mut vec![]).unwrap();
        for id in ["region/us", "category/source", "category/verified"] {
            assert_eq!(resolver.memo[id], expected);
        }
        assert!(
            !resolver.geo.contains_key("us"),
            "completed consumers must not retain a duplicate geographic set"
        );
        assert!(resolver.geo.contains_key("anycast"));
        let invalid:Recipe=serde_json::from_value(json!({"id":"category/invalid","name":"invalid","type":"category","geo_region":"us","sources":[{"source_id":"GEO/regions","selection":"us"}],"exclude_payloads":["1.1.1.0/24"]})).unwrap();
        let mut resolver = make(vec![invalid]);
        assert!(
            resolver
                .resolve("category/invalid", &mut vec![])
                .unwrap_err()
                .to_string()
                .contains("bypasses or drops")
        );
        assert_eq!(
            resolver.geo["us"], expected,
            "the authority set must survive failed verification"
        );
    }
    #[test]
    fn release_reuse_requires_identical_rule_and_readme_bytes() {
        let candidate = tempfile::tempdir().unwrap();
        let existing = tempfile::tempdir().unwrap();
        for path in [candidate.path(), existing.path()] {
            std::fs::create_dir(path.join("provider")).unwrap();
            std::fs::write(path.join("provider/test.list"), "PROCESS-NAME,original\n").unwrap();
            std::fs::write(path.join("README.md"), "# Original\n").unwrap();
        }
        verify_release_contents(candidate.path(), existing.path()).unwrap();
        for (path, changed, original) in [
            (
                "provider/test.list",
                "PROCESS-NAME,unrelated\n",
                "PROCESS-NAME,original\n",
            ),
            ("README.md", "# Changed\n", "# Original\n"),
        ] {
            std::fs::write(existing.path().join(path), changed).unwrap();
            assert!(
                verify_release_contents(candidate.path(), existing.path()).is_err(),
                "changed {path} reused an immutable release"
            );
            assert_eq!(
                std::fs::read_to_string(existing.path().join(path)).unwrap(),
                changed
            );
            std::fs::write(existing.path().join(path), original).unwrap();
        }
        std::fs::write(
            existing.path().join("unexpected.list"),
            "DOMAIN,test.example\n",
        )
        .unwrap();
        assert!(verify_release_contents(candidate.path(), existing.path()).is_err());
    }
    #[test]
    fn public_china_has_one_recipe_and_uses_the_internal_reconciled_view() {
        let all = recipes(Path::new(env!("CARGO_MANIFEST_DIR"))).unwrap();
        assert_eq!(all.len(), 376);
        assert!(!all.iter().any(|r| r.id == "region/cn-geo"));
        let cn = all.iter().find(|r| r.id == "region/cn").unwrap();
        assert_eq!(cn.geo_region.as_deref(), Some("cn-geo"));
        assert!(
            cn.sources
                .iter()
                .any(|s| s.source_id == "GEO/regions" && s.selection == "cn-geo")
        );
        assert!(!cn.sources.iter().any(|s| s.source_id.starts_with("G/")));
    }
    #[test]
    fn catalogue_rejects_a_second_public_copy_of_an_internal_region() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let temp = tempfile::tempdir().unwrap();
        std::fs::create_dir(temp.path().join("config")).unwrap();
        let mut c: Value = read_json(&root.join("config/recipes.json")).unwrap();
        c["recipes"].as_array_mut().unwrap().push(json!({
            "id":"region/cn-duplicate", "name":"第二个 CN", "type":"region",
            "scope":"不能对外重复内部中间数据", "geo_region":"cn-geo"
        }));
        std::fs::write(temp.path().join("config/recipes.json"), c.to_string()).unwrap();
        let error = recipes(temp.path()).unwrap_err().to_string();
        assert!(error.contains("duplicate public region binding"), "{error}");
    }
    #[test]
    fn geographical_output_cannot_reintroduce_unreviewed_ips_or_broad_conditions() {
        let recipe: Recipe = serde_json::from_value(
            json!({"id":"region/cn","name":"CN","type":"region","geo_region":"cn-geo"}),
        )
        .unwrap();
        let valid = Rule::new("IP-CIDR", "1.2.3.0/25", &["no-resolve"]).unwrap();
        let domain = Rule::new("DOMAIN-SUFFIX", "example.cn", &[]).unwrap();
        let geo = BTreeMap::from([("cn-geo".into(), [valid.clone()].into())]);
        let rows = [valid.clone(), domain.clone()].into();
        verify_geographic_rows(&recipe, &rows, &geo).unwrap();
        let split = [
            domain.clone(),
            Rule::new("IP-CIDR", "1.2.3.0/26", &["no-resolve"]).unwrap(),
            Rule::new("IP-CIDR", "1.2.3.64/26", &["no-resolve"]).unwrap(),
        ]
        .into();
        verify_geographic_rows(&recipe, &split, &geo).unwrap();
        let mut invalid_source = geo.clone();
        invalid_source
            .get_mut("cn-geo")
            .unwrap()
            .insert(domain.clone());
        assert!(verify_geographic_rows(&recipe, &rows, &invalid_source).is_err());
        let bad = Rule::new("IP-CIDR", "1.2.3.0/24", &["no-resolve"]).unwrap();
        assert!(verify_geographic_rows(&recipe, &[domain.clone(), bad].into(), &geo).is_err());
        assert!(verify_geographic_rows(&recipe, &[domain.clone()].into(), &geo).is_err());
        let broad = Rule::new("IP-ASN", "64501", &["no-resolve"]).unwrap();
        assert!(verify_geographic_rows(&recipe, &[domain, valid, broad].into(), &geo).is_err());
    }
}

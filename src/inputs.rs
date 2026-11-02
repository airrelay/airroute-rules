use crate::{atomic_write, build::Recipe, hash, read_json};
use anyhow::{Context, Result, ensure};
use flate2::read::GzDecoder;
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    io::Read,
    path::{Path, PathBuf},
    time::Duration,
};

pub struct Inputs {
    pub root: PathBuf,
    /// Configuration is frozen per build while content-addressed caches stay at `root`.
    pub config_root: PathBuf,
    pub offline: bool,
    pub client: reqwest::blocking::Client,
    pub heads: Value,
    pub mutable: BTreeMap<String, Value>,
    pub progress: Option<crate::progress::Reporter>,
}
type RuleInputs = (BTreeMap<String, String>, BTreeMap<String, Vec<u8>>);
impl Inputs {
    pub fn new(root: &Path, offline: bool) -> Result<Self> {
        Ok(Self {
            root: root.into(),
            config_root: root.into(),
            offline,
            client: reqwest::blocking::Client::builder()
                .timeout(Duration::from_secs(100))
                .user_agent("AirRoute-rules/0.2")
                .build()?,
            heads: json!({}),
            progress: None,
            mutable: if root.join(".cache/geography/inputs.json").exists() {
                read_json(&root.join(".cache/geography/inputs.json"))?
            } else {
                BTreeMap::new()
            },
        })
    }
    pub fn immutable(&self, url: &str) -> Result<Vec<u8>> {
        self.immutable_source(url, url)
    }
    fn immutable_source(&self, item: &str, url: &str) -> Result<Vec<u8>> {
        if let Some(p) = &self.progress {
            p.work(format!("读取来源文件 {item}"))?;
        }
        let path = self
            .root
            .join(".cache/blobs")
            .join(format!("{}.bin", hash(url)));
        if path.exists() {
            return Ok(std::fs::read(path)?);
        }
        ensure!(!self.offline, "offline input missing: {url}");
        let response = self.client.get(url).send()?.error_for_status()?;
        let data = self.download(response, item)?;
        ensure!(
            !data.is_empty() && data.len() <= 128 * 1024 * 1024,
            "empty/oversize input {url}"
        );
        atomic_write(&path, &data)?;
        Ok(data)
    }
    pub fn mutable(&mut self, name: &str, source: &Value) -> Result<Vec<u8>> {
        if let Some(p) = &self.progress {
            p.work(format!("读取来源 {name}"))?;
        }
        let template = source["url"].as_str().context("source URL")?;
        let month = chrono::Utc::now().format("%Y-%m").to_string();
        let mut url = template.replace("{month}", &month);
        let old = self.mutable.get(name).cloned();
        let base = self.root.join(".cache/geography/blobs");
        if self.offline {
            let old = old.with_context(|| format!("missing offline input {name}"))?;
            let sha = old["sha256"].as_str().context("source digest")?;
            let data = std::fs::read(base.join(sha))?;
            ensure!(hash(&data) == sha, "corrupt cached {name}");
            return Ok(data);
        }
        let mut response = self.mutable_response(&url, source, old.as_ref(), &base, name)?;
        // DB-IP's calendar month can roll over before the official free release.
        // Only an actual 404 may consult its configured official download page.
        if name == "dbip"
            && template.contains("{month}")
            && response.status() == reqwest::StatusCode::NOT_FOUND
        {
            let referer = source["referer"]
                .as_str()
                .context("DB-IP official download page missing")?;
            let page = self.client.get(referer).send()?.error_for_status()?;
            let page = self.download(page, "DB-IP official download page")?;
            url = dbip_published_url(template, referer, std::str::from_utf8(&page)?, &month, &url)?;
            response = self.mutable_response(&url, source, old.as_ref(), &base, name)?;
        }
        if response.status() == reqwest::StatusCode::NOT_MODIFIED {
            let old = old.context("304 without accepted input")?;
            ensure!(
                old["url"] == url,
                "304 without matching accepted input {name}"
            );
            let sha = old["sha256"].as_str().context("input hash")?;
            let bytes = std::fs::read(base.join(sha))?;
            ensure!(hash(&bytes) == sha, "corrupt {name}");
            return Ok(bytes);
        }
        let response = response
            .error_for_status()
            .with_context(|| format!("required source {name}"))?;
        let etag = response
            .headers()
            .get("etag")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        let modified = response
            .headers()
            .get("last-modified")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        let data = self.download(response, name)?;
        ensure!(
            !data.is_empty() && data.len() <= 128 * 1024 * 1024,
            "empty/oversize {name}"
        );
        let sha = hash(&data);
        atomic_write(&base.join(&sha), &data)?;
        self.mutable.insert(
            name.into(),
            json!({"url":url,"sha256":sha,"bytes":data.len(),"etag":etag,"last_modified":modified}),
        );
        Ok(data)
    }
    fn mutable_response(
        &self,
        url: &str,
        source: &Value,
        old: Option<&Value>,
        base: &Path,
        name: &str,
    ) -> Result<reqwest::blocking::Response> {
        let mut request = self.client.get(url).header("Accept-Encoding", "identity");
        if let Some(referer) = source["referer"].as_str() {
            request = request.header("Referer", referer);
        }
        if let Some(old) = old
            && old["url"] == url
            && old["sha256"]
                .as_str()
                .is_some_and(|s| base.join(s).exists())
        {
            if let Some(v) = old["etag"].as_str() {
                request = request.header("If-None-Match", v);
            } else if let Some(v) = old["last_modified"].as_str() {
                request = request.header("If-Modified-Since", v);
            }
        }
        request
            .send()
            .with_context(|| format!("required source {name}"))
    }
    fn download(&self, mut response: reqwest::blocking::Response, item: &str) -> Result<Vec<u8>> {
        let total = response.content_length();
        let mut data = vec![];
        let mut buf = [0u8; 65536];
        loop {
            let n = response.read(&mut buf)?;
            if n == 0 {
                break;
            }
            ensure!(data.len() + n <= 128 * 1024 * 1024, "oversize input {item}");
            data.extend_from_slice(&buf[..n]);
            if let Some(p) = &self.progress {
                p.receiving(item, data.len() as u64, total)?;
            }
        }
        Ok(data)
    }
    pub fn fetch_heads(&mut self) -> Result<()> {
        if self.offline {
            self.heads = read_json(&self.root.join(".cache/heads.json"))?;
            return Ok(());
        }
        let sources: BTreeMap<String, Value> =
            read_json(&self.config_root.join("config/sources.json"))?;
        let mut heads = serde_json::Map::new();
        for (key, s) in sources {
            if let Some(p) = &self.progress {
                p.work(format!("读取上游版本 {key}"))?;
            }
            let repo = s["repo"].as_str().context("source repo")?;
            let branch = s["branch"].as_str().context("source branch")?;
            let mut r = self.client.get(format!(
                "https://api.github.com/repos/{repo}/commits/{branch}"
            ));
            if let Ok(token) = std::env::var("GITHUB_TOKEN") {
                r = r.bearer_auth(token)
            }
            let v: Value = r.send()?.error_for_status()?.json()?;
            let sha = v["sha"].as_str().context("GitHub commit sha")?;
            ensure!(
                sha.len() == 40 && sha.bytes().all(|c| c.is_ascii_hexdigit()),
                "invalid upstream commit"
            );
            heads.insert(key, json!({"repo":repo,"sha":sha}));
        }
        self.heads = Value::Object(heads);
        Ok(())
    }
    pub fn raw(&self, key: &str, path: &str) -> Result<String> {
        let h = &self.heads[key];
        Ok(format!(
            "https://raw.githubusercontent.com/{}/{}/{path}",
            h["repo"].as_str().context("repo")?,
            h["sha"].as_str().context("sha")?
        ))
    }
    pub fn rule_inputs(&mut self, recipes: &[Recipe]) -> Result<RuleInputs> {
        self.fetch_heads()?;
        let h = &self.heads["dlc"];
        let mut urls = BTreeMap::from([
            (
                "dlc".into(),
                format!(
                    "https://codeload.github.com/{}/tar.gz/{}",
                    h["repo"].as_str().unwrap_or(""),
                    h["sha"].as_str().unwrap_or("")
                ),
            ),
            (
                "I/country".into(),
                format!(
                    "https://media.githubusercontent.com/media/{}/{}/ip-to-country/ip-to-country.csv.zip",
                    self.heads["country"]["repo"].as_str().unwrap_or(""),
                    self.heads["country"]["sha"].as_str().unwrap_or("")
                ),
            ),
            (
                "F/accelerated".into(),
                self.raw("dnsmasq", "accelerated-domains.china.conf")?,
            ),
            ("G/china.txt".into(), self.raw("china_ip", "china.txt")?),
            ("G/china6.txt".into(), self.raw("china_ip", "china6.txt")?),
        ]);
        for r in recipes {
            for s in &r.sources {
                if let Some(name) = s.source_id.strip_prefix("B/") {
                    let path = if name == "ChinaMax_Domain" {
                        "rule/Clash/ChinaMax/ChinaMax_Domain.txt".into()
                    } else {
                        format!("rule/Clash/{name}/{name}.list")
                    };
                    urls.insert(s.source_id.clone(), self.raw("blackmatrix", &path)?);
                }
            }
        }
        let urls: Vec<_> = urls.into_iter().collect();
        if let Some(p) = &self.progress {
            p.units(
                0,
                Some(urls.len() + 1),
                "个来源文件",
                "准备读取规则来源文件",
            )?;
            p.flush()?;
        }
        let mut data = BTreeMap::new();
        for batch in urls.chunks(8) {
            let inputs = &*self;
            let fetched = std::thread::scope(|scope| {
                let jobs: Vec<_> = batch
                    .iter()
                    .map(|(key, url)| {
                        scope.spawn(move || {
                            let bytes = inputs.immutable_source(key, url)?;
                            if let Some(p) = &inputs.progress {
                                p.advance(format!("已读取 {key}"))?;
                            }
                            Ok::<_, anyhow::Error>((key.clone(), bytes))
                        })
                    })
                    .collect();
                jobs.into_iter()
                    .map(|j| {
                        j.join()
                            .map_err(|_| anyhow::anyhow!("fetch worker panicked"))?
                    })
                    .collect::<Result<Vec<_>>>()
            })?;
            data.extend(fetched);
        }
        let archive = data.remove("dlc").context("DLC archive")?;
        if let Some(p) = &self.progress {
            p.work("展开域名目录归档")?;
            p.flush()?;
        }
        let mut tar = tar::Archive::new(GzDecoder::new(archive.as_slice()));
        let mut dlc = BTreeMap::new();
        for entry in tar.entries()? {
            let entry = entry?;
            if !entry.header().entry_type().is_file() {
                continue;
            }
            let path = entry.path()?.to_string_lossy().to_string();
            if let Some((_, name)) = path.split_once("/data/") {
                ensure!(!name.contains('/'), "nested DLC member");
                let mut text = String::new();
                entry.take(4 * 1024 * 1024).read_to_string(&mut text)?;
                dlc.insert(name.into(), text);
            }
        }
        ensure!(dlc.len() >= 1000, "incomplete DLC archive");
        Ok((dlc, data))
    }
    pub fn commit(&self) -> Result<()> {
        atomic_write(
            &self.root.join(".cache/heads.json"),
            &serde_json::to_vec(&self.heads)?,
        )?;
        atomic_write(
            &self.root.join(".cache/geography/inputs.json"),
            &serde_json::to_vec(&self.mutable)?,
        )
    }
}
pub fn unzip_csv(data: &[u8]) -> Result<Vec<u8>> {
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(data))?;
    let names: Vec<_> = archive
        .file_names()
        .filter(|n| n.ends_with(".csv"))
        .map(str::to_string)
        .collect();
    ensure!(names.len() == 1, "expected one country CSV");
    let mut out = vec![];
    archive
        .by_name(&names[0])?
        .take(512 * 1024 * 1024 + 1)
        .read_to_end(&mut out)?;
    ensure!(out.len() <= 512 * 1024 * 1024, "country CSV oversized");
    Ok(out)
}
pub fn gunzip(data: &[u8]) -> Result<Vec<u8>> {
    let mut out = vec![];
    GzDecoder::new(data)
        .take(512 * 1024 * 1024 + 1)
        .read_to_end(&mut out)?;
    ensure!(out.len() <= 512 * 1024 * 1024, "gzip expansion oversized");
    Ok(out)
}

// Accept only URLs already published on the configured page, matching every
// static byte of this one source's monthly template. Never guess prior months.
fn dbip_published_url(
    template: &str,
    referer: &str,
    page: &str,
    current_month: &str,
    failed: &str,
) -> Result<String> {
    let (prefix, suffix) = template
        .split_once("{month}")
        .context("DB-IP monthly template")?;
    ensure!(
        !suffix.contains("{month}"),
        "invalid DB-IP monthly template"
    );
    let page_url = reqwest::Url::parse(referer)?;
    let links = regex::Regex::new(r#"(?i)href\s*=\s*["']([^"']+)["']"#)?;
    let mut published = BTreeMap::new();
    for link in links.captures_iter(page) {
        let Ok(url) = page_url.join(&link[1]) else {
            continue;
        };
        let Some(month) = url
            .as_str()
            .strip_prefix(prefix)
            .and_then(|v| v.strip_suffix(suffix))
        else {
            continue;
        };
        if month.len() != 7
            || month.as_bytes()[4] != b'-'
            || !month
                .bytes()
                .enumerate()
                .all(|(i, b)| i == 4 || b.is_ascii_digit())
            || month > current_month
        {
            continue;
        }
        let Some((year, number)) = month.split_once('-') else {
            continue;
        };
        let (Ok(year), Ok(number)) = (year.parse::<i32>(), number.parse::<u32>()) else {
            continue;
        };
        if year < 1 || chrono::NaiveDate::from_ymd_opt(year, number, 1).is_none() {
            continue;
        }
        published.insert(month.to_string(), url.to_string());
    }
    let (_, selected) = published
        .pop_last()
        .context("DB-IP official page has no valid published monthly release")?;
    ensure!(
        selected != failed,
        "DB-IP official page still points to unavailable release {failed}"
    );
    Ok(selected)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Datelike;
    use std::{io::Write, net::TcpListener, thread};

    #[test]
    fn dbip_official_link_matches_exact_template_and_latest_non_future_month() {
        let template = "https://download.db-ip.com/free/dbip-country-lite-{month}.csv.gz";
        let referer = "https://db-ip.com/db/download/ip-to-country-lite";
        let page = r#"
          <a href="https://download.db-ip.com/free/dbip-country-lite-2026-11.csv.gz">old</a>
          <a href='https://download.db-ip.com/free/dbip-country-lite-2026-12.csv.gz'>published</a>
          <a href="https://download.db-ip.com/free/dbip-country-lite-2027-02.csv.gz">future</a>
          <a href="https://evil.example/free/dbip-country-lite-2027-01.csv.gz">foreign</a>
          <a href="https://download.db-ip.com/other/dbip-country-lite-2027-01.csv.gz">path</a>
          <a href="https://download.db-ip.com/free/dbip-country-lite-2026-13.csv.gz">invalid</a>
          <a href="https://download.db-ip.com/free/dbip-country-lite-2026-+1.csv.gz">invalid</a>
        "#;
        assert_eq!(
            dbip_published_url(
                template,
                referer,
                page,
                "2027-01",
                &template.replace("{month}", "2027-01")
            )
            .unwrap(),
            template.replace("{month}", "2026-12")
        );
        for page in [
            "no release",
            r#"<a href="https://evil.example/free/dbip-country-lite-2026-12.csv.gz">foreign</a>"#,
            r#"<a href="https://download.db-ip.com/free/dbip-country-lite-2027-02.csv.gz">future</a>"#,
        ] {
            assert!(
                dbip_published_url(
                    template,
                    referer,
                    page,
                    "2027-01",
                    &template.replace("{month}", "2027-01")
                )
                .is_err()
            );
        }
        assert!(
            dbip_published_url(
                template,
                referer,
                &format!(
                    "<a href=\"{}\">unavailable</a>",
                    template.replace("{month}", "2027-01")
                ),
                "2027-01",
                &template.replace("{month}", "2027-01")
            )
            .is_err()
        );
    }

    // Only scripted local HTTP responses; no real upstream or provider requests.
    fn fixture(
        responses: Vec<(String, u16, String, String, bool)>,
    ) -> (String, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = format!("http://{}", listener.local_addr().unwrap());
        let url = address.clone();
        let worker = thread::spawn(move || {
            for (path, status, headers, body, conditional) in responses {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                let mut request = Vec::new();
                while !request.ends_with(b"\r\n\r\n") {
                    let mut b = [0];
                    stream.read_exact(&mut b).unwrap();
                    request.push(b[0]);
                }
                let request = String::from_utf8(request).unwrap();
                assert!(
                    request.starts_with(&format!("GET {path} HTTP/1.1\r\n")),
                    "{request}"
                );
                assert_eq!(
                    request
                        .to_ascii_lowercase()
                        .contains("if-none-match: \"accepted\""),
                    conditional,
                    "{request}"
                );
                let body = body.replace("$ORIGIN", &url);
                write!(stream,"HTTP/1.1 {status} fixture\r\nContent-Length: {}\r\nConnection: close\r\n{headers}\r\n{body}",body.len()).unwrap();
            }
        });
        (address, worker)
    }

    #[test]
    fn dbip_404_uses_published_release_records_actual_url_and_revalidates_304_hash() {
        let d = tempfile::tempdir().unwrap();
        let date = chrono::Utc::now().date_naive();
        let current = date.format("%Y-%m").to_string();
        let published = chrono::NaiveDate::from_ymd_opt(date.year(), date.month(), 1)
            .unwrap()
            .checked_sub_months(chrono::Months::new(1))
            .unwrap()
            .format("%Y-%m")
            .to_string();
        let missing = format!("/free/dbip-country-lite-{current}.csv.gz");
        let accepted = format!("/free/dbip-country-lite-{published}.csv.gz");
        let page = format!("<a href=\"$ORIGIN{accepted}\">official published release</a>");
        let mut responses = vec![];
        for round in 0..3 {
            responses.push((missing.clone(), 404, String::new(), String::new(), false));
            responses.push(("/official".into(), 200, String::new(), page.clone(), false));
            responses.push((
                accepted.clone(),
                if round == 0 { 200 } else { 304 },
                "ETag: \"accepted\"\r\n".into(),
                if round == 0 {
                    "published CSV gzip bytes".into()
                } else {
                    String::new()
                },
                round > 0,
            ));
        }
        let (origin, worker) = fixture(responses);
        let source = json!({"url":format!("{origin}/free/dbip-country-lite-{{month}}.csv.gz"),"referer":format!("{origin}/official")});
        let mut inputs = Inputs::new(d.path(), false).unwrap();
        let bytes = inputs.mutable("dbip", &source).unwrap();
        assert_eq!(bytes, b"published CSV gzip bytes");
        assert_eq!(inputs.mutable["dbip"]["url"], format!("{origin}{accepted}"));
        assert_eq!(inputs.mutable["dbip"]["sha256"], hash(&bytes));
        assert_eq!(inputs.mutable("dbip", &source).unwrap(), bytes);
        inputs.commit().unwrap();
        let mut offline = Inputs::new(d.path(), true).unwrap();
        assert_eq!(offline.mutable("dbip", &source).unwrap(), bytes);
        std::fs::write(
            d.path().join(".cache/geography/blobs").join(hash(&bytes)),
            "corrupt",
        )
        .unwrap();
        assert!(
            format!("{:#}", inputs.mutable("dbip", &source).unwrap_err()).contains("corrupt dbip")
        );
        assert!(offline.mutable("dbip", &source).is_err());
        worker.join().unwrap();
    }

    #[test]
    fn dbip_non_404_errors_do_not_consult_official_page() {
        let d = tempfile::tempdir().unwrap();
        let month = chrono::Utc::now().format("%Y-%m").to_string();
        for status in [403, 429, 500] {
            let (origin, worker) = fixture(vec![(
                format!("/free/dbip-country-lite-{month}.csv.gz"),
                status,
                String::new(),
                String::new(),
                false,
            )]);
            let source = json!({"url":format!("{origin}/free/dbip-country-lite-{{month}}.csv.gz"),"referer":format!("{origin}/must-not-request")});
            let mut inputs = Inputs::new(d.path(), false).unwrap();
            let error = format!("{:#}", inputs.mutable("dbip", &source).unwrap_err());
            assert!(error.contains(&status.to_string()), "{error}");
            assert!(inputs.mutable.is_empty());
            worker.join().unwrap();
        }
    }
}

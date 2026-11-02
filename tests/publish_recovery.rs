use airroute_rules::{publish, store::Store};
use std::path::{Path, PathBuf};

fn git(path: &Path, args: &[&str]) -> String {
    let result = std::process::Command::new("git")
        .current_dir(path)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .args(args)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    String::from_utf8_lossy(&result.stdout).trim().to_owned()
}
struct Fixture {
    _dir: tempfile::TempDir,
    store: Store,
    output: PathBuf,
    remote: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("data")).unwrap();
        publish::initialize(dir.path(), &store).unwrap();
        let mut settings = publish::settings(&store).unwrap();
        settings.enabled = true;
        publish::save_settings(&store, &settings).unwrap();
        let output = dir.path().join("output");
        std::fs::create_dir_all(&output).unwrap();
        for kind in ["region", "category", "provider", "special"] {
            std::fs::create_dir(output.join(kind)).unwrap();
            std::fs::write(
                output.join(kind).join("example.list"),
                "DOMAIN,example.com\n",
            )
            .unwrap();
        }
        std::fs::write(output.join("README.md"), "version one\n").unwrap();
        std::fs::write(output.join("private.json"), "internal evidence").unwrap();
        let remote = dir.path().join("remote.git");
        git(dir.path(), &["init", "--bare", remote.to_str().unwrap()]);
        Self {
            _dir: dir,
            store,
            output,
            remote,
        }
    }
    fn queue(&self, release: &str, build: &str) -> i64 {
        self.store.set_meta("current-release", release).unwrap();
        self.store.set_meta("current-build-id", build).unwrap();
        let c = self.store.connect().unwrap();
        c.execute("INSERT INTO publications(release,repository,branch,status,not_before,created,build_id) VALUES(?,'example/rules','main','queued',0,0,?)", rusqlite::params![release,build]).unwrap();
        c.last_insert_rowid()
    }
    async fn run(&self, id: i64) -> serde_json::Value {
        publish::publish_queued_tree(
            &self.store,
            id,
            &self.output,
            self.remote.to_str().unwrap(),
            None,
        )
        .await
        .unwrap()
    }
    fn column(&self, id: i64, column: &str) -> String {
        self.store
            .connect()
            .unwrap()
            .query_row(
                &format!("SELECT {column} FROM publications WHERE id=?"),
                [id],
                |r| r.get(0),
            )
            .unwrap()
    }
    fn prepare(&self, id: i64, base: &str) -> String {
        let path = self
            .store
            .path
            .parent()
            .unwrap()
            .join("publication-git")
            .join(id.to_string());
        std::fs::create_dir_all(&path).unwrap();
        git(&path, &["init", "--quiet"]);
        git(
            &path,
            &["fetch", self.remote.to_str().unwrap(), "refs/heads/main"],
        );
        git(&path, &["checkout", "-B", "main", "FETCH_HEAD"]);
        std::fs::write(path.join("README.md"), "prepared next version\n").unwrap();
        git(&path, &["add", "README.md"]);
        git(
            &path,
            &[
                "-c",
                "user.name=Test",
                "-c",
                "user.email=test@example.invalid",
                "commit",
                "--quiet",
                "-m",
                "prepared",
            ],
        );
        let sha = git(&path, &["rev-parse", "HEAD"]);
        self.store
            .connect()
            .unwrap()
            .execute(
                "UPDATE publications SET push_state='prepared',commit_sha=?,base_sha=? WHERE id=?",
                rusqlite::params![sha, base, id],
            )
            .unwrap();
        sha
    }
    fn checkout(&self, id: i64) -> PathBuf {
        self.store
            .path
            .parent()
            .unwrap()
            .join("publication-git")
            .join(id.to_string())
    }
}

#[tokio::test]
async fn durable_commit_is_bound_to_build_and_only_public_files_are_pushed() {
    let f = Fixture::new();
    let library = "family,start,end,region,anycast\n4,1.1.1.0,1.1.1.255,us,false\n";
    std::fs::write(f.output.join("ip-library.csv"), library).unwrap();
    std::fs::write(
        f.output.join("manifest.sqlite3"),
        "private indexed disputes",
    )
    .unwrap();
    let id = f.queue("abc", "build-one");
    assert_eq!(f.run(id).await["published"], true);
    let sha = f.column(id, "commit_sha");
    assert_eq!(f.column(id, "build_id"), "build-one");
    assert_eq!(f.column(id, "verified_remote_sha"), sha);
    assert_eq!(f.run(id).await["commit"], sha);
    assert_eq!(git(&f.remote, &["rev-list", "--count", "main"]), "1");
    let paths = git(&f.remote, &["ls-tree", "-r", "--name-only", "main"]);
    assert!(!paths.contains("private"));
    assert!(!paths.contains("manifest.sqlite3"));
    assert!(paths.contains("ip-library.csv"));
    assert_eq!(
        git(&f.remote, &["show", "main:ip-library.csv"]),
        library.trim()
    );
}

#[tokio::test]
async fn stale_prepared_output_is_not_rebuilt_or_pushed_after_a_new_build() {
    let f = Fixture::new();
    let first = f.queue("abc", "one");
    f.run(first).await;
    let base = f.column(first, "commit_sha");
    let id = f.queue("def", "two");
    let sha = f.prepare(id, &base);
    f.store.set_meta("current-build-id", "three").unwrap();
    f.store.set_meta("current-release", "fed").unwrap();
    assert_eq!(f.run(id).await["superseded"], true);
    assert_eq!(f.column(id, "commit_sha"), sha);
    assert_eq!(git(&f.remote, &["rev-parse", "main"]), base);
}

#[tokio::test]
async fn definitive_git_rejection_retries_the_same_commit_without_rebase() {
    let f = Fixture::new();
    let first = f.queue("abc", "one");
    f.run(first).await;
    let id = f.queue("def", "two");
    std::fs::write(f.output.join("README.md"), "version two\n").unwrap();
    git(
        &f.remote,
        &["config", "receive.hideRefs", "refs/heads/main"],
    );
    assert_eq!(f.run(id).await["rejected"], true);
    let sha = f.column(id, "commit_sha");
    assert_eq!(f.column(id, "push_state"), "prepared");
    git(&f.remote, &["config", "--unset", "receive.hideRefs"]);
    assert_eq!(publish::retry(&f.store, id).unwrap(), 1);
    assert_eq!(f.run(id).await["commit"], sha);
    assert_eq!(git(&f.remote, &["rev-parse", "main"]), sha);
}

#[tokio::test]
async fn a_concurrent_remote_commit_blocks_old_prepared_output_without_rebase() {
    let f = Fixture::new();
    let first = f.queue("abc", "one");
    f.run(first).await;
    let base = f.column(first, "commit_sha");
    let id = f.queue("def", "two");
    let sha = f.prepare(id, &base);
    let other = f._dir.path().join("other");
    git(
        f._dir.path(),
        &[
            "clone",
            "--branch",
            "main",
            f.remote.to_str().unwrap(),
            other.to_str().unwrap(),
        ],
    );
    std::fs::write(other.join("elsewhere"), "external commit").unwrap();
    git(&other, &["add", "elsewhere"]);
    git(
        &other,
        &[
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "--quiet",
            "-m",
            "external",
        ],
    );
    git(&other, &["push", "origin", "main"]);
    let actual = git(&f.remote, &["rev-parse", "main"]);
    assert_eq!(f.run(id).await["ref_conflict"], true);
    assert_eq!(f.column(id, "commit_sha"), sha);
    assert_eq!(git(&f.remote, &["rev-parse", "main"]), actual);
}

#[tokio::test]
async fn crash_after_push_recovers_by_sha_and_ancestry_without_sending_again() {
    let f = Fixture::new();
    let first = f.queue("abc", "one");
    f.run(first).await;
    let base = f.column(first, "commit_sha");
    let id = f.queue("def", "two");
    let sha = f.prepare(id, &base);
    // Real git push succeeds, then emulate losing the acknowledgement / controller crash.
    git(
        &f.checkout(id),
        &["push", f.remote.to_str().unwrap(), "main"],
    );
    f.store
        .connect()
        .unwrap()
        .execute(
            "UPDATE publications SET status='running',push_state='sending' WHERE id=?",
            [id],
        )
        .unwrap();
    assert_eq!(f.run(id).await["commit"], sha);
    assert_eq!(f.column(id, "push_state"), "confirmed");
    // A later fast-forward still proves that the prepared commit reached the branch.
    let path = f.checkout(id);
    std::fs::write(path.join("later"), "external fast forward").unwrap();
    git(&path, &["add", "later"]);
    git(
        &path,
        &[
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "--quiet",
            "-m",
            "later",
        ],
    );
    git(&path, &["push", f.remote.to_str().unwrap(), "main"]);
    f.store
        .connect()
        .unwrap()
        .execute(
            "UPDATE publications SET status='unknown',push_state='unknown' WHERE id=?",
            [id],
        )
        .unwrap();
    assert_eq!(f.run(id).await["commit"], sha);
    assert_eq!(git(&f.remote, &["rev-list", "--count", "main"]), "3");
}

#[tokio::test]
async fn unknown_at_unchanged_base_never_resends_even_after_manual_retry_or_target_change() {
    let f = Fixture::new();
    let first = f.queue("abc", "one");
    f.run(first).await;
    let base = f.column(first, "commit_sha");
    let id = f.queue("def", "two");
    f.prepare(id, &base);
    f.store
        .connect()
        .unwrap()
        .execute(
            "UPDATE publications SET status='unknown',push_state='unknown' WHERE id=?",
            [id],
        )
        .unwrap();
    assert_eq!(publish::retry(&f.store, id).unwrap(), 1);
    for _ in 0..3 {
        assert_eq!(f.run(id).await["unknown"], true);
    }
    f.store.set_meta("current-release", "fed").unwrap();
    assert_eq!(f.run(id).await["unknown"], true);
    assert_eq!(git(&f.remote, &["rev-parse", "main"]), base);
}

#[test]
fn migration_retains_legacy_unknown_without_a_sha_and_is_repeatable() {
    let d = tempfile::tempdir().unwrap();
    let store = Store::open(d.path()).unwrap();
    let conn = store.connect().unwrap();
    conn.execute_batch("CREATE TABLE publications(id INTEGER PRIMARY KEY,release TEXT NOT NULL,repository TEXT NOT NULL,branch TEXT NOT NULL,status TEXT NOT NULL,attempts INTEGER NOT NULL DEFAULT 0,not_before INTEGER NOT NULL,created INTEGER NOT NULL,finished INTEGER,commit_sha TEXT,error TEXT,UNIQUE(release,repository,branch)); INSERT INTO publications VALUES(1,'abc','example/rules','main','retry',2,0,0,NULL,NULL,'timeout');").unwrap();
    publish::initialize(d.path(), &store).unwrap();
    publish::initialize(d.path(), &store).unwrap();
    let result: (String, String, i64) = conn
        .query_row(
            "SELECT status,push_state,attempts FROM publications WHERE id=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    assert_eq!(result, ("unknown".into(), "unknown".into(), 2));
}

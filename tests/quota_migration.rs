use airroute_rules::{
    globalping::{self, Config},
    now,
    store::Store,
};
use serde_json::json;

#[test]
fn legacy_shared_configuration_becomes_independent_accounts_without_resetting_usage_or_inflight_snapshots()
 {
    let d = tempfile::tempdir().unwrap();
    let store = Store::open(d.path()).unwrap();
    let conn = store.connect().unwrap();
    conn.execute_batch("CREATE TABLE gp_groups(id TEXT PRIMARY KEY,config TEXT NOT NULL);CREATE TABLE gp_usage(quota_group TEXT,bucket INTEGER,used INTEGER,blocked_until INTEGER,PRIMARY KEY(quota_group,bucket));").unwrap();
    let quota = json!({"tests_per_hour":400,"tests_per_day":9600,"minimum_interval_seconds":5});
    conn.execute(
        "INSERT INTO gp_groups VALUES('old-owner',?)",
        [quota.to_string()],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO gp_usage VALUES('old-owner',?,31,?)",
        rusqlite::params![now() / 3600, now() + 50],
    )
    .unwrap();
    for id in ["primary", "secondary"] {
        let a = json!({"id":id,"name":id,"enabled":false,"quota_group":"old-owner","regions":{"us":"US"},"credential_ref":"private-reference-retained"});
        conn.execute(
            "INSERT INTO gp_accounts VALUES(?,?,0)",
            rusqlite::params![id, a.to_string()],
        )
        .unwrap();
        if id == "primary" {
            let lease = json!({"id":"pending","case_key":"fixture","fingerprint":"fp","kind":"dns","target":"example.org","region":"us","token":"fixture","until":now()+180,"profile":{}});
            conn.execute("INSERT INTO gp_remote(job_id,account,remote_id,lease,next_poll,account_snapshot) VALUES('pending','primary','existing-id',?,0,?)",rusqlite::params![lease.to_string(),a.to_string()]).unwrap();
        }
    }
    let status = globalping::status(&store, &Config::default()).unwrap();
    assert!(status.get("quota_groups").is_none());
    for a in status["accounts"].as_array().unwrap() {
        assert!(a.get("quota").is_none());
        assert!(a.get("local_hourly_limit").is_none());
        assert!(a["limits"].is_null());
        assert_eq!(a["minimum_interval_seconds"], 5);
        assert_eq!(a["hourly_usage_used"], 31);
        assert!(a.get("quota_group").is_none());
    }
    let tables:i64=conn.query_row("SELECT count(*) FROM sqlite_master WHERE type='table' AND name IN ('gp_groups','gp_usage')",[],|r|r.get(0)).unwrap();
    assert_eq!(tables, 0);
    let snapshot: String = conn
        .query_row("SELECT account_snapshot FROM gp_remote", [], |r| r.get(0))
        .unwrap();
    let snapshot: serde_json::Value = serde_json::from_str(&snapshot).unwrap();
    assert_eq!(snapshot["credential_ref"], "private-reference-retained");
    assert!(snapshot.get("quota").is_none());
    assert!(snapshot.get("quota_group").is_none());
    conn.execute(
        "UPDATE gp_account_usage SET used=32 WHERE account='primary'",
        [],
    )
    .unwrap();
    let status = globalping::status(&store, &Config::default()).unwrap();
    assert_eq!(status["accounts"][0]["hourly_usage_used"], 32);
    assert_eq!(status["accounts"][1]["hourly_usage_used"], 31);
}

#[test]
fn legacy_file_is_readable_but_old_manual_quotas_are_not_controls() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("globalping.toml");
    std::fs::write(&p,"[quota_groups.old]\ntests_per_hour=400\ntests_per_day=9600\nminimum_interval_seconds=5\n[[accounts]]\nid='primary'\nquota_group='old'\n").unwrap();
    let c = globalping::load(&p).unwrap();
    let value = serde_json::to_value(c).unwrap();
    assert!(value["accounts"][0].get("quota").is_none());
    assert!(value.get("quota_groups").is_none());
    assert!(value["accounts"][0].get("quota_group").is_none());
}

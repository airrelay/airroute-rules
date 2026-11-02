use airroute_rules::{build, inputs::Inputs, progress::Reporter, store::Store};
use serde_json::{Value, json};
fn latest(store: &Store) -> Value {
    store.builds().unwrap()[0].clone()
}
#[test]
fn parallel_progress_is_durable_and_a_failed_build_keeps_its_stopping_point() {
    let d = tempfile::tempdir().unwrap();
    let s = Store::open(d.path()).unwrap();
    let id = s.start_build().unwrap();
    let report = Reporter::new(&s, &id).unwrap();
    report
        .phase(2, "sources", "fetch fixture", Some(128), "files")
        .unwrap();
    std::thread::scope(|scope| {
        for _ in 0..8 {
            let p = report.clone();
            scope.spawn(move || {
                for i in 0..16 {
                    p.advance(format!("source {i}")).unwrap();
                }
            });
        }
    });
    report.flush().unwrap();
    assert_eq!(latest(&s)["progress"]["completed"], 128);
    report
        .phase(3, "geo", "parse fixture", None, "records")
        .unwrap();
    report
        .units(100000, None, "records", "parse DB-IP")
        .unwrap();
    report.flush().unwrap();
    s.fail_build(&id, "required upstream source unavailable")
        .unwrap();
    report
        .phase(7, "late callback", "must not overwrite failure", None, "")
        .unwrap();
    let reopened = Store::open(d.path()).unwrap();
    let b = latest(&reopened);
    assert_eq!(b["status"], "failed");
    assert_eq!(b["progress"]["stage"], 3);
    assert_eq!(b["progress"]["completed"], 100000);
    assert_eq!(b["error"], "required upstream source unavailable");
    assert!(s.meta("current-release").unwrap().is_none());
}
#[test]
fn completion_and_crash_recovery_preserve_progress_without_advancing_an_invalid_release() {
    let d = tempfile::tempdir().unwrap();
    let s = Store::open(d.path()).unwrap();
    let id = s.start_build().unwrap();
    let p = Reporter::new(&s, &id).unwrap();
    p.phase(7, "commit", "validated fixture", None, "").unwrap();
    s.commit_build(&id, "abc123", &json!({}), &[], &[]).unwrap();
    p.phase(2, "stale callback", "ignored", None, "").unwrap();
    assert_eq!(latest(&s)["progress"]["stage"], 7);
    assert_eq!(latest(&s)["status"], "complete");
    let id = s.start_build().unwrap();
    let p = Reporter::new(&s, &id).unwrap();
    p.phase(5, "files", "provider/openai", Some(377), "files")
        .unwrap();
    build::recover_abandoned(&s, d.path()).unwrap();
    let b = latest(&s);
    assert_eq!(b["status"], "failed");
    assert_eq!(b["progress"]["detail"], "provider/openai");
    assert_eq!(
        s.meta("current-release").unwrap().as_deref(),
        Some("abc123")
    );
}
#[test]
fn source_download_progress_reports_actual_bytes_and_cache_preserves_the_body() {
    use std::io::{Read, Write};
    let d = tempfile::tempdir().unwrap();
    let s = Store::open(&d.path().join("data")).unwrap();
    let id = s.start_build().unwrap();
    let p = Reporter::new(&s, &id).unwrap();
    p.phase(2, "sources", "download fixture", Some(1), "file")
        .unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/fixture", listener.local_addr().unwrap());
    let body = vec![b'x'; 131072];
    let copy = body.clone();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = [0; 8192];
        let n = stream.read(&mut request).unwrap();
        assert!(n > 0, "expected an HTTP request");
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            copy.len()
        )
        .unwrap();
        stream.write_all(&copy).unwrap();
    });
    let mut input = Inputs::new(d.path(), false).unwrap();
    input.progress = Some(p.clone());
    assert_eq!(input.immutable(&url).unwrap(), body);
    p.flush().unwrap();
    let b = latest(&s);
    assert_eq!(b["progress"]["bytes_received"], body.len());
    assert_eq!(b["progress"]["bytes_total"], body.len());
    server.join().unwrap();
    input.offline = true;
    assert_eq!(input.immutable(&url).unwrap(), body);
    assert_eq!(latest(&s)["status"], "running");
}

#[test]
fn idle_recovery_does_not_wait_for_an_unrelated_database_writer() {
    let d = tempfile::tempdir().unwrap();
    let s = Store::open(d.path()).unwrap();
    let mut writer = s.connect().unwrap();
    let tx = writer
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .unwrap();
    // No build is running. Recovery is read-only and can finish under this writer.
    build::recover_abandoned(&s, d.path()).unwrap();
    tx.rollback().unwrap();
}

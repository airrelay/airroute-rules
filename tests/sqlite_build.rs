#[test]
fn bundled_sqlite_retains_thread_safety_without_global_allocation_statistics() {
    let c = rusqlite::Connection::open_in_memory().unwrap();
    let options: Vec<String> = c
        .prepare("PRAGMA compile_options")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    assert!(options.iter().any(|s| s == "DEFAULT_MEMSTATUS=0"));
    assert!(options.iter().any(|s| s == "THREADSAFE=1"));
}

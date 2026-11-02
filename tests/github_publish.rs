use airroute_rules::{
    publish::{self, Endpoints},
    store::Store,
};
use axum::{
    Json, Router,
    http::{HeaderMap, StatusCode},
    routing::{get, post},
};
use serde_json::{Value, json};
fn git(path: &std::path::Path, args: &[&str]) -> String {
    let out = std::process::Command::new("git")
        .current_dir(path)
        .args(args)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}
fn export(path: &std::path::Path) {
    std::fs::create_dir(path).unwrap();
    for kind in ["region", "category", "provider", "special"] {
        std::fs::create_dir(path.join(kind)).unwrap();
        std::fs::write(
            path.join(kind).join("sample.list"),
            "DOMAIN-SUFFIX,example.com\n",
        )
        .unwrap();
    }
    std::fs::write(path.join("README.md"), "Final rules\n").unwrap();
    std::fs::write(path.join("internal.json"), "should never be published").unwrap();
}
#[tokio::test]
async fn final_exports_publish_to_an_empty_main_branch_and_replay_without_commits() {
    let d = tempfile::tempdir().unwrap();
    let output = d.path().join("output");
    export(&output);
    let remote = d.path().join("remote.git");
    git(d.path(), &["init", "--bare", remote.to_str().unwrap()]);
    let url = remote.to_str().unwrap();
    let sha = publish::publish_tree(&output, url, "main", "abc123", None)
        .await
        .unwrap();
    assert_eq!(git(&remote, &["rev-parse", "refs/heads/main"]), sha);
    let files = git(
        &remote,
        &["ls-tree", "-r", "--name-only", "refs/heads/main"],
    );
    assert_eq!(files.lines().count(), 5);
    assert!(!files.contains("internal"));
    let replay = publish::publish_tree(&output, url, "main", "abc123", None)
        .await
        .unwrap();
    assert_eq!(replay, sha);
    std::fs::remove_file(output.join("region/sample.list")).unwrap();
    std::fs::write(
        output.join("region/new.list"),
        "DOMAIN,changed.example.com\n",
    )
    .unwrap();
    let next = publish::publish_tree(&output, url, "main", "def456", None)
        .await
        .unwrap();
    assert_ne!(next, sha);
    assert_eq!(
        git(&remote, &["rev-list", "--count", "refs/heads/main"]),
        "2"
    );
    let files = git(
        &remote,
        &["ls-tree", "-r", "--name-only", "refs/heads/main"],
    );
    assert!(files.contains("region/new.list"));
    assert!(!files.contains("region/sample.list"));
}
#[tokio::test]
async fn rejected_remote_push_does_not_advance_the_branch() {
    let d = tempfile::tempdir().unwrap();
    let output = d.path().join("output");
    export(&output);
    let remote = d.path().join("remote.git");
    git(d.path(), &["init", "--bare", remote.to_str().unwrap()]);
    let sha = publish::publish_tree(&output, remote.to_str().unwrap(), "main", "abc", None)
        .await
        .unwrap();
    git(&remote, &["config", "receive.hideRefs", "refs/heads/main"]);
    std::fs::write(output.join("README.md"), "changed rules").unwrap();
    assert!(
        publish::publish_tree(&output, remote.to_str().unwrap(), "main", "def", None)
            .await
            .is_err()
    );
    assert_eq!(git(&remote, &["rev-parse", "refs/heads/main"]), sha);
}
fn test_secret() -> String {
    uuid::Uuid::nil().to_string()
}
async fn identity(h: HeaderMap) -> (StatusCode, Json<Value>) {
    if h.get("authorization")
        .is_some_and(|v| v.to_str().unwrap() == format!("Bearer {}", test_secret()))
    {
        (StatusCode::OK, Json(json!({"login":"fixture-user"})))
    } else {
        (
            StatusCode::UNAUTHORIZED,
            Json(json!({"message":"invalid fixture"})),
        )
    }
}
async fn device() -> Json<Value> {
    Json(
        json!({"device_code":"fixture-device","user_code":"ABCD-1234","verification_uri":"https://github.com/login/device","expires_in":900,"interval":5}),
    )
}
async fn access() -> Json<Value> {
    Json(json!({"access_token":test_secret()}))
}
#[tokio::test]
async fn authorization_device_flow_waiting_repository_and_publication_queue_are_durable() {
    let app = Router::new()
        .route("/user", get(identity))
        .route(
            "/repos/example/rules",
            get(|| async { StatusCode::NOT_FOUND }),
        )
        .route("/login/device/code", post(device))
        .route("/login/oauth/access_token", post(access));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let ep = Endpoints {
        api: url.clone(),
        oauth: url,
    };
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let d = tempfile::tempdir().unwrap();
    let s = Store::open(d.path()).unwrap();
    publish::initialize(d.path(), &s).unwrap();
    let mut settings = publish::settings(&s).unwrap();
    settings.client_id = "fixture_client".into();
    publish::save_settings(&s, &settings).unwrap();
    let code = publish::start_device(&s, &ep).await.unwrap();
    assert_eq!(code["user_code"], "ABCD-1234");
    let public = publish::status(&s).unwrap();
    assert!(!public.to_string().contains("fixture-device"));
    assert_eq!(
        publish::poll_device(&s, &ep).await.unwrap()["pending"],
        true
    );
    s.connect()
        .unwrap()
        .execute(
            "UPDATE meta SET value=json_set(value,'$.next_poll',0) WHERE key='github-device'",
            [],
        )
        .unwrap();
    let connected = publish::poll_device(&s, &ep).await.unwrap();
    assert_eq!(connected["health"], "waiting-for-repository");
    assert!(publish::connect(&s, "bad-fixture", &ep).await.is_err());
    assert_eq!(publish::status(&s).unwrap()["login"], "fixture-user");
    assert!(
        !publish::status(&s)
            .unwrap()
            .to_string()
            .contains(&test_secret())
    );
    settings.enabled = true;
    publish::save_settings(&s, &settings).unwrap();
    s.set_meta("current-release", "abc").unwrap();
    assert_eq!(publish::enqueue_current(&s).unwrap(), 1);
    assert_eq!(publish::enqueue_current(&s).unwrap(), 0);
    let failed = s.start_build().unwrap();
    s.fail_build(&failed, "fixture source outage").unwrap();
    assert_eq!(publish::enqueue_current(&s).unwrap(), 0);
    s.set_meta("current-release", "def").unwrap();
    assert_eq!(publish::enqueue_current(&s).unwrap(), 1);
    let v = publish::status(&Store::open(d.path()).unwrap()).unwrap();
    assert_eq!(v["publications"][1]["status"], "superseded");
    assert_eq!(v["publications"][0]["release"], "def");
    publish::disconnect(&s).unwrap();
    assert_eq!(publish::status(&s).unwrap()["connected"], false);
    assert_eq!(publish::enqueue_current(&s).unwrap(), 0);
    server.abort();
}

#[tokio::test]
async fn disconnect_cancels_delayed_token_and_device_authorization() {
    for device_mode in [false, true] {
        let seen = std::sync::Arc::new(tokio::sync::Notify::new());
        let release = std::sync::Arc::new(tokio::sync::Notify::new());
        let user_seen = seen.clone();
        let user_release = release.clone();
        let access_seen = seen.clone();
        let access_release = release.clone();
        let app = Router::new()
            .route(
                "/user",
                get(move || {
                    let seen = user_seen.clone();
                    let release = user_release.clone();
                    async move {
                        if !device_mode {
                            seen.notify_one();
                            release.notified().await;
                        }
                        Json(json!({"login":"fixture-user"}))
                    }
                }),
            )
            .route("/login/device/code", post(device))
            .route(
                "/login/oauth/access_token",
                post(move || {
                    let seen = access_seen.clone();
                    let release = access_release.clone();
                    async move {
                        if device_mode {
                            seen.notify_one();
                            release.notified().await;
                        }
                        Json(json!({"access_token":test_secret()}))
                    }
                }),
            )
            .route(
                "/repos/example/rules",
                get(|| async { StatusCode::NOT_FOUND }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let ep = Endpoints {
            api: url.clone(),
            oauth: url,
        };
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let d = tempfile::tempdir().unwrap();
        let s = Store::open(d.path()).unwrap();
        publish::initialize(d.path(), &s).unwrap();
        if device_mode {
            let mut settings = publish::settings(&s).unwrap();
            settings.client_id = "fixture_client".into();
            publish::save_settings(&s, &settings).unwrap();
            publish::start_device(&s, &ep).await.unwrap();
            s.connect().unwrap().execute("UPDATE meta SET value=json_set(value,'$.next_poll',0) WHERE key='github-device'",[]).unwrap();
        }
        let copy = s.clone();
        let mut pending = tokio::spawn(async move {
            if device_mode {
                publish::poll_device(&copy, &ep).await
            } else {
                publish::connect(&copy, &test_secret(), &ep).await
            }
        });
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            tokio::select! {
                _ = seen.notified() => {},
                result = &mut pending => panic!("authorization exited before fixture entry (device={device_mode}): {result:?}"),
            }
        }).await.unwrap();
        publish::disconnect(&s).unwrap();
        release.notify_one();
        assert!(pending.await.unwrap().is_err());
        assert_eq!(
            publish::status(&s).unwrap()["connected"],
            false,
            "a late authorization response must not undo disconnect"
        );
        server.abort();
    }
}

#[test]
fn returning_to_a_superseded_publication_target_requeues_only_that_target() {
    let d = tempfile::tempdir().unwrap();
    let store = Store::open(d.path()).unwrap();
    publish::initialize(d.path(), &store).unwrap();
    store
        .set_meta(
            "github-credential",
            &json!({"reference":uuid::Uuid::nil().simple().to_string(),"login":"fixture"})
                .to_string(),
        )
        .unwrap();
    store.set_meta("current-release", "abc").unwrap();
    let mut settings = publish::settings(&store).unwrap();
    settings.enabled = true;
    publish::save_settings(&store, &settings).unwrap();
    assert_eq!(publish::enqueue_current(&store).unwrap(), 1);
    settings.branch = "alternate".into();
    publish::save_settings(&store, &settings).unwrap();
    assert_eq!(publish::enqueue_current(&store).unwrap(), 1);
    settings.branch = "main".into();
    publish::save_settings(&store, &settings).unwrap();
    assert_eq!(
        publish::enqueue_current(&store).unwrap(),
        1,
        "returning to the current release's original target must restore its superseded work"
    );
    let status = publish::status(&store).unwrap();
    assert_eq!(status["publications"][0]["status"], "superseded");
    assert_eq!(status["publications"][1]["status"], "queued");
    store
        .connect()
        .unwrap()
        .execute(
            "UPDATE publications SET status='published' WHERE branch='main'",
            [],
        )
        .unwrap();
    assert_eq!(
        publish::enqueue_current(&store).unwrap(),
        0,
        "published releases must retain their deduplication receipt"
    );
}

#[tokio::test]
async fn old_device_poll_errors_do_not_clear_or_restore_a_replacement() {
    for error in ["access_denied", "slow_down"] {
        for replace_with_token in [false, true] {
            let entered = std::sync::Arc::new(tokio::sync::Notify::new());
            let release = std::sync::Arc::new(tokio::sync::Notify::new());
            let seen = entered.clone();
            let resume = release.clone();
            let codes = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let count = codes.clone();
            let app = Router::new()
                .route("/login/device/code", post(move || {
                    let count = count.clone();
                    async move {
                        let id = count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        Json(json!({"device_code":format!("device-{id}"),"user_code":format!("USER-{id}"),"verification_uri":"https://github.com/login/device","expires_in":900,"interval":5}))
                    }
                }))
                .route("/login/oauth/access_token", post(move || {
                    let seen = seen.clone();
                    let resume = resume.clone();
                    async move { seen.notify_one(); resume.notified().await; Json(json!({"error":error})) }
                }))
                .route("/user", get(identity))
                .route("/repos/example/rules", get(|| async { StatusCode::NOT_FOUND }));
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://{}", listener.local_addr().unwrap());
            let ep = Endpoints {
                api: url.clone(),
                oauth: url,
            };
            let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
            let d = tempfile::tempdir().unwrap();
            let store = Store::open(d.path()).unwrap();
            publish::initialize(d.path(), &store).unwrap();
            let mut settings = publish::settings(&store).unwrap();
            settings.client_id = "fixture".into();
            publish::save_settings(&store, &settings).unwrap();
            publish::start_device(&store, &ep).await.unwrap();
            store.connect().unwrap().execute("UPDATE meta SET value=json_set(value,'$.next_poll',0) WHERE key='github-device'", []).unwrap();
            let copy = store.clone();
            let endpoints = ep.clone();
            let pending =
                tokio::spawn(async move { publish::poll_device(&copy, &endpoints).await });
            tokio::time::timeout(std::time::Duration::from_secs(2), entered.notified())
                .await
                .unwrap();
            if replace_with_token {
                publish::connect(&store, &test_secret(), &ep).await.unwrap();
            } else {
                publish::start_device(&store, &ep).await.unwrap();
            }
            let replacement = store.meta("github-device").unwrap();
            release.notify_one();
            let _ = pending.await.unwrap();
            assert_eq!(
                store.meta("github-device").unwrap(),
                replacement,
                "old {error} must not mutate a replacement authorization"
            );
            assert_eq!(
                publish::status(&store).unwrap()["connected"],
                replace_with_token
            );
            server.abort();
        }
    }
}

#[tokio::test]
async fn late_device_creation_cannot_restore_cancelled_or_replaced_authorization() {
    for replacement in ["disconnect", "token", "device"] {
        let entered = std::sync::Arc::new(tokio::sync::Notify::new());
        let release = std::sync::Arc::new(tokio::sync::Notify::new());
        let seen = entered.clone();
        let resume = release.clone();
        let codes = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let count = codes.clone();
        let app = Router::new()
            .route("/login/device/code", post(move || {
                let count = count.clone();
                let seen = seen.clone();
                let resume = resume.clone();
                async move {
                    let id = count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    if id == 0 { seen.notify_one(); resume.notified().await; }
                    Json(json!({"device_code":format!("device-{id}"),"user_code":format!("USER-{id}"),"verification_uri":"https://github.com/login/device","expires_in":900,"interval":5}))
                }
            }))
            .route("/user", get(identity))
            .route("/repos/example/rules", get(|| async { StatusCode::NOT_FOUND }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let ep = Endpoints {
            api: url.clone(),
            oauth: url,
        };
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let d = tempfile::tempdir().unwrap();
        let store = Store::open(d.path()).unwrap();
        publish::initialize(d.path(), &store).unwrap();
        let mut settings = publish::settings(&store).unwrap();
        settings.client_id = "fixture".into();
        publish::save_settings(&store, &settings).unwrap();
        let copy = store.clone();
        let endpoints = ep.clone();
        let pending = tokio::spawn(async move { publish::start_device(&copy, &endpoints).await });
        tokio::time::timeout(std::time::Duration::from_secs(2), entered.notified())
            .await
            .unwrap();
        match replacement {
            "disconnect" => publish::disconnect(&store).unwrap(),
            "token" => {
                publish::connect(&store, &test_secret(), &ep).await.unwrap();
            }
            _ => {
                publish::start_device(&store, &ep).await.unwrap();
            }
        }
        let current = store.meta("github-device").unwrap();
        release.notify_one();
        assert!(
            pending.await.unwrap().is_err(),
            "late device creation must observe {replacement}"
        );
        assert_eq!(store.meta("github-device").unwrap(), current);
        assert_eq!(
            publish::status(&store).unwrap()["connected"],
            replacement == "token"
        );
        server.abort();
    }
}

#[tokio::test]
async fn starting_a_new_token_attempt_cancels_an_older_device_result() {
    let device_seen = std::sync::Arc::new(tokio::sync::Notify::new());
    let device_resume = std::sync::Arc::new(tokio::sync::Notify::new());
    let token_seen = std::sync::Arc::new(tokio::sync::Notify::new());
    let token_resume = std::sync::Arc::new(tokio::sync::Notify::new());
    let ds = device_seen.clone();
    let dr = device_resume.clone();
    let ts = token_seen.clone();
    let tr = token_resume.clone();
    let app = Router::new()
        .route("/login/device/code", post(device))
        .route(
            "/login/oauth/access_token",
            post(move || {
                let seen = ds.clone();
                let resume = dr.clone();
                async move {
                    seen.notify_one();
                    resume.notified().await;
                    Json(json!({"access_token":uuid::Uuid::from_u128(1).to_string()}))
                }
            }),
        )
        .route(
            "/user",
            get(move |headers: HeaderMap| {
                let seen = ts.clone();
                let resume = tr.clone();
                async move {
                    let is_new = headers.get("authorization").is_some_and(|h| {
                        h.to_str().ok()
                            == Some(format!("Bearer {}", uuid::Uuid::from_u128(2)).as_str())
                    });
                    if is_new {
                        seen.notify_one();
                        resume.notified().await;
                    }
                    Json(json!({"login":if is_new {"new-account"} else {"old-account"}}))
                }
            }),
        )
        .route(
            "/repos/example/rules",
            get(|| async { StatusCode::NOT_FOUND }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let ep = Endpoints {
        api: url.clone(),
        oauth: url,
    };
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let d = tempfile::tempdir().unwrap();
    let store = Store::open(d.path()).unwrap();
    publish::initialize(d.path(), &store).unwrap();
    let mut settings = publish::settings(&store).unwrap();
    settings.client_id = "fixture".into();
    publish::save_settings(&store, &settings).unwrap();
    publish::start_device(&store, &ep).await.unwrap();
    store
        .connect()
        .unwrap()
        .execute(
            "UPDATE meta SET value=json_set(value,'$.next_poll',0) WHERE key='github-device'",
            [],
        )
        .unwrap();
    let copy = store.clone();
    let endpoints = ep.clone();
    let old = tokio::spawn(async move { publish::poll_device(&copy, &endpoints).await });
    tokio::time::timeout(std::time::Duration::from_secs(2), device_seen.notified())
        .await
        .unwrap();
    let copy = store.clone();
    let endpoints = ep.clone();
    let new = tokio::spawn(async move {
        publish::connect(&copy, &uuid::Uuid::from_u128(2).to_string(), &endpoints).await
    });
    tokio::time::timeout(std::time::Duration::from_secs(2), token_seen.notified())
        .await
        .unwrap();
    device_resume.notify_one();
    assert!(
        old.await.unwrap().is_err(),
        "a device flow must lose authority when a newer token connection starts"
    );
    token_resume.notify_one();
    assert_eq!(new.await.unwrap().unwrap()["login"], "new-account");
    assert_eq!(publish::status(&store).unwrap()["login"], "new-account");
    server.abort();
}

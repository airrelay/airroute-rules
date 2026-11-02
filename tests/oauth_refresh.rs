use airroute_rules::{
    now,
    publish::{self, Endpoints},
    store::Store,
};
use axum::{
    Form, Json, Router,
    http::{HeaderMap, StatusCode},
    routing::{get, post},
};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicU8, AtomicUsize, Ordering},
    },
};

#[derive(Clone)]
struct Remote {
    tokens: Arc<Vec<String>>,
    mode: Arc<AtomicU8>,
    calls: Arc<AtomicUsize>,
    entered: Arc<tokio::sync::Notify>,
    release: Arc<tokio::sync::Notify>,
}
struct Fixture {
    data: tempfile::TempDir,
    store: Store,
    ep: Endpoints,
    remote: Remote,
    server: tokio::task::JoinHandle<()>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.server.abort();
    }
}
impl Fixture {
    async fn new() -> Self {
        let remote = Remote {
            tokens: Arc::new((0..4).map(|_| uuid::Uuid::new_v4().to_string()).collect()),
            mode: Arc::new(AtomicU8::new(0)),
            calls: Arc::new(AtomicUsize::new(0)),
            entered: Arc::new(tokio::sync::Notify::new()),
            release: Arc::new(tokio::sync::Notify::new()),
        };
        let identity = remote.clone();
        let access = remote.clone();
        let app=Router::new().route("/user",get(move |h: HeaderMap| { let r=identity.clone(); async move {
            assert_eq!(h["authorization"],format!("Bearer {}",r.tokens[0]));
            Json(json!({"login":"fixture-user"}))
        }})).route("/repos/example/rules",get(||async{StatusCode::OK}))
        .route("/login/device/code",post(||async{Json(json!({"device_code":"fixture-device","user_code":"ABCD-1234","verification_uri":"https://github.com/login/device","expires_in":900,"interval":5}))}))
        .route("/login/oauth/access_token",post(move |Form(f): Form<HashMap<String,String>>| {let r=access.clone();async move {
            if f["grant_type"]=="refresh_token" {
                r.calls.fetch_add(1,Ordering::SeqCst);
                assert_eq!(f["client_id"],"fixture_client");
                assert_eq!(f["refresh_token"],r.tokens[1]);
                let mode=r.mode.load(Ordering::SeqCst);
                if mode==1 {return (StatusCode::OK,Json(json!({"error":"bad_refresh_token"})));}
                if mode==2 {r.entered.notify_one();r.release.notified().await;}
                if mode==3 {return (StatusCode::OK,Json(json!({"access_token":r.tokens[2],"expires_in":3600})));}
                if mode==4 {return (StatusCode::SERVICE_UNAVAILABLE,Json(json!({"error":"temporary"})));}
                (StatusCode::OK,Json(json!({"access_token":r.tokens[2],"refresh_token":r.tokens[3],"expires_in":7200,"refresh_token_expires_in":15897600})))
            } else {
                assert_eq!(f["grant_type"],"urn:ietf:params:oauth:grant-type:device_code");
                if r.mode.load(Ordering::SeqCst)==5 {return (StatusCode::OK,Json(json!({"access_token":r.tokens[0],"expires_in":3600})));}
                (StatusCode::OK,Json(json!({"access_token":r.tokens[0],"refresh_token":r.tokens[1],"expires_in":3600,"refresh_token_expires_in":15897600})))
            }
        }}));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let ep = Endpoints {
            api: url.clone(),
            oauth: url,
        };
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let data = tempfile::tempdir().unwrap();
        let store = Store::open(data.path()).unwrap();
        publish::initialize(data.path(), &store).unwrap();
        let mut settings = publish::settings(&store).unwrap();
        settings.client_id = "fixture_client".into();
        publish::save_settings(&store, &settings).unwrap();
        Self {
            data,
            store,
            ep,
            remote,
            server,
        }
    }
    async fn connect(&self) -> anyhow::Result<Value> {
        publish::start_device(&self.store, &self.ep).await?;
        self.store.connect()?.execute(
            "UPDATE meta SET value=json_set(value,'$.next_poll',0) WHERE key='github-device'",
            [],
        )?;
        publish::poll_device(&self.store, &self.ep).await
    }
    fn meta(&self) -> Value {
        serde_json::from_str(&self.store.meta("github-credential").unwrap().unwrap()).unwrap()
    }
    fn secret_count(&self) -> usize {
        std::fs::read_dir(self.data.path().join("credentials"))
            .map(|r| r.count())
            .unwrap_or(0)
    }
    fn expire(&self, field: &str) {
        let mut meta = self.meta();
        meta["renewal"][field] = json!(now() - 1);
        self.store
            .set_meta("github-credential", &meta.to_string())
            .unwrap();
    }
}

#[tokio::test]
async fn expiring_oauth_rotates_durably_before_publication_and_keeps_original_client_id() {
    let f = Fixture::new().await;
    f.connect().await.unwrap();
    let original = f.meta();
    let public = publish::status(&f.store).unwrap();
    assert_eq!(public["auto_refresh_available"], true);
    assert!(public["expires_at"].as_i64().unwrap() > now());
    for token in f.remote.tokens.iter() {
        assert!(!public.to_string().contains(token));
        assert!(!original.to_string().contains(token));
    }
    assert_eq!(f.secret_count(), 2);
    assert_eq!(
        publish::renew_authorization(&f.store, &f.ep, false)
            .await
            .unwrap()["refreshed"],
        false
    );
    assert_eq!(f.remote.calls.load(Ordering::SeqCst), 0);
    let mut settings = publish::settings(&f.store).unwrap();
    settings.client_id = "replacement_client".into();
    publish::save_settings(&f.store, &settings).unwrap();
    f.expire("expires_at");
    let reopened = Store::open(f.data.path()).unwrap();
    assert_eq!(
        publish::renew_authorization(&reopened, &f.ep, false)
            .await
            .unwrap()["refreshed"],
        true
    );
    assert_eq!(f.remote.calls.load(Ordering::SeqCst), 1);
    let rotated = f.meta();
    assert_ne!(rotated["reference"], original["reference"]);
    assert_eq!(
        airroute_rules::secrets::read(f.data.path(), rotated["reference"].as_str().unwrap())
            .unwrap(),
        f.remote.tokens[2]
    );
    assert_eq!(
        airroute_rules::secrets::read(
            f.data.path(),
            rotated["renewal"]["reference"].as_str().unwrap()
        )
        .unwrap(),
        f.remote.tokens[3]
    );
    assert_eq!(f.secret_count(), 2);
    assert!(
        !f.data
            .path()
            .join("credentials")
            .join(original["reference"].as_str().unwrap())
            .exists()
    );
    assert!(
        publish::status(&reopened).unwrap()["expires_at"]
            .as_i64()
            .unwrap()
            > now() + 7100
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for p in std::fs::read_dir(f.data.path().join("credentials")).unwrap() {
            assert_eq!(
                p.unwrap().metadata().unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }
    publish::disconnect(&f.store).unwrap();
    assert_eq!(f.secret_count(), 0);
    assert_eq!(publish::status(&f.store).unwrap()["connected"], false);
}

#[tokio::test]
async fn rejected_malformed_and_transient_refreshes_keep_credentials_and_expose_no_secrets() {
    for mode in [1, 3, 4] {
        let f = Fixture::new().await;
        f.connect().await.unwrap();
        let original = f.meta();
        f.remote.mode.store(mode, Ordering::SeqCst);
        let error = publish::renew_authorization(&f.store, &f.ep, true)
            .await
            .unwrap_err()
            .to_string();
        assert_eq!(f.meta(), original);
        assert_eq!(f.secret_count(), 2);
        for token in f.remote.tokens.iter() {
            assert!(!error.contains(token));
            assert!(
                !publish::status(&f.store)
                    .unwrap()
                    .to_string()
                    .contains(token)
            );
        }
        if mode == 1 {
            assert_eq!(
                publish::status(&f.store).unwrap()["health"],
                "reauthorization-required"
            );
        }
    }
}

#[tokio::test]
async fn expired_refresh_grant_requires_reauthorization_without_an_http_attempt() {
    let f = Fixture::new().await;
    f.connect().await.unwrap();
    f.expire("refresh_expires_at");
    assert!(
        publish::renew_authorization(&f.store, &f.ep, true)
            .await
            .is_err()
    );
    assert_eq!(f.remote.calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        publish::status(&f.store).unwrap()["health"],
        "reauthorization-required"
    );
}

#[tokio::test]
async fn incomplete_expiring_device_grant_is_never_saved_as_a_permanent_token() {
    let f = Fixture::new().await;
    f.remote.mode.store(5, Ordering::SeqCst);
    assert!(f.connect().await.is_err());
    assert_eq!(publish::status(&f.store).unwrap()["connected"], false);
    assert_eq!(f.secret_count(), 0);
}

#[tokio::test]
async fn refreshing_and_disconnect_are_serialized_without_restoring_a_disconnected_account() {
    let f = Fixture::new().await;
    f.connect().await.unwrap();
    f.remote.mode.store(2, Ordering::SeqCst);
    let store = f.store.clone();
    let ep = f.ep.clone();
    let pending =
        tokio::spawn(async move { publish::renew_authorization(&store, &ep, true).await });
    tokio::time::timeout(
        std::time::Duration::from_secs(2),
        f.remote.entered.notified(),
    )
    .await
    .unwrap();
    assert!(publish::disconnect(&f.store).is_err());
    f.remote.release.notify_one();
    pending.await.unwrap().unwrap();
    publish::disconnect(&f.store).unwrap();
    assert_eq!(publish::status(&f.store).unwrap()["connected"], false);
    assert_eq!(f.secret_count(), 0);
}

#[tokio::test]
async fn legacy_repository_tokens_keep_their_original_behavior() {
    let f = Fixture::new().await;
    publish::connect(&f.store, &f.remote.tokens[0], &f.ep)
        .await
        .unwrap();
    let mut original = f.meta();
    original.as_object_mut().unwrap().remove("renewal");
    f.store
        .set_meta("github-credential", &original.to_string())
        .unwrap();
    assert_eq!(
        publish::renew_authorization(&f.store, &f.ep, true)
            .await
            .unwrap()["refreshed"],
        false
    );
    assert_eq!(f.remote.calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        publish::status(&f.store).unwrap()["auto_refresh_available"],
        false
    );
    assert_eq!(f.secret_count(), 1);
}

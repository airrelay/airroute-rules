//! Persistent QUIC worker sessions. HTTP is reserved for the administrator console.
use crate::{
    atomic_write,
    measure::{self, ProbeConfig},
    now,
    store::{Lease, ProbeResult, Store},
};
use anyhow::{Context, Result, bail, ensure};
use quinn::{Connection, Endpoint, RecvStream, SendStream};
use rusqlite::{Connection as SqlConnection, params};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::File,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::{
    sync::{Semaphore, mpsc},
    task::JoinSet,
};
pub const VERSION: u16 = 1;
pub const ALPN: &[u8] = b"airroute-probe/1";
pub const MAX_FRAME: usize = 2 * 1024 * 1024;
pub const SERVER_NAME: &str = "airroute-rules";
const HEARTBEAT: u64 = 10;
const DEADLINE: u64 = 35;
#[derive(Serialize, Deserialize)]
pub enum Message {
    Hello {
        id: String,
        token: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        network: Option<crate::network::NetworkSupport>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        capacity: Option<u32>,
    },
    Welcome {
        session: String,
        heartbeat_seconds: u64,
        slots: u32,
    },
    Ready,
    Finished {
        id: String,
    },
    Heartbeat {
        active: Vec<(String, String)>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        network: Option<crate::network::NetworkSupport>,
    },
    Pong {
        server_time: i64,
    },
    Task(Box<Lease>),
    Idle,
    Result(Box<ProbeResult>),
    Ack {
        id: String,
        disposition: Disposition,
    },
    Rejected {
        id: String,
        retryable: bool,
    },
}
#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub enum Disposition {
    Accepted,
    Historical,
    Duplicate,
}
#[derive(Serialize, Deserialize)]
struct Envelope {
    version: u16,
    message: Message,
}
pub fn encode(message: Message) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    ciborium::into_writer(
        &Envelope {
            version: VERSION,
            message,
        },
        &mut bytes,
    )?;
    ensure!(bytes.len() <= MAX_FRAME, "binary frame exceeds limit");
    Ok(bytes)
}
pub fn decode(bytes: &[u8]) -> Result<Message> {
    ensure!(
        !bytes.is_empty() && bytes.len() <= MAX_FRAME,
        "invalid binary frame length"
    );
    let mut reader = bytes;
    let envelope: Envelope = ciborium::de::from_reader_with_recursion_limit(&mut reader, 64)?;
    ensure!(reader.is_empty(), "trailing binary frame data");
    ensure!(
        envelope.version == VERSION,
        "unsupported worker protocol version"
    );
    Ok(envelope.message)
}
pub async fn send(stream: &mut SendStream, message: Message) -> Result<()> {
    let bytes = encode(message)?;
    tokio::time::timeout(Duration::from_secs(15), async {
        stream
            .write_all(&(bytes.len() as u32).to_be_bytes())
            .await?;
        stream.write_all(&bytes).await?;
        anyhow::Ok(())
    })
    .await
    .context("binary send timeout")??;
    Ok(())
}
pub async fn receive(stream: &mut RecvStream) -> Result<Message> {
    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await?;
    let n = u32::from_be_bytes(header) as usize;
    ensure!(n > 0 && n <= MAX_FRAME, "invalid binary frame length");
    let mut bytes = vec![0; n];
    stream.read_exact(&mut bytes).await?;
    decode(&bytes)
}
fn reader(mut recv: RecvStream) -> (mpsc::Receiver<Result<Message>>, tokio::task::JoinHandle<()>) {
    let (tx, rx) = mpsc::channel(16);
    let task = tokio::spawn(async move {
        loop {
            let result = receive(&mut recv).await;
            let failed = result.is_err();
            if tx.send(result).await.is_err() || failed {
                break;
            }
        }
    });
    (rx, task)
}
fn transport_config() -> quinn::TransportConfig {
    let mut t = quinn::TransportConfig::default();
    t.max_idle_timeout(Some(Duration::from_secs(45).try_into().expect("timeout")))
        .keep_alive_interval(Some(Duration::from_secs(10)))
        .max_concurrent_bidi_streams(65u32.into())
        .max_concurrent_uni_streams(0u32.into())
        .stream_receive_window((MAX_FRAME as u32).into())
        .receive_window((MAX_FRAME as u32 * 8).into());
    t
}
pub fn certificate(data: &Path) -> Result<PathBuf> {
    let dir = data.join("quic");
    std::fs::create_dir_all(&dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
    }
    let cert = dir.join("controller-cert.der");
    let key = dir.join("controller-key.der");
    if !cert.exists() && !key.exists() {
        let generated = rcgen::generate_simple_self_signed(vec![
            SERVER_NAME.into(),
            "localhost".into(),
            "127.0.0.1".into(),
            "::1".into(),
        ])?;
        atomic_write(&key, &generated.signing_key.serialize_der())?;
        atomic_write(&cert, generated.cert.der())?;
    }
    ensure!(
        cert.exists() && key.exists(),
        "incomplete QUIC identity; restore the certificate/key pair rather than silently changing node trust"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(key, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(cert)
}
pub fn server_endpoint(data: &Path, bind: SocketAddr) -> Result<Endpoint> {
    let cert = CertificateDer::from(std::fs::read(certificate(data)?)?);
    let key = PrivatePkcs8KeyDer::from(std::fs::read(data.join("quic/controller-key.der"))?);
    let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])?
    .with_no_client_auth()
    .with_single_cert(vec![cert], key.into())?;
    tls.alpn_protocols = vec![ALPN.to_vec()];
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls)?;
    let mut config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    config.transport = Arc::new(transport_config());
    Ok(Endpoint::server(config, bind)?)
}
pub fn client_endpoint(ca: &Path, bind: SocketAddr) -> Result<Endpoint> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(CertificateDer::from(
        std::fs::read(ca).context("read controller trust certificate")?,
    ))?;
    let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])?
    .with_root_certificates(roots)
    .with_no_client_auth();
    tls.alpn_protocols = vec![ALPN.to_vec()];
    let mut c = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(tls)?,
    ));
    c.transport_config(Arc::new(transport_config()));
    let mut endpoint = Endpoint::client(bind)?;
    endpoint.set_default_client_config(c);
    Ok(endpoint)
}
#[derive(Clone, Default)]
pub struct Hub {
    sessions: Arc<Mutex<BTreeMap<String, (String, Connection)>>>,
}
impl Hub {
    pub fn disconnect(&self, id: &str) {
        if let Some((_, c)) = self.sessions.lock().expect("sessions").remove(id) {
            c.close(1u32.into(), b"node credentials or state changed");
        }
    }
    pub fn disconnect_all(&self) {
        for (_, (_, c)) in std::mem::take(&mut *self.sessions.lock().expect("sessions")) {
            c.close(0u32.into(), b"controller stopped");
        }
    }
}
pub struct Server {
    pub endpoint: Endpoint,
    pub hub: Hub,
    task: tokio::task::JoinHandle<()>,
    _lock: crate::FileLock,
}
impl Drop for Server {
    fn drop(&mut self) {
        self.hub.disconnect_all();
        self.endpoint.close(0u32.into(), b"controller stopped");
        self.task.abort();
    }
}
impl Server {
    pub async fn shutdown(mut self) {
        self.hub.disconnect_all();
        self.endpoint.close(0u32.into(), b"controller stopped");
        self.task.abort();
        let _ = (&mut self.task).await;
        let _ = tokio::time::timeout(Duration::from_secs(5), self.endpoint.wait_idle()).await;
        drop(self);
        // Quinn's endpoint driver releases the UDP socket after the final handle drops.
        tokio::task::yield_now().await;
    }
    pub fn start(data: &Path, store: Store, bind: SocketAddr) -> Result<Self> {
        let lock = crate::FileLock::try_new(File::create(data.join("control.transport.lock"))?)
            .context("a worker controller is already using this database")?;
        let endpoint = server_endpoint(data, bind)?;
        {
            let mut c = store.connect()?;
            let tx = c.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            tx.execute("UPDATE nodes SET connected=0,session_id=NULL WHERE connected<>0 OR session_id IS NOT NULL", [])?;
            crate::store::release_unstarted_on(&tx, None)?;
            tx.commit()?;
        }
        let hub = Hub::default();
        let copy = endpoint.clone();
        let sessions = hub.clone();
        let gate = Arc::new(Semaphore::new(128));
        let task = tokio::spawn(async move {
            let mut tasks = JoinSet::new();
            loop {
                tokio::select! {incoming=copy.accept()=>{let Some(incoming)=incoming else{break};let Ok(permit)=gate.clone().try_acquire_owned()else{incoming.refuse();continue};let s=store.clone();let h=sessions.clone();tasks.spawn(async move{let _permit=permit;let result=async{let connection=tokio::time::timeout(Duration::from_secs(10),incoming).await??;serve_connection(s,h,connection).await}.await;if let Err(e)=result{tracing::debug!(error=%e,"worker session ended");}});},_=tasks.join_next(),if !tasks.is_empty()=>{}}
            }
        });
        Ok(Self {
            endpoint,
            hub,
            task,
            _lock: lock,
        })
    }
}
struct SessionGuard {
    store: Store,
    hub: Hub,
    id: String,
    session: String,
    connection: Connection,
    reader: tokio::task::JoinHandle<()>,
}
enum Dispatch {
    Claimed(Option<Lease>),
    Started(Option<UnsentDispatch>),
}
/// Own the proof that this original attempt has never entered send(Task).
/// A blocking start worker can outlive its session/JoinSet; dropping its result
/// must return that exact opportunity instead of leaving a fictitious execution.
struct UnsentDispatch {
    store: Store,
    node: String,
    session: String,
    lease: Option<Lease>,
}
impl UnsentDispatch {
    fn enter_send(mut self) -> Lease {
        // From here a partial write or lost connection is uncertain. Never
        // refund based on an ACK failure or on whether send() later succeeds.
        self.lease.take().expect("unsent dispatch owns its lease")
    }
}
impl Drop for UnsentDispatch {
    fn drop(&mut self) {
        let Some(lease) = self.lease.take() else {
            return;
        };
        let (store, node, session) = (self.store.clone(), self.node.clone(), self.session.clone());
        let cleanup = move || {
            if let Err(error) = store.release_unsent_execution(&node, &session, &lease) {
                tracing::warn!(%error, node=%node, job=%lease.id, "unsent dispatch cleanup failed");
            }
        };
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn_blocking(cleanup);
        } else {
            cleanup();
        }
    }
}
fn start_dispatch(
    store: &Store,
    db: &mut SqlConnection,
    node: &str,
    session: &str,
    lease: Lease,
    physical: u32,
) -> Result<Dispatch> {
    let mut unsent = UnsentDispatch {
        store: store.clone(),
        node: node.into(),
        session: session.into(),
        lease: Some(lease),
    };
    if store.begin_execution_with_capacity_on(
        db,
        node,
        session,
        unsent.lease.as_ref().expect("dispatch lease"),
        physical,
    )? {
        Ok(Dispatch::Started(Some(unsent)))
    } else {
        // The send fence already returned this provably unstarted reservation.
        unsent.lease.take();
        Ok(Dispatch::Started(None))
    }
}
impl Drop for SessionGuard {
    fn drop(&mut self) {
        self.connection.close(0u32.into(), b"session ended");
        self.reader.abort();
        let (store, hub, id, session) = (
            self.store.clone(),
            self.hub.clone(),
            self.id.clone(),
            self.session.clone(),
        );
        let cleanup = move || {
            let mut sessions = hub.sessions.lock().expect("sessions");
            if sessions.get(&id).is_some_and(|(s, _)| s == &session) {
                sessions.remove(&id);
            }
            if offline(&store, &id, &session).unwrap_or(false) {
                store.wake.notify_waiters();
            }
        };
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn_blocking(cleanup);
        } else {
            cleanup();
        }
    }
}
fn offline(store: &Store, id: &str, session: &str) -> Result<bool> {
    let mut conn = store.connect()?;
    let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let n = tx.execute(
        "UPDATE nodes SET connected=0,session_id=NULL WHERE id=? AND session_id=?",
        params![id, session],
    )?;
    if n > 0 {
        crate::store::release_unstarted_on(&tx, Some(id))?;
    }
    tx.commit()?;
    Ok(n > 0)
}
pub async fn serve_connection(store: Store, hub: Hub, connection: Connection) -> Result<()> {
    let (mut send_stream, mut recv) =
        tokio::time::timeout(Duration::from_secs(10), connection.accept_bi()).await??;
    let Message::Hello {
        id,
        token,
        network,
        capacity,
    } = tokio::time::timeout(Duration::from_secs(10), receive(&mut recv)).await??
    else {
        bail!("worker hello required")
    };
    ensure!(
        id.len() <= 80 && token.len() <= 8192,
        "invalid worker hello"
    );
    let capacity = capacity.unwrap_or(16);
    ensure!((1..=1000).contains(&capacity), "invalid worker capacity");
    let network = network.unwrap_or(crate::network::NetworkSupport {
        ipv4: connection.remote_address().is_ipv4(),
        ipv6: connection.remote_address().is_ipv6(),
    });
    let session = uuid::Uuid::new_v4().to_string();
    // Authenticate before buffering control frames. A cancelled setup drops its
    // returned guard on the blocking thread, after any activation has finished.
    let (setup_store, setup_hub, setup_id, setup_session, setup_token) = (
        store.clone(),
        hub.clone(),
        id.clone(),
        session.clone(),
        token.clone(),
    );
    let setup_connection = connection.clone();
    let (node,guard,mut rx,claim_db,heartbeat_db,receipt_db)=tokio::task::spawn_blocking(move||->Result<_>{
        let node=setup_store.authenticate_node(&setup_id,&setup_token)?;
        let(rx,reader)=reader(recv);
        let guard=SessionGuard{store:setup_store.clone(),hub:setup_hub.clone(),id:setup_id.clone(),session:setup_session.clone(),connection:setup_connection.clone(),reader};
        setup_store.connect()?.execute("UPDATE nodes SET ipv4_supported=?,ipv6_supported=?,network_checked=?,worker_capacity=? WHERE id=?",params![network.ipv4,network.ipv6,now(),capacity,setup_id])?;
        let mut sessions = setup_hub.sessions.lock().expect("sessions");
        if let Some((old_session, old)) =
            sessions.insert(setup_id.clone(), (setup_session.clone(), setup_connection))
        {
            old.close(1u32.into(), b"node reconnected");
            offline(&setup_store, &setup_id, &old_session)?;
        }
        setup_store.connect()?.execute(
            "UPDATE nodes SET connected=1,session_id=?,last_seen=? WHERE id=?",
            params![setup_session, now(), setup_id],
        )?;
        drop(sessions);
        // The new session/capacity is one meaningful eligibility change.
        setup_store.wake.notify_waiters();
        let (claim_db, heartbeat_db, receipt_db)=(setup_store.connect()?,setup_store.connect()?,setup_store.connect()?);
        for db in [&claim_db,&heartbeat_db,&receipt_db] {
            // Cache only SQL statements on the existing bounded workers, not
            // query values or a read snapshot between operations.
            db.set_prepared_statement_cache_capacity(64);
        }
        Ok((node,guard,rx,claim_db,heartbeat_db,receipt_db))
    }).await??;
    send(
        &mut send_stream,
        Message::Welcome {
            session: session.clone(),
            heartbeat_seconds: HEARTBEAT,
            // Worker safety ceiling; the live policy below controls actual dispatch.
            slots: capacity,
        },
    )
    .await?;
    tracing::info!(node=%id,"QUIC worker connected");
    let mut last = Instant::now();
    let mut ready = false;
    let mut inflight = std::collections::BTreeSet::new();
    let mut idle_sent = false;
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    let mut uploads = JoinSet::new();
    // Only one claim is prepared at a time. Control frames and heartbeats keep
    // flowing while SQLite prepares that reservation on a blocking worker.
    let mut claims: JoinSet<(SqlConnection, Result<Dispatch>)> = JoinSet::new();
    let mut claim_db = Some(claim_db);
    let receipt_db = Arc::new(tokio::sync::Mutex::new(Some(receipt_db)));
    let mut want_claim = false;
    let mut heartbeat_writes: JoinSet<(SqlConnection, Result<bool>)> = JoinSet::new();
    let mut heartbeat_db = Some(heartbeat_db);
    let mut pending_heartbeat = None;
    let outcome: Result<()> = async {
        loop {
            tokio::select! {
                frame = rx.recv() => {
                    let frame = frame.context("worker stream ended")??;
                    let (s, i, t) = (store.clone(), id.clone(), token.clone());
                    tokio::task::spawn_blocking(move || s.authenticate_node(&i, &t)).await??;
                    match frame {
                        Message::Ready => { ready = true; last = Instant::now(); want_claim = true; },
                        Message::Finished { id: job } => {
                            ensure!(inflight.remove(&job), "unknown finished task");
                            want_claim = true;
                        },
                        Message::Heartbeat { active, network } => {
                            ensure!(active.len() <= 1000, "too many active worker leases");
                            last = Instant::now();
                            // Authentication is authoritative for connection liveness.
                            // Slow persistence is serialized/coalesced independently;
                            // old session/token fences still guard every lease write.
                            pending_heartbeat = Some((active, network));
                            send(&mut send_stream, Message::Pong { server_time: now() }).await?;
                        },
                        _ => bail!("unexpected worker control message"),
                    }
                },
                incoming = connection.accept_bi(), if uploads.len() < 64 => {
                    let (tx, rx) = incoming?;
                    let s = store.clone();
                    let node_id = id.clone();
                    let receipt_db = receipt_db.clone();
                    // submit_on owns the one notification for actual changes;
                    // ACK delivery, duplicates and failed frames add no broadcast.
                    uploads.spawn(async move { receive_result(&s, &node_id, receipt_db, tx, rx).await });
                },
                _ = store.wake.notified() => { want_claim = true; },
                _ = tick.tick() => {
                    ensure!(last.elapsed() < Duration::from_secs(DEADLINE), "worker heartbeat timed out");
                    let (s, i, t) = (store.clone(), id.clone(), token.clone());
                    tokio::task::spawn_blocking(move || s.authenticate_node(&i, &t)).await??;
                    want_claim = true;
                },
                result = uploads.join_next(), if !uploads.is_empty() => {
                    if let Some(Ok(Err(error))) = result {
                        tracing::debug!(%error, node=%id, "worker result stream failed");
                    }
                },
                result = claims.join_next(), if !claims.is_empty() => {
                    let (db, result) = result.context("claim worker ended")??;
                    claim_db = Some(db);
                    match result? {
                        Dispatch::Claimed(Some(lease)) => {
                            let (s, i, se, physical) =
                                (store.clone(), id.clone(), session.clone(), inflight.len() as u32);
                            // The send fence uses the same single blocking worker;
                            // waiting for its writer never suspends control frames.
                            let mut db = claim_db.take().expect("claim connection returned");
                            claims.spawn_blocking(move || {
                                let result = start_dispatch(&s, &mut db, &i, &se, lease, physical);
                                (db, result)
                            });
                        },
                        Dispatch::Started(unsent) => {
                            if let Some(unsent) = unsent {
                                let lease = unsent.enter_send();
                                idle_sent = false;
                                inflight.insert(lease.id.clone());
                                send(&mut send_stream, Message::Task(Box::new(lease))).await?;
                            }
                            want_claim = true;
                        },
                        Dispatch::Claimed(None) if !idle_sent => {
                            send(&mut send_stream, Message::Idle).await?;
                            idle_sent = true;
                        }
                        Dispatch::Claimed(None) => {},
                    }
                },
                result = heartbeat_writes.join_next(), if !heartbeat_writes.is_empty() => {
                    let (db, result) = result.context("heartbeat worker ended")??;
                    heartbeat_db = Some(db);
                    match result {
                        Ok(true) => {},
                        Ok(false) => bail!("worker heartbeat session is no longer current"),
                        Err(error) => tracing::warn!(%error,node=%id,"worker heartbeat persistence deferred"),
                    }
                },
                _ = connection.closed() => break,
            }
            if heartbeat_writes.is_empty()
                && let Some((active, network)) = pending_heartbeat.take()
            {
                let (s, i, se) = (store.clone(), id.clone(), session.clone());
                let mut db = heartbeat_db.take().expect("heartbeat connection returned");
                heartbeat_writes.spawn_blocking(move || {
                    let result = s.heartbeat_batch_on(&mut db, &i, &se, &active, network.as_ref());
                    (db, result)
                });
            }
            if ready && want_claim && claims.is_empty() {
                want_claim = false;
                let (s, n, se, physical) = (store.clone(), node.clone(), session.clone(), inflight.len());
                let mut db = claim_db.take().expect("claim connection returned");
                claims.spawn_blocking(move || {
                    let result = (|| -> Result<Option<Lease>> {
                        if physical >= Store::node_concurrency_on(&db, &n.id)?.min(capacity) as usize {
                            return Ok(None);
                        }
                        s.lease_session_on(&mut db, &n, &se)
                    })();
                    (db, result.map(Dispatch::Claimed))
                });
            }
        }
        Ok(())
    }.await;
    if let Err(error) = &outcome {
        tracing::warn!(%error, node=%id, "worker session ended");
    }
    drop(guard);
    outcome
}

async fn receive_result(
    store: &Store,
    node: &str,
    receipt_db: Arc<tokio::sync::Mutex<Option<SqlConnection>>>,
    mut send_stream: SendStream,
    mut recv: RecvStream,
) -> Result<()> {
    let Message::Result(result) =
        tokio::time::timeout(Duration::from_secs(20), receive(&mut recv)).await??
    else {
        bail!("result stream requires a receipt")
    };
    let id = result.id.clone();
    let (s, n) = (store.clone(), node.to_string());
    // Only this session's database segment is serialized. The existing 64
    // stream gate remains unchanged, and no transaction/lock spans an ACK.
    let mut slot = receipt_db.lock().await;
    let owned = slot.take();
    let (db, ack) = tokio::task::spawn_blocking(move || -> Result<_> {
        let mut db = owned.map(Ok).unwrap_or_else(|| s.connect())?;
        db.set_prepared_statement_cache_capacity(64);
        let ack = crate::receipt::submit_on(&s, &mut db, &n, &result);
        Ok((db, ack))
    })
    .await??;
    *slot = Some(db);
    drop(slot);
    let message = match ack {
        Ok(ack) => Message::Ack {
            id,
            disposition: if ack["duplicate"] == true {
                Disposition::Duplicate
            } else if ack["accepted"] == true {
                Disposition::Accepted
            } else {
                Disposition::Historical
            },
        },
        Err(e) => Message::Rejected {
            id,
            retryable: e.downcast_ref::<rusqlite::Error>().is_some(),
        },
    };
    send(&mut send_stream, message).await?;
    send_stream.finish()?;
    Ok(())
}
async fn upload(connection: &Connection, result: &ProbeResult) -> Result<bool> {
    let id = result.id.clone();
    let (mut tx, mut rx) = connection.open_bi().await?;
    send(&mut tx, Message::Result(Box::new(result.clone()))).await?;
    tx.finish()?;
    match tokio::time::timeout(Duration::from_secs(25), receive(&mut rx)).await?? {
        Message::Ack { id: ack, .. } if ack == id => Ok(true),
        Message::Rejected {
            id: ack,
            retryable: false,
        } if ack == id => Ok(false),
        _ => bail!("worker receipt not acknowledged; durable outbox retained"),
    }
}

// The receipt already exists durably in the spool. A lost ACK or retryable
// rejection retries only those immutable bytes on this connection; it is not a
// failed measurement and must not tear down unrelated running work.
async fn upload_persisted(connection: &Connection, path: &Path) -> Result<()> {
    let result: ProbeResult = crate::read_json(path)?;
    loop {
        match upload(connection, &result).await {
            Ok(accepted) => {
                if accepted {
                    std::fs::remove_file(path)?;
                } else {
                    let dir = path.parent().context("outbox")?.join("rejected");
                    std::fs::create_dir_all(&dir)?;
                    std::fs::rename(path, dir.join(path.file_name().context("receipt name")?))?;
                    tracing::warn!(result=%result.id, "worker receipt quarantined after permanent rejection");
                }
                return Ok(());
            }
            Err(error) => {
                if connection.close_reason().is_some() {
                    return Err(error);
                }
                tracing::warn!(error=%error, "receipt upload deferred; durable outbox retained");
                tokio::select! {
                    _ = connection.closed() => bail!("worker connection closed; durable outbox retained"),
                    _ = tokio::time::sleep(Duration::from_secs(1)) => {},
                }
            }
        }
    }
}

pub async fn run_agent(config: ProbeConfig, once: bool) -> Result<()> {
    let url = reqwest::Url::parse(&config.controller)?;
    ensure!(
        url.scheme() == "quic",
        "worker controller must use quic://host:port; HTTP polling has been retired"
    );
    let host = url.host_str().context("controller host")?;
    let host = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host);
    let port = url.port().context("controller QUIC port")?;
    let token =
        std::env::var(&config.token_env).context("node token environment variable missing")?;
    let spool = config.data_dir.join("spool");
    std::fs::create_dir_all(&spool)?;
    let cache = Store::open(&config.data_dir)?;
    let mut failures = 0u32;
    loop {
        let started = Instant::now();
        let addresses = tokio::net::lookup_host((host, port)).await;
        let result = async {
            let addresses = addresses?;
            let mut last = None;
            for address in addresses {
                let bind = if address.is_ipv4() {
                    "0.0.0.0:0"
                } else {
                    "[::]:0"
                }
                .parse()?;
                let endpoint = client_endpoint(&config.ca_cert, bind)?;
                let connected = tokio::time::timeout(
                    Duration::from_secs(12),
                    endpoint.connect(address, &config.server_name)?,
                )
                .await;
                match connected {
                    Ok(Ok(connection)) => {
                        let result = agent_session(
                            &config,
                            &cache,
                            &spool,
                            &token,
                            once,
                            connection.clone(),
                        )
                        .await;
                        connection.close(0u32.into(), b"worker session ended");
                        endpoint.close(0u32.into(), b"worker session ended");
                        return result;
                    }
                    other => {
                        last = Some(format!("{other:?}"));
                    }
                }
            }
            bail!(
                "controller QUIC connection failed: {}",
                last.unwrap_or_else(|| "no address".into())
            )
        }
        .await;
        if once {
            return result;
        }
        if started.elapsed() > Duration::from_secs(60) {
            failures = 0
        }
        failures = failures.saturating_add(1);
        if let Err(e) = result {
            tracing::warn!(error=%e,"QUIC disconnected; reconnecting, outbox retained");
        }
        let delay = (1u64 << failures.min(6)).min(60);
        let jitter = uuid::Uuid::new_v4().as_bytes()[0] as u64 * 4;
        tokio::time::sleep(Duration::from_millis(delay * 1000 + jitter)).await;
    }
}
fn network_report(value: &Mutex<crate::network::NetworkSupport>) -> crate::network::NetworkSupport {
    value.lock().expect("network support").clone()
}
async fn agent_session(
    config: &ProbeConfig,
    cache: &Store,
    spool: &Path,
    token: &str,
    once: bool,
    connection: Connection,
) -> Result<()> {
    let support =
        crate::network::detect(connection.remote_address(), config.allow_private_targets).await;
    let reported = Arc::new(Mutex::new(support));
    let report_copy = reported.clone();
    let peer = connection.remote_address();
    let allow_private = config.allow_private_targets;
    let network_task = AbortReader(tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(60)).await;
            let value = crate::network::detect(peer, allow_private).await;
            *report_copy.lock().expect("network support") = value;
        }
    }));
    let _network_task = network_task;
    let (mut tx, mut recv) = connection.open_bi().await?;
    send(
        &mut tx,
        Message::Hello {
            id: config.id.clone(),
            token: token.into(),
            network: Some(network_report(&reported)),
            capacity: Some(1000),
        },
    )
    .await?;
    let Message::Welcome {
        heartbeat_seconds,
        slots,
        ..
    } = tokio::time::timeout(Duration::from_secs(15), receive(&mut recv)).await??
    else {
        bail!("invalid controller welcome")
    };
    ensure!(
        (5..=30).contains(&heartbeat_seconds) && (1..=1000).contains(&slots),
        "invalid controller limits"
    );
    tracing::info!(node=%config.id,"QUIC worker authenticated");
    let (mut rx, reader) = reader(recv);
    let _reader = AbortReader(reader);
    let mut heartbeat = tokio::time::interval(Duration::from_secs(heartbeat_seconds));
    let mut last = Instant::now();
    let replay = async {
        let mut replayed = false;
        for entry in std::fs::read_dir(spool)? {
            let path = entry?.path();
            if path.extension().is_some_and(|e| e == "json") {
                upload_persisted(&connection, &path).await?;
                replayed = true;
            }
        }
        anyhow::Ok(replayed)
    };
    tokio::pin!(replay);
    let replayed = loop {
        tokio::select! {
            biased;
            result = &mut replay => break result?,
            message = rx.recv() => {
                ensure!(
                    matches!(message.context("controller control stream ended")??, Message::Pong { .. }),
                    "unexpected controller message before worker readiness"
                );
                last = Instant::now();
            },
            _ = heartbeat.tick() => {
                ensure!(last.elapsed() < Duration::from_secs(DEADLINE), "controller heartbeat timed out");
                send(&mut tx, Message::Heartbeat { active: vec![],network:Some(network_report(&reported)) }).await?;
            },
            _ = connection.closed() => bail!("controller QUIC connection closed"),
        }
    };
    if once && replayed {
        return Ok(());
    }
    send(&mut tx, Message::Ready).await?;
    let upload_gate = Arc::new(Semaphore::new(64));
    let mut jobs: JoinSet<(String, Result<()>)> = JoinSet::new();
    let mut active = BTreeMap::<String, String>::new();
    loop {
        tokio::select! {
         message=rx.recv()=>{last=Instant::now();match message.context("controller control stream ended")??{
          Message::Task(lease)=>{ensure!(active.len()<slots as usize&&!active.contains_key(&lease.id),"controller exceeded worker capacity");let id=lease.id.clone();active.insert(id.clone(),lease.token.clone());let config=config.clone();let cache=cache.clone();let spool=spool.to_path_buf();let c=connection.clone();let upload_gate=upload_gate.clone();jobs.spawn(async move{let result=measure::execute(&config,&lease,&cache).await;let path=spool.join(format!("{}.json",result.id));let r=async{atomic_write(&path,&serde_json::to_vec(&result)?)?;let _permit=upload_gate.acquire().await?;upload_persisted(&c,&path).await}.await;(id,r)});},
          Message::Pong{..}=>{},Message::Idle=>{if once&&active.is_empty(){return Ok(())}},_=>bail!("unexpected controller control message")}},
         result=jobs.join_next(),if !jobs.is_empty()=>{let(id,result)=result.context("worker task ended")??;active.remove(&id);result?;send(&mut tx,Message::Finished{id}).await?;if once{return Ok(())}},
         _=heartbeat.tick()=>{ensure!(last.elapsed()<Duration::from_secs(DEADLINE),"controller heartbeat timed out");send(&mut tx,Message::Heartbeat{active:active.iter().map(|(a,b)|(a.clone(),b.clone())).collect(),network:Some(network_report(&reported))}).await?;},
         _=connection.closed()=>bail!("controller QUIC connection closed"),
        }
    }
}
struct AbortReader(tokio::task::JoinHandle<()>);
impl Drop for AbortReader {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[cfg(test)]
mod dispatch_tests {
    use super::*;

    fn reserved() -> (tempfile::TempDir, Store, crate::store::Node, Lease) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let node = crate::store::Node {
            id: "unsent".into(),
            region: "us".into(),
            asn: 64501,
            capabilities: vec!["dns".into()],
        };
        store
            .register_node(&node, &crate::hash("public dispatch ownership fixture"))
            .unwrap();
        store.connect().unwrap().execute("UPDATE nodes SET connected=1,session_id='original',last_seen=?,ipv4_supported=1,ipv6_supported=1,worker_capacity=10", [now()]).unwrap();
        store
            .enqueue_observation(
                "unsent.example",
                &["us".into()],
                "dropped start worker fixture",
            )
            .unwrap();
        let lease = store.lease_session(&node, "original").unwrap().unwrap();
        (dir, store, node, lease)
    }

    #[tokio::test]
    async fn dropping_a_started_worker_before_any_send_returns_only_its_original_opportunity() {
        let (_dir, store, node, lease) = reserved();
        let (s, n) = (store.clone(), node.id.clone());
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (handoff_tx, handoff_rx) = std::sync::mpsc::channel();
        let mut workers = JoinSet::new();
        workers.spawn_blocking(move || {
            let mut db = s.connect().unwrap();
            let result = start_dispatch(&s, &mut db, &n, "original", lease, 0);
            started_tx.send(()).unwrap();
            // Deterministically hold the exact post-commit / pre-handoff window.
            handoff_rx.recv_timeout(Duration::from_secs(2)).unwrap();
            (db, result)
        });
        tokio::time::timeout(Duration::from_secs(2), started_rx)
            .await
            .unwrap()
            .unwrap();
        let count = || {
            store
                .connect()
                .unwrap()
                .query_row::<i64, _, _>("SELECT execution_count FROM jobs", [], |r| r.get(0))
                .unwrap()
        };
        assert_eq!(count(), 1, "the start transaction really committed");
        // A closed session drops its JoinSet while blocking work cannot abort.
        offline(&store, &node.id, "original").unwrap();
        drop(workers);
        handoff_tx.send(()).unwrap();
        let returned = tokio::time::timeout(Duration::from_millis(500), async {
            while count() != 0 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await;
        assert!(
            returned.is_ok(),
            "a consumed attempt that never reached send must be returned"
        );
        let row: (String, i64, bool) = store.connect().unwrap().query_row("SELECT j.status,j.attempt_seq,h.execution_refunded FROM jobs j JOIN lease_history h ON h.job_id=j.id", [], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?))).unwrap();
        assert_eq!(row, ("pending".into(), 1, true));
    }

    #[tokio::test]
    async fn entering_the_send_boundary_preserves_the_original_uncertain_execution() {
        let (_dir, store, node, lease) = reserved();
        let mut db = store.connect().unwrap();
        let Dispatch::Started(Some(unsent)) =
            start_dispatch(&store, &mut db, &node.id, "original", lease, 0).unwrap()
        else {
            panic!("reserved work must start");
        };
        let lease = unsent.enter_send();
        // Even an immediately closed socket after this boundary is uncertain:
        // retaining the original token is required for a possible late receipt.
        offline(&store, &node.id, "original").unwrap();
        drop(lease);
        tokio::time::sleep(Duration::from_millis(30)).await;
        let row: (String, i64, bool, bool) = store.connect().unwrap().query_row("SELECT j.status,j.execution_count,h.started_at IS NOT NULL,h.execution_refunded FROM jobs j JOIN lease_history h ON h.job_id=j.id", [], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).unwrap();
        assert_eq!(row, ("leased".into(), 1, true, false));
    }
}

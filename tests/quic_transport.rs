use airroute_rules::{
    hash,
    measure::{ProbeConfig, ResolverConfig},
    now,
    store::{Lease, Node, ProbeResult, Store},
    transport::{self, Disposition, Message, Server},
};
use quinn::{Connection, Endpoint, RecvStream, SendStream};
use serde_json::json;
use std::{path::Path, time::Duration};
fn token() -> String {
    hash("public QUIC integration fixture")
}
fn node(id: &str) -> Node {
    Node {
        id: id.into(),
        region: "us".into(),
        asn: 64501,
        capabilities: vec!["dns".into(), "traceroute".into()],
    }
}
async fn connect(
    data: &Path,
    addr: std::net::SocketAddr,
    id: &str,
    key: &str,
) -> (Endpoint, Connection, SendStream, RecvStream) {
    let ep = transport::client_endpoint(
        &transport::certificate(data).unwrap(),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    let c = ep
        .connect(addr, transport::SERVER_NAME)
        .unwrap()
        .await
        .unwrap();
    let (mut tx, mut rx) = c.open_bi().await.unwrap();
    transport::send(
        &mut tx,
        Message::Hello {
            id: id.into(),
            token: key.into(),
            network: None,
            capacity: Some(1000),
        },
    )
    .await
    .unwrap();
    assert!(matches!(
        transport::receive(&mut rx).await.unwrap(),
        Message::Welcome { .. }
    ));
    transport::send(&mut tx, Message::Ready).await.unwrap();
    (ep, c, tx, rx)
}
async fn task(rx: &mut RecvStream) -> Lease {
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            match transport::receive(rx).await.unwrap() {
                Message::Task(l) => return *l,
                Message::Idle | Message::Pong { .. } => {}
                _ => panic!("unexpected control frame"),
            }
        }
    })
    .await
    .expect("controller must push without a worker lease request")
}
async fn until(mut test: impl FnMut() -> bool) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while !test() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("state transition deadline");
}

#[tokio::test(flavor = "current_thread")]
async fn a_worker_registration_writer_wait_does_not_stop_network_timers() {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    };
    let d = tempfile::tempdir().unwrap();
    let store = Store::open(d.path()).unwrap();
    store.register_node(&node("writer-wait"), &token()).unwrap();
    let server = Server::start(d.path(), store.clone(), "127.0.0.1:0".parse().unwrap()).unwrap();
    let address = server.endpoint.local_addr().unwrap();
    let root = d.path().to_path_buf();
    let (locked_tx, locked_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let released = Arc::new(AtomicBool::new(false));
    let flag = released.clone();
    let writer = std::thread::spawn(move || {
        let c = store.connect().unwrap();
        c.execute_batch("BEGIN IMMEDIATE").unwrap();
        locked_tx.send(()).unwrap();
        let _ = release_rx.recv_timeout(Duration::from_secs(1));
        flag.store(true, Ordering::SeqCst);
        c.execute_batch("COMMIT").unwrap();
    });
    locked_rx.recv_timeout(Duration::from_secs(2)).unwrap();
    let connection =
        tokio::spawn(async move { connect(&root, address, "writer-wait", &token()).await });
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(
        !connection.is_finished(),
        "the worker must still be waiting for the database writer"
    );
    assert!(
        !released.load(Ordering::SeqCst),
        "network timers must advance independently of the writer"
    );
    release_tx.send(()).unwrap();
    let (ep, c, _, _) = connection.await.unwrap();
    writer.join().unwrap();
    c.close(0u32.into(), b"done");
    ep.close(0u32.into(), b"done");
    server.shutdown().await;
}
fn receipt(l: &Lease) -> ProbeResult {
    ProbeResult {
        id: uuid::Uuid::new_v4().to_string(),
        job_id: l.id.clone(),
        fingerprint: l.fingerprint.clone(),
        lease_token: l.token.clone(),
        observed_at: now(),
        outcome: "ok".into(),
        evidence: if l.kind == "dns" {
            json!({"kind":"dns","hostname":l.target,"resolvers":[{"transport":"udp","response_received":true,"observed_at":now(),"valid_until":now()+60,"records":[{"name":l.target,"type":"A","query_type":"A","ttl":60,"data":"1.1.1.1"}]}]})
        } else {
            json!({"kind":"traceroute","target":l.target,"protocol":"icmp","reached":true,"hops":[{"hop":1,"ip":l.target}]})
        },
    }
}
async fn upload(c: &Connection, r: ProbeResult) -> Disposition {
    let (mut tx, mut rx) = c.open_bi().await.unwrap();
    transport::send(&mut tx, Message::Result(Box::new(r)))
        .await
        .unwrap();
    tx.finish().unwrap();
    match transport::receive(&mut rx).await.unwrap() {
        Message::Ack { disposition, .. } => disposition,
        _ => panic!("missing acknowledgement"),
    }
}

#[tokio::test]
async fn duplicate_receipt_ack_does_not_broadcast_another_dispatch_wake() {
    let d = tempfile::tempdir().unwrap();
    let s = Store::open(d.path()).unwrap();
    let n = node("quiet-ack");
    s.register_node(&n, &token()).unwrap();
    s.enqueue_observation("quiet-ack.example", &["us".into()], "duplicate ACK fixture")
        .unwrap();
    let server = Server::start(d.path(), s.clone(), "127.0.0.1:0".parse().unwrap()).unwrap();
    let (ep, c, _tx, mut rx) = connect(
        d.path(),
        server.endpoint.local_addr().unwrap(),
        &n.id,
        &token(),
    )
    .await;
    let l = task(&mut rx).await;
    let r = receipt(&l);
    let notified = s.wake.notified();
    tokio::pin!(notified);
    notified.as_mut().enable();
    assert_eq!(upload(&c, r.clone()).await, Disposition::Accepted);
    tokio::time::timeout(Duration::from_secs(1), notified)
        .await
        .expect("real completion wakes the coordinator");
    let notified = s.wake.notified();
    tokio::pin!(notified);
    notified.as_mut().enable();
    assert_eq!(upload(&c, r).await, Disposition::Duplicate);
    assert!(
        tokio::time::timeout(Duration::from_millis(80), notified)
            .await
            .is_err(),
        "ACK-only replay changes no work"
    );
    assert_eq!(s.executor_stats().unwrap()[&n.id].completed_tasks, 1);
    c.close(0u32.into(), b"fixture done");
    ep.close(0u32.into(), b"fixture done");
    server.shutdown().await;
}
#[tokio::test]
async fn live_concurrency_increases_and_decreases_without_reconnecting_the_worker() {
    let d = tempfile::tempdir().unwrap();
    let s = Store::open(d.path()).unwrap();
    assert_eq!(
        airroute_rules::scheduler::policy(&s)
            .unwrap()
            .per_node_concurrency,
        10
    );
    let server = Server::start(d.path(), s.clone(), "127.0.0.1:0".parse().unwrap()).unwrap();
    let n = node("dynamic");
    s.register_node(&n, &token()).unwrap();
    for i in 0..13 {
        let key = s
            .enqueue_observation(
                &format!("t{i}.example"),
                &["us".into()],
                "dynamic limit fixture",
            )
            .unwrap();
        s.connect().unwrap().execute("UPDATE jobs SET status='obsolete' WHERE case_key=? AND (json_extract(profile,'$.window')<>0 OR json_extract(profile,'$.slot')<>0)",[key]).unwrap();
    }
    let (_ep, c, mut tx, mut rx) = connect(
        d.path(),
        server.endpoint.local_addr().unwrap(),
        &n.id,
        &token(),
    )
    .await;
    let mut tasks = vec![];
    for _ in 0..10 {
        tasks.push(task(&mut rx).await);
    }
    s.update_node_settings(&n.id, "Dynamic", Some(12)).unwrap();
    for _ in 0..2 {
        tasks.push(task(&mut rx).await);
    }
    assert_eq!(s.executor_stats().unwrap()[&n.id].running_tasks, 12);
    s.update_node_settings(&n.id, "Renamed online node", Some(3))
        .unwrap();
    assert_eq!(
        airroute_rules::scheduler::policy(&s)
            .unwrap()
            .per_node_concurrency,
        10
    );
    for t in tasks.iter().take(9) {
        upload(&c, receipt(t)).await;
        transport::send(&mut tx, Message::Finished { id: t.id.clone() })
            .await
            .unwrap();
    }
    assert_eq!(s.executor_stats().unwrap()[&n.id].running_tasks, 3);
    upload(&c, receipt(&tasks[9])).await;
    transport::send(
        &mut tx,
        Message::Finished {
            id: tasks[9].id.clone(),
        },
    )
    .await
    .unwrap();
    let next = task(&mut rx).await;
    assert!(!tasks.iter().any(|t| t.id == next.id));
    assert_eq!(s.executor_stats().unwrap()[&n.id].running_tasks, 3);
    assert!(s.meta("scheduler-console-override").unwrap().is_none());
    s.update_node_settings(&n.id, "Renamed online node", None)
        .unwrap();
    assert_eq!(s.node_concurrency(&n.id).unwrap(), 10);
    c.close(0u32.into(), b"done");
    server.shutdown().await;
}

#[test]
fn binary_frames_are_bounded_versioned_and_preserve_rule_metadata() {
    let l = Lease {
        id: "job".into(),
        case_key: "case".into(),
        fingerprint: "fp".into(),
        kind: "dns".into(),
        target: "example.com".into(),
        region: "us".into(),
        token: token(),
        until: now(),
        profile: json!({"window":1,"types":["A","HTTPS"],"flag":true}),
    };
    let encoded = transport::encode(Message::Task(Box::new(l.clone()))).unwrap();
    assert_ne!(encoded[0], b'{');
    let Message::Task(decoded) = transport::decode(&encoded).unwrap() else {
        panic!()
    };
    assert_eq!(decoded.profile, l.profile);
    assert_eq!(decoded.token, l.token);
    assert!(transport::decode(&vec![0; transport::MAX_FRAME + 1]).is_err());
    assert!(transport::decode(&[]).is_err());
    let mut trailing = encoded.clone();
    trailing.push(0);
    assert!(transport::decode(&trailing).is_err());
    let mut wrong = vec![];
    ciborium::into_writer(&json!({"version":99,"message":"Ready"}), &mut wrong).unwrap();
    assert!(transport::decode(&wrong).is_err());
}
#[tokio::test]
async fn controller_pushes_respects_capacity_and_recovers_disconnected_work_after_its_deadline() {
    let d = tempfile::tempdir().unwrap();
    let s = Store::open(d.path()).unwrap();
    airroute_rules::scheduler::save_policy(
        &s,
        &airroute_rules::scheduler::Policy {
            per_node_concurrency: 1,
            ..Default::default()
        },
        false,
    )
    .unwrap();
    let enqueue_one_view = |target: &str, reason: &str| {
        let key = s
            .enqueue_observation(target, &["us".into()], reason)
            .unwrap();
        assert_eq!(
            s.jobs(0, 100).unwrap()["items"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|j| j["case_key"] == key)
                .count(),
            1
        );
    };
    let server = Server::start(d.path(), s.clone(), "127.0.0.1:0".parse().unwrap()).unwrap();
    let n = node("one");
    s.register_node(&n, &token()).unwrap();
    s.update_node_settings(&n.id, "one", Some(1)).unwrap();
    let (_ep, c, mut tx, mut rx) = connect(
        d.path(),
        server.endpoint.local_addr().unwrap(),
        &n.id,
        &token(),
    )
    .await;
    assert_eq!(s.nodes().unwrap()[0]["connected"], true);
    enqueue_one_view("first.example", "first push fixture");
    let first = task(&mut rx).await;
    transport::send(
        &mut tx,
        Message::Heartbeat {
            active: vec![(first.id.clone(), first.token.clone())],
            network: None,
        },
    )
    .await
    .unwrap();
    enqueue_one_view("second.example", "second push fixture");
    assert_eq!(upload(&c, receipt(&first)).await, Disposition::Accepted);
    tokio::time::sleep(Duration::from_millis(100)).await;
    let leased: i64 = s
        .connect()
        .unwrap()
        .query_row("SELECT count(*) FROM jobs WHERE status='leased'", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(
        leased, 0,
        "completion ACK alone cannot overrun worker capacity"
    );
    transport::send(
        &mut tx,
        Message::Finished {
            id: first.id.clone(),
        },
    )
    .await
    .unwrap();
    let second = task(&mut rx).await;
    assert_ne!(first.case_key, second.case_key);
    s.connect()
        .unwrap()
        .execute(
            "UPDATE jobs SET not_before=? WHERE id=?",
            rusqlite::params![now() - 1, second.id],
        )
        .unwrap();
    c.close(0u32.into(), b"fixture disconnect");
    until(|| s.nodes().unwrap()[0]["connected"] == false).await;
    assert_eq!(
        s.connect()
            .unwrap()
            .query_row::<String, _, _>("SELECT status FROM jobs WHERE id=?", [&second.id], |r| r
                .get(0))
            .unwrap(),
        "leased"
    );
    // A sent attempt may still be executing. Advance its deadline explicitly;
    // a disconnect alone must never authorize overlapping execution.
    s.connect()
        .unwrap()
        .execute("UPDATE jobs SET lease_until=0 WHERE id=?", [&second.id])
        .unwrap();
    airroute_rules::jobs_v3::expire_due(&s).unwrap();
    s.connect()
        .unwrap()
        .execute("UPDATE jobs SET not_before=0 WHERE id=?", [&second.id])
        .unwrap();
    let mut other = node("two");
    other.asn = 64501;
    s.register_node(&other, &token()).unwrap();
    let (_ep2, c2, _tx2, mut rx2) = connect(
        d.path(),
        server.endpoint.local_addr().unwrap(),
        &other.id,
        &token(),
    )
    .await;
    let reassigned = task(&mut rx2).await;
    assert_eq!(
        reassigned.id, second.id,
        "work is reassignable after the old execution deadline"
    );
    c2.close(0u32.into(), b"done");
    server.shutdown().await;
}
#[tokio::test]
async fn reset_disconnects_the_session_and_rejects_old_credentials_and_wrong_trust() {
    let d = tempfile::tempdir().unwrap();
    let s = Store::open(d.path()).unwrap();
    let server = Server::start(d.path(), s.clone(), "127.0.0.1:0".parse().unwrap()).unwrap();
    let n = node("reset");
    s.register_node(&n, &token()).unwrap();
    let (_ep, c, _tx, _rx) = connect(
        d.path(),
        server.endpoint.local_addr().unwrap(),
        &n.id,
        &token(),
    )
    .await;
    let new = s.reset_node_token(&n.id).unwrap();
    server.hub.disconnect(&n.id);
    tokio::time::timeout(Duration::from_secs(2), c.closed())
        .await
        .unwrap();
    until(|| s.nodes().unwrap()[0]["connected"] == false).await;
    let ep = transport::client_endpoint(
        &transport::certificate(d.path()).unwrap(),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    let c = ep
        .connect(
            server.endpoint.local_addr().unwrap(),
            transport::SERVER_NAME,
        )
        .unwrap()
        .await
        .unwrap();
    let (mut tx, mut rx) = c.open_bi().await.unwrap();
    transport::send(
        &mut tx,
        Message::Hello {
            id: n.id.clone(),
            token: token(),
            network: None,
            capacity: None,
        },
    )
    .await
    .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_secs(2), transport::receive(&mut rx))
            .await
            .unwrap()
            .is_err()
    );
    let (_ep2, c2, _tx2, _rx2) =
        connect(d.path(), server.endpoint.local_addr().unwrap(), &n.id, &new).await;
    c2.close(0u32.into(), b"done");
    let wrong = tempfile::tempdir().unwrap();
    let ep = transport::client_endpoint(
        &transport::certificate(wrong.path()).unwrap(),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    assert!(
        ep.connect(
            server.endpoint.local_addr().unwrap(),
            transport::SERVER_NAME
        )
        .unwrap()
        .await
        .is_err()
    );
    server.shutdown().await;
}
async fn dns_fixture() -> (String, tokio::task::JoinHandle<()>) {
    use hickory_proto::{
        op::{Message, OpCode},
        rr::{RData, Record, rdata::A},
    };
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap().to_string();
    let task = tokio::spawn(async move {
        let mut bytes = [0; 65535];
        loop {
            let (n, peer) = socket.recv_from(&mut bytes).await.unwrap();
            let q = Message::from_vec(&bytes[..n]).unwrap();
            let mut r = Message::response(q.metadata.id, OpCode::Query);
            r.queries = q.queries.clone();
            r.answers.push(Record::from_rdata(
                q.queries[0].name().clone(),
                60,
                RData::A(A("1.1.1.1".parse().unwrap())),
            ));
            socket.send_to(&r.to_vec().unwrap(), peer).await.unwrap();
        }
    });
    (address, task)
}
fn config(root: &Path, ca: &Path, addr: std::net::SocketAddr, dns: String) -> ProbeConfig {
    ProbeConfig {
        controller: format!("quic://{addr}"),
        id: "binary".into(),
        token_env: "QUIC_TEST_SECRET".into(),
        ca_cert: ca.into(),
        server_name: transport::SERVER_NAME.into(),
        data_dir: root.join("probe"),
        tls: false,
        // DNS and QUIC are loopback fixtures. Do not make these transport tests
        // depend on public IPv4/IPv6 capability checks outside the test network.
        allow_private_targets: true,
        resolvers: vec![ResolverConfig {
            name: "fixture".into(),
            address: dns,
            transport: "udp".into(),
        }],
    }
}
fn command(path: &Path, once: bool) -> tokio::process::Command {
    let mut c = tokio::process::Command::new(
        std::env::var("QUIC_REGRESSION_PROBE")
            .unwrap_or_else(|_| env!("CARGO_BIN_EXE_rules-probe").into()),
    );
    c.arg("--config")
        .arg(path)
        .env("QUIC_TEST_SECRET", token())
        .kill_on_drop(true);
    if once {
        c.arg("--once");
    }
    c
}

#[tokio::test(flavor = "current_thread")]
async fn application_heartbeat_is_serviced_while_a_dispatch_claim_waits_for_the_writer() {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    };
    let d = tempfile::tempdir().unwrap();
    let s = Store::open(d.path()).unwrap();
    let n = node("claim-wait");
    s.register_node(&n, &token()).unwrap();
    s.enqueue_observation(
        "claim-wait.example",
        &["us".into()],
        "writer-blocked dispatch",
    )
    .unwrap();
    let server = Server::start(d.path(), s.clone(), "127.0.0.1:0".parse().unwrap()).unwrap();
    let ep = transport::client_endpoint(
        &transport::certificate(d.path()).unwrap(),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    let c = ep
        .connect(
            server.endpoint.local_addr().unwrap(),
            transport::SERVER_NAME,
        )
        .unwrap()
        .await
        .unwrap();
    let (mut tx, mut rx) = c.open_bi().await.unwrap();
    transport::send(
        &mut tx,
        Message::Hello {
            id: n.id.clone(),
            token: token(),
            network: None,
            capacity: Some(1),
        },
    )
    .await
    .unwrap();
    assert!(matches!(
        transport::receive(&mut rx).await.unwrap(),
        Message::Welcome { .. }
    ));
    let (locked_tx, locked_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let released = Arc::new(AtomicBool::new(false));
    let flag = released.clone();
    let store = s.clone();
    let writer = std::thread::spawn(move || {
        let conn = store.connect().unwrap();
        conn.execute_batch("BEGIN IMMEDIATE").unwrap();
        locked_tx.send(()).unwrap();
        let _ = release_rx.recv_timeout(Duration::from_secs(5));
        conn.execute_batch("COMMIT").unwrap();
        flag.store(true, Ordering::SeqCst);
    });
    locked_rx.recv_timeout(Duration::from_secs(2)).unwrap();
    transport::send(&mut tx, Message::Ready).await.unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    transport::send(
        &mut tx,
        Message::Heartbeat {
            active: vec![],
            network: None,
        },
    )
    .await
    .unwrap();
    let pong = tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            match transport::receive(&mut rx).await {
                Ok(Message::Pong { .. }) => break true,
                Ok(Message::Idle) => {}
                _ => break false,
            }
        }
    })
    .await
    .unwrap_or(false);
    let replied_before_writer_released = !released.load(Ordering::SeqCst);
    release_tx.send(()).unwrap();
    writer.join().unwrap();
    c.close(0u32.into(), b"fixture done");
    ep.close(0u32.into(), b"fixture done");
    server.shutdown().await;
    assert!(
        pong && replied_before_writer_released,
        "a blocked dispatch claim must not block the authenticated heartbeat response"
    );
}

#[tokio::test]
async fn a_timed_out_receipt_retries_on_the_same_connection_without_cancelling_other_measurements()
{
    let d = tempfile::tempdir().unwrap();
    let s = Store::open(d.path()).unwrap();
    let n = node("binary");
    s.register_node(&n, &token()).unwrap();
    for host in ["first-ack.example", "second-ack.example"] {
        s.enqueue_observation(host, &["us".into()], "slow ACK fixture")
            .unwrap();
    }
    let first = s.lease(&n).unwrap().unwrap();
    let second = s.lease(&n).unwrap().unwrap();
    let first_job = first.id.clone();
    let second_job = second.id.clone();
    let endpoint = transport::server_endpoint(d.path(), "127.0.0.1:0".parse().unwrap()).unwrap();
    let address = endpoint.local_addr().unwrap();
    let ep = endpoint.clone();
    let store = s.clone();
    let handler = tokio::spawn(async move {
        let c = ep.accept().await.unwrap().await.unwrap();
        let (mut tx, mut rx) = c.accept_bi().await.unwrap();
        assert!(matches!(
            transport::receive(&mut rx).await.unwrap(),
            Message::Hello { .. }
        ));
        transport::send(
            &mut tx,
            Message::Welcome {
                session: "held-ack".into(),
                heartbeat_seconds: 5,
                slots: 2,
            },
        )
        .await
        .unwrap();
        loop {
            match transport::receive(&mut rx).await.unwrap() {
                Message::Ready => break,
                Message::Heartbeat { .. } => {
                    transport::send(&mut tx, Message::Pong { server_time: now() })
                        .await
                        .unwrap()
                }
                _ => panic!("unexpected initial control frame"),
            }
        }
        transport::send(&mut tx, Message::Task(Box::new(first)))
            .await
            .unwrap();
        let (held_ack, mut first_rx) = c.accept_bi().await.unwrap();
        let Message::Result(original) = transport::receive(&mut first_rx).await.unwrap() else {
            panic!("original receipt required")
        };
        assert_eq!(original.job_id, first_job);
        assert_eq!(store.submit("binary", &original).unwrap()["accepted"], true);
        let original_body = serde_json::to_vec(&original).unwrap();
        let original_id = original.id.clone();
        let since_first = std::time::Instant::now();
        // receive() spans a length prefix and body; keep one persistent reader
        // rather than cancel a partial frame when another stream becomes ready.
        let (frames_tx, mut frames) = tokio::sync::mpsc::channel(8);
        let control_reader = tokio::spawn(async move {
            loop {
                let frame = transport::receive(&mut rx).await;
                let failed = frame.is_err();
                if frames_tx.send(frame).await.is_err() || failed {
                    break;
                }
            }
        });
        // Hold just this ACK past its real 25-second deadline. The unrelated
        // task and heartbeat must keep progressing on the original connection.
        transport::send(&mut tx, Message::Task(Box::new(second)))
            .await
            .unwrap();
        let mut second_received = false;
        let mut second_finished = false;
        let mut first_finished = false;
        let mut retried = false;
        let mut heartbeat_count = 0;
        tokio::time::timeout(Duration::from_secs(33),async {
            while !(retried&&second_finished&&first_finished) {
                tokio::select! {
                    frame=frames.recv()=>match frame.expect("control reader ended").expect("the original control connection must remain alive") {
                        Message::Heartbeat{..}=>{heartbeat_count+=1;transport::send(&mut tx,Message::Pong{server_time:now()}).await.unwrap();},
                        Message::Finished{id} if id==second_job=>{second_finished=true;assert!(second_received);},
                        Message::Finished{id} if id==first_job=>{first_finished=true;assert!(retried);},
                        _=>panic!("unexpected control frame during held ACK"),
                    },
                    incoming=c.accept_bi()=>{
                        let(mut ack,mut receipt_rx)=incoming.expect("receipt retry must keep the original QUIC connection");
                        let Message::Result(result)=transport::receive(&mut receipt_rx).await.unwrap() else {panic!("receipt required")};
                        let disposition=if result.job_id==second_job {
                            assert!(!second_received,"another task must not be re-executed");
                            assert!(since_first.elapsed()<Duration::from_secs(20),"the unrelated task must finish before the held ACK expires");
                            assert_eq!(store.submit("binary",&result).unwrap()["accepted"],true);
                            second_received=true;
                            Disposition::Accepted
                        }else {
                            assert_eq!(result.id,original_id);
                            assert_eq!(serde_json::to_vec(&result).unwrap(),original_body,"retry the same durable body and original attempt token");
                            assert!(since_first.elapsed()>=Duration::from_secs(24),"must exercise the real upload deadline");
                            assert_eq!(store.submit("binary",&result).unwrap()["duplicate"],true);
                            retried=true;
                            Disposition::Duplicate
                        };
                        transport::send(&mut ack,Message::Ack{id:result.id,disposition}).await.unwrap();
                        ack.finish().unwrap();
                    },
                    _=c.closed()=>panic!("a timed-out durable receipt must not close the live connection"),
                }
            }
        }).await.expect("same-connection retry and unrelated completion must finish within a bounded interval");
        assert!(second_received && heartbeat_count >= 4);
        control_reader.abort();
        drop(held_ack);
    });
    let (dns, dns_task) = dns_fixture().await;
    let cfg = config(
        d.path(),
        &transport::certificate(d.path()).unwrap(),
        address,
        dns,
    );
    let path = d.path().join("probe.toml");
    std::fs::write(&path, toml::to_string(&cfg).unwrap()).unwrap();
    let mut child = command(&path, false)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let outcome = handler.await;
    child.start_kill().unwrap();
    child.wait().await.unwrap();
    dns_task.abort();
    endpoint.close(0u32.into(), b"fixture done");
    outcome.unwrap();
    assert_eq!(
        s.connect()
            .unwrap()
            .query_row::<i64, _, _>("SELECT count(*) FROM results WHERE accepted=1", [], |r| r
                .get(0))
            .unwrap(),
        2
    );
    assert_eq!(
        std::fs::read_dir(cfg.data_dir.join("spool"))
            .unwrap()
            .filter(|entry| entry
                .as_ref()
                .unwrap()
                .path()
                .extension()
                .is_some_and(|extension| extension == "json"))
            .count(),
        0
    );
}
#[tokio::test]
async fn binary_worker_reconnects_after_controller_restart_and_receives_push() {
    let d = tempfile::tempdir().unwrap();
    let s = Store::open(d.path()).unwrap();
    s.register_node(&node("binary"), &token()).unwrap();
    let server = Server::start(d.path(), s.clone(), "127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = server.endpoint.local_addr().unwrap();
    let (dns, dns_task) = dns_fixture().await;
    let config = config(
        d.path(),
        &transport::certificate(d.path()).unwrap(),
        addr,
        dns,
    );
    let path = d.path().join("probe.toml");
    std::fs::write(&path, toml::to_string(&config).unwrap()).unwrap();
    let mut child = command(&path, false)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    until(|| s.nodes().unwrap()[0]["connected"] == true).await;
    server.shutdown().await;
    until(|| s.nodes().unwrap()[0]["connected"] == false).await;
    let server = Server::start(d.path(), s.clone(), addr).unwrap();
    until(|| s.nodes().unwrap()[0]["connected"] == true).await;
    s.enqueue_observation("fixture.example", &["us".into()], "reconnect fixture")
        .unwrap();
    until(|| {
        s.connect()
            .unwrap()
            .query_row::<i64, _, _>("SELECT count(*) FROM results WHERE accepted=1", [], |r| {
                r.get(0)
            })
            .unwrap()
            == 1
    })
    .await;
    child.start_kill().unwrap();
    child.wait().await.unwrap();
    server.shutdown().await;
    dns_task.abort();
}
#[tokio::test]
async fn binary_worker_reconnects_after_reenable_with_the_existing_key() {
    let d = tempfile::tempdir().unwrap();
    let s = Store::open(d.path()).unwrap();
    s.register_node(&node("binary"), &token()).unwrap();
    let server = Server::start(d.path(), s.clone(), "127.0.0.1:0".parse().unwrap()).unwrap();
    let (dns, dns_task) = dns_fixture().await;
    let config = config(
        d.path(),
        &transport::certificate(d.path()).unwrap(),
        server.endpoint.local_addr().unwrap(),
        dns,
    );
    let path = d.path().join("probe.toml");
    std::fs::write(&path, toml::to_string(&config).unwrap()).unwrap();
    let mut child = command(&path, false)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    until(|| s.nodes().unwrap()[0]["connected"] == true).await;
    s.set_node_enabled("binary", false).unwrap();
    server.hub.disconnect("binary");
    assert!(s.authenticate_node("binary", &token()).is_err());
    s.set_node_enabled("binary", true).unwrap();
    tokio::time::timeout(Duration::from_secs(15), async {
        while s.nodes().unwrap()[0]["connected"] != true {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("enabled worker must reconnect without changing its configuration");
    s.enqueue_observation(
        "reenabled.example",
        &["us".into()],
        "reactivated probe fixture",
    )
    .unwrap();
    until(|| s.nodes().unwrap()[0]["completed_tasks"] == 1).await;
    assert!(s.authenticate_node("binary", &token()).is_ok());
    child.start_kill().unwrap();
    child.wait().await.unwrap();
    server.shutdown().await;
    dns_task.abort();
}
#[tokio::test]
async fn binary_worker_replays_a_stored_receipt_when_the_ack_is_lost() {
    let d = tempfile::tempdir().unwrap();
    let s = Store::open(d.path()).unwrap();
    let n = node("binary");
    s.register_node(&n, &token()).unwrap();
    s.enqueue_observation("fixture.example", &["us".into()], "receipt replay fixture")
        .unwrap();
    let lease = s.lease(&n).unwrap().unwrap();
    let endpoint = transport::server_endpoint(d.path(), "127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = endpoint.local_addr().unwrap();
    let copy = endpoint.clone();
    let store = s.clone();
    let handler = tokio::spawn(async move {
        for attempt in 0..2 {
            let c = copy.accept().await.unwrap().await.unwrap();
            let (mut tx, mut rx) = c.accept_bi().await.unwrap();
            assert!(matches!(
                transport::receive(&mut rx).await.unwrap(),
                Message::Hello { .. }
            ));
            transport::send(
                &mut tx,
                Message::Welcome {
                    session: "fixture".into(),
                    heartbeat_seconds: 10,
                    slots: 1,
                },
            )
            .await
            .unwrap();
            if attempt == 0 {
                assert!(matches!(
                    transport::receive(&mut rx).await.unwrap(),
                    Message::Ready
                ));
                transport::send(&mut tx, Message::Task(Box::new(lease.clone())))
                    .await
                    .unwrap();
            }
            let (mut result_tx, mut result_rx) = c.accept_bi().await.unwrap();
            let Message::Result(result) = transport::receive(&mut result_rx).await.unwrap() else {
                panic!()
            };
            let ack = store.submit("binary", &result).unwrap();
            if attempt == 0 {
                assert_eq!(ack["accepted"], true);
                c.close(2u32.into(), b"fixture ack loss");
            } else {
                assert_eq!(ack["duplicate"], true);
                transport::send(
                    &mut result_tx,
                    Message::Ack {
                        id: result.id,
                        disposition: Disposition::Duplicate,
                    },
                )
                .await
                .unwrap();
                result_tx.finish().unwrap();
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    });
    let (dns, dns_task) = dns_fixture().await;
    let cfg = config(
        d.path(),
        &transport::certificate(d.path()).unwrap(),
        addr,
        dns,
    );
    let path = d.path().join("probe.toml");
    std::fs::write(&path, toml::to_string(&cfg).unwrap()).unwrap();
    let first = command(&path, true).output().await.unwrap();
    assert!(!first.status.success());
    assert_eq!(
        std::fs::read_dir(cfg.data_dir.join("spool"))
            .unwrap()
            .count(),
        1
    );
    let second = command(&path, true).output().await.unwrap();
    assert!(
        second.status.success(),
        "{}",
        String::from_utf8_lossy(&second.stderr)
    );
    assert_eq!(
        std::fs::read_dir(cfg.data_dir.join("spool"))
            .unwrap()
            .count(),
        0
    );
    assert_eq!(
        s.connect()
            .unwrap()
            .query_row::<i64, _, _>("SELECT count(*) FROM results WHERE accepted=1", [], |r| r
                .get(0))
            .unwrap(),
        1
    );
    handler.await.unwrap();
    dns_task.abort();
    endpoint.close(0u32.into(), b"done");
}

#[tokio::test]
async fn a_transport_alive_peer_without_application_heartbeats_becomes_offline() {
    let d = tempfile::tempdir().unwrap();
    let s = Store::open(d.path()).unwrap();
    let server = Server::start(d.path(), s.clone(), "127.0.0.1:0".parse().unwrap()).unwrap();
    let n = node("silent");
    s.register_node(&n, &token()).unwrap();
    let (_ep, c, _tx, mut rx) = connect(
        d.path(),
        server.endpoint.local_addr().unwrap(),
        &n.id,
        &token(),
    )
    .await;
    s.enqueue_observation(
        "silent.example",
        &["us".into()],
        "heartbeat timeout fixture",
    )
    .unwrap();
    let lease = task(&mut rx).await;
    tokio::time::timeout(Duration::from_secs(38), c.closed())
        .await
        .expect("application heartbeat timeout");
    until(|| s.nodes().unwrap()[0]["connected"] == false).await;
    assert_eq!(
        s.connect()
            .unwrap()
            .query_row::<String, _, _>("SELECT status FROM jobs WHERE id=?", [lease.id], |r| r
                .get(0))
            .unwrap(),
        "leased"
    );
    server.shutdown().await;
}

#[tokio::test]
async fn binary_worker_connects_to_an_ipv6_controller_literal() {
    let d = tempfile::tempdir().unwrap();
    let s = Store::open(d.path()).unwrap();
    s.register_node(&node("binary"), &token()).unwrap();
    let server = Server::start(d.path(), s, "[::1]:0".parse().unwrap()).unwrap();
    let cfg = config(
        d.path(),
        &transport::certificate(d.path()).unwrap(),
        server.endpoint.local_addr().unwrap(),
        "127.0.0.1:1".into(),
    );
    let path = d.path().join("probe.toml");
    std::fs::write(&path, toml::to_string(&cfg).unwrap()).unwrap();
    let output = tokio::time::timeout(Duration::from_secs(5), command(&path, true).output())
        .await
        .unwrap()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    server.shutdown().await;
}

#[tokio::test]
async fn binary_worker_sends_heartbeats_while_replaying_its_outbox() {
    let d = tempfile::tempdir().unwrap();
    let endpoint = transport::server_endpoint(d.path(), "127.0.0.1:0".parse().unwrap()).unwrap();
    let cfg = config(
        d.path(),
        &transport::certificate(d.path()).unwrap(),
        endpoint.local_addr().unwrap(),
        "127.0.0.1:1".into(),
    );
    let spool = cfg.data_dir.join("spool");
    std::fs::create_dir_all(&spool).unwrap();
    let result = ProbeResult {
        id: "stored-receipt".into(),
        job_id: "stored-job".into(),
        fingerprint: "fixture".into(),
        lease_token: "fixture".into(),
        observed_at: now(),
        outcome: "ok".into(),
        evidence: json!({}),
    };
    std::fs::write(
        spool.join("receipt.json"),
        serde_json::to_vec(&result).unwrap(),
    )
    .unwrap();
    let copy = endpoint.clone();
    let handler = tokio::spawn(async move {
        let c = copy.accept().await.unwrap().await.unwrap();
        let (mut tx, mut rx) = c.accept_bi().await.unwrap();
        assert!(matches!(
            transport::receive(&mut rx).await.unwrap(),
            Message::Hello { .. }
        ));
        transport::send(
            &mut tx,
            Message::Welcome {
                session: "fixture".into(),
                heartbeat_seconds: 5,
                slots: 1,
            },
        )
        .await
        .unwrap();
        let (mut result_tx, mut result_rx) = c.accept_bi().await.unwrap();
        let Message::Result(receipt) = transport::receive(&mut result_rx).await.unwrap() else {
            panic!("stored receipt required")
        };
        let heartbeats = tokio::time::timeout(Duration::from_secs(7), async {
            for _ in 0..2 {
                assert!(matches!(
                    transport::receive(&mut rx).await.unwrap(),
                    Message::Heartbeat { active, .. } if active.is_empty()
                ));
                transport::send(&mut tx, Message::Pong { server_time: now() })
                    .await
                    .unwrap();
            }
        })
        .await;
        if heartbeats.is_err() {
            c.close(1u32.into(), b"outbox replay stopped application heartbeats");
            return false;
        }
        transport::send(
            &mut result_tx,
            Message::Ack {
                id: receipt.id,
                disposition: Disposition::Duplicate,
            },
        )
        .await
        .unwrap();
        result_tx.finish().unwrap();
        let _ = c.closed().await;
        true
    });
    let path = d.path().join("probe.toml");
    std::fs::write(&path, toml::to_string(&cfg).unwrap()).unwrap();
    let output = tokio::time::timeout(Duration::from_secs(10), command(&path, true).output())
        .await
        .unwrap()
        .unwrap();
    assert!(handler.await.unwrap(), "heartbeats must run before Ready");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(std::fs::read_dir(spool).unwrap().count(), 0);
    endpoint.close(0u32.into(), b"done");
}
#[test]
fn legacy_hello_remains_readable_and_new_worker_reports_network_and_capacity() {
    #[derive(serde::Serialize)]
    enum LegacyMessage {
        Hello { id: String, token: String },
    }
    #[derive(serde::Serialize)]
    struct LegacyEnvelope {
        version: u16,
        message: LegacyMessage,
    }
    let mut bytes = Vec::new();
    ciborium::into_writer(
        &LegacyEnvelope {
            version: 1,
            message: LegacyMessage::Hello {
                id: "old".into(),
                token: "fixture".into(),
            },
        },
        &mut bytes,
    )
    .unwrap();
    assert!(matches!(
        transport::decode(&bytes).unwrap(),
        Message::Hello {
            network: None,
            capacity: None,
            ..
        }
    ));
    let bytes = transport::encode(Message::Hello {
        id: "new".into(),
        token: "fixture".into(),
        network: Some(airroute_rules::network::NetworkSupport {
            ipv4: true,
            ipv6: false,
        }),
        capacity: Some(1000),
    })
    .unwrap();
    let Message::Hello {
        network: Some(network),
        capacity: Some(capacity),
        ..
    } = transport::decode(&bytes).unwrap()
    else {
        panic!()
    };
    assert!(network.ipv4);
    assert!(!network.ipv6);
    assert_eq!(capacity, 1000);
}
#[tokio::test]
async fn large_capacity_and_network_changes_take_effect_on_the_live_connection() {
    let d = tempfile::tempdir().unwrap();
    let s = Store::open(d.path()).unwrap();
    let server = Server::start(d.path(), s.clone(), "127.0.0.1:0".parse().unwrap()).unwrap();
    let n = node("large-live");
    s.register_node(&n, &token()).unwrap();
    s.update_node_settings(&n.id, "large", Some(1000)).unwrap();
    for i in 0..70 {
        s.enqueue_observation(
            &format!("large-{i}.example"),
            &["us".into()],
            "large native push",
        )
        .unwrap();
    }
    s.enqueue_observation("2001:4860::8888", &["us".into()], "IPv6 capability refresh")
        .unwrap();
    let (_ep, c, mut tx, mut rx) = connect(
        d.path(),
        server.endpoint.local_addr().unwrap(),
        &n.id,
        &token(),
    )
    .await;
    let mut active = vec![];
    for _ in 0..70 {
        let l = task(&mut rx).await;
        assert_eq!(l.kind, "dns");
        active.push((l.id, l.token));
    }
    assert_eq!(s.executor_stats().unwrap()[&n.id].running_tasks, 70);
    transport::send(
        &mut tx,
        Message::Heartbeat {
            active,
            network: Some(airroute_rules::network::NetworkSupport {
                ipv4: true,
                ipv6: true,
            }),
        },
    )
    .await
    .unwrap();
    assert_eq!(task(&mut rx).await.target, "2001:4860::8888");
    c.close(0u32.into(), b"done");
    server.shutdown().await;
}

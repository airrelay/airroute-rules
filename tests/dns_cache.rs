use airroute_rules::{
    measure::{self, ProbeConfig, ResolverConfig},
    now,
    store::{Lease, Store},
};
use hickory_proto::{
    op::{Message, OpCode},
    rr::{RData, Record, RecordType, rdata::A},
};
use serde_json::json;
use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

struct DnsFixture {
    address: String,
    queries: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for DnsFixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn fixture(ttl: u32, aaaa_delay: Duration) -> DnsFixture {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap().to_string();
    let queries = Arc::new(AtomicUsize::new(0));
    let counter = queries.clone();
    let task = tokio::spawn(async move {
        let mut buf = [0; 65535];
        loop {
            let (n, peer) = socket.recv_from(&mut buf).await.unwrap();
            counter.fetch_add(1, Ordering::SeqCst);
            let query = Message::from_vec(&buf[..n]).unwrap();
            let kind = query.queries[0].query_type();
            if kind == RecordType::AAAA {
                tokio::time::sleep(aaaa_delay).await;
            }
            let mut response = Message::response(query.metadata.id, OpCode::Query);
            response.queries = query.queries.clone();
            if kind == RecordType::A {
                response.answers.push(Record::from_rdata(
                    query.queries[0].name().clone(),
                    ttl,
                    RData::A(A("1.1.1.1".parse().unwrap())),
                ));
            }
            socket
                .send_to(&response.to_vec().unwrap(), peer)
                .await
                .unwrap();
        }
    });
    DnsFixture {
        address,
        queries,
        task,
    }
}

async fn response_fixture(
    code: hickory_proto::op::ResponseCode,
    cname: bool,
    address_record: bool,
) -> DnsFixture {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap().to_string();
    let queries = Arc::new(AtomicUsize::new(0));
    let counter = queries.clone();
    let task = tokio::spawn(async move {
        let mut buf = [0; 65535];
        loop {
            let (n, peer) = socket.recv_from(&mut buf).await.unwrap();
            counter.fetch_add(1, Ordering::SeqCst);
            let query = Message::from_vec(&buf[..n]).unwrap();
            let mut response = Message::response(query.metadata.id, OpCode::Query);
            response.queries = query.queries.clone();
            response.metadata.response_code = code;
            if cname {
                response.answers.push(Record::from_rdata(
                    query.queries[0].name().clone(),
                    600,
                    RData::CNAME(hickory_proto::rr::rdata::CNAME(
                        "gone.example.".parse().unwrap(),
                    )),
                ));
            }
            if address_record {
                response.answers.push(Record::from_rdata(
                    query.queries[0].name().clone(),
                    600,
                    RData::A(A("127.0.0.1".parse().unwrap())),
                ));
            }
            socket
                .send_to(&response.to_vec().unwrap(), peer)
                .await
                .unwrap();
        }
    });
    DnsFixture {
        address,
        queries,
        task,
    }
}

fn config(root: &std::path::Path, dns: &DnsFixture) -> ProbeConfig {
    ProbeConfig {
        controller: "quic://127.0.0.1:1".into(),
        id: "fixture".into(),
        token_env: "UNUSED".into(),
        resolvers: vec![ResolverConfig {
            name: "fixture".into(),
            address: dns.address.clone(),
            transport: "udp".into(),
        }],
        allow_private_targets: false,
        tls: false,
        ca_cert: root.join("unused.der"),
        server_name: airroute_rules::transport::SERVER_NAME.into(),
        data_dir: root.into(),
    }
}

fn lease(window: u32) -> Lease {
    Lease {
        id: format!("fixture-{window}"),
        case_key: "fixture".into(),
        fingerprint: "fixture".into(),
        kind: "dns".into(),
        target: "fixture.example".into(),
        region: "us".into(),
        token: "fixture".into(),
        until: now() + 180,
        profile: json!({"window":window,"observer":{"id":"fixture","region":"us","asn":64500}}),
    }
}

#[tokio::test]
async fn real_empty_dns_replies_record_the_actual_query_type_and_code() {
    use airroute_rules::{
        receipt::{ResultClass, qualify},
        store::Node,
    };
    use hickory_proto::op::ResponseCode;
    let root = tempfile::tempdir().unwrap();
    let store = Store::open(root.path()).unwrap();
    let node = Node {
        id: "fixture".into(),
        region: "us".into(),
        asn: 64500,
        capabilities: vec!["dns".into()],
    };
    for code in [
        ResponseCode::NoError,
        ResponseCode::NXDomain,
        ResponseCode::ServFail,
        ResponseCode::Refused,
    ] {
        let dns = response_fixture(code, false, false).await;
        let config = config(root.path(), &dns);
        for kind in ["A", "AAAA"] {
            let mut l = lease(0);
            l.profile["query_type"] = json!(kind);
            let result = measure::execute(&config, &l, &store).await;
            assert_eq!(
                result.outcome, "ok",
                "a real reply is retained, including a resolver error"
            );
            let actual = &result.evidence["resolvers"][0]["rcodes"][0];
            assert_eq!(actual["query_type"], kind);
            assert_eq!(actual["code"], u16::from(code));
            assert_eq!(actual["name"], "fixture.example");
            assert!(actual["observed_at"].as_i64().unwrap() <= result.observed_at);
            assert_eq!(result.evidence["resolvers"][0]["records"], json!([]));
            let q = qualify(&l, &node, &result);
            assert!(!q.qualified);
            assert_eq!(q.evidence_until, None);
            let completed = matches!(code, ResponseCode::NoError | ResponseCode::NXDomain);
            assert_eq!(
                q.execution_terminal, completed,
                "{kind} {code}: {}",
                q.reason
            );
            assert_eq!(
                q.class,
                if completed {
                    ResultClass::Observation
                } else {
                    ResultClass::ExecutorFailure
                }
            );
        }
        assert_eq!(dns.queries.load(Ordering::SeqCst), 2);
    }
}

#[tokio::test]
async fn real_nxdomain_alias_keeps_history_without_positive_ttl_or_cache_reuse() {
    use airroute_rules::{receipt::qualify, store::Node};
    let root = tempfile::tempdir().unwrap();
    let store = Store::open(root.path()).unwrap();
    let dns = response_fixture(hickory_proto::op::ResponseCode::NXDomain, true, false).await;
    let config = config(root.path(), &dns);
    let mut l = lease(0);
    l.profile["query_type"] = json!("A");
    let first = measure::execute(&config, &l, &store).await;
    assert_eq!(
        first.evidence["resolvers"][0]["records"][0]["type"],
        "CNAME"
    );
    let q = qualify(
        &l,
        &Node {
            id: "fixture".into(),
            region: "us".into(),
            asn: 64500,
            capabilities: vec!["dns".into()],
        },
        &first,
    );
    assert!(q.execution_terminal);
    assert!(!q.qualified);
    assert_eq!(q.evidence_until, None);
    let count = dns.queries.load(Ordering::SeqCst);
    let second = measure::execute(&config, &l, &store).await;
    assert_eq!(second.evidence["resolvers"][0]["cache_hit"], false);
    assert_eq!(dns.queries.load(Ordering::SeqCst), count * 2);
}

#[tokio::test]
async fn an_actual_failed_dns_answer_never_enters_the_addresses_used_for_tls() {
    let root = tempfile::tempdir().unwrap();
    let store = Store::open(root.path()).unwrap();
    let dns = response_fixture(hickory_proto::op::ResponseCode::ServFail, false, true).await;
    let mut config = config(root.path(), &dns);
    config.allow_private_targets = true;
    // No HTTPS request is performed by this fixture. private_answers exposes
    // the same address set that domain() would otherwise use for TLS requests.
    config.tls = false;
    let mut l = lease(0);
    l.profile["query_type"] = json!("A");
    let evidence = measure::domain(&config, &l, &store).await.unwrap();
    assert_eq!(
        evidence["resolvers"][0]["records"][0]["data"], "127.0.0.1",
        "the failed answer stays in raw history"
    );
    assert_eq!(
        evidence["resolvers"][0]["records"][0]["query_name"],
        "fixture.example"
    );
    assert_eq!(evidence["resolvers"][0]["addresses"], json!([]));
    assert_eq!(evidence["private_answers"], json!([]));
    assert_eq!(evidence["tls"], json!([]));
}

#[tokio::test]
async fn artificial_windows_do_not_bypass_a_valid_observer_dns_cache() {
    let root = tempfile::tempdir().unwrap();
    let store = Store::open(root.path()).unwrap();
    let dns = fixture(86400, Duration::ZERO).await;
    let config = config(root.path(), &dns);
    measure::domain(&config, &lease(0), &store).await.unwrap();
    assert_eq!(dns.queries.load(Ordering::SeqCst), 5);
    let second = measure::domain(&config, &lease(1), &store).await.unwrap();
    assert_eq!(second["resolvers"][0]["cache_hit"], true);
    assert_eq!(dns.queries.load(Ordering::SeqCst), 5);
}

#[tokio::test]
async fn an_answer_that_expires_during_collection_is_not_cached_again() {
    let root = tempfile::tempdir().unwrap();
    let store = Store::open(root.path()).unwrap();
    let dns = fixture(1, Duration::from_millis(1200)).await;
    let config = config(root.path(), &dns);
    measure::domain(&config, &lease(0), &store).await.unwrap();
    let second = measure::domain(&config, &lease(0), &store).await.unwrap();
    assert_eq!(second["resolvers"][0]["cache_hit"], false);
    assert_eq!(dns.queries.load(Ordering::SeqCst), 10);
}

#[tokio::test]
async fn real_dns_receipt_accepts_the_documented_https_transport_name() {
    let root = tempfile::tempdir().unwrap();
    let store = Store::open(root.path()).unwrap();
    let dns = fixture(60, Duration::ZERO).await;
    let config = config(root.path(), &dns);
    let l = lease(0);
    // Obtain records, clocks and TTL from a real DNS wire round-trip. This
    // checks receipt naming compatibility, not an HTTPS/TLS network handshake.
    let mut evidence = measure::domain(&config, &l, &store).await.unwrap();
    assert!(dns.queries.load(Ordering::SeqCst) > 0);
    assert_eq!(evidence["resolvers"][0]["transport"], "udp");
    let documented: ProbeConfig =
        toml::from_str(include_str!("../config/probe.example.toml")).unwrap();
    let https = documented
        .resolvers
        .iter()
        .find(|r| r.transport == "https")
        .unwrap();
    // measure::domain serializes ResolverConfig.transport verbatim. Apply its
    // documented DoH name to the otherwise untouched actual receipt body.
    evidence["resolvers"][0]["transport"] = json!(https.transport);
    let result = airroute_rules::store::ProbeResult {
        id: "real-wire-https-name".into(),
        job_id: l.id.clone(),
        fingerprint: l.fingerprint.clone(),
        lease_token: l.token.clone(),
        observed_at: airroute_rules::now(),
        outcome: "ok".into(),
        evidence,
    };
    let node = airroute_rules::store::Node {
        id: "fixture".into(),
        region: "us".into(),
        asn: 64500,
        capabilities: vec!["dns".into()],
    };
    let qualification = airroute_rules::receipt::qualify(&l, &node, &result);
    assert!(
        qualification.qualified,
        "documented resolver transport must be accepted: {}",
        qualification.reason
    );
}

#[tokio::test]
async fn explicit_dns_methods_are_executed_and_do_not_share_incompatible_cache_entries() {
    let d = tempfile::tempdir().unwrap();
    let cache = Store::open(d.path()).unwrap();
    let fixture = fixture(60, Duration::ZERO).await;
    let config = config(d.path(), &fixture);
    let mut a = lease(0);
    a.profile["query_type"] = json!("A");
    a.profile["protocol"] = json!("UDP");
    measure::domain(&config, &a, &cache).await.unwrap();
    assert_eq!(fixture.queries.load(Ordering::SeqCst), 1);
    let mut aaaa = a.clone();
    aaaa.profile["query_type"] = json!("AAAA");
    measure::domain(&config, &aaaa, &cache).await.unwrap();
    assert_eq!(
        fixture.queries.load(Ordering::SeqCst),
        2,
        "an A observation cannot answer the AAAA method"
    );
    assert_eq!(
        measure::domain(&config, &a, &cache).await.unwrap()["resolvers"][0]["cache_hit"],
        true
    );
    assert_eq!(fixture.queries.load(Ordering::SeqCst), 2);

    let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = tcp.local_addr().unwrap().to_string();
    let serving = tokio::spawn(async move {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (mut stream, _) = tcp.accept().await.unwrap();
        let size = stream.read_u16().await.unwrap();
        let mut bytes = vec![0; size as usize];
        stream.read_exact(&mut bytes).await.unwrap();
        let query = Message::from_vec(&bytes).unwrap();
        assert_eq!(query.queries[0].query_type(), RecordType::A);
        let mut answer = Message::response(query.metadata.id, OpCode::Query);
        answer.queries = query.queries.clone();
        answer.answers.push(Record::from_rdata(
            query.queries[0].name().clone(),
            60,
            RData::A(A("1.1.1.1".parse().unwrap())),
        ));
        let bytes = answer.to_vec().unwrap();
        stream.write_u16(bytes.len() as u16).await.unwrap();
        stream.write_all(&bytes).await.unwrap();
    });
    let mut tcp_config = config.clone();
    tcp_config.resolvers[0].address = address;
    let mut tcp_query = a.clone();
    tcp_query.profile["protocol"] = json!("TCP");
    let result = measure::domain(&tcp_config, &tcp_query, &cache)
        .await
        .unwrap();
    assert_eq!(result["resolvers"][0]["transport"], "tcp");
    serving.await.unwrap();

    let mut unavailable = a;
    unavailable.profile["protocol"] = json!("HTTPS");
    let refused = measure::execute(&config, &unavailable, &cache).await;
    assert_eq!(refused.outcome, "unsupported");
    assert_eq!(refused.evidence["not_executed"], true);
    assert_eq!(fixture.queries.load(Ordering::SeqCst), 2);
}

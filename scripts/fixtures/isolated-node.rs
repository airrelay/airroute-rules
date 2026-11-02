// Isolated acceptance fixture: never executes a measurement or resolves a name.
use airroute_rules::{now, network::NetworkSupport, store::{Node, ProbeResult, Store}, transport::{self, Message}};
use anyhow::{Result, bail};
use serde_json::json;
use std::{path::Path, time::{Duration, Instant}};

const ID: &str = "isolated-native-fixture";
const TOKEN: &str = "isolated-public-fixture-token-not-a-real-credential";
fn setting(name:&str,default:u32)->u32 { std::env::var(name).ok().and_then(|v|v.parse().ok()).unwrap_or(default) }
fn node_id(index:u32)->String { if index==0 {ID.into()} else {format!("{ID}-{index}")} }

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    let data = Path::new(args.get(1).expect("seed|run DATA"));
    if args[0] == "seed" || args[0]=="register" {
        let count = args.get(2).map_or(Ok(5000), |s| s.parse::<usize>())?;
        let mode=args.get(3).map(String::as_str).unwrap_or("trace");
        let sessions=setting("AIRROUTE_FIXTURE_SESSIONS",1);
        let capacity=setting("AIRROUTE_FIXTURE_CAPACITY",10);
        let started = Instant::now();
        let store = Store::open(data)?;
        for index in 0..sessions {
            let id=node_id(index);
            store.register_node(&Node { id:id.clone(), region: "us".into(), asn: 64501+index, capabilities: if mode=="discovery" {vec!["dns".into(),"traceroute".into()]} else {vec!["traceroute".into()]} }, TOKEN)?;
            store.update_node_settings(&id,&format!("isolated workload {index}"),Some(capacity))?;
        }
        if args[0]=="seed" && mode=="discovery" {
            let mut c=store.connect()?;
            let tx=c.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            let keys={let mut q=tx.prepare("SELECT key FROM cases WHERE kind='manual-ip' AND reason='isolated synthetic observation fixture; no packets sent'")?;q.query_map([],|r|r.get::<_,String>(0))?.collect::<std::result::Result<Vec<_>,_>>()?};
            for key in keys { tx.execute("UPDATE cases SET active=0,status='observed' WHERE key=?",[&key])?;airroute_rules::work::mark_case(&tx,&key)?; }
            for i in 0..count {
                let host=format!("fixture-dns-{i:06}.invalid");
                let key=format!("discover:{host}");
                let fp=airroute_rules::fingerprint(&json!(["shared-target-discovery-v3",host]));
                let payload=json!({"kind":"target-discovery","targets":[host],"regions":[],"purpose":"find addresses in unresolved conflict ranges"});
                tx.execute("INSERT INTO discovery_domains(host,bucket) VALUES(?,0) ON CONFLICT(host) DO NOTHING",[&host])?;
                tx.execute("INSERT INTO cases(key,fp,revision,kind,subject,reason,payload,status,active,updated) VALUES(?,?,1,'target-discovery',?,'accepted-domain DNS target discovery',?,'needs-active',1,?)",rusqlite::params![key,fp,host,payload.to_string(),now()])?;
                airroute_rules::work::plan_on(&tx,&key,&fp,&payload)?;
                airroute_rules::work::mark_case(&tx,&key)?;
                tx.execute("INSERT INTO discovery_checks(kind,key,checked,next_check,error) VALUES('shared-dns',?,?,?,NULL)",rusqlite::params![host,now(),now()+3600])?;
            }
            tx.commit()?;
        } else if args[0]=="seed" {
            for i in 0..count {
                let target = format!("11.10.{}.{}", i / 254, i % 254 + 1);
                store.request_observation(&target, &["us".into()], "isolated synthetic observation fixture; no packets sent", false)?;
            }
        }
        loop {
            airroute_rules::work::refresh(&store)?;
            if !store.connect()?.query_row::<bool,_,_>("SELECT EXISTS(SELECT 1 FROM replan_cases)", [], |r|r.get(0))? { break; }
        }
        store.connect()?.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")?;
        println!("{}", json!({"seeded":if args[0]=="seed" {count}else{0},"mode":mode,"sessions":sessions,"capacity":capacity,"seconds":started.elapsed().as_secs_f64()}));
        return Ok(());
    }
    let address = args.get(2).map(String::as_str).unwrap_or("127.0.0.1:8788").parse()?;
    let id=std::env::var("AIRROUTE_FIXTURE_NODE_ID").unwrap_or_else(|_|ID.into());
    let capacity=setting("AIRROUTE_FIXTURE_CAPACITY",10);
    let dns_ttl=setting("AIRROUTE_FIXTURE_DNS_TTL",3600);
    let delay_ms=setting("AIRROUTE_FIXTURE_DELAY_MS",500);
    let endpoint = transport::client_endpoint(&data.join("quic/controller-cert.der"), "127.0.0.1:0".parse()?)?;
    let connection = endpoint.connect(address, transport::SERVER_NAME)?.await?;
    let (mut tx, mut rx) = connection.open_bi().await?;
    transport::send(&mut tx, Message::Hello { id:id.clone(),token:TOKEN.into(), network:Some(NetworkSupport{ipv4:true,ipv6:false}),capacity:Some(capacity)}).await?;
    let Message::Welcome { .. } = transport::receive(&mut rx).await? else { bail!("no Welcome"); };
    transport::send(&mut tx,Message::Ready).await?;
    let (frames_tx,mut frames_rx)=tokio::sync::mpsc::channel(32);
    tokio::spawn(async move {
        loop {
            let frame=transport::receive(&mut rx).await;
            let failed=frame.is_err();
            if frames_tx.send(frame).await.is_err() || failed { break; }
        }
    });
    let mut active = std::collections::BTreeMap::new();
    let mut executions = tokio::task::JoinSet::new();
    let mut heartbeat = tokio::time::interval(Duration::from_secs(5));
    let mut drain_signal=tokio::signal::unix::signal(tokio::signal::unix::SignalKind::user_defined1())?;
    let mut draining=false;
    let mut drain_checks=tokio::time::interval(Duration::from_millis(100));
    let mut drained_since=None;
    let mut refill_started = Instant::now();
    println!("{}",json!({"connected":true,"node":id,"capacity":capacity,"synthetic_delay_ms":delay_ms,"dns_fixture":{"query_type":"A","transport":"udp","positive_ttl":dns_ttl,"nxdomain_every_10th_index":true}}));
    loop {
        tokio::select! {
            frame=frames_rx.recv()=> match frame.ok_or_else(||anyhow::anyhow!("control stream ended"))?? {
                Message::Task(lease)=> {
                    let dispatch_ms=refill_started.elapsed().as_secs_f64()*1000.;
                    active.insert(lease.id.clone(),lease.token.clone());
                    let c=connection.clone();
                    executions.spawn(async move {
                        tokio::time::sleep(Duration::from_millis(u64::from(delay_ms))).await;
                        let observed=now();
                        let index=lease.target.split('.').next().and_then(|s|s.rsplit('-').next()).and_then(|s|s.parse::<usize>().ok()).unwrap_or(1);
                        let nxdomain=index%10==0;
                        let evidence=if lease.kind=="dns" {
                            json!({"kind":"dns","fixture":true,"hostname":lease.target,"resolvers":[{"transport":"udp","response_received":true,"observed_at":observed,"valid_until":observed+i64::from(dns_ttl),"rcodes":[{"query_type":"A","code":if nxdomain{3}else{0},"response_code":if nxdomain{"NXDOMAIN"}else{"NOERROR"}}],"records":if nxdomain {vec![]}else{vec![json!({"name":lease.target,"type":"A","query_type":"A","ttl":dns_ttl,"data":"1.1.1.1"})]}}]})
                        } else {
                            json!({"kind":"traceroute","fixture":true,"target":lease.target,"protocol":"icmp","reached":true,"hops":[{"hop":1,"ip":lease.target}]})
                        };
                        let kind=lease.kind.clone();
                        let result=ProbeResult{id:uuid::Uuid::new_v4().to_string(),job_id:lease.id.clone(),fingerprint:lease.fingerprint.clone(),lease_token:lease.token.clone(),observed_at:observed,outcome:"ok".into(),evidence};
                        let (mut result_tx, mut result_rx)=c.open_bi().await?;
                        let started=Instant::now();
                        transport::send(&mut result_tx,Message::Result(Box::new(result))).await?;
                        result_tx.finish()?;
                        let ack=tokio::time::timeout(Duration::from_secs(30),transport::receive(&mut result_rx)).await??;
                        let disposition=match ack { Message::Ack{disposition,..}=>format!("{disposition:?}"),Message::Rejected{retryable,..}=>format!("Rejected({retryable})"),_=>"Unexpected".into() };
                        anyhow::Ok((lease.id,kind,nxdomain,started.elapsed().as_secs_f64()*1000.,dispatch_ms,disposition))
                    });
                },
                Message::Pong{..}|Message::Idle=>{},
                _=>bail!("unexpected control frame"),
            },
            result=executions.join_next(),if !executions.is_empty()=> {
                let (id,kind,nxdomain,receipt_ms,dispatch_ms,disposition)=result.expect("execution")??;
                active.remove(&id);
                if !draining { transport::send(&mut tx,Message::Finished{id:id.clone()}).await?; }
                refill_started=Instant::now();
                println!("{}",json!({"job_id":id,"kind":kind,"dns_nxdomain":kind=="dns" && nxdomain,"receipt_ms":receipt_ms,"time_since_latest_finished_ms":dispatch_ms,"dispatch_gap_ms":dispatch_ms,"disposition":disposition}));
            },
            _=heartbeat.tick()=> {
                transport::send(&mut tx,Message::Heartbeat{active:active.iter().map(|(a,b)|(a.clone(),b.clone())).collect(),network:Some(NetworkSupport{ipv4:true,ipv6:false})}).await?;
            },
            _=connection.closed()=>bail!("controller connection closed"),
            _=drain_signal.recv()=> { draining=true; },
            _=drain_checks.tick(),if draining=>{},
        }
        if draining && active.is_empty() && executions.is_empty() {
            let since=drained_since.get_or_insert_with(Instant::now);
            if since.elapsed()>=Duration::from_secs(2) {
                println!("{}",json!({"drained":true}));
                connection.close(0u32.into(),b"isolated fixture drained");
                return Ok(());
            }
        } else { drained_since=None; }
    }
}

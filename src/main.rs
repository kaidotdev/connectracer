use clap::Parser;
use std::str::FromStr;
use trust_dns_client::client::ClientHandle;

mod bpf;
mod server;

#[derive(clap::Parser, Clone)]
pub struct Args {
    #[clap(short, long)]
    hosts: Vec<String>,
    #[clap(short, long)]
    listen: Option<String>,
    #[clap(short, long)]
    nameserver: Option<String>,
}

#[derive(Clone, Debug)]
pub struct IPMap {
    ipv4: std::collections::HashMap<u32, String>,
    ipv6: std::collections::HashMap<u128, String>,
}

impl IPMap {
    fn new() -> Self {
        Self {
            ipv4: std::collections::HashMap::new(),
            ipv6: std::collections::HashMap::new(),
        }
    }
}

struct IPCache {
    ipv4: std::collections::HashMap<String, Vec<u32>>,
    ipv6: std::collections::HashMap<String, Vec<u128>>,
}

impl IPCache {
    fn new() -> Self {
        Self {
            ipv4: std::collections::HashMap::new(),
            ipv6: std::collections::HashMap::new(),
        }
    }
}

fn start(hm: IPMap) -> std::sync::Arc<std::sync::atomic::AtomicBool> {
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));

    let cloned_stop = std::sync::Arc::clone(&stop);
    std::thread::spawn(move || {
        bpf::watch(hm, cloned_stop).unwrap();
    });

    std::sync::Arc::clone(&stop)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
    let args: Args = Args::parse();

    let address: std::net::SocketAddr =
        args.listen.unwrap_or("0.0.0.0:3000".to_string()).parse()?;
    let exporter = opentelemetry_prometheus::exporter().init();
    let signal = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let server = server::serve(address, exporter, signal);

    let mut handles = vec![];

    let address: std::net::SocketAddr = args
        .nameserver
        .unwrap_or("8.8.8.8:53".to_string())
        .parse()?;
    let conn = trust_dns_client::udp::UdpClientStream::<tokio::net::UdpSocket>::with_timeout(
        address,
        std::time::Duration::from_secs(10),
    );
    let (client, bg) = trust_dns_client::client::AsyncClient::connect(conn).await?;
    handles.push(tokio::spawn(bg));

    let (tx, mut rx): (
        tokio::sync::mpsc::UnboundedSender<IPMap>,
        tokio::sync::mpsc::UnboundedReceiver<IPMap>,
    ) = tokio::sync::mpsc::unbounded_channel();
    let hm = std::sync::Arc::new(futures::lock::Mutex::new(IPMap::new()));

    for host in args.hosts {
        for record_type in vec![
            trust_dns_client::rr::RecordType::A,
            trust_dns_client::rr::RecordType::AAAA,
        ] {
            let mut cloned_client = client.clone();
            let cloned_hm = std::sync::Arc::clone(&hm);
            let cloned_tx = tx.clone();
            let host = host.clone();
            handles.push(tokio::spawn(async move {
                let name = trust_dns_client::rr::Name::from_str(&host).unwrap();
                let mut cache = IPCache::new();
                loop {
                    let response: trust_dns_client::op::DnsResponse = cloned_client
                        .query(
                            name.clone(),
                            trust_dns_client::rr::DNSClass::IN,
                            record_type,
                        )
                        .await
                        .unwrap();
                    let answers: &[trust_dns_client::rr::Record] = response.answers();
                    let mut max_ttl = 0;

                    match record_type {
                        trust_dns_client::proto::rr::RecordType::A => {
                            let mut new = vec![];
                            for record in answers {
                                if record.ttl() > max_ttl {
                                    max_ttl = record.ttl();
                                }
                                if let trust_dns_client::proto::rr::RData::A(ref ip) =
                                    record.rdata()
                                {
                                    new.push(u32::swap_bytes(ip.clone().into()))
                                }
                            }
                            new.sort();

                            let default = vec![];
                            let old = cache.ipv4.get(&host).unwrap_or(&default);
                            if old != &new {
                                let mut hm = cloned_hm.lock().await;
                                if let trust_dns_client::proto::rr::RecordType::A = record_type {
                                    for ip in old {
                                        hm.ipv4.remove(ip);
                                    }
                                    for ip in new.iter() {
                                        hm.ipv4.insert(ip.clone(), host.clone());
                                    }
                                }
                                cloned_tx.send(hm.clone()).unwrap();

                                cache.ipv4.insert(host.clone(), new);
                            }
                        }
                        trust_dns_client::proto::rr::RecordType::AAAA => {
                            let mut new = vec![];
                            for record in answers {
                                if record.ttl() > max_ttl {
                                    max_ttl = record.ttl();
                                }
                                if let trust_dns_client::proto::rr::RData::AAAA(ref ip) =
                                    record.rdata()
                                {
                                    new.push(ip.clone().into())
                                }
                            }
                            new.sort();

                            let default = vec![];
                            let old = cache.ipv6.get(&host).unwrap_or(&default);
                            if old != &new {
                                let mut hm = cloned_hm.lock().await;
                                if let trust_dns_client::proto::rr::RecordType::AAAA = record_type {
                                    for ip in old {
                                        hm.ipv6.remove(ip);
                                    }
                                    for ip in new.iter() {
                                        hm.ipv6.insert(ip.clone(), host.clone());
                                    }
                                }
                                cloned_tx.send(hm.clone()).unwrap();

                                cache.ipv6.insert(host.clone(), new);
                            }
                        }
                        _ => {
                            continue;
                        }
                    }

                    if max_ttl > 60 {
                        tokio::time::sleep(std::time::Duration::from_secs(max_ttl as u64)).await;
                    } else {
                        tokio::time::sleep(std::time::Duration::from_secs(60)).await;
                    }
                }
            }));
        }
    }

    let mut before_stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    handles.push(tokio::spawn(async move {
        loop {
            if let Ok(value) =
                tokio::time::timeout(std::time::Duration::from_secs(1), rx.recv()).await
            {
                if let Some(hm) = value {
                    let after_stop = start(hm);
                    before_stop.store(true, std::sync::atomic::Ordering::Relaxed);
                    before_stop = after_stop;
                }
            }
        }
    }));

    server.await?;

    for handle in handles {
        handle.abort();
    }

    Ok(())
}

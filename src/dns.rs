use hickory_proto::op::{Message, Query};
use hickory_proto::rr::{Name, RecordType};
use hickory_resolver::config::{NameServerConfig, NameServerConfigGroup, ResolverConfig};
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::AsyncResolver;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use tokio::io;
use tokio::sync::Mutex;

pub enum DNSServerKind {
    TCP,
    UDP,
    TLS,
    HTTPS,
}

enum Upstream {
    Hickory(AsyncResolver<TokioConnectionProvider>),
    Https {
        client: reqwest::Client,
        url: String,
    },
}

pub struct CachedResolver {
    upstream: Upstream,
    cache: Mutex<HashMap<String, IpAddr>>,
}

impl CachedResolver {
    pub async fn new(dns_server: &str, kind: DNSServerKind) -> io::Result<Self> {
        let upstream = match kind {
            DNSServerKind::TLS => Upstream::Hickory(create_dot_resolver(dns_server).await?),
            DNSServerKind::TCP => Upstream::Hickory(create_tcp_resolver(dns_server).await?),
            DNSServerKind::UDP => Upstream::Hickory(create_udp_resolver(dns_server).await?),
            DNSServerKind::HTTPS => Upstream::Https {
                client: reqwest::Client::builder()
                    .build()
                    .map_err(io::Error::other)?,
                url: dns_server.to_string(),
            },
        };
        Ok(Self {
            upstream,
            cache: Mutex::new(HashMap::new()),
        })
    }

    pub async fn lookup_ip(&self, host: String) -> io::Result<IpAddr> {
        // Check if host is already an IP address
        if let Ok(host) = host.parse::<std::net::IpAddr>() {
            return Ok(host);
        }

        if let Some(ip) = self.cache.lock().await.get(&host) {
            log::debug!("cache hit for {host}");
            return Ok(*ip);
        }
        log::debug!("cache miss for {host}, resolving...");
        let mut ips = match &self.upstream {
            Upstream::Hickory(resolver) => resolver.lookup_ip(&host).await?.iter().collect(),
            Upstream::Https { client, url } => doh_lookup(client, url, &host).await?,
        };
        if ips.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "No IP addresses found",
            ));
        }
        let ip = ips.pop().unwrap();
        self.cache.lock().await.insert(host, ip);
        Ok(ip)
    }
}

pub async fn create_dot_resolver(
    dns_server: &str,
) -> io::Result<AsyncResolver<TokioConnectionProvider>> {
    let resolver_ips = match dns_server.parse::<std::net::IpAddr>() {
        Ok(ip) => vec![ip],
        Err(_) => tokio::net::lookup_host(format!("{}:853", dns_server))
            .await?
            .map(|ip| ip.ip())
            .collect::<Vec<_>>(),
    };
    Ok(AsyncResolver::tokio(
        ResolverConfig::from_parts(
            None,
            vec![],
            NameServerConfigGroup::from_ips_tls(&resolver_ips, 853, dns_server.to_string(), true),
        ),
        Default::default(),
    ))
}

async fn doh_lookup(
    client: &reqwest::Client,
    url: &str,
    host: &str,
) -> io::Result<Vec<IpAddr>> {
    let name = Name::from_ascii(host).map_err(io::Error::other)?;
    let mut ips = Vec::new();
    for record_type in [RecordType::A, RecordType::AAAA] {
        let mut request = Message::new();
        request
            .set_id(0)
            .set_recursion_desired(true)
            .add_query(Query::query(name.clone(), record_type));
        let body = request.to_vec().map_err(io::Error::other)?;

        let response = client
            .post(url)
            .header("content-type", "application/dns-message")
            .header("accept", "application/dns-message")
            .body(body)
            .send()
            .await
            .and_then(|r| r.error_for_status())
            .map_err(io::Error::other)?
            .bytes()
            .await
            .map_err(io::Error::other)?;

        let message = Message::from_vec(&response).map_err(io::Error::other)?;
        ips.extend(
            message
                .answers()
                .iter()
                .filter_map(|record| record.data().and_then(|data| data.ip_addr())),
        );
    }
    Ok(ips)
}

pub async fn create_tcp_resolver(
    dns_server: &str,
) -> io::Result<AsyncResolver<TokioConnectionProvider>> {
    let resolver_ips = match dns_server.parse::<std::net::IpAddr>() {
        Ok(ip) => vec![ip],
        Err(_) => tokio::net::lookup_host(format!("{}:53", dns_server))
            .await?
            .map(|ip| ip.ip())
            .collect::<Vec<_>>(),
    };
    assert!(resolver_ips.len() > 0);
    let mut name_servers = NameServerConfigGroup::new();

    let tcp = NameServerConfig {
        socket_addr: SocketAddr::new(resolver_ips[0], 53),
        protocol: hickory_resolver::config::Protocol::Tcp,
        tls_dns_name: None,
        trust_negative_responses: true,
        bind_addr: None,
    };

    name_servers.push(tcp);

    Ok(AsyncResolver::tokio(
        ResolverConfig::from_parts(None, vec![], name_servers),
        Default::default(),
    ))
}

pub async fn create_udp_resolver(
    dns_server: &str,
) -> io::Result<AsyncResolver<TokioConnectionProvider>> {
    let resolver_ips = match dns_server.parse::<std::net::IpAddr>() {
        Ok(ip) => vec![ip],
        Err(_) => tokio::net::lookup_host(format!("{}:53", dns_server))
            .await?
            .map(|ip| ip.ip())
            .collect::<Vec<_>>(),
    };
    assert!(resolver_ips.len() > 0);
    let mut name_servers = NameServerConfigGroup::new();

    let udp = NameServerConfig {
        socket_addr: SocketAddr::new(resolver_ips[0], 53),
        protocol: hickory_resolver::config::Protocol::Udp,
        tls_dns_name: None,
        trust_negative_responses: true,
        bind_addr: None,
    };

    name_servers.push(udp);

    Ok(AsyncResolver::tokio(
        ResolverConfig::from_parts(None, vec![], name_servers),
        Default::default(),
    ))
}

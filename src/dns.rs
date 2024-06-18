use hickory_resolver::config::{NameServerConfig, NameServerConfigGroup, ResolverConfig};
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::AsyncResolver;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use tokio::io;
use tokio::sync::Mutex;

pub enum DNSServerKind {
    TCP,
    TLS,
}

pub struct CachedResolver {
    resolver: AsyncResolver<TokioConnectionProvider>,
    cache: Mutex<HashMap<String, IpAddr>>,
}

impl CachedResolver {
    pub async fn new(dns_server: &str, kind: DNSServerKind) -> io::Result<Self> {
        let resolver = match kind {
            DNSServerKind::TLS => create_dot_resolver(dns_server).await?,
            DNSServerKind::TCP => create_tcp_resolver(dns_server).await?,
        };
        Ok(Self {
            resolver,
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
        let response = self.resolver.lookup_ip(&host).await?;
        let mut ips = response.iter().collect::<Vec<_>>();
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

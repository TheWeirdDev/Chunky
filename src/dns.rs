use hickory_resolver::config::{NameServerConfigGroup, ResolverConfig};
use hickory_resolver::name_server::{ConnectionProvider, TokioConnectionProvider};
use hickory_resolver::AsyncResolver;
use std::collections::HashMap;
use std::net::IpAddr;
use tokio::io;
use tokio::sync::Mutex;

pub struct CachedResolver {
    resolver: AsyncResolver<TokioConnectionProvider>,
    cache: Mutex<HashMap<String, IpAddr>>,
}

impl CachedResolver {
    pub async fn new(dns_server: &str) -> io::Result<Self> {
        let resolver = create_dot_resolver(dns_server).await?;
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

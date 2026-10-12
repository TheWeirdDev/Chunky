use hickory_proto::op::{Message, Query};
use hickory_proto::rr::{Name, RecordType};
use hickory_resolver::config::{NameServerConfig, NameServerConfigGroup, Protocol, ResolverConfig};
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::AsyncResolver;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use tokio::io;
use tokio::sync::Mutex;

type HickoryResolver = AsyncResolver<TokioConnectionProvider>;

pub enum DNSServerKind {
    Tcp,
    Udp,
    Tls,
    Https,
}

enum Upstream {
    Hickory(HickoryResolver),
    Https {
        client: reqwest::Client,
        url: String,
    },
}

pub struct CachedResolver {
    upstream: Upstream,
    cache: Mutex<HashMap<String, IpAddr>>,
    prefer_ipv6: bool,
}

impl CachedResolver {
    pub async fn new(dns_server: &str, kind: DNSServerKind, prefer_ipv6: bool) -> io::Result<Self> {
        let upstream = match kind {
            DNSServerKind::Tls => Upstream::Hickory(create_tls_resolver(dns_server).await?),
            DNSServerKind::Tcp => {
                Upstream::Hickory(create_plain_resolver(dns_server, Protocol::Tcp).await?)
            }
            DNSServerKind::Udp => {
                Upstream::Hickory(create_plain_resolver(dns_server, Protocol::Udp).await?)
            }
            DNSServerKind::Https => Upstream::Https {
                client: reqwest::Client::builder()
                    .build()
                    .map_err(io::Error::other)?,
                url: dns_server.to_string(),
            },
        };
        Ok(Self {
            upstream,
            cache: Mutex::new(HashMap::new()),
            prefer_ipv6,
        })
    }

    pub async fn lookup_ip(&self, host: String) -> io::Result<IpAddr> {
        // Check if host is already an IP address
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(ip);
        }

        if let Some(ip) = self.cache.lock().await.get(&host) {
            log::debug!("cache hit for {host}");
            return Ok(*ip);
        }
        log::debug!("cache miss for {host}, resolving...");
        let ips: Vec<IpAddr> = match &self.upstream {
            Upstream::Hickory(resolver) => resolver.lookup_ip(&host).await?.iter().collect(),
            Upstream::Https { client, url } => doh_lookup(client, url, &host).await?,
        };
        let ip = pick_ip(&ips, self.prefer_ipv6)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "No IP addresses found"))?;
        self.cache.lock().await.insert(host, ip);
        Ok(ip)
    }
}

/// Picks an address from `ips`, preferring IPv6 when configured. Falls back to the last one.
fn pick_ip(ips: &[IpAddr], prefer_ipv6: bool) -> Option<IpAddr> {
    let preferred = if prefer_ipv6 {
        ips.iter().copied().find(IpAddr::is_ipv6)
    } else {
        None
    };
    preferred.or_else(|| ips.last().copied())
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

/// Resolves the server address, which may be an IP or a hostname, to all of its IPs.
async fn resolve_server_ips(dns_server: &str, port: u16) -> io::Result<Vec<IpAddr>> {
    if let Ok(ip) = dns_server.parse::<IpAddr>() {
        return Ok(vec![ip]);
    }
    let ips: Vec<IpAddr> = tokio::net::lookup_host((dns_server, port))
        .await?
        .map(|addr| addr.ip())
        .collect();
    if ips.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("No IP addresses found for DNS server {dns_server}"),
        ));
    }
    Ok(ips)
}

async fn create_tls_resolver(dns_server: &str) -> io::Result<HickoryResolver> {
    const PORT: u16 = 853;
    let ips = resolve_server_ips(dns_server, PORT).await?;
    let servers = NameServerConfigGroup::from_ips_tls(&ips, PORT, dns_server.to_string(), true);
    Ok(AsyncResolver::tokio(
        ResolverConfig::from_parts(None, vec![], servers),
        Default::default(),
    ))
}

/// Plain TCP or UDP resolver on port 53. Only the first resolved address is used.
async fn create_plain_resolver(dns_server: &str, protocol: Protocol) -> io::Result<HickoryResolver> {
    const PORT: u16 = 53;
    let ips = resolve_server_ips(dns_server, PORT).await?;
    let server = NameServerConfig {
        socket_addr: SocketAddr::new(ips[0], PORT),
        protocol,
        tls_dns_name: None,
        trust_negative_responses: true,
        bind_addr: None,
    };
    let mut servers = NameServerConfigGroup::new();
    servers.push(server);
    Ok(AsyncResolver::tokio(
        ResolverConfig::from_parts(None, vec![], servers),
        Default::default(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(a: u8) -> IpAddr {
        IpAddr::from([192, 0, 2, a])
    }

    fn v6(a: u16) -> IpAddr {
        IpAddr::from([0x2001, 0xdb8, 0, 0, 0, 0, 0, a])
    }

    #[test]
    fn pick_ip_returns_none_for_no_addresses() {
        assert_eq!(pick_ip(&[], false), None);
        assert_eq!(pick_ip(&[], true), None);
    }

    #[test]
    fn pick_ip_prefers_ipv6_when_enabled() {
        let ips = [v4(1), v6(1), v4(2)];
        assert_eq!(pick_ip(&ips, true), Some(v6(1)));
    }

    #[test]
    fn pick_ip_falls_back_to_v4_when_no_v6() {
        let ips = [v4(1), v4(2)];
        assert_eq!(pick_ip(&ips, true), Some(v4(2)));
    }

    #[test]
    fn pick_ip_ignores_v6_when_not_preferred() {
        let ips = [v6(1), v4(1)];
        assert_eq!(pick_ip(&ips, false), Some(v4(1)));
    }
}

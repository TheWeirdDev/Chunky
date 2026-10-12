use hickory_proto::op::{Message, Query};
use hickory_proto::rr::{Name, RecordType};
use hickory_resolver::config::{NameServerConfig, NameServerConfigGroup, Protocol, ResolverConfig};
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::AsyncResolver;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use tokio::io;
use tokio::sync::Mutex;
use url::{Host, Url};

type HickoryResolver = AsyncResolver<TokioConnectionProvider>;

/// A DoH server IP together with a client pinned to connect to that IP.
type DohEndpoint = (IpAddr, reqwest::Client);

pub enum DNSServerKind {
    Tcp,
    Udp,
    Tls,
    Https,
}

enum Upstream {
    Hickory(HickoryResolver),
    Https {
        endpoints: Vec<DohEndpoint>,
        url: String,
    },
}

/// Which address family to try first when a host has both IPv4 and IPv6 addresses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IpPreference {
    Any,
    Ipv4,
    Ipv6,
}

pub struct CachedResolver {
    upstream: Upstream,
    cache: Mutex<HashMap<String, Vec<IpAddr>>>,
    prefer: IpPreference,
}

impl CachedResolver {
    pub async fn new(dns_server: &str, kind: DNSServerKind, prefer: IpPreference) -> io::Result<Self> {
        let upstream = match kind {
            DNSServerKind::Tls => Upstream::Hickory(create_tls_resolver(dns_server).await?),
            DNSServerKind::Tcp => {
                Upstream::Hickory(create_plain_resolver(dns_server, Protocol::Tcp).await?)
            }
            DNSServerKind::Udp => {
                Upstream::Hickory(create_plain_resolver(dns_server, Protocol::Udp).await?)
            }
            DNSServerKind::Https => Upstream::Https {
                endpoints: create_doh_endpoints(dns_server).await?,
                url: dns_server.to_string(),
            },
        };
        Ok(Self {
            upstream,
            cache: Mutex::new(HashMap::new()),
            prefer,
        })
    }

    /// Returns every address for `host`, best first, so callers can fall back to the next one.
    pub async fn lookup_ips(&self, host: String) -> io::Result<Vec<IpAddr>> {
        // Check if host is already an IP address
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(vec![ip]);
        }

        if let Some(ips) = self.cache.lock().await.get(&host) {
            log::debug!("cache hit for {host}");
            return Ok(ips.clone());
        }
        log::debug!("cache miss for {host}, resolving...");
        let ips: Vec<IpAddr> = match &self.upstream {
            Upstream::Hickory(resolver) => resolver.lookup_ip(&host).await?.iter().collect(),
            Upstream::Https { endpoints, url } => doh_lookup_any(endpoints, url, &host).await?,
        };
        let ordered = order_ips(&ips, self.prefer);
        if ordered.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "No IP addresses found",
            ));
        }
        self.cache.lock().await.insert(host, ordered.clone());
        Ok(ordered)
    }
}

/// Picks an address from `ips`, preferring the configured family. Falls back to the last one.
fn pick_ip(ips: &[IpAddr], prefer: IpPreference) -> Option<IpAddr> {
    let preferred = match prefer {
        IpPreference::Any => None,
        IpPreference::Ipv4 => ips.iter().copied().find(IpAddr::is_ipv4),
        IpPreference::Ipv6 => ips.iter().copied().find(IpAddr::is_ipv6),
    };
    preferred.or_else(|| ips.last().copied())
}

/// Orders `ips` for connecting: the address `pick_ip` chooses comes first, then the rest.
/// Duplicates are removed.
fn order_ips(ips: &[IpAddr], prefer: IpPreference) -> Vec<IpAddr> {
    let mut ordered = Vec::with_capacity(ips.len());
    for ip in pick_ip(ips, prefer).into_iter().chain(ips.iter().copied()) {
        if !ordered.contains(&ip) {
            ordered.push(ip);
        }
    }
    ordered
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

/// Builds one client per IP of the DoH server, each pinned to connect to that IP.
/// TLS still validates against the server's hostname.
async fn create_doh_endpoints(dns_server: &str) -> io::Result<Vec<DohEndpoint>> {
    let invalid = |msg: &str| io::Error::new(io::ErrorKind::InvalidInput, msg.to_string());
    let url = Url::parse(dns_server).map_err(io::Error::other)?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| invalid("DoH URL has no port"))?;
    let (domain, ips) = match url.host() {
        Some(Host::Domain(domain)) => (Some(domain), resolve_server_ips(domain, port).await?),
        Some(Host::Ipv4(ip)) => (None, vec![IpAddr::V4(ip)]),
        Some(Host::Ipv6(ip)) => (None, vec![IpAddr::V6(ip)]),
        None => return Err(invalid("DoH URL has no host")),
    };
    ips.into_iter()
        .map(|ip| {
            let mut builder = reqwest::Client::builder();
            if let Some(domain) = domain {
                builder = builder.resolve(domain, SocketAddr::new(ip, port));
            }
            let client = builder.build().map_err(io::Error::other)?;
            Ok((ip, client))
        })
        .collect()
}

/// Tries each DoH endpoint in order and returns the first successful answer.
async fn doh_lookup_any(endpoints: &[DohEndpoint], url: &str, host: &str) -> io::Result<Vec<IpAddr>> {
    let mut last_err = None;
    for (ip, client) in endpoints {
        match doh_lookup(client, url, host).await {
            Ok(ips) => return Ok(ips),
            Err(e) => {
                log::warn!("DoH lookup for {host} via {ip} failed, trying next: {e}");
                last_err = Some(e);
            }
        }
    }
    Err(last_err.unwrap_or_else(|| io::Error::new(io::ErrorKind::NotFound, "No DoH endpoints")))
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
        assert_eq!(pick_ip(&[], IpPreference::Any), None);
        assert_eq!(pick_ip(&[], IpPreference::Ipv6), None);
    }

    #[test]
    fn pick_ip_prefers_ipv6_when_enabled() {
        let ips = [v4(1), v6(1), v4(2)];
        assert_eq!(pick_ip(&ips, IpPreference::Ipv6), Some(v6(1)));
    }

    #[test]
    fn pick_ip_prefers_ipv4_when_enabled() {
        let ips = [v6(1), v4(1), v6(2)];
        assert_eq!(pick_ip(&ips, IpPreference::Ipv4), Some(v4(1)));
    }

    #[test]
    fn pick_ip_falls_back_when_preferred_family_missing() {
        let v4_only = [v4(1), v4(2)];
        assert_eq!(pick_ip(&v4_only, IpPreference::Ipv6), Some(v4(2)));
        let v6_only = [v6(1), v6(2)];
        assert_eq!(pick_ip(&v6_only, IpPreference::Ipv4), Some(v6(2)));
    }

    #[test]
    fn pick_ip_ignores_family_when_not_preferred() {
        let ips = [v6(1), v4(1)];
        assert_eq!(pick_ip(&ips, IpPreference::Any), Some(v4(1)));
    }

    #[test]
    fn order_ips_puts_chosen_address_first_then_the_rest() {
        let ips = [v4(1), v6(1), v4(2)];
        assert_eq!(
            order_ips(&ips, IpPreference::Ipv6),
            vec![v6(1), v4(1), v4(2)]
        );
        assert_eq!(
            order_ips(&ips, IpPreference::Any),
            vec![v4(2), v4(1), v6(1)]
        );
    }

    #[test]
    fn order_ips_removes_duplicates_and_handles_empty() {
        assert!(order_ips(&[], IpPreference::Ipv6).is_empty());
        assert_eq!(
            order_ips(&[v4(1), v4(1)], IpPreference::Any),
            vec![v4(1)]
        );
    }

    /// Reads one HTTP request from `sock` and replies with a DNS answer for 192.0.2.1.
    async fn serve_fake_doh(mut sock: tokio::net::TcpStream) {
        use hickory_proto::op::MessageType;
        use hickory_proto::rr::rdata::A;
        use hickory_proto::rr::{RData, Record};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let mut buf = Vec::new();
        let mut chunk = [0u8; 1024];
        let head_end = loop {
            let n = sock.read(&mut chunk).await.unwrap();
            assert_ne!(n, 0, "client closed before sending headers");
            buf.extend_from_slice(&chunk[..n]);
            if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                break pos + 4;
            }
        };
        let head = String::from_utf8_lossy(&buf[..head_end]).to_lowercase();
        let body_len: usize = head
            .lines()
            .find_map(|l| l.strip_prefix("content-length:"))
            .map(|v| v.trim().parse().unwrap())
            .unwrap_or(0);
        while buf.len() < head_end + body_len {
            let n = sock.read(&mut chunk).await.unwrap();
            assert_ne!(n, 0, "client closed before sending body");
            buf.extend_from_slice(&chunk[..n]);
        }

        let mut answer = Message::new();
        answer.set_message_type(MessageType::Response);
        answer.add_answer(Record::from_rdata(
            Name::from_ascii("example.org.").unwrap(),
            60,
            RData::A(A::new(192, 0, 2, 1)),
        ));
        let body = answer.to_vec().unwrap();
        let response = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/dns-message\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
            body.len()
        );
        sock.write_all(response.as_bytes()).await.unwrap();
        sock.write_all(&body).await.unwrap();
        sock.shutdown().await.unwrap();
    }

    /// Starts a fake DoH server on 127.0.0.1 and returns its port.
    async fn start_fake_doh() -> u16 {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let (sock, _) = listener.accept().await.unwrap();
                tokio::spawn(serve_fake_doh(sock));
            }
        });
        port
    }

    /// Client for `http://doh.test:{port}` that connects to `ip` instead of resolving the name.
    fn pinned_endpoint(ip: [u8; 4], port: u16) -> DohEndpoint {
        let ip = IpAddr::from(ip);
        let client = reqwest::Client::builder()
            .resolve("doh.test", SocketAddr::new(ip, port))
            .build()
            .unwrap();
        (ip, client)
    }

    #[tokio::test]
    async fn doh_falls_back_to_next_endpoint_on_failure() {
        let port = start_fake_doh().await;
        let url = format!("http://doh.test:{port}/dns-query");
        // Nothing listens on 127.0.0.2, so the first endpoint fails to connect.
        let endpoints = [
            pinned_endpoint([127, 0, 0, 2], port),
            pinned_endpoint([127, 0, 0, 1], port),
        ];
        let ips = doh_lookup_any(&endpoints, &url, "example.org").await.unwrap();
        assert!(!ips.is_empty());
        assert!(ips.iter().all(|ip| *ip == IpAddr::from([192, 0, 2, 1])));
    }

    #[tokio::test]
    async fn doh_errors_when_all_endpoints_fail() {
        let port = start_fake_doh().await;
        let url = format!("http://doh.test:{port}/dns-query");
        let endpoints = [
            pinned_endpoint([127, 0, 0, 2], port),
            pinned_endpoint([127, 0, 0, 3], port),
        ];
        assert!(doh_lookup_any(&endpoints, &url, "example.org").await.is_err());
    }
}

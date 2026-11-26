use hickory_proto::op::{Message, Query};
use hickory_proto::rr::{Name, RecordType};
use hickory_resolver::config::{NameServerConfig, NameServerConfigGroup, Protocol, ResolverConfig};
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::AsyncResolver;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};
use tokio::io;
use tokio::sync::Mutex;
use url::{Host, Url};

type HickoryResolver = AsyncResolver<TokioConnectionProvider>;

/// A DoH server IP together with a client pinned to connect to that IP.
type DohEndpoint = (IpAddr, reqwest::Client);

const DEFAULT_CACHE_TTL: Duration = Duration::from_secs(300);
const DEFAULT_CACHE_CAPACITY: usize = 4096;
const DOH_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DNSServerKind {
    Tcp,
    Udp,
    Tls,
    Https,
}

enum Upstream {
    Hickory(Box<HickoryResolver>),
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

struct CacheEntry {
    ips: Vec<IpAddr>,
    expires_at: Instant,
    last_used: u64,
}

#[derive(Default)]
struct CacheState {
    entries: HashMap<String, CacheEntry>,
    tick: u64,
}

impl CacheState {
    fn get(&mut self, host: &str, now: Instant) -> Option<Vec<IpAddr>> {
        let entry = self.entries.get_mut(host)?;
        if entry.expires_at <= now {
            self.entries.remove(host);
            return None;
        }
        self.tick = self.tick.wrapping_add(1);
        entry.last_used = self.tick;
        Some(entry.ips.clone())
    }

    fn insert(&mut self, host: String, ips: Vec<IpAddr>, expires_at: Instant, now: Instant, capacity: usize) {
        if capacity == 0 {
            return;
        }
        if !self.entries.contains_key(&host) && self.entries.len() >= capacity {
            self.entries.retain(|_, entry| entry.expires_at > now);
            while self.entries.len() >= capacity {
                let oldest = self
                    .entries
                    .iter()
                    .min_by_key(|(_, entry)| entry.last_used)
                    .map(|(key, _)| key.clone());
                let Some(key) = oldest else {
                    break;
                };
                self.entries.remove(&key);
            }
        }
        self.tick = self.tick.wrapping_add(1);
        self.entries.insert(
            host,
            CacheEntry {
                ips,
                expires_at,
                last_used: self.tick,
            },
        );
    }
}

pub struct CachedResolver {
    upstream: Upstream,
    cache: Mutex<CacheState>,
    prefer: IpPreference,
    max_cache_ttl: Duration,
    cache_capacity: usize,
}

impl CachedResolver {
    #[allow(dead_code)]
    pub async fn new(
        dns_server: &str,
        kind: DNSServerKind,
        prefer: IpPreference,
    ) -> io::Result<Self> {
        Self::new_with_options(
            dns_server,
            kind,
            prefer,
            &[],
            DEFAULT_CACHE_TTL,
            DEFAULT_CACHE_CAPACITY,
        )
        .await
    }

    pub async fn new_with_options(
        dns_server: &str,
        kind: DNSServerKind,
        prefer: IpPreference,
        bootstrap_ips: &[IpAddr],
        max_cache_ttl: Duration,
        cache_capacity: usize,
    ) -> io::Result<Self> {
        let upstream = match kind {
            DNSServerKind::Tls => Upstream::Hickory(Box::new(
                create_tls_resolver(dns_server, bootstrap_ips).await?,
            )),
            DNSServerKind::Tcp => Upstream::Hickory(Box::new(
                create_plain_resolver(dns_server, Protocol::Tcp, bootstrap_ips).await?,
            )),
            DNSServerKind::Udp => Upstream::Hickory(Box::new(
                create_plain_resolver(dns_server, Protocol::Udp, bootstrap_ips).await?,
            )),
            DNSServerKind::Https => Upstream::Https {
                endpoints: create_doh_endpoints(dns_server, bootstrap_ips).await?,
                url: dns_server.to_string(),
            },
        };
        Ok(Self {
            upstream,
            cache: Mutex::new(CacheState::default()),
            prefer,
            max_cache_ttl,
            cache_capacity,
        })
    }

    /// Returns every address for `host`, best first, so callers can fall back to the next one.
    pub async fn lookup_ips_for(&self, host: &str) -> io::Result<Vec<IpAddr>> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(vec![ip]);
        }

        let cache_enabled = !self.max_cache_ttl.is_zero() && self.cache_capacity > 0;
        let now = Instant::now();
        if cache_enabled {
            if let Some(ips) = self.cache.lock().await.get(host, now) {
                log::debug!("cache hit for {host}");
                return Ok(ips);
            }
        }
        log::debug!("cache miss for {host}, resolving...");

        let (ips, record_ttl) = match &self.upstream {
            Upstream::Hickory(resolver) => {
                let lookup = resolver.lookup_ip(host).await?;
                let ttl = lookup.valid_until().saturating_duration_since(Instant::now());
                let ips: Vec<IpAddr> = lookup.iter().collect();
                (ips, Some(ttl))
            }
            Upstream::Https { endpoints, url } => doh_lookup_any(endpoints, url, host).await?,
        };

        let ordered = order_ips(&ips, self.prefer);
        if ordered.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "No IP addresses found",
            ));
        }

        if cache_enabled {
            let effective_ttl = record_ttl
                .map(|ttl| ttl.clamp(Duration::from_secs(1), self.max_cache_ttl))
                .unwrap_or(self.max_cache_ttl);
            let now = Instant::now();
            self.cache.lock().await.insert(
                host.to_owned(),
                ordered.clone(),
                now + effective_ttl,
                now,
                self.cache_capacity,
            );
        }

        Ok(ordered)
    }
}

/// Orders `ips` for connecting. IPv4 addresses come first by default, since IPv6 is often
/// unreachable and costs a timeout. With `IpPreference::Ipv6`, IPv6 comes first. Within each
/// family the DNS order is kept, and duplicates are removed.
pub fn order_ips(ips: &[IpAddr], prefer: IpPreference) -> Vec<IpAddr> {
    let (v4, v6): (Vec<IpAddr>, Vec<IpAddr>) = ips.iter().copied().partition(IpAddr::is_ipv4);
    let families = if prefer == IpPreference::Ipv6 {
        [v6, v4]
    } else {
        [v4, v6]
    };
    let mut ordered = Vec::with_capacity(ips.len());
    for ip in families.into_iter().flatten() {
        if !ordered.contains(&ip) {
            ordered.push(ip);
        }
    }
    ordered
}

async fn doh_lookup_record(
    client: &reqwest::Client,
    url: &str,
    name: &Name,
    record_type: RecordType,
) -> io::Result<(Vec<IpAddr>, Option<u32>)> {
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
    let mut ips = Vec::new();
    let mut min_ttl: Option<u32> = None;
    for record in message.answers() {
        if let Some(ip) = record.data().and_then(|data| data.ip_addr()) {
            ips.push(ip);
            let ttl = record.ttl();
            min_ttl = Some(min_ttl.map_or(ttl, |cur| cur.min(ttl)));
        }
    }
    Ok((ips, min_ttl))
}

async fn doh_lookup(
    client: &reqwest::Client,
    url: &str,
    host: &str,
) -> io::Result<(Vec<IpAddr>, Option<Duration>)> {
    let name = Name::from_ascii(host).map_err(io::Error::other)?;
    let (res_a, res_aaaa) = tokio::join!(
        doh_lookup_record(client, url, &name, RecordType::A),
        doh_lookup_record(client, url, &name, RecordType::AAAA),
    );

    let mut ips = Vec::new();
    let mut min_ttl: Option<u32> = None;
    let mut last_err = None;
    let mut any_ok = false;

    for res in [res_a, res_aaaa] {
        match res {
            Ok((found_ips, ttl)) => {
                any_ok = true;
                ips.extend(found_ips);
                if let Some(ttl) = ttl {
                    min_ttl = Some(min_ttl.map_or(ttl, |cur| cur.min(ttl)));
                }
            }
            Err(err) => {
                last_err = Some(err);
            }
        }
    }

    if !any_ok {
        return Err(last_err.unwrap_or_else(|| io::Error::other("DoH lookup failed")));
    }

    Ok((ips, min_ttl.map(|secs| Duration::from_secs(secs as u64))))
}

/// Builds one client per IP of the DoH server, each pinned to connect to that IP.
/// TLS still validates against the server's hostname.
async fn create_doh_endpoints(
    dns_server: &str,
    bootstrap_ips: &[IpAddr],
) -> io::Result<Vec<DohEndpoint>> {
    let invalid = |msg: &str| io::Error::new(io::ErrorKind::InvalidInput, msg.to_string());
    let url = Url::parse(dns_server).map_err(io::Error::other)?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| invalid("DoH URL has no port"))?;
    let (domain, ips) = match url.host() {
        Some(Host::Domain(domain)) => (
            Some(domain),
            resolve_server_ips(domain, port, bootstrap_ips).await?,
        ),
        Some(Host::Ipv4(ip)) => (None, vec![IpAddr::V4(ip)]),
        Some(Host::Ipv6(ip)) => (None, vec![IpAddr::V6(ip)]),
        None => return Err(invalid("DoH URL has no host")),
    };
    ips.into_iter()
        .map(|ip| {
            let mut builder = reqwest::Client::builder().timeout(DOH_REQUEST_TIMEOUT);
            if let Some(domain) = domain {
                builder = builder.resolve(domain, SocketAddr::new(ip, port));
            }
            let client = builder.build().map_err(io::Error::other)?;
            Ok((ip, client))
        })
        .collect()
}

/// Tries each DoH endpoint in order and returns the first successful answer.
async fn doh_lookup_any(
    endpoints: &[DohEndpoint],
    url: &str,
    host: &str,
) -> io::Result<(Vec<IpAddr>, Option<Duration>)> {
    let mut last_err = None;
    for (ip, client) in endpoints {
        match doh_lookup(client, url, host).await {
            Ok((ips, ttl)) if !ips.is_empty() => return Ok((ips, ttl)),
            Ok(_) => {
                last_err = Some(io::Error::new(
                    io::ErrorKind::NotFound,
                    "No IP addresses found",
                ));
            }
            Err(e) => {
                log::warn!("DoH lookup for {host} via {ip} failed, trying next: {e}");
                last_err = Some(e);
            }
        }
    }
    Err(last_err.unwrap_or_else(|| io::Error::new(io::ErrorKind::NotFound, "No DoH endpoints")))
}

/// Resolves the server address, which may be an IP or a hostname, to all of its IPs.
/// When `bootstrap_ips` is provided for a hostname, those IPs are used without querying OS DNS.
async fn resolve_server_ips(
    dns_server: &str,
    port: u16,
    bootstrap_ips: &[IpAddr],
) -> io::Result<Vec<IpAddr>> {
    if let Ok(ip) = dns_server.parse::<IpAddr>() {
        return Ok(vec![ip]);
    }
    if !bootstrap_ips.is_empty() {
        return Ok(bootstrap_ips.to_vec());
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

async fn create_tls_resolver(
    dns_server: &str,
    bootstrap_ips: &[IpAddr],
) -> io::Result<HickoryResolver> {
    const PORT: u16 = 853;
    let ips = resolve_server_ips(dns_server, PORT, bootstrap_ips).await?;
    let servers = NameServerConfigGroup::from_ips_tls(&ips, PORT, dns_server.to_string(), true);
    Ok(AsyncResolver::tokio(
        ResolverConfig::from_parts(None, vec![], servers),
        Default::default(),
    ))
}

/// Plain TCP or UDP resolver on port 53, trying every resolved/bootstrap IP.
async fn create_plain_resolver(
    dns_server: &str,
    protocol: Protocol,
    bootstrap_ips: &[IpAddr],
) -> io::Result<HickoryResolver> {
    const PORT: u16 = 53;
    let ips = resolve_server_ips(dns_server, PORT, bootstrap_ips).await?;
    let mut servers = NameServerConfigGroup::new();
    for ip in ips {
        servers.push(NameServerConfig {
            socket_addr: SocketAddr::new(ip, PORT),
            protocol,
            tls_dns_name: None,
            trust_negative_responses: true,
            bind_addr: None,
        });
    }
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
    fn order_ips_puts_ipv4_first_by_default() {
        let ips = [v6(1), v4(1), v6(2), v4(2)];
        assert_eq!(
            order_ips(&ips, IpPreference::Any),
            vec![v4(1), v4(2), v6(1), v6(2)]
        );
        assert_eq!(
            order_ips(&ips, IpPreference::Ipv4),
            vec![v4(1), v4(2), v6(1), v6(2)]
        );
    }

    #[test]
    fn order_ips_puts_ipv6_first_when_preferred() {
        let ips = [v4(1), v6(1), v4(2), v6(2)];
        assert_eq!(
            order_ips(&ips, IpPreference::Ipv6),
            vec![v6(1), v6(2), v4(1), v4(2)]
        );
    }

    #[test]
    fn order_ips_keeps_dns_order_within_a_family() {
        assert_eq!(
            order_ips(&[v4(2), v4(1)], IpPreference::Any),
            vec![v4(2), v4(1)]
        );
        assert_eq!(
            order_ips(&[v6(2), v6(1)], IpPreference::Any),
            vec![v6(2), v6(1)]
        );
    }

    #[test]
    fn order_ips_removes_duplicates_and_handles_empty() {
        assert!(order_ips(&[], IpPreference::Ipv6).is_empty());
        assert_eq!(
            order_ips(&[v4(1), v4(1), v6(1), v6(1)], IpPreference::Any),
            vec![v4(1), v6(1)]
        );
    }

    #[test]
    fn cache_respects_ttl_and_evicts_lru_on_capacity() {
        let mut cache = CacheState::default();
        let now = Instant::now();
        cache.insert(
            "a.example".into(),
            vec![v4(1)],
            now + Duration::from_secs(60),
            now,
            2,
        );
        cache.insert(
            "b.example".into(),
            vec![v4(2)],
            now + Duration::from_secs(60),
            now,
            2,
        );
        // Touch a.example so b.example becomes LRU.
        assert_eq!(cache.get("a.example", now), Some(vec![v4(1)]));
        cache.insert(
            "c.example".into(),
            vec![v4(3)],
            now + Duration::from_secs(60),
            now,
            2,
        );
        assert!(cache.get("b.example", now).is_none());
        assert_eq!(cache.get("a.example", now), Some(vec![v4(1)]));
        assert_eq!(cache.get("c.example", now), Some(vec![v4(3)]));

        // Expired entries are dropped on lookup.
        let later = now + Duration::from_secs(61);
        assert!(cache.get("a.example", later).is_none());
    }

    #[tokio::test]
    async fn resolve_server_ips_uses_bootstrap_for_hostnames() {
        let bootstrap = [v4(42), v4(43)];
        let resolved = resolve_server_ips("unresolvable.invalid", 443, &bootstrap)
            .await
            .unwrap();
        assert_eq!(resolved, bootstrap);
    }

    /// Reads one HTTP request from `sock` and replies with a DNS answer for 192.0.2.1 (or ::1 for AAAA).
    async fn serve_fake_doh(mut sock: tokio::net::TcpStream) {
        use hickory_proto::op::MessageType;
        use hickory_proto::rr::rdata::{A, AAAA};
        use hickory_proto::rr::{RData, Record};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let mut buf = Vec::new();
        let mut chunk = [0u8; 1024];
        let head_end = loop {
            let n = sock.read(&mut chunk).await.unwrap();
            if n == 0 {
                return;
            }
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
        let req = Message::from_vec(&buf[head_end..head_end + body_len]).unwrap();
        let qtype = req
            .queries()
            .first()
            .map(|q| q.query_type())
            .unwrap_or(RecordType::A);

        let mut answer = Message::new();
        answer.set_message_type(MessageType::Response);
        let rdata = match qtype {
            RecordType::AAAA => RData::AAAA(AAAA::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            _ => RData::A(A::new(192, 0, 2, 1)),
        };
        answer.add_answer(Record::from_rdata(
            Name::from_ascii("example.org.").unwrap(),
            45,
            rdata,
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
            .timeout(DOH_REQUEST_TIMEOUT)
            .resolve("doh.test", SocketAddr::new(ip, port))
            .build()
            .unwrap();
        (ip, client)
    }

    #[tokio::test]
    async fn doh_falls_back_to_next_endpoint_on_failure_and_queries_v4_v6() {
        let port = start_fake_doh().await;
        let url = format!("http://doh.test:{port}/dns-query");
        // Nothing listens on 127.0.0.2, so the first endpoint fails to connect.
        let endpoints = [
            pinned_endpoint([127, 0, 0, 2], port),
            pinned_endpoint([127, 0, 0, 1], port),
        ];
        let (ips, ttl) = doh_lookup_any(&endpoints, &url, "example.org")
            .await
            .unwrap();
        assert!(ips.contains(&IpAddr::from([192, 0, 2, 1])));
        assert!(ips.contains(&v6(1)));
        assert_eq!(ttl, Some(Duration::from_secs(45)));
    }

    #[tokio::test]
    async fn doh_errors_when_all_endpoints_fail() {
        let port = start_fake_doh().await;
        let url = format!("http://doh.test:{port}/dns-query");
        let endpoints = [
            pinned_endpoint([127, 0, 0, 2], port),
            pinned_endpoint([127, 0, 0, 3], port),
        ];
        assert!(doh_lookup_any(&endpoints, &url, "example.org")
            .await
            .is_err());
    }
}

use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::Poll;
use std::time::Duration;

use tokio::io::{self, AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tokio::time::{sleep, timeout};

use crate::bypass::{BypassList, EvadePolicy};
use crate::config::{Credential, TlsSettings};
use crate::dns::CachedResolver;
use crate::http;
use crate::pac;
use crate::socks4;
use crate::socks5;
use crate::spoof::Spoofer;
use crate::tls;

/// How long a single connection attempt may take before failing.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// RFC 8305 Happy Eyeballs stagger delay before starting the next address attempt.
const HAPPY_EYEBALLS_DELAY: Duration = Duration::from_millis(250);

/// Live runtime state shared across connections and atomically swapped on SIGHUP reload.
pub struct RuntimeState {
    pub listen_host: String,
    pub listen_port: u16,
    pub resolver: Arc<CachedResolver>,
    pub tls: TlsSettings,
    pub spoofer: Option<Arc<Spoofer>>,
    pub policy: EvadePolicy,
    pub auth: Vec<Credential>,
    pub pac_path: Option<String>,
    pub pac_proxy: Option<String>,
}

/// Entry point for every client connection on the unified listening port.
/// Auto-detects SOCKS4 (`0x04`), SOCKS5 (`0x05`), vs HTTP/HTTPS proxy requests.
pub async fn handle_connection(stream: TcpStream, state: Arc<RuntimeState>) -> io::Result<()> {
    let mut first = [0u8; 1];
    if stream.peek(&mut first).await? == 0 {
        return Ok(());
    }
    match first[0] {
        0x04 => handle_socks4(stream, &state).await,
        0x05 => handle_socks5(stream, &state).await,
        _ => handle_http(stream, &state).await,
    }
}

async fn handle_socks4(mut stream: TcpStream, state: &RuntimeState) -> io::Result<()> {
    let peer = stream.peer_addr()?;
    let target = socks4::handshake(&mut stream, &state.auth).await?;
    log::debug!(
        "new SOCKS4 connection from {peer:?} to {}:{}",
        target.host,
        target.port
    );

    let (upstream, should_split) = match connect_socks_upstream(state, &target.host, target.port).await {
        Ok(res) => res,
        Err(e) => {
            let _ = socks4::send_reply(&mut stream, socks4::REP_REJECTED, None).await;
            return Err(e);
        }
    };
    socks4::send_reply(&mut stream, socks4::REP_GRANTED, upstream.local_addr().ok()).await?;
    tunnel_socks(stream, upstream, state, should_split).await
}

async fn handle_socks5(mut stream: TcpStream, state: &RuntimeState) -> io::Result<()> {
    let peer = stream.peer_addr()?;
    let target = socks5::handshake(&mut stream, &state.auth).await?;
    log::debug!(
        "new SOCKS5 connection from {peer:?} to {}:{}",
        target.host,
        target.port
    );

    let (upstream, should_split) = match connect_socks_upstream(state, &target.host, target.port).await {
        Ok(res) => res,
        Err(e) => {
            let _ = socks5::send_reply(
                &mut stream,
                socks5::REP_GENERAL_FAILURE,
                SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            )
            .await;
            return Err(e);
        }
    };

    let bound = upstream
        .local_addr()
        .unwrap_or_else(|_| SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0));
    socks5::send_reply(&mut stream, socks5::REP_SUCCEEDED, bound).await?;
    tunnel_socks(stream, upstream, state, should_split).await
}

async fn connect_socks_upstream(
    state: &RuntimeState,
    host: &str,
    port: u16,
) -> io::Result<(TcpStream, bool)> {
    let ips = state.resolver.lookup_ips_for(host).await?;
    let decision = state.policy.decide(host, &ips);
    if let Some(reason) = &decision.reason {
        log::debug!("policy for {host} ({reason}): evade={}", decision.evade);
    }

    let upstream = connect_upstream(
        &decision.ips,
        port,
        state
            .spoofer
            .as_deref()
            .map(|spoofer| move |ip| spoofer.connect(ip, port)),
        !decision.evade,
    )
    .await?;

    let should_split = decision.evade && (state.spoofer.is_none() || state.tls.split_sni);
    if should_split {
        let _ = upstream.set_nodelay(true);
    }
    Ok((upstream, should_split))
}

async fn tunnel_socks(
    stream: TcpStream,
    upstream: TcpStream,
    state: &RuntimeState,
    should_split: bool,
) -> io::Result<()> {
    let (client_reader, client_writer) = stream.into_split();
    let (upstream_reader, upstream_writer) = upstream.into_split();
    tunnel(
        BufReader::new(client_reader),
        client_writer,
        BufReader::new(upstream_reader),
        upstream_writer,
        should_split,
        state.tls.chunk_size,
        state.tls.split_sni,
    )
    .await
}

async fn handle_http(stream: TcpStream, state: &RuntimeState) -> io::Result<()> {
    let addr = stream.peer_addr()?;
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let (req_line, headers) = read_request_head(&mut reader).await?;
    let req = http::parse_http_request_with_headers(&req_line, &headers)?;

    // Serve PAC endpoint on origin-form GET/HEAD requests matching `pac_path`.
    if req.is_origin_form {
        let req_path = req.path_and_query.split('?').next().unwrap_or("");
        if let Some(pac_path) = &state.pac_path {
            if req_path == pac_path && (req.method == "GET" || req.method == "HEAD") {
                let proxy_addr = state
                    .pac_proxy
                    .clone()
                    .or_else(|| http::header_value(&headers, "host").map(str::to_string))
                    .unwrap_or_else(|| format!("{}:{}", state.listen_host, state.listen_port));
                let body = pac::generate_pac(&state.policy, &proxy_addr);
                let resp = format!(
                    "{} 200 OK\r\nContent-Type: application/x-ns-proxy-autoconfig\r\nContent-Length: {}\r\nCache-Control: no-cache\r\nConnection: close\r\n\r\n",
                    req.version,
                    body.len()
                );
                writer.write_all(resp.as_bytes()).await?;
                if req.method == "GET" {
                    writer.write_all(body.as_bytes()).await?;
                }
                writer.shutdown().await?;
                return Ok(());
            }
        }
    }

    if !state.auth.is_empty() && !http::verify_basic_auth(&headers, &state.auth) {
        let resp = format!(
            "{} 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"chunky\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            req.version
        );
        writer.write_all(resp.as_bytes()).await?;
        writer.shutdown().await?;
        return Ok(());
    }

    if req.is_origin_form && req.host.is_empty() {
        let resp = format!(
            "{} 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            req.version
        );
        writer.write_all(resp.as_bytes()).await?;
        writer.shutdown().await?;
        return Ok(());
    }

    log::debug!(
        "new HTTP {} connection from {addr:?} to {}:{}",
        req.method,
        req.host,
        req.port
    );
    let ips = state.resolver.lookup_ips_for(&req.host).await?;
    log::debug!("resolved host: {ips:?}");

    let decision = state.policy.decide(&req.host, &ips);
    if let Some(reason) = &decision.reason {
        log::debug!("policy for {} ({reason}): evade={}", req.host, decision.evade);
    }

    let port = req.port;
    let upstream = connect_upstream(
        &decision.ips,
        port,
        state
            .spoofer
            .as_deref()
            .map(|spoofer| move |ip| spoofer.connect(ip, port)),
        !decision.evade,
    )
    .await?;

    let should_split =
        req.is_https && decision.evade && (state.spoofer.is_none() || state.tls.split_sni);
    if should_split {
        let _ = upstream.set_nodelay(true);
    }

    let (upstream_reader, mut upstream_writer) = upstream.into_split();
    let upstream_reader = BufReader::new(upstream_reader);

    if req.is_https {
        writer
            .write_all(format!("{} 200 OK\r\n\r\n", req.version).as_bytes())
            .await?;
    } else {
        let forwarded_head = http::format_upstream_request_head(&req, &headers);
        upstream_writer.write_all(forwarded_head.as_bytes()).await?;
    }

    tunnel(
        reader,
        writer,
        upstream_reader,
        upstream_writer,
        should_split,
        state.tls.chunk_size,
        state.tls.split_sni,
    )
    .await
}

/// Legacy test-friendly entrypoint for HTTP/HTTPS proxy handling.
#[allow(dead_code)]
pub async fn proxy(
    stream: TcpStream,
    resolver: &CachedResolver,
    chunk_size: usize,
    spoofer: Option<&Spoofer>,
    bypass: &BypassList,
) -> io::Result<()> {
    let addr = stream.peer_addr()?;
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let (req_line, headers) = read_request_head(&mut reader).await?;
    let req = http::parse_http_request_with_headers(&req_line, &headers)?;

    log::debug!("new connection from {addr:?} to {}:{}", req.host, req.port);
    let ips = resolver.lookup_ips_for(&req.host).await?;
    let bypassed = bypass.check(&req.host, &ips);
    let ips = match &bypassed {
        Some(found) => found.ips.clone(),
        None => ips,
    };

    let port = req.port;
    let upstream = connect_upstream(
        &ips,
        port,
        spoofer.map(|s| move |ip| s.connect(ip, port)),
        bypassed.is_some(),
    )
    .await?;
    let (upstream_reader, mut upstream_writer) = upstream.into_split();
    let upstream_reader = BufReader::new(upstream_reader);

    if req.is_https {
        writer
            .write_all(format!("{} 200 OK\r\n\r\n", req.version).as_bytes())
            .await?;
    } else {
        let forwarded_head = http::format_upstream_request_head(&req, &headers);
        upstream_writer.write_all(forwarded_head.as_bytes()).await?;
    }

    tunnel(
        reader,
        writer,
        upstream_reader,
        upstream_writer,
        req.is_https && spoofer.is_none() && bypassed.is_none(),
        chunk_size,
        false,
    )
    .await
}

async fn tunnel(
    client_reader: BufReader<OwnedReadHalf>,
    client_writer: OwnedWriteHalf,
    upstream_reader: BufReader<OwnedReadHalf>,
    upstream_writer: OwnedWriteHalf,
    needs_tls_split: bool,
    chunk_size: usize,
    split_sni: bool,
) -> io::Result<()> {
    let client_to_server = tokio::spawn(forward(
        client_reader,
        upstream_writer,
        needs_tls_split,
        "client",
        chunk_size,
        split_sni,
    ));
    let server_to_client = tokio::spawn(forward(
        upstream_reader,
        client_writer,
        false,
        "server",
        chunk_size,
        false,
    ));
    let (r1, r2) = tokio::join!(client_to_server, server_to_client);
    r1??;
    r2??;
    Ok(())
}

/// Connects using `spoof` when given, unless evasion is skipped (`plain_connect`).
async fn connect_upstream<F, Fut>(
    ips: &[IpAddr],
    port: u16,
    spoof: Option<F>,
    plain_connect: bool,
) -> io::Result<TcpStream>
where
    F: Fn(IpAddr) -> Fut,
    Fut: Future<Output = io::Result<TcpStream>> + Send,
{
    match spoof {
        Some(spoof) if !plain_connect => connect_any_with(ips, CONNECT_TIMEOUT, spoof).await,
        _ => connect_any(ips, port).await,
    }
}

async fn connect_any(ips: &[IpAddr], port: u16) -> io::Result<TcpStream> {
    connect_any_with(ips, CONNECT_TIMEOUT, move |ip| TcpStream::connect((ip, port))).await
}

/// Interleaves IPv4 and IPv6 addresses (RFC 8305 style) while keeping the first address first.
fn interleave_addresses(ips: &[IpAddr]) -> Vec<IpAddr> {
    if ips.len() <= 2 {
        return ips.to_vec();
    }
    let first_is_v4 = ips[0].is_ipv4();
    let (primary, secondary): (Vec<IpAddr>, Vec<IpAddr>) =
        ips.iter().copied().partition(|ip| ip.is_ipv4() == first_is_v4);
    let mut out = Vec::with_capacity(ips.len());
    let max_len = primary.len().max(secondary.len());
    for i in 0..max_len {
        if let Some(&ip) = primary.get(i) {
            out.push(ip);
        }
        if let Some(&ip) = secondary.get(i) {
            out.push(ip);
        }
    }
    out
}

/// Happy Eyeballs (RFC 8305) connection racing: starts attempts staggered by
/// `min(250ms, limit / 2)`, advancing immediately if an attempt fails early.
async fn connect_any_with<F, Fut>(
    ips: &[IpAddr],
    limit: Duration,
    connect: F,
) -> io::Result<TcpStream>
where
    F: Fn(IpAddr) -> Fut,
    Fut: Future<Output = io::Result<TcpStream>> + Send,
{
    let ordered = interleave_addresses(ips);
    if ordered.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "No addresses to connect to",
        ));
    }

    let stagger = HAPPY_EYEBALLS_DELAY.min((limit / 2).max(Duration::from_millis(1)));
    let mut active = Vec::new();
    let mut next_idx = 0usize;
    let mut last_err = None;

    loop {
        if next_idx < ordered.len() && active.is_empty() {
            let ip = ordered[next_idx];
            next_idx += 1;
            active.push(Box::pin(timeout(limit, connect(ip))));
        }

        if next_idx < ordered.len() {
            tokio::select! {
                res = poll_any_timed(&mut active) => {
                    match res {
                        Some(Ok(Ok(stream))) => return Ok(stream),
                        Some(Ok(Err(e))) => {
                            log::debug!("connect attempt failed, trying next: {e}");
                            last_err = Some(e);
                        }
                        Some(Err(_)) => {
                            log::debug!("connect attempt timed out after {limit:?}, trying next");
                            last_err = Some(io::Error::new(io::ErrorKind::TimedOut, "connect timed out"));
                        }
                        None => {}
                    }
                }
                _ = sleep(stagger) => {
                    let ip = ordered[next_idx];
                    next_idx += 1;
                    active.push(Box::pin(timeout(limit, connect(ip))));
                }
            }
        } else {
            match poll_any_timed(&mut active).await {
                Some(Ok(Ok(stream))) => return Ok(stream),
                Some(Ok(Err(e))) => {
                    log::debug!("connect attempt failed: {e}");
                    last_err = Some(e);
                }
                Some(Err(_)) => {
                    log::debug!("connect attempt timed out after {limit:?}");
                    last_err = Some(io::Error::new(io::ErrorKind::TimedOut, "connect timed out"));
                }
                None => break,
            }
        }
    }

    Err(last_err
        .unwrap_or_else(|| io::Error::new(io::ErrorKind::NotFound, "No addresses to connect to")))
}

async fn poll_any_timed<Fut>(
    futs: &mut Vec<Pin<Box<tokio::time::Timeout<Fut>>>>,
) -> Option<Result<io::Result<TcpStream>, tokio::time::error::Elapsed>>
where
    Fut: Future<Output = io::Result<TcpStream>> + Send,
{
    std::future::poll_fn(|cx| {
        for idx in 0..futs.len() {
            if let Poll::Ready(res) = futs[idx].as_mut().poll(cx) {
                drop(futs.swap_remove(idx));
                return Poll::Ready(Some(res));
            }
        }
        if futs.is_empty() {
            Poll::Ready(None)
        } else {
            Poll::Pending
        }
    })
    .await
}

/// Reads the request line and the header block, up to the blank line that ends them.
async fn read_request_head<R: AsyncBufRead + Unpin>(
    reader: &mut R,
) -> io::Result<(String, String)> {
    let mut req_line = String::new();
    let mut headers = String::new();
    while req_line.is_empty() {
        if reader.read_line(&mut req_line).await? == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Connection closed before a request was received",
            ));
        }
        while reader.read_line(&mut headers).await? > 2 {}
    }
    Ok((req_line, headers))
}

/// Copies bytes from `reader` to `writer` until EOF.
///
/// When `needs_tls_split` is set, inspects the first write; if it starts with a TLS Handshake
/// record (`0x16 0x03 <4`), splits the record (at SNI/ECH boundaries when `split_sni` is set,
/// and/or into `chunk_size` records) and sends each record separately. Non-TLS traffic (such as
/// SSH or plain protocols over SOCKS5) is forwarded immediately without blocking for extra bytes.
async fn forward(
    mut reader: BufReader<OwnedReadHalf>,
    mut writer: OwnedWriteHalf,
    needs_tls_split: bool,
    name: &str,
    chunk_size: usize,
    split_sni: bool,
) -> io::Result<()> {
    let mut buf = [0u8; 4096];

    if needs_tls_split {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            writer.shutdown().await?;
            log::debug!("Connection closed by {name}");
            return Ok(());
        }
        if buf[0] == 0x16 {
            let mut initial = buf[..n].to_vec();
            while initial.len() < 5 {
                let m = reader.read(&mut buf).await?;
                if m == 0 {
                    writer.write_all(&initial).await?;
                    writer.shutdown().await?;
                    return Ok(());
                }
                initial.extend_from_slice(&buf[..m]);
            }
            let header: [u8; 3] = [initial[0], initial[1], initial[2]];
            if tls::is_tls_handshake(&header) {
                let record_len = u16::from_be_bytes([initial[3], initial[4]]) as usize;
                let total_len = 5 + record_len;
                while initial.len() < total_len {
                    let m = reader.read(&mut buf).await?;
                    if m == 0 {
                        writer.write_all(&initial).await?;
                        writer.shutdown().await?;
                        return Ok(());
                    }
                    initial.extend_from_slice(&buf[..m]);
                }
                let payload = &initial[5..total_len];
                let records = tls::split_tls_record(&header, payload, chunk_size, split_sni);
                log::debug!(
                    "Split TLS ClientHello ({} bytes) into {} records (split_sni={split_sni})",
                    payload.len(),
                    records.len()
                );
                for record in records {
                    writer.write_all(&record).await?;
                    writer.flush().await?;
                }
                if initial.len() > total_len {
                    writer.write_all(&initial[total_len..]).await?;
                }
            } else {
                writer.write_all(&initial).await?;
            }
        } else {
            writer.write_all(&buf[..n]).await?;
        }
    }

    loop {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            writer.shutdown().await?;
            log::debug!("Connection closed by {name}");
            return Ok(());
        }
        writer.write_all(&buf[..n]).await?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD as BASE64;
    use base64::Engine as _;
    use crate::bypass::BypassList;
    use crate::dns::{DNSServerKind, IpPreference};

    fn test_state(
        resolver: Arc<CachedResolver>,
        policy: EvadePolicy,
        auth: Vec<Credential>,
        pac_path: Option<String>,
        chunk_size: usize,
        split_sni: bool,
    ) -> Arc<RuntimeState> {
        Arc::new(RuntimeState {
            listen_host: "127.0.0.1".to_string(),
            listen_port: 8000,
            resolver,
            tls: TlsSettings {
                chunk_size,
                split_sni,
                fake_sni: None,
                fake_ttl: None,
                fake_bad_checksum: false,
            },
            spoofer: None,
            policy,
            auth,
            pac_path,
            pac_proxy: None,
        })
    }

    #[tokio::test]
    async fn connect_any_falls_back_to_next_address() {
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let ips = [IpAddr::from([127, 0, 0, 2]), IpAddr::from([127, 0, 0, 1])];
        let stream = connect_any(&ips, port).await.unwrap();
        assert_eq!(
            stream.peer_addr().unwrap().ip(),
            IpAddr::from([127, 0, 0, 1])
        );
    }

    #[tokio::test]
    async fn connect_any_moves_on_after_timeout_via_happy_eyeballs() {
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let stalled = IpAddr::from([127, 0, 0, 2]);
        let ips = [stalled, IpAddr::from([127, 0, 0, 1])];
        let stream = connect_any_with(&ips, Duration::from_millis(50), move |ip| async move {
            if ip == stalled {
                std::future::pending().await
            } else {
                TcpStream::connect((ip, port)).await
            }
        })
        .await
        .unwrap();
        assert_eq!(
            stream.peer_addr().unwrap().ip(),
            IpAddr::from([127, 0, 0, 1])
        );
    }

    #[tokio::test]
    async fn connect_any_errors_when_no_address_works() {
        let ips = [IpAddr::from([127, 0, 0, 2]), IpAddr::from([127, 0, 0, 3])];
        assert!(connect_any(&ips, 1).await.is_err());
        assert!(connect_any(&[], 1).await.is_err());
    }

    #[tokio::test]
    async fn read_request_head_errors_on_eof_before_request() {
        let mut reader = BufReader::new(&b""[..]);
        let err = read_request_head(&mut reader).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[tokio::test]
    async fn read_request_head_returns_line_and_headers() {
        let mut reader = BufReader::new(&b"GET http://a/ HTTP/1.1\r\nHost: a\r\n\r\nbody"[..]);
        let (req_line, headers) = read_request_head(&mut reader).await.unwrap();
        assert_eq!(req_line, "GET http://a/ HTTP/1.1\r\n");
        assert_eq!(headers, "Host: a\r\n\r\n");
    }

    #[test]
    fn chunks_payload_into_records() {
        let header = [0x16, 0x03, 0x01];
        let payload = [1u8, 2, 3, 4, 5];
        let out: Vec<u8> = tls::split_tls_record(&header, &payload, 2, false)
            .into_iter()
            .flatten()
            .collect();
        assert_eq!(
            out,
            [
                0x16, 0x03, 0x01, 0x00, 0x02, 1, 2, //
                0x16, 0x03, 0x01, 0x00, 0x02, 3, 4, //
                0x16, 0x03, 0x01, 0x00, 0x01, 5,
            ]
        );
    }

    const CHUNK_SIZE: usize = 4;
    const CLIENT_RECORD: [u8; 15] = [0x16, 0x03, 0x01, 0x00, 0x0a, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
    const PING: &[u8] = b"ping";
    const SERVER_REPLY: [u8; 10] = [0x16, 0x03, 0x03, 0x00, 0x05, b'h', b'e', b'l', b'l', b'o'];

    /// Runs `proxy` for a CONNECT to a local fake upstream and returns the bytes it received.
    async fn run_proxy_roundtrip(bypass: BypassList, expected_upstream: Vec<u8>) {
        use tokio::net::{TcpListener, TcpStream};

        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_port = upstream_listener.local_addr().unwrap().port();
        let upstream_len = expected_upstream.len();
        let upstream = tokio::spawn(async move {
            let (mut sock, _) = upstream_listener.accept().await.unwrap();
            let mut received = vec![0u8; upstream_len];
            sock.read_exact(&mut received).await.unwrap();
            sock.write_all(&SERVER_REPLY).await.unwrap();
            sock.shutdown().await.unwrap();
            received
        });

        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();
        let resolver = CachedResolver::new("127.0.0.1", DNSServerKind::Tcp, IpPreference::Any)
            .await
            .unwrap();
        let proxy_task = tokio::spawn(async move {
            let (stream, _) = proxy_listener.accept().await.unwrap();
            super::proxy(stream, &resolver, CHUNK_SIZE, None, &bypass).await
        });

        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        let connect = format!("CONNECT 127.0.0.1:{upstream_port} HTTP/1.1\r\n\r\n");
        client.write_all(connect.as_bytes()).await.unwrap();
        let mut established = [0u8; 19];
        client.read_exact(&mut established).await.unwrap();
        assert_eq!(&established, b"HTTP/1.1 200 OK\r\n\r\n");

        client.write_all(&CLIENT_RECORD).await.unwrap();
        client.write_all(PING).await.unwrap();

        let mut reply = [0u8; 10];
        timeout(Duration::from_secs(5), client.read_exact(&mut reply))
            .await
            .expect("timed out waiting for server reply")
            .unwrap();
        assert_eq!(reply, SERVER_REPLY);

        let received = timeout(Duration::from_secs(5), upstream)
            .await
            .expect("timed out waiting for upstream")
            .unwrap();
        assert_eq!(received, expected_upstream);

        client.shutdown().await.unwrap();
        timeout(Duration::from_secs(5), proxy_task)
            .await
            .expect("proxy did not finish")
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn proxy_chunks_client_hello_only() {
        let mut expected_upstream = vec![
            0x16, 0x03, 0x01, 0x00, 0x04, 1, 2, 3, 4, //
            0x16, 0x03, 0x01, 0x00, 0x04, 5, 6, 7, 8, //
            0x16, 0x03, 0x01, 0x00, 0x02, 9, 10,
        ];
        expected_upstream.extend_from_slice(PING);
        run_proxy_roundtrip(BypassList::default(), expected_upstream).await;
    }

    #[tokio::test]
    async fn bypassed_destinations_skip_the_spoofed_connect() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let ips = [IpAddr::from([127, 0, 0, 1])];

        let calls = Arc::new(AtomicUsize::new(0));
        let calls_true = calls.clone();
        let spoofed = move |_ip| {
            calls_true.fetch_add(1, Ordering::SeqCst);
            async { Err(io::Error::other("spoofed connect used")) }
        };
        assert!(connect_upstream(&ips, port, Some(spoofed), true)
            .await
            .is_ok());
        assert_eq!(calls.load(Ordering::SeqCst), 0);

        let calls_false = calls.clone();
        let spoofed = move |_ip| {
            calls_false.fetch_add(1, Ordering::SeqCst);
            async { Err(io::Error::other("spoofed connect used")) }
        };
        assert!(connect_upstream(&ips, port, Some(spoofed), false)
            .await
            .is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn proxy_does_not_chunk_bypassed_host() {
        let mut bypass = BypassList::default();
        bypass.add_ip("127.0.0.1").unwrap();

        let mut expected_upstream = CLIENT_RECORD.to_vec();
        expected_upstream.extend_from_slice(PING);
        run_proxy_roundtrip(bypass, expected_upstream).await;
    }

    #[tokio::test]
    async fn unified_port_serves_socks5_with_auth_and_chunks_tls() {
        use tokio::net::TcpListener;

        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_port = upstream_listener.local_addr().unwrap().port();
        let mut expected = vec![
            0x16, 0x03, 0x01, 0x00, 0x04, 1, 2, 3, 4, //
            0x16, 0x03, 0x01, 0x00, 0x04, 5, 6, 7, 8, //
            0x16, 0x03, 0x01, 0x00, 0x02, 9, 10,
        ];
        expected.extend_from_slice(PING);
        let expected_len = expected.len();

        let upstream = tokio::spawn(async move {
            let (mut sock, _) = upstream_listener.accept().await.unwrap();
            let mut got = vec![0u8; expected_len];
            sock.read_exact(&mut got).await.unwrap();
            sock.write_all(&SERVER_REPLY).await.unwrap();
            sock.shutdown().await.unwrap();
            got
        });

        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();
        let resolver = Arc::new(
            CachedResolver::new("127.0.0.1", DNSServerKind::Tcp, IpPreference::Any)
                .await
                .unwrap(),
        );
        let state = test_state(
            resolver,
            EvadePolicy::default(),
            vec![Credential::parse("u1:p1").unwrap()],
            None,
            4,
            false,
        );

        let proxy_task = tokio::spawn(async move {
            let (stream, _) = proxy_listener.accept().await.unwrap();
            handle_connection(stream, state).await
        });

        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        // Greeting offering no-auth (0x00) and userpass (0x02).
        client.write_all(&[0x05, 0x02, 0x00, 0x02]).await.unwrap();
        let mut method_resp = [0u8; 2];
        client.read_exact(&mut method_resp).await.unwrap();
        assert_eq!(method_resp, [0x05, 0x02]);

        // RFC 1929 auth
        client.write_all(&[0x01, 2, b'u', b'1', 2, b'p', b'1']).await.unwrap();
        let mut auth_resp = [0u8; 2];
        client.read_exact(&mut auth_resp).await.unwrap();
        assert_eq!(auth_resp, [0x01, 0x00]);

        // CONNECT 127.0.0.1:upstream_port
        let mut req = vec![0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1];
        req.extend_from_slice(&upstream_port.to_be_bytes());
        client.write_all(&req).await.unwrap();
        let mut rep = [0u8; 10];
        client.read_exact(&mut rep).await.unwrap();
        assert_eq!(&rep[..2], &[0x05, 0x00]);

        client.write_all(&CLIENT_RECORD).await.unwrap();
        client.write_all(PING).await.unwrap();
        client.shutdown().await.unwrap();

        let mut reply = [0u8; 10];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, SERVER_REPLY);
        assert_eq!(upstream.await.unwrap(), expected);
        proxy_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn unified_port_requires_http_basic_auth_and_serves_pac() {
        use tokio::net::TcpListener;

        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();
        let resolver = Arc::new(
            CachedResolver::new("127.0.0.1", DNSServerKind::Tcp, IpPreference::Any)
                .await
                .unwrap(),
        );
        let state = test_state(
            resolver,
            EvadePolicy::default(),
            vec![Credential::parse("user:pass").unwrap()],
            Some("/proxy.pac".to_string()),
            500,
            false,
        );

        let state_pac = state.clone();
        let srv = tokio::spawn(async move {
            for _ in 0..2 {
                let (stream, _) = proxy_listener.accept().await.unwrap();
                let st = state_pac.clone();
                tokio::spawn(async move {
                    let _ = handle_connection(stream, st).await;
                });
            }
        });

        // 1. PAC endpoint works without auth
        let mut pac_client = TcpStream::connect(proxy_addr).await.unwrap();
        pac_client
            .write_all(b"GET /proxy.pac HTTP/1.1\r\nHost: 127.0.0.1:8000\r\n\r\n")
            .await
            .unwrap();
        let mut pac_resp = String::new();
        pac_client.read_to_string(&mut pac_resp).await.unwrap();
        assert!(pac_resp.starts_with("HTTP/1.1 200 OK"));
        assert!(pac_resp.contains("FindProxyForURL"));
        assert!(pac_resp.contains("PROXY 127.0.0.1:8000; DIRECT"));

        // 2. Unauthenticated CONNECT returns 407
        let mut unauth_client = TcpStream::connect(proxy_addr).await.unwrap();
        unauth_client
            .write_all(b"CONNECT example.com:443 HTTP/1.1\r\n\r\n")
            .await
            .unwrap();
        let mut unauth_resp = String::new();
        unauth_client.read_to_string(&mut unauth_resp).await.unwrap();
        assert!(unauth_resp.starts_with("HTTP/1.1 407 Proxy Authentication Required"));
        assert!(unauth_resp.contains("Proxy-Authenticate: Basic"));

        srv.await.unwrap();
    }

    #[tokio::test]
    async fn http_post_forwards_body_and_strips_proxy_auth() {
        use tokio::net::TcpListener;

        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_port = upstream_listener.local_addr().unwrap().port();
        let upstream = tokio::spawn(async move {
            let (mut sock, _) = upstream_listener.accept().await.unwrap();
            let mut got = String::new();
            sock.read_to_string(&mut got).await.unwrap();
            sock.write_all(b"HTTP/1.1 201 Created\r\nContent-Length: 2\r\n\r\nok")
                .await
                .unwrap();
            sock.shutdown().await.unwrap();
            got
        });

        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();
        let resolver = Arc::new(
            CachedResolver::new("127.0.0.1", DNSServerKind::Tcp, IpPreference::Any)
                .await
                .unwrap(),
        );
        let state = test_state(
            resolver,
            EvadePolicy::default(),
            vec![Credential::parse("alice:secret").unwrap()],
            None,
            500,
            false,
        );
        let proxy_task = tokio::spawn(async move {
            let (stream, _) = proxy_listener.accept().await.unwrap();
            handle_connection(stream, state).await
        });

        let token = BASE64.encode("alice:secret");
        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        let req = format!(
            "POST http://127.0.0.1:{upstream_port}/items HTTP/1.1\r\nHost: 127.0.0.1:{upstream_port}\r\nProxy-Authorization: Basic {token}\r\nContent-Length: 4\r\n\r\nbody"
        );
        client.write_all(req.as_bytes()).await.unwrap();
        client.shutdown().await.unwrap();

        let mut resp = String::new();
        client.read_to_string(&mut resp).await.unwrap();
        assert!(resp.contains("201 Created"));
        assert!(resp.ends_with("ok"));

        let got = upstream.await.unwrap();
        assert!(got.starts_with("POST /items HTTP/1.1\r\n"));
        assert!(!got.contains("Proxy-Authorization"));
        assert!(got.ends_with("\r\n\r\nbody"));
        proxy_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn allowlist_mode_evades_only_matching_targets() {
        use tokio::net::TcpListener;

        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_port = upstream_listener.local_addr().unwrap().port();
        let expected_len = CLIENT_RECORD.len() + PING.len();
        let upstream = tokio::spawn(async move {
            let (mut sock, _) = upstream_listener.accept().await.unwrap();
            let mut got = vec![0u8; expected_len];
            sock.read_exact(&mut got).await.unwrap();
            sock.write_all(&SERVER_REPLY).await.unwrap();
            sock.shutdown().await.unwrap();
            got
        });

        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();
        let resolver = Arc::new(
            CachedResolver::new("127.0.0.1", DNSServerKind::Tcp, IpPreference::Any)
                .await
                .unwrap(),
        );
        // Allowlist only matches 10.0.0.0/8, so 127.0.0.1 is NOT chunked.
        let mut evade = BypassList::default();
        evade.add_ip("10.0.0.0/8").unwrap();
        let policy = EvadePolicy::new(crate::bypass::RuleMode::Evade, BypassList::default(), evade);
        let state = test_state(resolver, policy, Vec::new(), None, 4, false);

        let proxy_task = tokio::spawn(async move {
            let (stream, _) = proxy_listener.accept().await.unwrap();
            handle_connection(stream, state).await
        });

        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        client
            .write_all(format!("CONNECT 127.0.0.1:{upstream_port} HTTP/1.1\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let mut ok_buf = [0u8; 19];
        client.read_exact(&mut ok_buf).await.unwrap();
        client.write_all(&CLIENT_RECORD).await.unwrap();
        client.write_all(PING).await.unwrap();
        client.shutdown().await.unwrap();

        let mut reply = [0u8; 10];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, SERVER_REPLY);

        let mut expected = CLIENT_RECORD.to_vec();
        expected.extend_from_slice(PING);
        assert_eq!(upstream.await.unwrap(), expected);
        proxy_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn unified_port_serves_socks4_and_socks4a_and_rejects_with_auth() {
        use tokio::net::TcpListener;

        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_port = upstream_listener.local_addr().unwrap().port();
        let mut expected = vec![
            0x16, 0x03, 0x01, 0x00, 0x04, 1, 2, 3, 4, //
            0x16, 0x03, 0x01, 0x00, 0x04, 5, 6, 7, 8, //
            0x16, 0x03, 0x01, 0x00, 0x02, 9, 10,
        ];
        expected.extend_from_slice(PING);
        let expected_len = expected.len();

        let upstream = tokio::spawn(async move {
            let (mut sock, _) = upstream_listener.accept().await.unwrap();
            let mut got = vec![0u8; expected_len];
            sock.read_exact(&mut got).await.unwrap();
            sock.write_all(&SERVER_REPLY).await.unwrap();
            sock.shutdown().await.unwrap();
            got
        });

        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();
        let resolver = Arc::new(
            CachedResolver::new("127.0.0.1", DNSServerKind::Tcp, IpPreference::Any)
                .await
                .unwrap(),
        );
        let state_open = test_state(
            resolver.clone(),
            EvadePolicy::default(),
            Vec::new(),
            None,
            4,
            false,
        );
        let state_authed = test_state(
            resolver,
            EvadePolicy::default(),
            vec![Credential::parse("u:p").unwrap()],
            None,
            4,
            false,
        );

        let srv = tokio::spawn(async move {
            let (s1, _) = proxy_listener.accept().await.unwrap();
            handle_connection(s1, state_open).await.unwrap();
            let (s2, _) = proxy_listener.accept().await.unwrap();
            let err = handle_connection(s2, state_authed).await.unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        });

        // 1. SOCKS4a CONNECT to 127.0.0.1 (via 0.0.0.1 + "127.0.0.1\0")
        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        let mut req = vec![0x04, 0x01];
        req.extend_from_slice(&upstream_port.to_be_bytes());
        req.extend_from_slice(&[0, 0, 0, 1]);
        req.extend_from_slice(b"user\0");
        req.extend_from_slice(b"127.0.0.1\0");
        client.write_all(&req).await.unwrap();

        let mut rep = [0u8; 8];
        client.read_exact(&mut rep).await.unwrap();
        assert_eq!(&rep[..2], &[0x00, socks4::REP_GRANTED]);

        client.write_all(&CLIENT_RECORD).await.unwrap();
        client.write_all(PING).await.unwrap();
        client.shutdown().await.unwrap();

        let mut reply = [0u8; 10];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, SERVER_REPLY);
        assert_eq!(upstream.await.unwrap(), expected);

        // 2. SOCKS4 rejected when auth is enabled
        let mut c2 = TcpStream::connect(proxy_addr).await.unwrap();
        let mut req2 = vec![0x04, 0x01];
        req2.extend_from_slice(&upstream_port.to_be_bytes());
        req2.extend_from_slice(&[127, 0, 0, 1]);
        req2.extend_from_slice(b"\0");
        c2.write_all(&req2).await.unwrap();
        let mut rep2 = [0u8; 8];
        c2.read_exact(&mut rep2).await.unwrap();
        assert_eq!(&rep2[..2], &[0x00, socks4::REP_REJECTED]);

        srv.await.unwrap();
    }
}

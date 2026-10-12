use std::future::Future;
use std::net::IpAddr;
use std::time::Duration;

use tokio::io::{self, AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tokio::{select, time::timeout};

use crate::dns::CachedResolver;
use crate::http;
use crate::spoof::Spoofer;

pub async fn proxy(
    stream: TcpStream,
    resolver: &CachedResolver,
    chunk_size: usize,
    spoofer: Option<&Spoofer>,
) -> io::Result<()> {
    let addr = stream.peer_addr()?;
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let (req_line, headers) = read_request_head(&mut reader).await?;

    let http::HttpRequest {
        version,
        host,
        port,
        is_https,
    } = http::parse_http_request(&req_line)?;

    log::debug!("new connection from {addr:?} to {host}:{port}");
    let ips = resolver.lookup_ips(host).await?;
    log::debug!("resolved host: {ips:?}");

    let upstream = match spoofer {
        Some(spoofer) => connect_any_with(&ips, CONNECT_TIMEOUT, |ip| spoofer.connect(ip, port)).await?,
        None => connect_any(&ips, port).await?,
    };
    let (upstream_reader, mut upstream_writer) = upstream.into_split();
    let upstream_reader = BufReader::new(upstream_reader);

    if is_https {
        writer
            .write_all(format!("{version} 200 OK\r\n\r\n").as_bytes())
            .await?;
    } else {
        upstream_writer.write_all(req_line.as_bytes()).await?;
        upstream_writer.write_all(headers.as_bytes()).await?;
    }

    // Only the client's TLS ClientHello is split; the server's replies are forwarded as-is.
    // With SNI spoofing on, the ClientHello is sent whole.
    let client_to_server = tokio::spawn(forward(
        reader,
        upstream_writer,
        is_https && spoofer.is_none(),
        "client",
        chunk_size,
    ));
    let server_to_client = tokio::spawn(forward(
        upstream_reader,
        writer,
        false,
        "server",
        chunk_size,
    ));
    select! {
        r = client_to_server => r??,
        r = server_to_client => r??,
    }

    Ok(())
}

/// How long a single connection attempt may take before the next address is tried.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Connects to the first address in `ips` that accepts the connection within `CONNECT_TIMEOUT`.
/// Returns the last connection error if none do.
async fn connect_any(ips: &[IpAddr], port: u16) -> io::Result<TcpStream> {
    connect_any_with(ips, CONNECT_TIMEOUT, |ip| TcpStream::connect((ip, port))).await
}

async fn connect_any_with<F, Fut>(
    ips: &[IpAddr],
    limit: Duration,
    connect: F,
) -> io::Result<TcpStream>
where
    F: Fn(IpAddr) -> Fut,
    Fut: Future<Output = io::Result<TcpStream>>,
{
    let mut last_err = None;
    for ip in ips {
        match timeout(limit, connect(*ip)).await {
            Ok(Ok(stream)) => return Ok(stream),
            Ok(Err(e)) => {
                log::debug!("connect to {ip} failed, trying next: {e}");
                last_err = Some(e);
            }
            Err(_) => {
                log::debug!("connect to {ip} timed out after {limit:?}, trying next");
                last_err = Some(io::Error::new(io::ErrorKind::TimedOut, "connect timed out"));
            }
        }
    }
    Err(last_err.unwrap_or_else(|| {
        io::Error::new(io::ErrorKind::NotFound, "No addresses to connect to")
    }))
}

/// Reads the request line and the header block, up to the blank line that ends them.
///
/// Returns `UnexpectedEof` if the client closes the connection before sending a request line.
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
/// If `needs_chunking` is set, the first TLS handshake record is split into smaller records
/// before forwarding. Everything after that is copied as-is.
async fn forward(
    mut reader: BufReader<OwnedReadHalf>,
    mut writer: OwnedWriteHalf,
    needs_chunking: bool,
    name: &str,
    chunk_size: usize,
) -> io::Result<()> {
    if needs_chunking {
        // Read the first 3 bytes to check if it's a TLS handshake
        let mut header = [0u8; 3];
        reader.read_exact(&mut header).await?;
        if is_tls_handshake(&header) {
            log::debug!("Found TLS handshake");
            let length = reader.read_u16().await?;
            let mut payload = vec![0; length as usize];
            reader.read_exact(&mut payload).await?;
            writer
                .write_all(&chunk_tls_record(&header, &payload, chunk_size))
                .await?;
        } else {
            log::debug!("Found the first non-handshake packet, forwarding as-is");
            writer.write_all(&header).await?;
        }
    }

    let mut buf = [0u8; 4096];
    let mut first = true;
    loop {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            writer.shutdown().await?;
            log::debug!("Connection closed by {name}");
            return Ok(());
        }
        if first {
            log::debug!("first {n} bytes from {name}: {:02x?}", &buf[..n.min(32)]);
            first = false;
        }
        writer.write_all(&buf[..n]).await?;
    }
}

/// TLS record header: content type 0x16 (handshake), major version 3, minor version < 4.
fn is_tls_handshake(header: &[u8; 3]) -> bool {
    header[0] == 0x16 && header[1] == 0x03 && header[2] < 4
}

/// Splits `payload` into TLS records of at most `chunk_size` bytes, each reusing `header`.
fn chunk_tls_record(header: &[u8], payload: &[u8], chunk_size: usize) -> Vec<u8> {
    let chunk_count = payload.len().div_ceil(chunk_size);
    let mut message = Vec::with_capacity(chunk_count * (header.len() + 2) + payload.len());
    for chunk in payload.chunks(chunk_size) {
        message.extend_from_slice(header);
        // Last chunk might be smaller than chunk_size
        message.extend_from_slice(&(chunk.len() as u16).to_be_bytes());
        message.extend_from_slice(chunk);
    }
    message
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_tls_handshake_header() {
        assert!(is_tls_handshake(&[0x16, 0x03, 0x01]));
        assert!(is_tls_handshake(&[0x16, 0x03, 0x03]));
        assert!(!is_tls_handshake(&[0x17, 0x03, 0x03]));
        assert!(!is_tls_handshake(&[0x16, 0x03, 0x04]));
        assert!(!is_tls_handshake(&[0x16, 0x02, 0x01]));
    }

    #[tokio::test]
    async fn connect_any_falls_back_to_next_address() {
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        // Nothing listens on 127.0.0.2, so the first address is refused.
        let ips = [IpAddr::from([127, 0, 0, 2]), IpAddr::from([127, 0, 0, 1])];
        let stream = connect_any(&ips, port).await.unwrap();
        assert_eq!(stream.peer_addr().unwrap().ip(), IpAddr::from([127, 0, 0, 1]));
    }

    #[tokio::test]
    async fn connect_any_moves_on_after_timeout() {
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let stalled = IpAddr::from([127, 0, 0, 2]);
        let ips = [stalled, IpAddr::from([127, 0, 0, 1])];
        // The first attempt never completes, so only the timeout can move on to the second.
        let stream = connect_any_with(&ips, Duration::from_millis(50), |ip| async move {
            if ip == stalled {
                std::future::pending().await
            } else {
                TcpStream::connect((ip, port)).await
            }
        })
        .await
        .unwrap();
        assert_eq!(stream.peer_addr().unwrap().ip(), IpAddr::from([127, 0, 0, 1]));
    }

    #[tokio::test]
    async fn connect_any_errors_when_no_address_works() {
        let ips = [IpAddr::from([127, 0, 0, 2]), IpAddr::from([127, 0, 0, 3])];
        // Port 1 is almost never open on loopback, so every attempt is refused.
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
        let out = chunk_tls_record(&header, &payload, 2);
        assert_eq!(
            out,
            [
                0x16, 0x03, 0x01, 0x00, 0x02, 1, 2, //
                0x16, 0x03, 0x01, 0x00, 0x02, 3, 4, //
                0x16, 0x03, 0x01, 0x00, 0x01, 5,
            ]
        );
    }

    /// Runs `proxy` for a CONNECT to a local fake upstream and checks the bytes on the wire.
    #[tokio::test]
    async fn proxy_chunks_client_hello_only() {
        use crate::dns::{CachedResolver, DNSServerKind, IpPreference};
        use tokio::net::{TcpListener, TcpStream};
        use tokio::time::{timeout, Duration};

        const CHUNK_SIZE: usize = 4;
        let client_record = [0x16, 0x03, 0x01, 0x00, 0x0a, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let ping = b"ping";
        let server_reply = [0x16, 0x03, 0x03, 0x00, 0x05, b'h', b'e', b'l', b'l', b'o'];
        // The 10-byte record is split into 4+4+2 records, each with the original 3-byte header.
        // Everything after the record is forwarded unchanged.
        let mut expected_upstream = vec![
            0x16, 0x03, 0x01, 0x00, 0x04, 1, 2, 3, 4, //
            0x16, 0x03, 0x01, 0x00, 0x04, 5, 6, 7, 8, //
            0x16, 0x03, 0x01, 0x00, 0x02, 9, 10,
        ];
        expected_upstream.extend_from_slice(ping);

        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_port = upstream_listener.local_addr().unwrap().port();
        let upstream_len = expected_upstream.len();
        let upstream = tokio::spawn(async move {
            let (mut sock, _) = upstream_listener.accept().await.unwrap();
            let mut received = vec![0u8; upstream_len];
            sock.read_exact(&mut received).await.unwrap();
            sock.write_all(&server_reply).await.unwrap();
            received
        });

        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();
        let resolver = CachedResolver::new("127.0.0.1", DNSServerKind::Tcp, IpPreference::Any)
            .await
            .unwrap();
        let proxy_task = tokio::spawn(async move {
            let (stream, _) = proxy_listener.accept().await.unwrap();
            super::proxy(stream, &resolver, CHUNK_SIZE, None).await
        });

        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        let connect = format!("CONNECT 127.0.0.1:{upstream_port} HTTP/1.1\r\n\r\n");
        client.write_all(connect.as_bytes()).await.unwrap();
        let mut established = [0u8; 19];
        client.read_exact(&mut established).await.unwrap();
        assert_eq!(&established, b"HTTP/1.1 200 OK\r\n\r\n");

        client.write_all(&client_record).await.unwrap();
        client.write_all(ping).await.unwrap();

        let mut reply = [0u8; 10];
        timeout(Duration::from_secs(5), client.read_exact(&mut reply))
            .await
            .expect("timed out waiting for server reply")
            .unwrap();
        assert_eq!(reply, server_reply);

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
}

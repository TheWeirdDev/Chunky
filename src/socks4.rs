use std::net::{Ipv4Addr, SocketAddr};

use tokio::io::{self, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::config::Credential;

const SOCKS4_VERSION: u8 = 0x04;
const CMD_CONNECT: u8 = 0x01;
const MAX_CSTRING_LEN: usize = 512;

pub const REP_GRANTED: u8 = 90;
pub const REP_REJECTED: u8 = 91;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Socks4Target {
    pub host: String,
    pub port: u16,
}

/// Parses a SOCKS4 / SOCKS4a CONNECT request.
///
/// SOCKS4 has no password authentication, so requests are rejected when `--auth` is configured.
pub async fn handshake(stream: &mut TcpStream, auth: &[Credential]) -> io::Result<Socks4Target> {
    let mut header = [0u8; 8];
    stream.read_exact(&mut header).await?;
    if header[0] != SOCKS4_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "not a SOCKS4 request",
        ));
    }

    let cmd = header[1];
    let port = u16::from_be_bytes([header[2], header[3]]);
    let ip_bytes = [header[4], header[5], header[6], header[7]];
    let _userid = read_cstring(stream).await?;

    let is_socks4a = ip_bytes[0] == 0 && ip_bytes[1] == 0 && ip_bytes[2] == 0 && ip_bytes[3] != 0;
    let host = if is_socks4a {
        let domain = read_cstring(stream).await?;
        if domain.is_empty() {
            let _ = send_reply(stream, REP_REJECTED, None).await;
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "empty SOCKS4a hostname",
            ));
        }
        domain
    } else {
        Ipv4Addr::from(ip_bytes).to_string()
    };

    if !auth.is_empty() {
        let _ = send_reply(stream, REP_REJECTED, None).await;
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "SOCKS4 rejected: proxy authentication requires SOCKS5 or HTTP Basic",
        ));
    }

    if cmd != CMD_CONNECT {
        let _ = send_reply(stream, REP_REJECTED, None).await;
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!("unsupported SOCKS4 command: {cmd}"),
        ));
    }

    Ok(Socks4Target { host, port })
}

async fn read_cstring(stream: &mut TcpStream) -> io::Result<String> {
    let mut bytes = Vec::new();
    loop {
        let byte = stream.read_u8().await?;
        if byte == 0 {
            break;
        }
        if bytes.len() >= MAX_CSTRING_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "SOCKS4 string exceeds maximum length",
            ));
        }
        bytes.push(byte);
    }
    String::from_utf8(bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid SOCKS4 UTF-8"))
}

pub async fn send_reply(
    stream: &mut TcpStream,
    rep: u8,
    bound: Option<SocketAddr>,
) -> io::Result<()> {
    let (port, ip) = match bound {
        Some(SocketAddr::V4(v4)) => (v4.port(), v4.ip().octets()),
        _ => (0, [0, 0, 0, 0]),
    };
    let port_bytes = port.to_be_bytes();
    let reply = [
        0x00,
        rep,
        port_bytes[0],
        port_bytes[1],
        ip[0],
        ip[1],
        ip[2],
        ip[3],
    ];
    stream.write_all(&reply).await
}

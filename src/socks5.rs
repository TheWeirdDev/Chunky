use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use tokio::io::{self, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::config::Credential;

const SOCKS5_VERSION: u8 = 0x05;
const AUTH_NONE: u8 = 0x00;
const AUTH_USERPASS: u8 = 0x02;
const AUTH_NO_ACCEPTABLE: u8 = 0xff;
const USERPASS_VERSION: u8 = 0x01;

const CMD_CONNECT: u8 = 0x01;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

pub const REP_SUCCEEDED: u8 = 0x00;
pub const REP_GENERAL_FAILURE: u8 = 0x01;
pub const REP_COMMAND_NOT_SUPPORTED: u8 = 0x07;
pub const REP_ADDRESS_TYPE_NOT_SUPPORTED: u8 = 0x08;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Socks5Target {
    pub host: String,
    pub port: u16,
}

/// Performs the SOCKS5 greeting, optional RFC 1929 username/password auth, and parses CONNECT target.
pub async fn handshake(stream: &mut TcpStream, auth: &[Credential]) -> io::Result<Socks5Target> {
    let mut header = [0u8; 2];
    stream.read_exact(&mut header).await?;
    if header[0] != SOCKS5_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "not a SOCKS5 greeting",
        ));
    }
    let nmethods = header[1] as usize;
    let mut methods = vec![0u8; nmethods];
    stream.read_exact(&mut methods).await?;

    if auth.is_empty() {
        if !methods.contains(&AUTH_NONE) {
            let _ = stream.write_all(&[SOCKS5_VERSION, AUTH_NO_ACCEPTABLE]).await;
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "SOCKS5 client did not offer no-auth method",
            ));
        }
        stream.write_all(&[SOCKS5_VERSION, AUTH_NONE]).await?;
    } else {
        if !methods.contains(&AUTH_USERPASS) {
            let _ = stream.write_all(&[SOCKS5_VERSION, AUTH_NO_ACCEPTABLE]).await;
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "SOCKS5 client did not offer username/password auth",
            ));
        }
        stream.write_all(&[SOCKS5_VERSION, AUTH_USERPASS]).await?;
        verify_userpass(stream, auth).await?;
    }

    let mut req = [0u8; 4];
    stream.read_exact(&mut req).await?;
    if req[0] != SOCKS5_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid SOCKS5 request version",
        ));
    }
    if req[1] != CMD_CONNECT {
        let _ = send_reply(
            stream,
            REP_COMMAND_NOT_SUPPORTED,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        )
        .await;
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!("unsupported SOCKS5 command: {}", req[1]),
        ));
    }

    let host = match req[3] {
        ATYP_IPV4 => {
            let mut octets = [0u8; 4];
            stream.read_exact(&mut octets).await?;
            Ipv4Addr::from(octets).to_string()
        }
        ATYP_DOMAIN => {
            let len = stream.read_u8().await? as usize;
            let mut domain = vec![0u8; len];
            stream.read_exact(&mut domain).await?;
            String::from_utf8(domain)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid domain UTF-8"))?
        }
        ATYP_IPV6 => {
            let mut octets = [0u8; 16];
            stream.read_exact(&mut octets).await?;
            Ipv6Addr::from(octets).to_string()
        }
        other => {
            let _ = send_reply(
                stream,
                REP_ADDRESS_TYPE_NOT_SUPPORTED,
                SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            )
            .await;
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported SOCKS5 address type: {other}"),
            ));
        }
    };

    let port = stream.read_u16().await?;
    Ok(Socks5Target { host, port })
}

async fn verify_userpass(stream: &mut TcpStream, auth: &[Credential]) -> io::Result<()> {
    let ver = stream.read_u8().await?;
    if ver != USERPASS_VERSION {
        let _ = stream.write_all(&[USERPASS_VERSION, 0x01]).await;
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid SOCKS5 auth subnegotiation version",
        ));
    }
    let ulen = stream.read_u8().await? as usize;
    let mut uname = vec![0u8; ulen];
    stream.read_exact(&mut uname).await?;
    let plen = stream.read_u8().await? as usize;
    let mut passwd = vec![0u8; plen];
    stream.read_exact(&mut passwd).await?;

    let ok = match (std::str::from_utf8(&uname), std::str::from_utf8(&passwd)) {
        (Ok(u), Ok(p)) => auth.iter().any(|c| c.username == u && c.password == p),
        _ => false,
    };
    if ok {
        stream.write_all(&[USERPASS_VERSION, 0x00]).await?;
        Ok(())
    } else {
        let _ = stream.write_all(&[USERPASS_VERSION, 0x01]).await;
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "SOCKS5 authentication failed",
        ))
    }
}

pub async fn send_reply(stream: &mut TcpStream, rep: u8, bound: SocketAddr) -> io::Result<()> {
    let mut buf = Vec::with_capacity(22);
    buf.push(SOCKS5_VERSION);
    buf.push(rep);
    buf.push(0x00);
    match bound.ip() {
        IpAddr::V4(v4) => {
            buf.push(ATYP_IPV4);
            buf.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            buf.push(ATYP_IPV6);
            buf.extend_from_slice(&v6.octets());
        }
    }
    buf.extend_from_slice(&bound.port().to_be_bytes());
    stream.write_all(&buf).await
}

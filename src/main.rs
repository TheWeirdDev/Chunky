mod args;
mod dns;
mod handler;
mod http;

use std::sync::Arc;

use clap::Parser;
use tokio::io;
use tokio::net::TcpListener;

use crate::args::Args;
use crate::dns::{CachedResolver, DNSServerKind, IpPreference};

#[tokio::main]
async fn main() -> io::Result<()> {
    let Args {
        host,
        port,
        chunk_size,
        dot_server,
        dns_tcp_server,
        dns_udp_server,
        dns_https_server,
        prefer_ipv6,
        prefer_ipv4,
        verbose,
    } = Args::parse();

    let prefer = match (prefer_ipv6, prefer_ipv4) {
        (true, _) => IpPreference::Ipv6,
        (_, true) => IpPreference::Ipv4,
        _ => IpPreference::Any,
    };

    let env = env_logger::Env::default()
        .filter_or("CHUNKY_LOG_LEVEL", if verbose { "debug" } else { "info" });
    env_logger::init_from_env(env);

    let listener = TcpListener::bind((host.as_str(), port)).await?;
    log::info!("Listening on {host}:{port}");

    let (dns_server, dns_server_kind) = match (dns_tcp_server, dns_udp_server, dns_https_server) {
        (Some(server), _, _) => (server, DNSServerKind::Tcp),
        (None, Some(server), _) => (server, DNSServerKind::Udp),
        (None, None, Some(server)) => (server, DNSServerKind::Https),
        _ => (dot_server, DNSServerKind::Tls),
    };

    let resolver = Arc::new(
        CachedResolver::new(&dns_server, dns_server_kind, prefer).await?,
    );
    log::info!("DNS resolver configured. using: {dns_server}");
    log::info!("Chunk size is: {chunk_size}");

    loop {
        let (client, _) = listener.accept().await?;
        let resolver = resolver.clone();
        tokio::spawn(async move {
            if let Err(e) = handler::proxy(client, &resolver, chunk_size).await {
                log::error!("Error: {e}");
            }
        });
    }
}

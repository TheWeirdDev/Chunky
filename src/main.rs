mod args;
mod dns;
mod handler;
mod http;
mod spoof;

use std::sync::Arc;

use clap::Parser;
use tokio::io;
use tokio::net::TcpListener;

use crate::args::Args;
use crate::dns::{CachedResolver, DNSServerKind, IpPreference};
use crate::spoof::Spoofer;

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
        fake_sni,
        verbose,
    } = Args::parse();

    let prefer = match (prefer_ipv6, prefer_ipv4) {
        (true, _) => IpPreference::Ipv6,
        (_, true) => IpPreference::Ipv4,
        _ => IpPreference::Any,
    };

    if fake_sni.is_some() && !spoof::has_cap_net_raw() {
        let binary = std::env::current_exe()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|_| "<chunky>".to_string());
        eprintln!(
            "--fake-sni needs CAP_NET_RAW, which this process does not have.\n\
             Grant it once with: sudo setcap cap_net_raw+ep {binary}\n\
             Then run chunky again. Without --fake-sni, no extra permissions are needed."
        );
        std::process::exit(1);
    }

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
    let spoofer = match fake_sni {
        Some(sni) => {
            let spoofer = Spoofer::start(&sni).map_err(|e| {
                io::Error::new(
                    e.kind(),
                    format!("SNI spoofing could not start: {e}. It needs CAP_NET_RAW, e.g. `sudo setcap cap_net_raw+ep <binary>`"),
                )
            })?;
            log::info!("Chunking is disabled while SNI spoofing is on");
            Some(Arc::new(spoofer))
        }
        None => {
            log::info!("Chunk size is: {chunk_size}");
            None
        }
    };

    loop {
        let (client, _) = listener.accept().await?;
        let resolver = resolver.clone();
        let spoofer = spoofer.clone();
        tokio::spawn(async move {
            if let Err(e) = handler::proxy(client, &resolver, chunk_size, spoofer.as_deref()).await {
                log::error!("Error: {e}");
            }
        });
    }
}

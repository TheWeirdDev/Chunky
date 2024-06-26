mod args;
mod dns;
mod handler;
mod http;

use std::sync::Arc;

use crate::args::Args;

use clap::Parser;
use dns::{CachedResolver, DNSServerKind};
use tokio::io;
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> io::Result<()> {
    let args = Args::parse();
    let Args {
        host,
        port,
        chunk_size,
        dot_server,
        dns_tcp_server,
        // doh_server,
        verbose,
    } = args;

    let env = env_logger::Env::default()
        .filter_or("CHUNKY_LOG_LEVEL", if verbose { "debug" } else { "info" });
    env_logger::init_from_env(env);
    log::trace!("test");

    let listener = TcpListener::bind((host.clone(), port)).await?;
    log::info!("Listening on {host}:{port}");

    let dot_server = dot_server.unwrap();
    let (dns_server, dns_server_kind) = if dns_tcp_server.is_some() {
        (dns_tcp_server.unwrap(), DNSServerKind::TCP)
    } else {
        (dot_server, DNSServerKind::TLS)
    };

    let resolver = Arc::new(CachedResolver::new(dns_server.as_str(), dns_server_kind).await?);
    log::info!("DNS resolver configured. using: {dns_server}");
    log::info!("Chunk size is: {chunk_size}");

    loop {
        let (client, _) = listener.accept().await?;
        let resolver = resolver.clone();
        tokio::spawn(async move {
            match handler::proxy(client, &resolver, chunk_size).await {
                Ok(_) => {}
                Err(e) => log::error!("Error: {e}"),
            }
        });
    }
}

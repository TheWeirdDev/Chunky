mod args;
mod bypass;
mod config;
mod dns;
mod handler;
mod http;
mod limits;
mod pac;
mod socks4;
mod socks5;
#[cfg(any(target_os = "linux", target_os = "android"))]
mod spoof;
mod tls;

/// SNI spoofing needs AF_PACKET sockets, which only Linux and Android have. Elsewhere `--fake-sni`
/// is accepted but fails at startup.
#[cfg(not(any(target_os = "linux", target_os = "android")))]
mod spoof {
    use std::io;
    use std::net::IpAddr;

    use tokio::net::TcpStream;

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct SpoofOptions {
        pub fake_sni: String,
        pub fake_ttl: Option<u8>,
        pub fake_bad_checksum: bool,
    }

    fn unsupported() -> io::Error {
        io::Error::new(
            io::ErrorKind::Unsupported,
            format!(
                "--fake-sni is only supported on Linux and Android, not on {}",
                std::env::consts::OS
            ),
        )
    }

    pub fn has_cap_net_raw() -> bool {
        true
    }

    pub struct Spoofer;

    impl Spoofer {
        pub fn start(_options: SpoofOptions) -> io::Result<Self> {
            Err(unsupported())
        }

        pub async fn connect(&self, _remote: IpAddr, _port: u16) -> io::Result<TcpStream> {
            Err(unsupported())
        }
    }
}

use std::sync::Arc;

use clap::Parser;
use tokio::io;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::args::Args;
use crate::bypass::RuleMode;
use crate::config::ResolvedConfig;
use crate::dns::CachedResolver;
use crate::handler::RuntimeState;
use crate::spoof::{SpoofOptions, Spoofer};

#[derive(Clone, PartialEq, Eq)]
struct ActiveSpoof {
    fake_sni: String,
    fake_ttl: Option<u8>,
    fake_bad_checksum: bool,
}

async fn build_runtime_state(
    cfg: ResolvedConfig,
    prev_spoof: Option<&(ActiveSpoof, Arc<Spoofer>)>,
) -> io::Result<(Arc<RuntimeState>, Option<(ActiveSpoof, Arc<Spoofer>)>)> {
    let resolver = Arc::new(
        CachedResolver::new_with_options(
            &cfg.dns.server,
            cfg.dns.kind,
            cfg.dns.prefer,
            &cfg.dns.bootstrap,
            cfg.dns.cache_ttl,
            cfg.dns.cache_capacity,
        )
        .await?,
    );
    log::info!(
        "DNS resolver configured: {} (bootstrap={:?}, cache_ttl={:?}, capacity={})",
        cfg.dns.server,
        cfg.dns.bootstrap,
        cfg.dns.cache_ttl,
        cfg.dns.cache_capacity
    );

    let next_spoof = match &cfg.tls.fake_sni {
        Some(sni) => {
            let wanted = ActiveSpoof {
                fake_sni: sni.clone(),
                fake_ttl: cfg.tls.fake_ttl,
                fake_bad_checksum: cfg.tls.fake_bad_checksum,
            };
            if let Some((prev_key, prev_spoofer)) = prev_spoof {
                if prev_key == &wanted {
                    Some((wanted, prev_spoofer.clone()))
                } else {
                    let spoofer = start_spoofer(&wanted)?;
                    Some((wanted, Arc::new(spoofer)))
                }
            } else {
                let spoofer = start_spoofer(&wanted)?;
                Some((wanted, Arc::new(spoofer)))
            }
        }
        None => {
            log::info!(
                "TLS splitting: chunk_size={}, split_sni={}",
                cfg.tls.chunk_size,
                cfg.tls.split_sni
            );
            None
        }
    };

    if !cfg.policy.is_empty() {
        match cfg.policy.mode() {
            RuleMode::Bypass => {
                log::info!("Rule mode: bypass (matched destinations skip DPI evasion)");
            }
            RuleMode::Evade => {
                log::info!("Rule mode: evade allowlist (only matched destinations use DPI evasion)");
            }
        }
    }
    if !cfg.auth.is_empty() {
        log::info!("Proxy authentication enabled ({} credential(s))", cfg.auth.len());
    }
    if let Some(pac) = &cfg.pac_path {
        log::info!("PAC endpoint enabled at {pac}");
    }

    let spoofer = next_spoof.as_ref().map(|(_, s)| s.clone());
    let state = Arc::new(RuntimeState {
        listen_host: cfg.host,
        listen_port: cfg.port,
        resolver,
        tls: cfg.tls,
        limits: cfg.limits,
        spoofer,
        policy: cfg.policy,
        auth: cfg.auth,
        pac_path: cfg.pac_path,
        pac_proxy: cfg.pac_proxy,
    });
    Ok((state, next_spoof))
}

fn start_spoofer(opts: &ActiveSpoof) -> io::Result<Spoofer> {
    let spoofer = Spoofer::start(SpoofOptions {
        fake_sni: opts.fake_sni.clone(),
        fake_ttl: opts.fake_ttl,
        fake_bad_checksum: opts.fake_bad_checksum,
    })
    .map_err(|e| io::Error::new(e.kind(), format!("SNI spoofing could not start: {e}")))?;
    log::info!(
        "SNI spoofing enabled (fake_sni={}, fake_ttl={:?}, fake_bad_checksum={})",
        opts.fake_sni,
        opts.fake_ttl,
        opts.fake_bad_checksum
    );
    Ok(spoofer)
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let args = Args::parse();
    let cfg = ResolvedConfig::load(&args)?;

    if cfg.tls.fake_sni.is_some() && !spoof::has_cap_net_raw() {
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

    let env = env_logger::Env::default().filter_or(
        "CHUNKY_LOG_LEVEL",
        if cfg.verbose { "debug" } else { "info" },
    );
    env_logger::init_from_env(env);

    let nofile_limit = limits::raise_nofile_limit();
    let max_connections = cfg.limits.effective_max_connections(nofile_limit);
    match (max_connections, nofile_limit) {
        (Some(max), Some(nofile)) => {
            log::info!("Connection limit: {max} (open file limit {nofile})");
        }
        (Some(max), None) => log::info!("Connection limit: {max}"),
        (None, Some(nofile)) => {
            log::warn!("Connection limit disabled (open file limit {nofile})");
        }
        (None, None) => log::info!("Connection limit disabled"),
    }
    let limiter = Arc::new(Semaphore::new(
        max_connections.map_or(Semaphore::MAX_PERMITS, |n| n.min(Semaphore::MAX_PERMITS)),
    ));

    let listener = TcpListener::bind((cfg.host.as_str(), cfg.port)).await?;
    log::info!("Listening on {}:{} (HTTP/HTTPS + SOCKS4/5)", cfg.host, cfg.port);

    let (mut state, mut active_spoof) = build_runtime_state(cfg, None).await?;

    #[cfg(unix)]
    let mut sighup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())?;

    loop {
        #[cfg(unix)]
        tokio::select! {
            accepted = accept_connection(&listener, &limiter) => {
                let (client, permit) = accepted?;
                spawn_connection(client, permit, state.clone());
            }
            Some(()) = sighup.recv() => {
                log::info!("Received SIGHUP, reloading configuration and rules...");
                match ResolvedConfig::load(&args) {
                    Ok(new_cfg) => {
                        match build_runtime_state(new_cfg, active_spoof.as_ref()).await {
                            Ok((new_state, new_spoof)) => {
                                state = new_state;
                                active_spoof = new_spoof;
                                log::info!("Reloaded configuration successfully");
                            }
                            Err(e) => {
                                log::error!("Failed to apply reloaded configuration, keeping existing state: {e}");
                            }
                        }
                    }
                    Err(e) => {
                        log::error!("Failed to load configuration on SIGHUP, keeping existing state: {e}");
                    }
                }
            }
        }

        #[cfg(not(unix))]
        {
            let (client, permit) = accept_connection(&listener, &limiter).await?;
            spawn_connection(client, permit, state.clone());
        }
    }
}

/// Waits for a free connection slot, then accepts a client. Transient `accept()` failures (such
/// as `EMFILE`) are retried with backoff rather than ending the proxy. Cancel-safe.
async fn accept_connection(
    listener: &TcpListener,
    limiter: &Arc<Semaphore>,
) -> io::Result<(TcpStream, OwnedSemaphorePermit)> {
    if limiter.available_permits() == 0 {
        log::debug!("Connection limit reached; waiting for a slot");
    }
    let permit = limiter
        .clone()
        .acquire_owned()
        .await
        .map_err(|e| io::Error::other(format!("connection limiter closed: {e}")))?;
    let (client, _) = limits::accept_with_retry(
        || listener.accept(),
        limits::ACCEPT_BACKOFF_INITIAL,
        limits::ACCEPT_BACKOFF_MAX,
    )
    .await?;
    Ok((client, permit))
}

/// Serves one client; the connection slot is released when the task ends.
fn spawn_connection(client: TcpStream, permit: OwnedSemaphorePermit, state: Arc<RuntimeState>) {
    tokio::spawn(async move {
        let _permit = permit;
        if let Err(e) = handler::handle_connection(client, state).await {
            log::error!("Error: {e}");
        }
    });
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[tokio::test]
    async fn connection_limit_applies_backpressure_until_a_slot_frees() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let limiter = Arc::new(Semaphore::new(1));

        let _c1 = TcpStream::connect(addr).await.unwrap();
        let (_s1, permit1) = accept_connection(&listener, &limiter).await.unwrap();
        assert_eq!(limiter.available_permits(), 0);

        let _c2 = TcpStream::connect(addr).await.unwrap();
        let blocked =
            tokio::time::timeout(Duration::from_millis(100), accept_connection(&listener, &limiter))
                .await;
        assert!(blocked.is_err(), "second accept must wait for a free slot");

        drop(permit1);
        let (_s2, _permit2) =
            tokio::time::timeout(Duration::from_secs(5), accept_connection(&listener, &limiter))
                .await
                .expect("accept should proceed once a slot is free")
                .unwrap();
    }

    #[tokio::test]
    async fn spawned_connection_releases_its_slot_when_done() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let limiter = Arc::new(Semaphore::new(1));
        let resolver = Arc::new(
            CachedResolver::new(
                "127.0.0.1",
                crate::dns::DNSServerKind::Tcp,
                crate::dns::IpPreference::Any,
            )
            .await
            .unwrap(),
        );
        let args = <Args as Parser>::parse_from(["chunky"]);
        let cfg = ResolvedConfig::load(&args).unwrap();
        let state = Arc::new(RuntimeState {
            listen_host: cfg.host,
            listen_port: cfg.port,
            resolver,
            tls: cfg.tls,
            limits: cfg.limits,
            spoofer: None,
            policy: cfg.policy,
            auth: cfg.auth,
            pac_path: cfg.pac_path,
            pac_proxy: cfg.pac_proxy,
        });

        let client = TcpStream::connect(addr).await.unwrap();
        let (server_side, permit) = accept_connection(&listener, &limiter).await.unwrap();
        spawn_connection(server_side, permit, state);
        assert_eq!(limiter.available_permits(), 0);

        // The client hangs up without sending anything: the handler ends and frees the slot.
        drop(client);
        let _slot = tokio::time::timeout(Duration::from_secs(5), limiter.acquire())
            .await
            .expect("slot was never released")
            .unwrap();
    }
}

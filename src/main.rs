mod args;
mod bypass;
mod config;
mod dns;
mod handler;
mod http;
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
use tokio::net::TcpListener;

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

    let listener = TcpListener::bind((cfg.host.as_str(), cfg.port)).await?;
    log::info!("Listening on {}:{} (HTTP/HTTPS + SOCKS4/5)", cfg.host, cfg.port);

    let (mut state, mut active_spoof) = build_runtime_state(cfg, None).await?;

    #[cfg(unix)]
    let mut sighup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())?;

    loop {
        #[cfg(unix)]
        tokio::select! {
            accepted = listener.accept() => {
                let (client, _) = accepted?;
                let conn_state = state.clone();
                tokio::spawn(async move {
                    if let Err(e) = handler::handle_connection(client, conn_state).await {
                        log::error!("Error: {e}");
                    }
                });
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
            let (client, _) = listener.accept().await?;
            let conn_state = state.clone();
            tokio::spawn(async move {
                if let Err(e) = handler::handle_connection(client, conn_state).await {
                    log::error!("Error: {e}");
                }
            });
        }
    }
}

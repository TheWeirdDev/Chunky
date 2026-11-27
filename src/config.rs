use std::io;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;

use crate::args::{Args, RuleModeArg};
use crate::bypass::{BypassList, EvadePolicy, RuleMode};
use crate::dns::{DNSServerKind, IpPreference};
use crate::limits::{
    ConnectionLimits, DEFAULT_HANDSHAKE_TIMEOUT_SECS, DEFAULT_IDLE_TIMEOUT_SECS,
};

pub const DEFAULT_HOST: &str = "127.0.0.1";
pub const DEFAULT_PORT: u16 = 8000;
pub const DEFAULT_DOT_SERVER: &str = "1.1.1.1";
pub const DEFAULT_CHUNK_SIZE: usize = 500;
pub const DEFAULT_DNS_CACHE_TTL_SECS: u64 = 300;
pub const DEFAULT_DNS_CACHE_CAPACITY: usize = 4096;
pub const DEFAULT_PAC_PATH: &str = "/proxy.pac";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Credential {
    pub username: String,
    pub password: String,
}

impl Credential {
    pub fn parse(raw: &str) -> io::Result<Self> {
        let Some((user, pass)) = raw.split_once(':') else {
            return Err(invalid_input(format!(
                "invalid credential {raw:?}: expected USER:PASS"
            )));
        };
        if user.is_empty() {
            return Err(invalid_input("proxy auth username must not be empty"));
        }
        Ok(Self {
            username: user.to_string(),
            password: pass.to_string(),
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TomlConfig {
    pub host: Option<String>,
    pub port: Option<u16>,
    pub verbose: Option<bool>,
    pub auth: Option<OneOrMany<String>>,
    pub pac_path: Option<String>,
    pub no_pac: Option<bool>,
    pub pac_proxy: Option<String>,
    pub tls: TomlTlsConfig,
    pub limits: TomlLimitsConfig,
    pub dns: TomlDnsConfig,
    pub rules: TomlRulesConfig,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TomlTlsConfig {
    pub chunk_size: Option<usize>,
    pub split_sni: Option<bool>,
    pub fake_sni: Option<String>,
    pub fake_ttl: Option<u8>,
    pub fake_bad_checksum: Option<bool>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TomlLimitsConfig {
    pub max_connections: Option<usize>,
    pub idle_timeout: Option<u64>,
    pub handshake_timeout: Option<u64>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TomlDnsConfig {
    pub mode: Option<String>,
    pub server: Option<String>,
    pub bootstrap: Vec<String>,
    pub prefer: Option<String>,
    pub cache_ttl: Option<u64>,
    pub cache_capacity: Option<usize>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TomlRulesConfig {
    pub mode: Option<String>,
    pub bypass_private: Option<bool>,
    pub bypass_ip: Vec<String>,
    pub bypass_domain: Vec<String>,
    pub bypass_tld: Vec<String>,
    pub bypass_geoip: Vec<String>,
    pub bypass_file: Vec<PathBuf>,
    pub geoip_db: Option<PathBuf>,
    pub evade_ip: Vec<String>,
    pub evade_domain: Vec<String>,
    pub evade_tld: Vec<String>,
    pub evade_geoip: Vec<String>,
    pub evade_file: Vec<PathBuf>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(untagged)]
pub enum OneOrMany<T> {
    One(T),
    Many(Vec<T>),
}

impl<T> OneOrMany<T> {
    pub fn into_vec(self) -> Vec<T> {
        match self {
            Self::One(v) => vec![v],
            Self::Many(v) => v,
        }
    }
}

#[derive(Clone, Debug)]
pub struct TlsSettings {
    pub chunk_size: usize,
    pub split_sni: bool,
    pub fake_sni: Option<String>,
    pub fake_ttl: Option<u8>,
    pub fake_bad_checksum: bool,
}

#[derive(Clone, Debug)]
pub struct DnsSettings {
    pub server: String,
    pub kind: DNSServerKind,
    pub bootstrap: Vec<IpAddr>,
    pub prefer: IpPreference,
    pub cache_ttl: Duration,
    pub cache_capacity: usize,
}

pub struct ResolvedConfig {
    pub host: String,
    pub port: u16,
    pub verbose: bool,
    pub tls: TlsSettings,
    pub limits: ConnectionLimits,
    pub dns: DnsSettings,
    pub policy: EvadePolicy,
    pub auth: Vec<Credential>,
    pub pac_path: Option<String>,
    pub pac_proxy: Option<String>,
}

impl ResolvedConfig {
    pub fn load(args: &Args) -> io::Result<Self> {
        let toml = match &args.config {
            Some(path) => load_toml_file(path)?,
            None => TomlConfig::default(),
        };
        Self::merge(args, toml)
    }

    pub fn merge(args: &Args, toml: TomlConfig) -> io::Result<Self> {
        let host = args
            .host
            .clone()
            .or(toml.host)
            .unwrap_or_else(|| DEFAULT_HOST.to_string());
        let port = args.port.or(toml.port).unwrap_or(DEFAULT_PORT);
        let verbose = args.verbose || toml.verbose.unwrap_or(false);

        let chunk_size = args
            .chunk_size
            .or(toml.tls.chunk_size)
            .unwrap_or(DEFAULT_CHUNK_SIZE);
        if chunk_size == 0 {
            return Err(invalid_input("chunk_size must be greater than 0"));
        }

        let fake_sni = args.fake_sni.clone().or(toml.tls.fake_sni);
        let fake_ttl = args.fake_ttl.or(toml.tls.fake_ttl);
        if fake_ttl == Some(0) {
            return Err(invalid_input("fake_ttl must be between 1 and 255"));
        }
        let fake_bad_checksum =
            args.fake_bad_checksum || toml.tls.fake_bad_checksum.unwrap_or(false);
        let split_sni = args.split_sni || toml.tls.split_sni.unwrap_or(false);

        let limits = ConnectionLimits {
            max_connections: args.max_connections.or(toml.limits.max_connections),
            idle_timeout: Duration::from_secs(
                args.idle_timeout
                    .or(toml.limits.idle_timeout)
                    .unwrap_or(DEFAULT_IDLE_TIMEOUT_SECS),
            ),
            handshake_timeout: Duration::from_secs(
                args.handshake_timeout
                    .or(toml.limits.handshake_timeout)
                    .unwrap_or(DEFAULT_HANDSHAKE_TIMEOUT_SECS),
            ),
        };

        let (dns_server, dns_kind) = resolve_dns_server(args, &toml.dns)?;
        let prefer = resolve_ip_preference(args, toml.dns.prefer.as_deref())?;

        let mut bootstrap = Vec::new();
        for raw in toml
            .dns
            .bootstrap
            .iter()
            .chain(args.dns_bootstrap.iter())
        {
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                continue;
            }
            let ip = trimmed.parse::<IpAddr>().map_err(|e| {
                invalid_input(format!("invalid DNS bootstrap IP {trimmed:?}: {e}"))
            })?;
            bootstrap.push(ip);
        }

        let cache_ttl_secs = args
            .dns_cache_ttl
            .or(toml.dns.cache_ttl)
            .unwrap_or(DEFAULT_DNS_CACHE_TTL_SECS);
        let cache_capacity = args
            .dns_cache_capacity
            .or(toml.dns.cache_capacity)
            .unwrap_or(DEFAULT_DNS_CACHE_CAPACITY);

        let policy = build_policy(args, &toml.rules)?;

        let mut auth = Vec::new();
        if let Some(toml_auth) = toml.auth {
            for raw in toml_auth.into_vec() {
                auth.push(Credential::parse(&raw)?);
            }
        }
        for raw in &args.auth {
            auth.push(Credential::parse(raw)?);
        }

        let no_pac = args.no_pac || toml.no_pac.unwrap_or(false);
        let pac_path = if no_pac {
            None
        } else {
            let path = args
                .pac_path
                .clone()
                .or(toml.pac_path)
                .unwrap_or_else(|| DEFAULT_PAC_PATH.to_string());
            let trimmed = path.trim();
            if trimmed.is_empty() {
                None
            } else if trimmed.starts_with('/') {
                Some(trimmed.to_string())
            } else {
                Some(format!("/{trimmed}"))
            }
        };
        let pac_proxy = args.pac_proxy.clone().or(toml.pac_proxy);

        Ok(Self {
            host,
            port,
            verbose,
            tls: TlsSettings {
                chunk_size,
                split_sni,
                fake_sni,
                fake_ttl,
                fake_bad_checksum,
            },
            limits,
            dns: DnsSettings {
                server: dns_server,
                kind: dns_kind,
                bootstrap,
                prefer,
                cache_ttl: Duration::from_secs(cache_ttl_secs),
                cache_capacity,
            },
            policy,
            auth,
            pac_path,
            pac_proxy,
        })
    }
}

fn load_toml_file(path: &Path) -> io::Result<TomlConfig> {
    let text = std::fs::read_to_string(path).map_err(|e| {
        invalid_input(format!(
            "could not read config file {}: {e}",
            path.display()
        ))
    })?;
    let mut cfg: TomlConfig = toml::from_str(&text).map_err(|e| {
        invalid_input(format!(
            "invalid TOML in config file {}: {e}",
            path.display()
        ))
    })?;

    // Resolve relative rule/geoip paths relative to the config file directory when present.
    if let Some(base_dir) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        for p in &mut cfg.rules.bypass_file {
            if p.is_relative() {
                *p = base_dir.join(&*p);
            }
        }
        for p in &mut cfg.rules.evade_file {
            if p.is_relative() {
                *p = base_dir.join(&*p);
            }
        }
        if let Some(geoip) = &mut cfg.rules.geoip_db {
            if geoip.is_relative() {
                *geoip = base_dir.join(&*geoip);
            }
        }
    }

    Ok(cfg)
}

fn resolve_dns_server(args: &Args, toml: &TomlDnsConfig) -> io::Result<(String, DNSServerKind)> {
    // CLI DNS flags take full precedence over TOML dns settings.
    if let Some(server) = &args.dns_tcp_server {
        return Ok((server.clone(), DNSServerKind::Tcp));
    }
    if let Some(server) = &args.dns_udp_server {
        return Ok((server.clone(), DNSServerKind::Udp));
    }
    if let Some(server) = &args.dns_https_server {
        return Ok((server.clone(), DNSServerKind::Https));
    }
    if let Some(server) = &args.dot_server {
        return Ok((server.clone(), DNSServerKind::Tls));
    }

    let kind = match toml.mode.as_deref().map(str::to_ascii_lowercase).as_deref() {
        None | Some("tls") | Some("dot") => DNSServerKind::Tls,
        Some("tcp") => DNSServerKind::Tcp,
        Some("udp") => DNSServerKind::Udp,
        Some("https") | Some("doh") => DNSServerKind::Https,
        Some(other) => {
            return Err(invalid_input(format!(
                "invalid dns.mode {other:?}; expected one of tls, tcp, udp, https"
            )));
        }
    };
    let server = toml
        .server
        .clone()
        .unwrap_or_else(|| DEFAULT_DOT_SERVER.to_string());
    Ok((server, kind))
}

fn resolve_ip_preference(args: &Args, toml_prefer: Option<&str>) -> io::Result<IpPreference> {
    if args.prefer_ipv6 {
        return Ok(IpPreference::Ipv6);
    }
    if args.prefer_ipv4 {
        return Ok(IpPreference::Ipv4);
    }
    match toml_prefer.map(str::to_ascii_lowercase).as_deref() {
        None | Some("any") => Ok(IpPreference::Any),
        Some("ipv4") | Some("v4") => Ok(IpPreference::Ipv4),
        Some("ipv6") | Some("v6") => Ok(IpPreference::Ipv6),
        Some(other) => Err(invalid_input(format!(
            "invalid dns.prefer {other:?}; expected one of any, ipv4, ipv6"
        ))),
    }
}

fn build_policy(args: &Args, toml: &TomlRulesConfig) -> io::Result<EvadePolicy> {
    let geoip_db = args.geoip_db.as_deref().or(toml.geoip_db.as_deref());

    let mut bypass = BypassList::default();
    for rule in toml.bypass_ip.iter().chain(args.bypass_ip.iter()) {
        bypass.add_ip(rule)?;
    }
    for rule in toml.bypass_domain.iter().chain(args.bypass_domain.iter()) {
        bypass.add_domain(rule)?;
    }
    for rule in toml.bypass_tld.iter().chain(args.bypass_tld.iter()) {
        bypass.add_tld(rule)?;
    }
    for country in toml.bypass_geoip.iter().chain(args.bypass_geoip.iter()) {
        bypass.add_country(country)?;
    }
    if args.bypass_private || toml.bypass_private.unwrap_or(false) {
        bypass.add_private_nets()?;
    }
    for path in toml.bypass_file.iter().chain(args.bypass_file.iter()) {
        bypass.load_file(path)?;
    }
    bypass.finalize_geoip(geoip_db)?;

    let mut evade = BypassList::default();
    for rule in toml.evade_ip.iter().chain(args.evade_ip.iter()) {
        evade.add_ip(rule)?;
    }
    for rule in toml.evade_domain.iter().chain(args.evade_domain.iter()) {
        evade.add_domain(rule)?;
    }
    for rule in toml.evade_tld.iter().chain(args.evade_tld.iter()) {
        evade.add_tld(rule)?;
    }
    for country in toml.evade_geoip.iter().chain(args.evade_geoip.iter()) {
        evade.add_country(country)?;
    }
    for path in toml.evade_file.iter().chain(args.evade_file.iter()) {
        evade.load_file(path)?;
    }
    evade.finalize_geoip(geoip_db)?;

    let explicit_mode = match args.rule_mode {
        Some(RuleModeArg::Bypass) => Some(RuleMode::Bypass),
        Some(RuleModeArg::Evade) => Some(RuleMode::Evade),
        None => match toml.mode.as_deref().map(str::to_ascii_lowercase).as_deref() {
            None => None,
            Some("bypass") => Some(RuleMode::Bypass),
            Some("evade") => Some(RuleMode::Evade),
            Some(other) => {
                return Err(invalid_input(format!(
                    "invalid rules.mode {other:?}; expected bypass or evade"
                )));
            }
        },
    };

    // If evade rules were supplied without an explicit mode, automatically switch to allowlist mode.
    let mode = explicit_mode.unwrap_or_else(|| {
        if evade.is_empty() {
            RuleMode::Bypass
        } else {
            RuleMode::Evade
        }
    });

    Ok(EvadePolicy::new(mode, bypass, evade))
}

fn invalid_input(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, msg.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use std::net::Ipv4Addr;

    fn parse_args(extra: &[&str]) -> Args {
        Args::parse_from(std::iter::once("chunky").chain(extra.iter().copied()))
    }

    #[test]
    fn limits_have_defaults() {
        let resolved = ResolvedConfig::merge(&parse_args(&[]), TomlConfig::default()).unwrap();
        assert_eq!(resolved.limits, ConnectionLimits::default());
        assert_eq!(resolved.limits.max_connections, None);
        assert_eq!(resolved.limits.idle_timeout, Duration::from_secs(300));
        assert_eq!(resolved.limits.handshake_timeout, Duration::from_secs(30));
    }

    #[test]
    fn limits_come_from_toml_and_cli_overrides() {
        let toml: TomlConfig = toml::from_str(
            "[limits]\nmax_connections = 100\nidle_timeout = 60\nhandshake_timeout = 5\n",
        )
        .unwrap();
        let resolved = ResolvedConfig::merge(&parse_args(&[]), toml.clone()).unwrap();
        assert_eq!(resolved.limits.max_connections, Some(100));
        assert_eq!(resolved.limits.idle_timeout, Duration::from_secs(60));
        assert_eq!(resolved.limits.handshake_timeout, Duration::from_secs(5));

        let args = parse_args(&["--max-connections", "0", "--idle-timeout", "0", "--handshake-timeout", "9"]);
        let resolved = ResolvedConfig::merge(&args, toml).unwrap();
        assert_eq!(resolved.limits.max_connections, Some(0));
        assert_eq!(resolved.limits.idle_timeout, Duration::ZERO);
        assert_eq!(resolved.limits.handshake_timeout, Duration::from_secs(9));
    }

    #[test]
    fn parses_toml_and_cli_overrides() {
        let toml_text = r#"
host = "0.0.0.0"
port = 9000
auth = "alice:secret"
pac_path = "/custom.pac"

[tls]
chunk_size = 250
split_sni = true
fake_sni = "example.org"
fake_ttl = 4
fake_bad_checksum = true

[dns]
mode = "https"
server = "https://dns.google/dns-query"
bootstrap = ["8.8.8.8", "8.8.4.4"]
prefer = "ipv6"
cache_ttl = 120
cache_capacity = 512

[rules]
mode = "evade"
evade_domain = [".youtube.com"]
bypass_private = true
"#;
        let toml: TomlConfig = toml::from_str(toml_text).unwrap();
        let args = parse_args(&["--port", "8080", "--auth", "bob:pw2"]);
        let resolved = ResolvedConfig::merge(&args, toml).unwrap();

        assert_eq!(resolved.host, "0.0.0.0");
        assert_eq!(resolved.port, 8080);
        assert_eq!(resolved.tls.chunk_size, 250);
        assert!(resolved.tls.split_sni);
        assert_eq!(resolved.tls.fake_sni.as_deref(), Some("example.org"));
        assert_eq!(resolved.tls.fake_ttl, Some(4));
        assert!(resolved.tls.fake_bad_checksum);
        assert_eq!(resolved.dns.kind, DNSServerKind::Https);
        assert_eq!(resolved.dns.server, "https://dns.google/dns-query");
        assert_eq!(
            resolved.dns.bootstrap,
            vec![
                IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
                IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4))
            ]
        );
        assert_eq!(resolved.dns.prefer, IpPreference::Ipv6);
        assert_eq!(resolved.dns.cache_ttl, Duration::from_secs(120));
        assert_eq!(resolved.dns.cache_capacity, 512);
        assert_eq!(resolved.auth.len(), 2);
        assert_eq!(resolved.pac_path.as_deref(), Some("/custom.pac"));
        assert_eq!(resolved.policy.mode(), RuleMode::Evade);
    }

    #[test]
    fn credential_rejects_bad_format() {
        assert!(Credential::parse("nocolon").is_err());
        assert!(Credential::parse(":emptyuser").is_err());
        let c = Credential::parse("user:p:a:s:s").unwrap();
        assert_eq!(c.username, "user");
        assert_eq!(c.password, "p:a:s:s");
    }

    #[test]
    fn evade_args_auto_select_allowlist_mode() {
        let args = parse_args(&["--evade-domain", "example.com"]);
        let resolved = ResolvedConfig::load(&args).unwrap();
        assert_eq!(resolved.policy.mode(), RuleMode::Evade);
    }
}

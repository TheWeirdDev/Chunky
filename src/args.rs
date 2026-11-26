use std::path::PathBuf;

use clap::{Parser, ValueEnum};

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum RuleModeArg {
    Bypass,
    Evade,
}

#[derive(Parser, Debug, Clone)]
#[command(version, about = "Lightweight HTTP/HTTPS/SOCKS5 proxy for DPI circumvention")]
pub struct Args {
    /// Path to a TOML configuration file (reloaded on SIGHUP on Unix).
    #[arg(short = 'C', long, value_name = "PATH")]
    pub config: Option<PathBuf>,

    /// The host to listen on. [default: 127.0.0.1]
    #[arg(long)]
    pub host: Option<String>,

    /// The port to listen on. [default: 8000]
    #[arg(long)]
    pub port: Option<u16>,

    /// The DNS-over-TLS server to use. [default: 1.1.1.1]
    #[arg(short = 'T', long)]
    pub dot_server: Option<String>,

    /// Use a plain DNS-over-TCP server instead of DNS-over-TLS. Takes an IP or hostname.
    #[arg(short = 't', long)]
    pub dns_tcp_server: Option<String>,

    /// Use a plain DNS-over-UDP server instead of DNS-over-TLS. Takes an IP or hostname.
    #[arg(short = 'u', long)]
    pub dns_udp_server: Option<String>,

    /// Use a DNS-over-HTTPS server instead of DNS-over-TLS. Takes a URL.
    #[arg(short = 'H', long)]
    pub dns_https_server: Option<String>,

    /// Bootstrap IP(s) for DoH/DoT server hostnames (avoids OS DNS). Repeatable or comma-separated.
    #[arg(long, value_name = "IP", value_delimiter = ',')]
    pub dns_bootstrap: Vec<String>,

    /// Max DNS cache TTL in seconds (0 disables caching). [default: 300]
    #[arg(long, value_name = "SECONDS")]
    pub dns_cache_ttl: Option<u64>,

    /// Max entries in the DNS cache. [default: 4096]
    #[arg(long, value_name = "COUNT")]
    pub dns_cache_capacity: Option<usize>,

    /// Prefer IPv6 addresses when a host has both IPv4 and IPv6.
    #[arg(short = '6', long, conflicts_with = "prefer_ipv4")]
    pub prefer_ipv6: bool,

    /// Prefer IPv4 addresses when a host has both IPv4 and IPv6.
    #[arg(short = '4', long, conflicts_with = "prefer_ipv6")]
    pub prefer_ipv4: bool,

    /// Spoof the SNI: inject a fake ClientHello with this host name before the real one.
    /// Needs CAP_NET_RAW.
    #[arg(long, value_name = "HOST")]
    pub fake_sni: Option<String>,

    /// IP TTL (or IPv6 hop limit) for injected fake ClientHello packets (1-255).
    #[arg(long, value_name = "TTL", value_parser = clap::value_parser!(u8).range(1..))]
    pub fake_ttl: Option<u8>,

    /// Deliberately corrupt the TCP checksum on injected fake ClientHello packets.
    #[arg(long)]
    pub fake_bad_checksum: bool,

    /// The size of each TLS ClientHello chunk in bytes. [default: 500]
    #[arg(short = 'c', long)]
    pub chunk_size: Option<usize>,

    /// Split TLS ClientHello at SNI and ECH extension boundaries with TCP_NODELAY.
    #[arg(long)]
    pub split_sni: bool,

    /// Rule mode: `bypass` (default: evade all except bypass rules) or `evade` (allowlist: evade only evade rules).
    #[arg(long, value_enum)]
    pub rule_mode: Option<RuleModeArg>,

    /// Bypass chunking and SNI spoofing for this IP or CIDR. Repeatable, or comma-separated.
    #[arg(long, value_name = "IP|CIDR", value_delimiter = ',')]
    pub bypass_ip: Vec<String>,

    /// Bypass this domain. Supports `*.example.com` and `.example.com` (apex + subdomains).
    /// Repeatable, or comma-separated.
    #[arg(long, value_name = "PATTERN", value_delimiter = ',')]
    pub bypass_domain: Vec<String>,

    /// Bypass every host under this top-level domain, e.g. `ir` or `co.uk`.
    /// Repeatable, or comma-separated.
    #[arg(long, value_name = "TLD", value_delimiter = ',')]
    pub bypass_tld: Vec<String>,

    /// Bypass addresses located in this two-letter country (requires --geoip-db).
    /// Repeatable, or comma-separated.
    #[arg(long, value_name = "COUNTRY", value_delimiter = ',')]
    pub bypass_geoip: Vec<String>,

    /// MaxMind GeoLite2-Country or DB-IP country database used by --bypass-geoip / --evade-geoip.
    #[arg(long, value_name = "PATH")]
    pub geoip_db: Option<PathBuf>,

    /// Load bypass rules from a file. Repeatable.
    #[arg(long, value_name = "PATH")]
    pub bypass_file: Vec<PathBuf>,

    /// Bypass loopback, private, link-local, and CGNAT addresses.
    #[arg(long)]
    pub bypass_private: bool,

    /// Allowlist mode: evade this IP or CIDR. Repeatable, or comma-separated.
    #[arg(long, value_name = "IP|CIDR", value_delimiter = ',')]
    pub evade_ip: Vec<String>,

    /// Allowlist mode: evade this domain (`*.example.com` or `.example.com`). Repeatable, or comma-separated.
    #[arg(long, value_name = "PATTERN", value_delimiter = ',')]
    pub evade_domain: Vec<String>,

    /// Allowlist mode: evade every host under this TLD. Repeatable, or comma-separated.
    #[arg(long, value_name = "TLD", value_delimiter = ',')]
    pub evade_tld: Vec<String>,

    /// Allowlist mode: evade addresses in this two-letter country (requires --geoip-db).
    #[arg(long, value_name = "COUNTRY", value_delimiter = ',')]
    pub evade_geoip: Vec<String>,

    /// Load allowlist evade rules from a file. Repeatable.
    #[arg(long, value_name = "PATH")]
    pub evade_file: Vec<PathBuf>,

    /// Require Basic / SOCKS5 username:password authentication. Repeatable.
    #[arg(long, value_name = "USER:PASS")]
    pub auth: Vec<String>,

    /// HTTP path to serve the PAC (Proxy Auto-Config) script on. [default: /proxy.pac]
    #[arg(long, value_name = "PATH")]
    pub pac_path: Option<String>,

    /// Disable the PAC HTTP endpoint.
    #[arg(long)]
    pub no_pac: bool,

    /// Override the `PROXY host:port` address advertised by the PAC script.
    #[arg(long, value_name = "HOST:PORT")]
    pub pac_proxy: Option<String>,

    #[arg(short = 'v', long)]
    pub verbose: bool,
}

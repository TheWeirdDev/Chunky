use std::path::PathBuf;

use clap::Parser;

#[derive(Parser, Debug)]
pub struct Args {
    #[arg(long, default_value = "127.0.0.1")]
    pub host: String,

    #[arg(long, default_value = "8000")]
    pub port: u16,

    #[arg(short = 'T', long, default_value = "1.1.1.1")]
    pub dot_server: String,

    #[arg(short = 't', long)]
    pub dns_tcp_server: Option<String>,

    #[arg(short = 'u', long)]
    pub dns_udp_server: Option<String>,

    #[arg(short = 'H', long)]
    pub dns_https_server: Option<String>,

    #[arg(short = '6', long, conflicts_with = "prefer_ipv4")]
    pub prefer_ipv6: bool,

    #[arg(short = '4', long, conflicts_with = "prefer_ipv6")]
    pub prefer_ipv4: bool,

    /// Spoof the SNI: inject a fake ClientHello with this host name before the real one, and turn
    /// chunking off. Needs CAP_NET_RAW.
    #[arg(long, value_name = "HOST")]
    pub fake_sni: Option<String>,

    #[arg(short = 'c', long, default_value = "500")]
    pub chunk_size: usize,

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

    /// MaxMind GeoLite2-Country or DB-IP country database used by --bypass-geoip.
    #[arg(long, value_name = "PATH")]
    pub geoip_db: Option<PathBuf>,

    /// Load bypass rules from a file. Repeatable.
    #[arg(long, value_name = "PATH")]
    pub bypass_file: Vec<PathBuf>,

    /// Bypass loopback, private, link-local, and CGNAT addresses.
    #[arg(long)]
    pub bypass_private: bool,

    #[arg(short = 'v', long)]
    pub verbose: bool,
}

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

    #[arg(short = 'v', long)]
    pub verbose: bool,
}

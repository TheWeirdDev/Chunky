use clap::Parser;

#[derive(Parser, Debug)]
pub struct Args {
    #[arg(long, default_value = "127.0.0.1")]
    pub host: String,

    #[arg(long, default_value = "8000")]
    pub port: u16,

    #[arg(short = 'T', long, default_value = "1.1.1.1")]
    pub dot_server: Option<String>,

    #[arg(short = 't', long)]
    pub dns_tcp_server: Option<String>,

    // #[arg(short = 'H', long)]
    // pub doh_server: Option<Vec<String>>,
    #[arg(short = 'c', long, default_value = "500")]
    pub chunk_size: usize,

    #[arg(short = 'v', long)]
    pub verbose: bool,
}

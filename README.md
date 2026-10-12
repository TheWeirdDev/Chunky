# Chunky

Chunky is a lightweight http(s) proxy designed to circumvent censorship in countries where internet access is restricted. It works by chunking the TLS handshake and making it difficult for deep packet inspection (DPI) to detect and block the handshake.

## Configuration

Chunky has a few configuration options that can be set using command line arguments. The following options are available:

- `--host`: The host to listen on. Default: **127.0.0.1**
- `--port`: The port to listen on. Default: **8000**
- `-T` or `--dot-server`: The DNS-over-TLS server to use. Default: **1.1.1.1**
- `-t` or `--dns-tcp-server`: Use a plain DNS-over-TCP server instead of DNS-over-TLS. Takes an IP or hostname.
- `-u` or `--dns-udp-server`: Use a plain DNS-over-UDP server instead of DNS-over-TLS. Takes an IP or hostname.
- `-H` or `--dns-https-server`: Use a DNS-over-HTTPS server instead of DNS-over-TLS. Takes a URL, e.g. `https://dns.google/dns-query`.
- `-6` or `--prefer-ipv6`: Prefer IPv6 addresses when a host has both IPv4 and IPv6. Default: **Disabled**
- `-4` or `--prefer-ipv4`: Prefer IPv4 addresses when a host has both IPv4 and IPv6. Cannot be used with `-6`. Default: **Disabled**
- `-c` or `--chunk-size`: The size of each chunk in bytes. Default: **500**
- `-v` or `--verbose`: Enable verbose logging. Default: **Disabled**
- `-h` or `--help`: Display the help message

## How to run

To run Chunky, you need to have the Rust toolchain installed. You can install it by following the instructions [here](https://www.rust-lang.org/tools/install).

Once you have the Rust toolchain installed, you can run the following command to build and run Chunky:

```bash
cargo run --release
```

If the DNS server returns several addresses for a host, or a DNS-over-HTTPS server has several IPs, Chunky tries them in order. A connection attempt that fails or takes longer than 5 seconds moves on to the next address.

This will start the Chunky proxy on the default host and port mentioned above. You can then **configure your browser or system to use the proxy to access the internet**.

## Credits

- [DPYProxy](https://github.com/UPB-SysSec/DPYProxy)

## License

This project is licensed under the GPL-3.0 License - see the [LICENSE](LICENSE) file for details.

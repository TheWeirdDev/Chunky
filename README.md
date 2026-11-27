# Chunky

Chunky is a lightweight HTTP(S), SOCKS4/4a, and SOCKS5 proxy designed to circumvent censorship in countries where internet access is restricted. It works by splitting or spoofing the TLS ClientHello so deep packet inspection (DPI) cannot detect and block the handshake.

## Features

- **Unified HTTP(S) + SOCKS4/4a + SOCKS5 listener** on a single port (auto-detected per connection), supporting all plain HTTP methods (`GET`, `POST`, `PUT`, `DELETE`, `HEAD`, `OPTIONS`, `PATCH`, etc.) and `CONNECT`
- **SNI & ECH-aware TLS splitting** (`--split-sni`) with `TCP_NODELAY`, plus configurable `--chunk-size`
- **SNI spoofing (`--fake-sni`)** on Linux and Android across IPv4, IPv6, and multiple interfaces, with optional `--fake-ttl` and `--fake-bad-checksum`
- **Encrypted & resilient DNS** via DoT, DoH (concurrent `A`/`AAAA` queries), TCP, or UDP, with `--dns-bootstrap`, TTL/LRU caching, and RFC 8305 Happy Eyeballs connection racing
- **Blocklist (`bypass`) and Allowlist (`evade`) rules** by IP/CIDR, domain/wildcard, TLD, GeoIP country, private ranges, or rule files
- **TOML configuration (`--config`) with `SIGHUP` hot-reload**, **Basic / SOCKS5 proxy authentication (`--auth`)**, and an integrated **PAC endpoint (`/proxy.pac`)**

## Configuration

The following CLI options are available (all can also be configured via a TOML file passed to `--config`, with CLI flags overriding TOML values):

- `-C` or `--config`: Path to a TOML configuration file (reloaded on `SIGHUP` on Unix).
- `--host`: The host to listen on. Default: **127.0.0.1**
- `--port`: The port to listen on (accepts both HTTP/HTTPS and SOCKS5). Default: **8000**
- `-T` or `--dot-server`: The DNS-over-TLS server to use. Default: **1.1.1.1**
- `-t` or `--dns-tcp-server`: Use a plain DNS-over-TCP server instead of DNS-over-TLS. Takes an IP or hostname.
- `-u` or `--dns-udp-server`: Use a plain DNS-over-UDP server instead of DNS-over-TLS. Takes an IP or hostname.
- `-H` or `--dns-https-server`: Use a DNS-over-HTTPS server instead of DNS-over-TLS. Takes a URL, e.g. `https://dns.google/dns-query`.
- `--dns-bootstrap`: Bootstrap IP(s) for DoH/DoT server hostnames (avoids OS DNS). Repeatable or comma-separated.
- `--dns-cache-ttl`: Max DNS cache TTL in seconds (`0` disables caching). Default: **300**
- `--dns-cache-capacity`: Max entries in the DNS cache. Default: **4096**
- `-6` or `--prefer-ipv6`: Prefer IPv6 addresses when a host has both IPv4 and IPv6. Default: **Disabled**
- `-4` or `--prefer-ipv4`: Prefer IPv4 addresses when a host has both IPv4 and IPv6. Cannot be used with `-6`. Default: **Disabled**
- `--fake-sni`: Spoof the SNI: inject a fake ClientHello with this host name before the real one. Needs `CAP_NET_RAW` (e.g. `sudo setcap cap_net_raw+ep <binary>`). Supports IPv4, IPv6, and dynamic multi-interface routing on Linux/Android. Default: **Disabled**
- `--fake-ttl`: IP TTL (or IPv6 hop limit) for injected fake ClientHello packets (`1..=255`). Sends the fake ClientHello in-sequence so it expires before reaching the origin server.
- `--fake-bad-checksum`: Deliberately corrupt the TCP checksum on injected fake ClientHello packets so the origin server drops them while DPI inspects them.
- `-c` or `--chunk-size`: The size of each TLS ClientHello chunk in bytes. Default: **500**
- `--split-sni`: Parse the TLS ClientHello and split at SNI (`0x0000`) and ECH (`0xfe0d`) extension boundaries with `TCP_NODELAY`.
- `--rule-mode`: `bypass` (default: evade everything except bypass rules) or `evade` (allowlist: evade only evade rules).
- `--bypass-ip` / `--evade-ip`: Bypass or allowlist an IP or CIDR. Repeatable or comma-separated.
- `--bypass-domain` / `--evade-domain`: Match a domain, `*.example.com` wildcard, or `.example.com` (apex and subdomains). Repeatable or comma-separated.
- `--bypass-tld` / `--evade-tld`: Match every host under a top-level domain, e.g. `ir` or `co.uk`. Repeatable or comma-separated.
- `--bypass-geoip` / `--evade-geoip`: Match addresses in a two-letter country code. Needs `--geoip-db`. Repeatable or comma-separated.
- `--geoip-db`: Path to a MaxMind GeoLite2-Country or DB-IP country database. Only available when built with `--features geoip`.
- `--bypass-file` / `--evade-file`: Load rules from a file. Repeatable.
- `--bypass-private`: Bypass loopback, private, link-local, and CGNAT addresses.
- `--auth`: Require HTTP Basic (`Proxy-Authorization`) and SOCKS5 username/password authentication (`USER:PASS`). Repeatable.
- `--pac-path`: HTTP path to serve the PAC (`FindProxyForURL`) script on. Default: **/proxy.pac**
- `--no-pac`: Disable the PAC HTTP endpoint.
- `--max-connections`: Max concurrent client connections (`0` = unlimited). Further clients wait in the listen backlog. Default: **derived from the open file limit** (the soft limit is raised to the hard limit at startup).
- `--idle-timeout`: Close a tunnel after this many seconds without traffic in either direction (`0` disables). Default: **300**
- `--handshake-timeout`: Seconds a client has to finish its SOCKS/HTTP handshake (`0` disables). Default: **30**
- `--pac-proxy`: Override the `PROXY host:port` address returned by the PAC script.
- `-v` or `--verbose`: Enable verbose logging. Default: **Disabled**
- `-h` or `--help`: Display the help message

## How to run

To run Chunky, you need to have the Rust toolchain installed. You can install it by following the instructions [here](https://www.rust-lang.org/tools/install).

```bash
cargo run --release
```

Chunky listens for both HTTP/HTTPS proxy requests and SOCKS5 connections on `--host:--port`. Upstream addresses are raced using RFC 8305 Happy Eyeballs (250ms stagger, 5s timeout per attempt).

### TOML Config & Hot Reload

Example `chunky.toml`:

```toml
host = "127.0.0.1"
port = 8000
auth = ["alice:secret"]
pac_path = "/proxy.pac"

[tls]
chunk_size = 500
split_sni = true
# fake_sni = "www.speedtest.net"
# fake_ttl = 3
# fake_bad_checksum = false

[limits]
# max_connections = 1000
idle_timeout = 300
handshake_timeout = 30

[dns]
mode = "https"
server = "https://dns.google/dns-query"
bootstrap = ["8.8.8.8", "8.8.4.4"]
prefer = "ipv4"
cache_ttl = 300
cache_capacity = 4096

[rules]
mode = "bypass"
bypass_private = true
bypass_tld = ["ir"]
bypass_file = ["bypass.txt"]
```

Run with `chunky --config chunky.toml`, and send `SIGHUP` (`kill -HUP <pid>`) to hot-reload the TOML config, rule files, DNS resolver, and auth credentials without dropping active connections.

## Bypass and Allowlist Rules

In `bypass` mode (default), matching destinations are still proxied, but Chunky skips chunking and SNI spoofing for them. In `evade` allowlist mode (`--rule-mode evade`, or automatically whenever any `--evade-*` flag is used), **only** destinations matching `--evade-*` rules receive DPI evasion (while any `--bypass-*` rules act as exclusions).

Rules can be passed on the command line or loaded from a file (`--bypass-file` / `--evade-file`):

```text
# Blank lines and text after '#' are ignored.
ip 10.0.0.0/8
ip 2001:db8::/32
domain example.com
domain *.example.com
tld ir
geoip CN
```

Domain patterns support `*`, `?`, and character classes. A leading dot, as in `.example.com`, matches the apex and all of its subdomains. TLD rules match on a label boundary, so `ir` matches `example.ir` but not `notir`. IP and GeoIP rules match any address the host resolves to.

### GeoIP

Country matching needs a local GeoIP database and a build with the `geoip` feature, because the database is not bundled:

```bash
cargo build --release --features geoip
./target/release/chunky --geoip-db GeoLite2-Country.mmdb --bypass-geoip CN,IR
```

Both MaxMind GeoLite2-Country and DB-IP country databases in MaxMind DB format work. Without the feature, `--geoip-db`, `--bypass-geoip`, and `--evade-geoip` are rejected at startup.

## Building for Android and iOS

`scripts/build-mobile.sh` builds the Android and iOS binaries and packages each one as `dist/chunky-<target>.zip`, the same layout as the release assets.

```bash
scripts/build-mobile.sh [android|ios|all]   # default: all
```

Both targets need the Rust targets, which the script adds with `rustup target add`.

**Android** (Linux or macOS host):

1. Install the [Android NDK](https://developer.android.com/ndk/downloads).
2. Set `ANDROID_NDK` to the NDK directory, for example `export ANDROID_NDK=/path/to/Android-SDK/ndk/30.0.16248370`.

**iOS on macOS**: install Xcode. The script builds with Xcode and ad-hoc signs the binary with `codesign`.

**iOS on Linux**: this needs the [THEOS](https://theos.dev) `darwin-tools` package and the iPhoneOS SDK.

1. Set `THEOS_TOOLS` to its `bin` directory, which provides `ld`, `ar`, and `ranlib`.
2. Optionally set `LDID` to the `ldid` binary and `ENTITLEMENTS` to an entitlements plist (default: `ent.xml`). The script signs the binary with `ldid -S` when `LDID` is set.

For example: `export THEOS_TOOLS=~/theos/darwin-tools-linux/packages/linux/iphone/bin LDID=$THEOS_TOOLS/ldid`.

Two platform limits apply to both mobile targets:

- `--fake-sni` is only supported on Linux and Android, because it needs raw sockets. Chunking works everywhere.
- The binaries are command-line programs. Android runs them from a terminal app such as Termux, and iOS needs a jailbroken device.

## Credits

- [DPYProxy](https://github.com/UPB-SysSec/DPYProxy)

## License

This project is licensed under the GPL-3.0 License - see the [LICENSE](LICENSE) file for details.

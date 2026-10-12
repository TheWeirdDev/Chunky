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
- `--fake-sni`: Spoof the SNI: send a fake ClientHello with this host name before the real one, and turn chunking off. Needs `CAP_NET_RAW` (e.g. `sudo setcap cap_net_raw+ep <binary>`). Default: **Disabled**
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

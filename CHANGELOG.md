# 0.2.0
- Add unified HTTP(S) + SOCKS4/4a + SOCKS5 auto-detection on a single listening port
- Support all HTTP methods (`POST`, `PUT`, `DELETE`, `HEAD`, `OPTIONS`, `PATCH`, etc.) and strip proxy-only headers
- Add HTTP Basic and SOCKS5 username/password authentication (`--auth`)
- Add PAC (`FindProxyForURL`) HTTP endpoint (`/proxy.pac`, `--pac-path`, `--no-pac`, `--pac-proxy`)
- Add TOML configuration (`--config`) and `SIGHUP` hot-reload
- Add SNI (`0x0000`) and ECH (`0xfe0d`) boundary TLS ClientHello splitting with `TCP_NODELAY` (`--split-sni`)
- Add `--fake-ttl`, `--fake-bad-checksum`, IPv6 support, and dynamic multi-interface routing to SNI spoofing
- Add DNS cache TTL + bounded LRU eviction (`--dns-cache-ttl`, `--dns-cache-capacity`), DoH/DoT `--dns-bootstrap` IPs, concurrent DoH `A`/`AAAA` queries, multi-server TCP/UDP fallback, and RFC 8305 Happy Eyeballs connection racing
- Add allowlist (`evade`) rule mode (`--rule-mode evade`, `--evade-ip`, `--evade-domain`, `--evade-tld`, `--evade-geoip`, `--evade-file`)
- Add bypass lists: matched destinations are still proxied but skip chunking and SNI spoofing
- Match bypass rules by IP/CIDR, exact or wildcard domain, top-level domain, and GeoIP country
- Load rules from the command line or a `--bypass-file`, with optional `--bypass-private` ranges
- GeoIP support is behind the `geoip` feature so the database and dependency stay optional

# 0.1.0
- Initial release

# 0.1.2
- Use vendored openssl

# 0.1.3
- Add tcp dns server support

# 0.1.4
- Add udp dns server support

# 0.1.5
- Add DNS-over-HTTPS upstream via -H
- Add -6/--prefer-ipv6 and -4/--prefer-ipv4 (mutually exclusive)
- Try the next resolved address when a DoH server or the target host fails, with a 5 second connect timeout
- Order addresses IPv4 first by default, so unreachable IPv6 addresses don't cost a timeout
- Add --fake-sni to spoof the SNI with a fake ClientHello sent before the real one, which turns chunking off. Needs CAP_NET_RAW, and checked at startup
- Only the client's TLS ClientHello is chunked; server replies are forwarded unchanged
- Return errors instead of panicking on malformed request lines, and stop spinning when a client disconnects before sending a request
- Refactor DNS and HTTP code and add unit tests

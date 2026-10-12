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

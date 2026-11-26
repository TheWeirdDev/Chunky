use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use tokio::io;
use url::Url;

use crate::config::Credential;

pub struct HttpRequest {
    pub method: String,
    pub version: String,
    pub host: String,
    pub port: u16,
    pub path_and_query: String,
    pub is_https: bool,
    pub is_origin_form: bool,
}

#[allow(dead_code)]
pub fn parse_http_request(line: &str) -> io::Result<HttpRequest> {
    parse_http_request_with_headers(line, "")
}

pub fn parse_http_request_with_headers(line: &str, headers: &str) -> io::Result<HttpRequest> {
    if !line.ends_with("\r\n") {
        return Err(invalid_data("Invalid HTTP request"));
    }
    let mut parts = line.split_whitespace();
    let (Some(method), Some(uri), Some(version)) = (parts.next(), parts.next(), parts.next())
    else {
        return Err(invalid_data("Invalid HTTP request"));
    };
    if parts.next().is_some() {
        return Err(invalid_data("Invalid HTTP request"));
    }

    if !is_valid_http_method(method) {
        return Err(invalid_data("Invalid HTTP method"));
    }
    let method = method.to_ascii_uppercase();
    let is_connect = method == "CONNECT";

    if version != "HTTP/1.1" && version != "HTTP/1.0" {
        return Err(invalid_data("Invalid HTTP version"));
    }

    if !is_connect && (uri.starts_with('/') || uri == "*") {
        let (host, port) = extract_host_header(headers).unwrap_or_default();
        return Ok(HttpRequest {
            method,
            version: version.to_string(),
            host,
            port,
            path_and_query: uri.to_string(),
            is_https: false,
            is_origin_form: true,
        });
    }

    let parseable_uri = if !is_connect && !uri.contains("://") {
        format!("http://{uri}")
    } else if is_connect && !uri.starts_with("https://") {
        format!("https://{uri}")
    } else {
        uri.to_string()
    };

    let (host, port, path_and_query) = parse_uri(&parseable_uri, is_connect)?;
    Ok(HttpRequest {
        method,
        version: version.to_string(),
        host,
        port,
        path_and_query,
        is_https: is_connect,
        is_origin_form: false,
    })
}

fn is_valid_http_method(method: &str) -> bool {
    !method.is_empty()
        && method.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(
                    b,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

fn parse_uri(uri: &str, is_connect: bool) -> io::Result<(String, u16, String)> {
    log::debug!("parsing uri: {uri}");
    let parsed = Url::parse(uri).map_err(|_| invalid_data("Invalid URI"))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| invalid_data("Invalid host"))?;
    let port = parsed
        .port_or_known_default()
        .unwrap_or(if is_connect { 443 } else { 80 });
    let mut path_and_query = parsed.path().to_string();
    if path_and_query.is_empty() {
        path_and_query.push('/');
    }
    if let Some(q) = parsed.query() {
        path_and_query.push('?');
        path_and_query.push_str(q);
    }
    Ok((host.to_string(), port, path_and_query))
}

pub fn extract_host_header(headers: &str) -> Option<(String, u16)> {
    let value = header_value(headers, "host")?;
    let parsed = Url::parse(&format!("http://{value}")).ok()?;
    let host = parsed.host_str()?.to_string();
    let port = parsed.port_or_known_default().unwrap_or(80);
    Some((host, port))
}

pub fn header_value<'a>(headers: &'a str, name: &str) -> Option<&'a str> {
    for line in headers.split("\r\n") {
        let Some((k, v)) = line.split_once(':') else {
            continue;
        };
        if k.trim().eq_ignore_ascii_case(name) {
            return Some(v.trim());
        }
    }
    None
}

/// Verifies `Proxy-Authorization: Basic <base64(user:pass)>` against configured credentials.
pub fn verify_basic_auth(headers: &str, credentials: &[Credential]) -> bool {
    let Some(value) = header_value(headers, "proxy-authorization") else {
        return false;
    };
    let mut parts = value.splitn(2, char::is_whitespace);
    let Some(scheme) = parts.next() else {
        return false;
    };
    let Some(encoded) = parts.next() else {
        return false;
    };
    if !scheme.eq_ignore_ascii_case("basic") {
        return false;
    }
    let Ok(decoded) = BASE64.decode(encoded.trim()) else {
        return false;
    };
    let Ok(pair) = std::str::from_utf8(&decoded) else {
        return false;
    };
    let Some((user, pass)) = pair.split_once(':') else {
        return false;
    };
    credentials
        .iter()
        .any(|c| c.username == user && c.password == pass)
}

/// Formats the plain-HTTP request line + headers for forwarding to the origin server,
/// converting absolute-form URIs to origin-form and stripping proxy-only headers.
pub fn format_upstream_request_head(req: &HttpRequest, headers: &str) -> String {
    let mut out = format!("{} {} {}\r\n", req.method, req.path_and_query, req.version);
    for line in headers.split("\r\n") {
        if line.is_empty() {
            continue;
        }
        if let Some((name, _)) = line.split_once(':') {
            let name = name.trim();
            if name.eq_ignore_ascii_case("proxy-authorization")
                || name.eq_ignore_ascii_case("proxy-connection")
            {
                continue;
            }
        }
        out.push_str(line);
        out.push_str("\r\n");
    }
    out.push_str("\r\n");
    out
}

fn invalid_data(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(line: &str) -> io::Result<HttpRequest> {
        parse_http_request(line)
    }

    #[test]
    fn get_with_absolute_uri() {
        let req = parse("GET http://example.com/path?a=1 HTTP/1.1\r\n").unwrap();
        assert_eq!(req.method, "GET");
        assert_eq!(req.host, "example.com");
        assert_eq!(req.port, 80);
        assert_eq!(req.path_and_query, "/path?a=1");
        assert_eq!(req.version, "HTTP/1.1");
        assert!(!req.is_https);
        assert!(!req.is_origin_form);
    }

    #[test]
    fn get_without_scheme_gets_http_prefix() {
        let req = parse("GET example.com:8080/x HTTP/1.0\r\n").unwrap();
        assert_eq!(req.host, "example.com");
        assert_eq!(req.port, 8080);
        assert_eq!(req.path_and_query, "/x");
        assert_eq!(req.version, "HTTP/1.0");
        assert!(!req.is_https);
    }

    #[test]
    fn supports_all_http_methods() {
        for method in ["POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "TRACE"] {
            let line = format!("{method} http://api.example.com/v1/items HTTP/1.1\r\n");
            let req = parse(&line).unwrap();
            assert_eq!(req.method, method);
            assert_eq!(req.host, "api.example.com");
            assert_eq!(req.path_and_query, "/v1/items");
            assert!(!req.is_https);
        }
    }

    #[test]
    fn connect_with_port() {
        let req = parse("CONNECT example.com:8443 HTTP/1.1\r\n").unwrap();
        assert_eq!(req.host, "example.com");
        assert_eq!(req.port, 8443);
        assert!(req.is_https);
    }

    #[test]
    fn connect_without_port_defaults_to_443() {
        let req = parse("CONNECT example.com HTTP/1.1\r\n").unwrap();
        assert_eq!(req.host, "example.com");
        assert_eq!(req.port, 443);
        assert!(req.is_https);
    }

    #[test]
    fn method_is_case_insensitive() {
        let req = parse("connect example.com:443 HTTP/1.1\r\n").unwrap();
        assert!(req.is_https);
    }

    #[test]
    fn origin_form_extracts_host_header() {
        let req = parse_http_request_with_headers(
            "GET /proxy.pac HTTP/1.1\r\n",
            "Host: 127.0.0.1:8000\r\n\r\n",
        )
        .unwrap();
        assert!(req.is_origin_form);
        assert_eq!(req.path_and_query, "/proxy.pac");
        assert_eq!(req.host, "127.0.0.1");
        assert_eq!(req.port, 8000);
    }

    #[test]
    fn verifies_basic_proxy_auth() {
        let creds = vec![Credential::parse("alice:s3cr3t").unwrap()];
        let token = BASE64.encode("alice:s3cr3t");
        let headers = format!("Host: a\r\nProxy-Authorization: Basic {token}\r\n\r\n");
        assert!(verify_basic_auth(&headers, &creds));

        let bad_token = BASE64.encode("alice:wrong");
        let bad_headers = format!("Host: a\r\nProxy-Authorization: Basic {bad_token}\r\n\r\n");
        assert!(!verify_basic_auth(&bad_headers, &creds));
        assert!(!verify_basic_auth("Host: a\r\n\r\n", &creds));
    }

    #[test]
    fn upstream_request_strips_proxy_headers_and_converts_uri() {
        let req = parse("POST http://example.com/submit?x=1 HTTP/1.1\r\n").unwrap();
        let formatted = format_upstream_request_head(
            &req,
            "Host: example.com\r\nProxy-Authorization: Basic dXNlcjpwYXNz\r\nProxy-Connection: keep-alive\r\nContent-Length: 4\r\n\r\n",
        );
        assert_eq!(
            formatted,
            "POST /submit?x=1 HTTP/1.1\r\nHost: example.com\r\nContent-Length: 4\r\n\r\n"
        );
    }

    #[test]
    fn rejects_missing_crlf() {
        let err = parse("GET http://a/ HTTP/1.1\n").err().unwrap();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn rejects_invalid_method_token() {
        let err = parse("G@T http://a/ HTTP/1.1\r\n").err().unwrap();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert_eq!(err.to_string(), "Invalid HTTP method");
    }

    #[test]
    fn rejects_unsupported_version() {
        let err = parse("GET http://a/ HTTP/2.0\r\n").err().unwrap();
        assert_eq!(err.to_string(), "Invalid HTTP version");
    }

    #[test]
    fn rejects_missing_parts_without_panicking() {
        for line in ["GET\r\n", "GET http://a/\r\n", "\r\n"] {
            let err = parse(line).err().unwrap();
            assert_eq!(err.kind(), io::ErrorKind::InvalidData, "line: {line:?}");
        }
    }

    #[test]
    fn rejects_invalid_uri() {
        let err = parse("GET http:// HTTP/1.1\r\n").err().unwrap();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }
}

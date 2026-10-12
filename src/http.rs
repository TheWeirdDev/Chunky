use tokio::io;
use url::Url;

pub struct HttpRequest {
    pub version: String,
    pub host: String,
    pub port: u16,
    pub is_https: bool,
}

pub fn parse_http_request(line: &str) -> io::Result<HttpRequest> {
    if !line.ends_with("\r\n") {
        return Err(invalid_data("Invalid HTTP request"));
    }
    let mut parts = line.split_whitespace();
    let (Some(method), Some(uri), Some(version)) = (parts.next(), parts.next(), parts.next())
    else {
        return Err(invalid_data("Invalid HTTP request"));
    };

    let method = method.to_uppercase();
    let is_get = method == "GET";
    let is_connect = method == "CONNECT";
    if !is_get && !is_connect {
        return Err(invalid_data("Invalid HTTP method"));
    }
    if version != "HTTP/1.1" && version != "HTTP/1.0" {
        return Err(invalid_data("Invalid HTTP version"));
    }

    let uri = if is_get && !uri.starts_with("http://") {
        format!("http://{uri}")
    } else if is_connect && !uri.starts_with("https://") {
        format!("https://{uri}")
    } else {
        uri.to_string()
    };
    let (host, port) = parse_uri(&uri)?;
    Ok(HttpRequest {
        version: version.to_string(),
        host,
        port,
        is_https: is_connect,
    })
}

fn parse_uri(uri: &str) -> io::Result<(String, u16)> {
    log::debug!("parsing uri: {uri}");
    let parsed = Url::parse(uri).map_err(|_| invalid_data("Invalid URI"))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| invalid_data("Invalid host"))?;
    let port = parsed.port_or_known_default().unwrap_or(80);
    Ok((host.to_string(), port))
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
        let req = parse("GET http://example.com/path HTTP/1.1\r\n").unwrap();
        assert_eq!(req.host, "example.com");
        assert_eq!(req.port, 80);
        assert_eq!(req.version, "HTTP/1.1");
        assert!(!req.is_https);
    }

    #[test]
    fn get_without_scheme_gets_http_prefix() {
        let req = parse("GET example.com:8080/x HTTP/1.0\r\n").unwrap();
        assert_eq!(req.host, "example.com");
        assert_eq!(req.port, 8080);
        assert_eq!(req.version, "HTTP/1.0");
        assert!(!req.is_https);
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
    fn rejects_missing_crlf() {
        let err = parse("GET http://a/ HTTP/1.1\n").err().unwrap();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn rejects_unsupported_method() {
        let err = parse("POST http://a/ HTTP/1.1\r\n").err().unwrap();
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

use tokio::io;
use url::Url;

pub struct HttpRequest {
    pub version: String,
    pub host: String,
    pub port: u16,
    pub is_https: bool,
}

pub async fn parse_http_request(line: &str) -> io::Result<HttpRequest> {
    if !line.ends_with("\r\n") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Invalid HTTP request",
        ));
    }
    let mut parts = line.split_whitespace();
    let method = parts.next().unwrap().to_uppercase();
    let is_get = method == "GET";
    let is_connect = method == "CONNECT";
    if !is_get && !is_connect {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Invalid HTTP method",
        ));
    }

    let uri = parts.next().unwrap();
    let version = parts.next().unwrap();

    if version != "HTTP/1.1" && version != "HTTP/1.0" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Invalid HTTP version",
        ));
    }
    let mut uri = uri.to_string();
    if is_get && !uri.starts_with("http://") {
        uri = format!("http://{uri}");
    }
    if is_connect && !uri.starts_with("https://") {
        uri = format!("https://{uri}");
    }
    let (host, port) = parse_uri(uri.as_str())?;
    Ok(HttpRequest {
        version: version.to_string(),
        host,
        port,
        is_https: is_connect,
    })
}

fn parse_uri(uri: &str) -> io::Result<(String, u16)> {
    log::debug!("parsing uri: {uri}");
    let parsed = Url::parse(uri);
    if parsed.is_err() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid URI"));
    }
    let parsed = parsed.unwrap();
    let host = parsed.host_str();
    let port = parsed.port_or_known_default();
    if host.is_none() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid host"));
    }
    Ok((host.unwrap().to_string(), port.unwrap_or(80)))
}

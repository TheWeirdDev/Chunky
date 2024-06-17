use tokio::io::{self, AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::tcp::OwnedWriteHalf;
use tokio::net::TcpStream;
use tokio::{pin, select};

use crate::http::HttpRequest;
use crate::{http, CachedResolver};

pub async fn proxy(
    stream: TcpStream,
    resolver: &CachedResolver,
    chunk_size: usize,
) -> io::Result<()> {
    let addr = stream.peer_addr()?;
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut req_line = String::new();
    let mut headers = String::new();
    while req_line.is_empty() {
        reader.read_line(&mut req_line).await?;
        while reader.read_line(&mut headers).await? > 2 {}
    }

    let HttpRequest {
        version,
        host,
        port,
        is_https,
    } = http::parse_http_request(&req_line).await?;

    log::debug!("new connection from {addr:?} to {host}:{port}");
    let host = resolver.lookup_ip(host).await?;
    log::debug!("resolved host: {host}");

    let upstream = TcpStream::connect((host, port)).await?;

    let (upstream_reader, mut upstream_writer) = upstream.into_split();
    let upstream_reader = BufReader::new(upstream_reader);

    if is_https {
        writer
            .write_all(format!("{version} 200 OK\r\n\r\n").as_bytes())
            .await?;
    } else {
        upstream_writer.write_all(req_line.as_bytes()).await?;
        upstream_writer.write_all(headers.as_bytes()).await?;
    }

    let i1: tokio::task::JoinHandle<io::Result<()>> = tokio::spawn(async move {
        forward(reader, upstream_writer, is_https, "client", chunk_size).await
    });
    let i2: tokio::task::JoinHandle<io::Result<()>> = tokio::spawn(async move {
        forward(upstream_reader, writer, is_https, "server", chunk_size).await
    });
    select! {
        r = i1 => r??,
        r = i2 => r??,
    }

    Ok(())
}

async fn forward<TReader: AsyncRead>(
    reader: BufReader<TReader>,
    mut writer: OwnedWriteHalf,
    mut needs_chunking: bool,
    name: &str,
    chunk_size: usize,
) -> io::Result<()> {
    pin!(reader);
    loop {
        if needs_chunking {
            needs_chunking = false;

            // Read the first 3 bytes to check if it's a TLS handshake
            let mut header = vec![0; 3];
            reader.read_exact(&mut header).await?;
            match header[..] {
                // TLS handshake header
                [0x16, 0x03, ver] if ver < 4_u8 => {
                    log::debug!("Found TLS handshake")
                }
                _ => {
                    log::debug!("Found the first non-handshake packet, forwarding as-is");
                    writer.write_all(&header).await?;
                    continue;
                }
            }

            let length = reader.read_u16().await?;

            let mut buf = vec![0; length as usize];
            reader.read_exact(&mut buf).await?;
            let chunks = buf.chunks(chunk_size).collect::<Vec<_>>();
            let mut message = Vec::with_capacity(chunks.len() * 5 + buf.len());
            // Turn each chunk into a TLS record
            for c in chunks {
                message.extend(&header);
                // Last chunk might be smaller than chunk_size
                message.extend((c.len() as u16).to_be_bytes());
                message.extend(c);
            }
            writer.write_all(&message).await?;
            continue;
        }

        // Forwaring the rest without chunking
        let mut buf = vec![0; 4096];
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            writer.shutdown().await?;
            log::debug!("Connection closed by {name}");
            break;
        }
        writer.write_all(&buf[..n]).await?;
    }
    Ok(())
}

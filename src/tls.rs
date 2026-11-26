/// TLS record header: content type 0x16 (handshake), major version 3, minor version < 4.
pub fn is_tls_handshake(header: &[u8; 3]) -> bool {
    header[0] == 0x16 && header[1] == 0x03 && header[2] < 4
}

/// Splits a TLS record payload into one or more TLS records.
///
/// When `split_sni` is true, parses the ClientHello to place split boundaries inside the SNI
/// hostname (`0x0000`) and ECH (`0xfe0d`) extensions, and also caps each record at `chunk_size`.
pub fn split_tls_record(
    header: &[u8; 3],
    payload: &[u8],
    chunk_size: usize,
    split_sni: bool,
) -> Vec<Vec<u8>> {
    let chunk_size = chunk_size.max(1);
    if payload.is_empty() {
        return vec![build_record(header, payload)];
    }

    let mut boundaries = if split_sni {
        find_client_hello_split_points(payload)
    } else {
        Vec::new()
    };
    boundaries.push(payload.len());

    let mut records = Vec::new();
    let mut start = 0;
    for end in boundaries {
        if end <= start || end > payload.len() {
            continue;
        }
        for chunk in payload[start..end].chunks(chunk_size) {
            records.push(build_record(header, chunk));
        }
        start = end;
    }
    records
}

fn build_record(header: &[u8; 3], chunk: &[u8]) -> Vec<u8> {
    let mut record = Vec::with_capacity(header.len() + 2 + chunk.len());
    record.extend_from_slice(header);
    record.extend_from_slice(&(chunk.len() as u16).to_be_bytes());
    record.extend_from_slice(chunk);
    record
}

/// Parses a TLS ClientHello handshake payload and returns byte offsets inside SNI and ECH
/// extensions where splitting breaks DPI inspection.
pub fn find_client_hello_split_points(payload: &[u8]) -> Vec<usize> {
    let mut points = Vec::new();
    // Handshake: msg_type (1) == 0x01, length (3), legacy_version (2), random (32)
    if payload.len() < 38 || payload[0] != 0x01 {
        return points;
    }
    let mut pos = 38;

    // session_id (1-byte length)
    let Some(&sid_len) = payload.get(pos) else {
        return points;
    };
    pos += 1 + sid_len as usize;

    // cipher_suites (2-byte length)
    let Some(cs_len) = read_u16(payload, pos) else {
        return points;
    };
    pos += 2 + cs_len as usize;

    // compression_methods (1-byte length)
    let Some(&comp_len) = payload.get(pos) else {
        return points;
    };
    pos += 1 + comp_len as usize;

    // extensions_total_len (2-byte length)
    let Some(ext_total_len) = read_u16(payload, pos) else {
        return points;
    };
    pos += 2;
    let ext_end = pos.saturating_add(ext_total_len as usize).min(payload.len());

    while pos + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([payload[pos], payload[pos + 1]]);
        let ext_len = u16::from_be_bytes([payload[pos + 2], payload[pos + 3]]) as usize;
        let data_start = pos + 4;
        let data_end = data_start + ext_len;
        if data_end > ext_end {
            break;
        }

        match ext_type {
            // server_name (SNI)
            0x0000 => {
                if let Some(split) = find_sni_hostname_midpoint(payload, data_start, data_end) {
                    points.push(split);
                } else if ext_len >= 2 {
                    points.push(data_start + ext_len / 2);
                }
            }
            // encrypted_client_hello (ECH)
            0xfe0d if ext_len >= 2 => {
                points.push(data_start + ext_len / 2);
            }
            _ => {}
        }

        pos = data_end;
    }

    points.sort_unstable();
    points.dedup();
    points.retain(|&p| p > 0 && p < payload.len());
    points
}

fn find_sni_hostname_midpoint(payload: &[u8], start: usize, end: usize) -> Option<usize> {
    if start + 2 > end {
        return None;
    }
    let list_len = read_u16(payload, start)? as usize;
    let list_end = (start + 2 + list_len).min(end);
    let mut cur = start + 2;
    while cur + 3 <= list_end {
        let name_type = payload[cur];
        let name_len = read_u16(payload, cur + 1)? as usize;
        let name_start = cur + 3;
        let name_end = name_start + name_len;
        if name_end > list_end {
            break;
        }
        if name_type == 0 && name_len >= 2 {
            return Some(name_start + name_len / 2);
        }
        cur = name_end;
    }
    None
}

fn read_u16(buf: &[u8], offset: usize) -> Option<u16> {
    let hi = *buf.get(offset)?;
    let lo = *buf.get(offset + 1)?;
    Some(u16::from_be_bytes([hi, lo]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_test_client_hello(sni: &str, ech_payload: Option<&[u8]>) -> Vec<u8> {
        let mut exts = Vec::new();
        // SNI extension (0x0000)
        let mut sni_data = Vec::new();
        sni_data.extend_from_slice(&((sni.len() + 3) as u16).to_be_bytes());
        sni_data.push(0);
        sni_data.extend_from_slice(&(sni.len() as u16).to_be_bytes());
        sni_data.extend_from_slice(sni.as_bytes());
        exts.extend_from_slice(&0x0000u16.to_be_bytes());
        exts.extend_from_slice(&(sni_data.len() as u16).to_be_bytes());
        exts.extend_from_slice(&sni_data);

        if let Some(ech) = ech_payload {
            exts.extend_from_slice(&0xfe0du16.to_be_bytes());
            exts.extend_from_slice(&(ech.len() as u16).to_be_bytes());
            exts.extend_from_slice(ech);
        }

        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[0xaa; 32]); // random
        body.push(0); // session id len
        body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // cipher suite
        body.extend_from_slice(&[0x01, 0x00]); // compression
        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend_from_slice(&exts);

        let mut hs = vec![0x01];
        hs.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        hs.extend_from_slice(&body);
        hs
    }

    #[test]
    fn detects_tls_handshake_header() {
        assert!(is_tls_handshake(&[0x16, 0x03, 0x01]));
        assert!(is_tls_handshake(&[0x16, 0x03, 0x03]));
        assert!(!is_tls_handshake(&[0x17, 0x03, 0x03]));
        assert!(!is_tls_handshake(&[0x16, 0x03, 0x04]));
        assert!(!is_tls_handshake(&[0x16, 0x02, 0x01]));
    }

    #[test]
    fn finds_sni_and_ech_split_points() {
        let sni = "blocked.example.com";
        let ech = [0x11u8; 32];
        let payload = build_test_client_hello(sni, Some(&ech));
        let points = find_client_hello_split_points(&payload);
        assert_eq!(points.len(), 2);

        let sni_pos = payload.windows(sni.len()).position(|w| w == sni.as_bytes()).unwrap();
        assert_eq!(points[0], sni_pos + sni.len() / 2);

        let ech_pos = payload.windows(ech.len()).position(|w| w == ech).unwrap();
        assert_eq!(points[1], ech_pos + ech.len() / 2);
    }

    #[test]
    fn split_tls_record_breaks_sni_even_when_chunk_size_is_large() {
        let sni = "blocked.example.com";
        let payload = build_test_client_hello(sni, None);
        let records = split_tls_record(&[0x16, 0x03, 0x01], &payload, 500, true);
        assert_eq!(records.len(), 2);

        // Neither record contains the full SNI string intact.
        for rec in &records {
            assert!(!rec.windows(sni.len()).any(|w| w == sni.as_bytes()));
        }

        // Reassembling the record payloads yields the exact original ClientHello.
        let mut reassembled = Vec::new();
        for rec in &records {
            assert_eq!(&rec[..3], &[0x16, 0x03, 0x01]);
            let len = u16::from_be_bytes([rec[3], rec[4]]) as usize;
            assert_eq!(len, rec.len() - 5);
            reassembled.extend_from_slice(&rec[5..]);
        }
        assert_eq!(reassembled, payload);
    }
}

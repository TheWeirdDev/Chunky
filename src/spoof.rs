//! SNI spoofing. Before the real ClientHello is sent, a fake ClientHello (with a different SNI) is
//! injected so DPI sees the decoy SNI while the server ignores or drops it:
//! - Default: injected with a sequence number just before the real stream (server treats as old data).
//! - `--fake-ttl`: injected in-sequence with a low IP TTL / IPv6 hop limit so it expires before the server.
//! - `--fake-bad-checksum`: injected in-sequence with a corrupted TCP checksum so the server drops it.
//!
//! Packets are captured and injected with `AF_PACKET` sockets per egress interface, which needs `CAP_NET_RAW`.

use std::collections::{HashMap, HashSet};
use std::ffi::CString;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use pnet_packet::ethernet::{EtherTypes, EthernetPacket};
use pnet_packet::ip::IpNextHeaderProtocols;
use pnet_packet::ipv4::{self, Ipv4Packet, MutableIpv4Packet};
use pnet_packet::ipv6::{Ipv6Packet, MutableIpv6Packet};
use pnet_packet::tcp::{self, MutableTcpPacket, TcpFlags, TcpPacket};
use pnet_packet::Packet;
use tokio::net::{TcpSocket, TcpStream};
use tokio::sync::oneshot;
use tokio::time::timeout;

pub const ETHERNET_HEADER_LEN: usize = 14;
const IPV6_HEADER_LEN: usize = 40;
/// How long to wait for the fake ClientHello to be sent before giving up on the connection.
const FAKE_SEND_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Clone, Debug)]
pub struct SpoofOptions {
    pub fake_sni: String,
    pub fake_ttl: Option<u8>,
    pub fake_bad_checksum: bool,
}

/// Identifies a connection across interfaces and address families.
#[derive(Hash, PartialEq, Eq, Clone, Copy, Debug)]
struct ConnKey {
    local_ip: IpAddr,
    local_port: u16,
    remote_ip: IpAddr,
    remote_port: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Syn,
    SynAck,
    Ack,
    FakeAck,
}

/// What the sniffer should do after seeing a frame.
#[derive(Debug, PartialEq, Eq)]
pub enum Step {
    Ignore,
    /// Send this frame, which is the fake ClientHello.
    Inject(Vec<u8>),
    /// The server acknowledged the fake ClientHello. The real data may now be sent.
    Done,
    Fail(&'static str),
}

/// The handshake state machine for one connection. It is pure, so it can be tested without a
/// network.
pub struct Handshake {
    local_ip: IpAddr,
    remote_ip: IpAddr,
    local_port: u16,
    remote_port: u16,
    l2_len: usize,
    fake_record: Vec<u8>,
    fake_ttl: Option<u8>,
    fake_bad_checksum: bool,
    syn_seq: u32,
    syn_ack_seq: u32,
    phase: Phase,
}

struct ParsedPacket<'a> {
    src_ip: IpAddr,
    dst_ip: IpAddr,
    tcp: TcpPacket<'a>,
}

fn parse_l3_tcp<'a>(frame: &'a [u8], l2_len: usize) -> Option<ParsedPacket<'a>> {
    if l2_len == ETHERNET_HEADER_LEN {
        let eth = EthernetPacket::new(frame)?;
        let ethertype = eth.get_ethertype();
        let payload = frame.get(ETHERNET_HEADER_LEN..)?;
        match ethertype {
            EtherTypes::Ipv4 => parse_ipv4_tcp(payload),
            EtherTypes::Ipv6 => parse_ipv6_tcp(payload),
            _ => None,
        }
    } else if l2_len == 0 {
        let version = frame.first().map(|b| b >> 4)?;
        match version {
            4 => parse_ipv4_tcp(frame),
            6 => parse_ipv6_tcp(frame),
            _ => None,
        }
    } else {
        None
    }
}

fn parse_ipv4_tcp(payload: &[u8]) -> Option<ParsedPacket<'_>> {
    let ip = Ipv4Packet::new(payload)?;
    if ip.get_next_level_protocol() != IpNextHeaderProtocols::Tcp {
        return None;
    }
    let ip_hl = ip.get_header_length() as usize * 4;
    if ip_hl < 20 || payload.len() < ip_hl {
        return None;
    }
    let tcp = TcpPacket::new(&payload[ip_hl..])?;
    Some(ParsedPacket {
        src_ip: IpAddr::V4(ip.get_source()),
        dst_ip: IpAddr::V4(ip.get_destination()),
        tcp,
    })
}

fn parse_ipv6_tcp(payload: &[u8]) -> Option<ParsedPacket<'_>> {
    let ip = Ipv6Packet::new(payload)?;
    if ip.get_next_header() != IpNextHeaderProtocols::Tcp || payload.len() < IPV6_HEADER_LEN {
        return None;
    }
    let tcp = TcpPacket::new(&payload[IPV6_HEADER_LEN..])?;
    Some(ParsedPacket {
        src_ip: IpAddr::V6(ip.get_source()),
        dst_ip: IpAddr::V6(ip.get_destination()),
        tcp,
    })
}

impl Handshake {
    pub fn new(
        local: SocketAddr,
        remote: SocketAddr,
        l2_len: usize,
        fake_record: Vec<u8>,
        fake_ttl: Option<u8>,
        fake_bad_checksum: bool,
    ) -> Self {
        Self {
            local_ip: local.ip(),
            remote_ip: remote.ip(),
            local_port: local.port(),
            remote_port: remote.port(),
            l2_len,
            fake_record,
            fake_ttl,
            fake_bad_checksum,
            syn_seq: 0,
            syn_ack_seq: 0,
            phase: Phase::Syn,
        }
    }

    pub fn handle_frame(&mut self, frame: &[u8]) -> Step {
        let Some(pkt) = parse_l3_tcp(frame, self.l2_len) else {
            return Step::Ignore;
        };
        let Some(outbound) = self.direction(&pkt) else {
            return Step::Ignore;
        };
        let flags = pkt.tcp.get_flags();
        let is_syn = flags & TcpFlags::SYN != 0;
        let is_ack = flags & TcpFlags::ACK != 0;
        let is_rst = flags & TcpFlags::RST != 0;
        let seq = pkt.tcp.get_sequence();
        let ack = pkt.tcp.get_acknowledgement();
        let has_payload = !pkt.tcp.payload().is_empty();

        match self.phase {
            Phase::Syn => {
                if outbound && is_syn && !is_ack {
                    self.syn_seq = seq;
                    self.phase = Phase::SynAck;
                }
                Step::Ignore
            }
            Phase::SynAck => {
                if is_rst && !outbound {
                    return Step::Fail("connection reset during handshake");
                }
                if !outbound && is_syn && is_ack && ack == self.syn_seq.wrapping_add(1) {
                    self.syn_ack_seq = seq;
                    self.phase = Phase::Ack;
                }
                Step::Ignore
            }
            Phase::Ack => {
                let handshake_ack = outbound
                    && is_ack
                    && !is_syn
                    && !has_payload
                    && seq == self.syn_seq.wrapping_add(1)
                    && ack == self.syn_ack_seq.wrapping_add(1);
                if handshake_ack {
                    let in_sequence = self.fake_ttl.is_some() || self.fake_bad_checksum;
                    let fake_seq = if in_sequence {
                        self.syn_seq.wrapping_add(1)
                    } else {
                        fake_seq_for(self.syn_seq, self.fake_record.len())
                    };
                    let fake_ack = self.syn_ack_seq.wrapping_add(1);
                    self.phase = Phase::FakeAck;
                    return match build_fake_frame(
                        frame,
                        self.l2_len,
                        &self.fake_record,
                        fake_seq,
                        fake_ack,
                        self.fake_ttl,
                        self.fake_bad_checksum,
                    ) {
                        Some(injected) => Step::Inject(injected),
                        None => Step::Fail("could not build fake frame"),
                    };
                }
                Step::Ignore
            }
            Phase::FakeAck => {
                if is_rst && !outbound {
                    return Step::Fail("connection reset while waiting for fake ACK");
                }
                let fake_acked = !outbound
                    && is_ack
                    && !is_syn
                    && !has_payload
                    && seq == self.syn_ack_seq.wrapping_add(1)
                    && ack == self.syn_seq.wrapping_add(1);
                if fake_acked {
                    return Step::Done;
                }
                Step::Ignore
            }
        }
    }

    /// Returns `Some(true)` for a packet we sent on this connection, `Some(false)` for one we
    /// received, and `None` for anything else.
    fn direction(&self, pkt: &ParsedPacket<'_>) -> Option<bool> {
        let outbound = pkt.src_ip == self.local_ip
            && pkt.tcp.get_source() == self.local_port
            && pkt.dst_ip == self.remote_ip
            && pkt.tcp.get_destination() == self.remote_port;
        let inbound = pkt.src_ip == self.remote_ip
            && pkt.tcp.get_source() == self.remote_port
            && pkt.dst_ip == self.local_ip
            && pkt.tcp.get_destination() == self.local_port;
        match (outbound, inbound) {
            (true, _) => Some(true),
            (_, true) => Some(false),
            _ => None,
        }
    }
}

/// Sequence number of the fake segment: it ends exactly where the real stream starts.
fn fake_seq_for(syn_seq: u32, fake_len: usize) -> u32 {
    syn_seq.wrapping_add(1).wrapping_sub(fake_len as u32)
}

/// Builds the injected frame. Copies the L2/L3/L4 headers of `frame` (our handshake ACK),
/// replaces the payload with `payload`, updates sequence/ACK/TTL/checksums.
fn build_fake_frame(
    frame: &[u8],
    l2_len: usize,
    payload: &[u8],
    seq: u32,
    ack: u32,
    fake_ttl: Option<u8>,
    fake_bad_checksum: bool,
) -> Option<Vec<u8>> {
    let version = frame.get(l2_len).map(|b| b >> 4)?;
    match version {
        4 => build_fake_ipv4_frame(
            frame,
            l2_len,
            payload,
            seq,
            ack,
            fake_ttl,
            fake_bad_checksum,
        ),
        6 => build_fake_ipv6_frame(
            frame,
            l2_len,
            payload,
            seq,
            ack,
            fake_ttl,
            fake_bad_checksum,
        ),
        _ => None,
    }
}

fn build_fake_ipv4_frame(
    frame: &[u8],
    l2_len: usize,
    payload: &[u8],
    seq: u32,
    ack: u32,
    fake_ttl: Option<u8>,
    fake_bad_checksum: bool,
) -> Option<Vec<u8>> {
    let (ip_hl, tcp_hl) = {
        let ip = Ipv4Packet::new(frame.get(l2_len..)?)?;
        let ip_hl = ip.get_header_length() as usize * 4;
        let tcp = TcpPacket::new(frame.get(l2_len + ip_hl..)?)?;
        (ip_hl, tcp.get_data_offset() as usize * 4)
    };
    let headers_len = l2_len + ip_hl + tcp_hl;
    if frame.len() < headers_len {
        return None;
    }
    let mut buf = frame[..headers_len].to_vec();
    buf.extend_from_slice(payload);

    let (src, dst) = {
        let mut ip = MutableIpv4Packet::new(&mut buf[l2_len..])?;
        ip.set_total_length((ip_hl + tcp_hl + payload.len()) as u16);
        ip.set_identification(ip.get_identification().wrapping_add(1));
        if let Some(ttl) = fake_ttl {
            ip.set_ttl(ttl);
        }
        (ip.get_source(), ip.get_destination())
    };
    {
        let mut tcp = MutableTcpPacket::new(&mut buf[l2_len + ip_hl..])?;
        tcp.set_sequence(seq);
        tcp.set_acknowledgement(ack);
        tcp.set_flags(tcp.get_flags() | TcpFlags::PSH);
        tcp.set_checksum(0);
    }
    let mut tcp_csum = tcp::ipv4_checksum(&TcpPacket::new(&buf[l2_len + ip_hl..])?, &src, &dst);
    if fake_bad_checksum {
        tcp_csum = tcp_csum.wrapping_add(1);
    }
    MutableTcpPacket::new(&mut buf[l2_len + ip_hl..])?.set_checksum(tcp_csum);

    let ip_csum = ipv4::checksum(&Ipv4Packet::new(&buf[l2_len..])?);
    MutableIpv4Packet::new(&mut buf[l2_len..])?.set_checksum(ip_csum);
    Some(buf)
}

fn build_fake_ipv6_frame(
    frame: &[u8],
    l2_len: usize,
    payload: &[u8],
    seq: u32,
    ack: u32,
    fake_ttl: Option<u8>,
    fake_bad_checksum: bool,
) -> Option<Vec<u8>> {
    let tcp_hl = {
        let ip = Ipv6Packet::new(frame.get(l2_len..)?)?;
        if ip.get_next_header() != IpNextHeaderProtocols::Tcp {
            return None;
        }
        let tcp = TcpPacket::new(frame.get(l2_len + IPV6_HEADER_LEN..)?)?;
        tcp.get_data_offset() as usize * 4
    };
    let headers_len = l2_len + IPV6_HEADER_LEN + tcp_hl;
    if frame.len() < headers_len {
        return None;
    }
    let mut buf = frame[..headers_len].to_vec();
    buf.extend_from_slice(payload);

    let (src, dst) = {
        let mut ip = MutableIpv6Packet::new(&mut buf[l2_len..])?;
        ip.set_payload_length((tcp_hl + payload.len()) as u16);
        if let Some(ttl) = fake_ttl {
            ip.set_hop_limit(ttl);
        }
        (ip.get_source(), ip.get_destination())
    };
    {
        let mut tcp = MutableTcpPacket::new(&mut buf[l2_len + IPV6_HEADER_LEN..])?;
        tcp.set_sequence(seq);
        tcp.set_acknowledgement(ack);
        tcp.set_flags(tcp.get_flags() | TcpFlags::PSH);
        tcp.set_checksum(0);
    }
    let mut tcp_csum = tcp::ipv6_checksum(
        &TcpPacket::new(&buf[l2_len + IPV6_HEADER_LEN..])?,
        &src,
        &dst,
    );
    if fake_bad_checksum {
        tcp_csum = tcp_csum.wrapping_add(1);
    }
    MutableTcpPacket::new(&mut buf[l2_len + IPV6_HEADER_LEN..])?.set_checksum(tcp_csum);
    Some(buf)
}

/// Builds a TLS record holding a ClientHello for `sni`. The random fields are random.
pub fn fake_client_hello(sni: &str) -> Vec<u8> {
    use rand::RngCore;

    let mut rng = rand::thread_rng();
    let mut random = [0u8; 32];
    rng.fill_bytes(&mut random);
    let mut session_id = [0u8; 32];
    rng.fill_bytes(&mut session_id);

    let name = sni.as_bytes();
    let mut server_name = Vec::new();
    server_name.extend_from_slice(&((name.len() + 3) as u16).to_be_bytes());
    server_name.push(0); // host_name
    server_name.extend_from_slice(&(name.len() as u16).to_be_bytes());
    server_name.extend_from_slice(name);

    let mut alpn = Vec::new();
    alpn.extend_from_slice(&[0x00, 0x0c, 0x02, b'h', b'2', 0x08]);
    alpn.extend_from_slice(b"http/1.1");

    let mut exts = Vec::new();
    push_extension(&mut exts, 0x0000, &server_name);
    push_extension(&mut exts, 0x002b, &[0x02, 0x03, 0x04]);
    push_extension(&mut exts, 0x0010, &alpn);

    let mut body = vec![0x03, 0x03];
    body.extend_from_slice(&random);
    body.push(session_id.len() as u8);
    body.extend_from_slice(&session_id);
    body.extend_from_slice(&[0x00, 0x06, 0x13, 0x01, 0x13, 0x02, 0xc0, 0x2f]);
    body.extend_from_slice(&[0x01, 0x00]);
    body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    body.extend_from_slice(&exts);

    let mut handshake = vec![0x01];
    handshake.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    handshake.extend_from_slice(&body);

    let mut record = vec![0x16, 0x03, 0x01];
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);
    record
}

fn push_extension(out: &mut Vec<u8>, ext_type: u16, data: &[u8]) {
    out.extend_from_slice(&ext_type.to_be_bytes());
    out.extend_from_slice(&(data.len() as u16).to_be_bytes());
    out.extend_from_slice(data);
}

/// An `AF_PACKET` socket bound to one interface.
struct RawSocket {
    fd: OwnedFd,
}

impl RawSocket {
    fn open(ifindex: i32) -> io::Result<Self> {
        let proto = (libc::ETH_P_ALL as u16).to_be();
        // SAFETY: plain socket(2) call with constant arguments.
        let raw = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW, proto as i32) };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `raw` is a fresh descriptor that nothing else owns.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };

        // SAFETY: sockaddr_ll is plain old data, so an all-zero value is valid.
        let mut addr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        addr.sll_family = libc::AF_PACKET as u16;
        addr.sll_protocol = proto;
        addr.sll_ifindex = ifindex;
        // SAFETY: `addr` is a valid sockaddr_ll, and the length passed matches it.
        let rc = unsafe {
            libc::bind(
                fd.as_raw_fd(),
                &addr as *const libc::sockaddr_ll as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_ll>() as u32,
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { fd })
    }

    fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        // SAFETY: the pointer and length describe a valid, writable buffer.
        let n = unsafe {
            libc::recv(
                self.fd.as_raw_fd(),
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
                0,
            )
        };
        if n < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(n as usize)
        }
    }

    fn send(&self, frame: &[u8]) -> io::Result<()> {
        // SAFETY: the pointer and length describe a valid, readable buffer.
        let n = unsafe {
            libc::send(
                self.fd.as_raw_fd(),
                frame.as_ptr() as *const libc::c_void,
                frame.len(),
                0,
            )
        };
        if n < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}

type Pending = Arc<Mutex<HashMap<ConnKey, PendingConn>>>;

struct PendingConn {
    handshake: Handshake,
    done: Option<oneshot::Sender<Result<(), &'static str>>>,
}

#[derive(Clone, Debug)]
struct InterfaceInfo {
    name: String,
    index: i32,
    l2_len: usize,
}

/// Runs SNI spoofing for outgoing IPv4 and IPv6 connections across interfaces.
pub struct Spoofer {
    fake_record: Vec<u8>,
    fake_ttl: Option<u8>,
    fake_bad_checksum: bool,
    pending: Pending,
    active_ifaces: Arc<Mutex<HashSet<i32>>>,
}

impl Spoofer {
    /// Starts SNI spoofing. Pre-opens the default interface (when present) to validate `CAP_NET_RAW`.
    pub fn start(options: SpoofOptions) -> io::Result<Self> {
        if !has_cap_net_raw() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "CAP_NET_RAW is required for SNI spoofing",
            ));
        }

        let spoofer = Self {
            fake_record: fake_client_hello(&options.fake_sni),
            fake_ttl: options.fake_ttl,
            fake_bad_checksum: options.fake_bad_checksum,
            pending: Arc::new(Mutex::new(HashMap::new())),
            active_ifaces: Arc::new(Mutex::new(HashSet::new())),
        };

        if let Ok(iface) = default_route_interface() {
            if let Ok(index) = interface_index(&iface) {
                spoofer.ensure_sniffer(&InterfaceInfo {
                    name: iface.clone(),
                    index,
                    l2_len: interface_l2_len(&iface),
                })?;
                log::info!("SNI spoofing ready on default interface {iface} (fake SNI {})", options.fake_sni);
            }
        } else {
            log::info!("SNI spoofing ready (dynamic interface detection, fake SNI {})", options.fake_sni);
        }

        Ok(spoofer)
    }

    fn ensure_sniffer(&self, iface: &InterfaceInfo) -> io::Result<()> {
        let mut active = self.active_ifaces.lock().unwrap_or_else(|e| e.into_inner());
        if active.contains(&iface.index) {
            return Ok(());
        }
        let socket = RawSocket::open(iface.index)?;
        let pending = self.pending.clone();
        let active_ifaces = self.active_ifaces.clone();
        let ifindex = iface.index;
        let l2_len = iface.l2_len;
        let name = iface.name.clone();

        std::thread::Builder::new()
            .name(format!("sni-spoof-{name}"))
            .spawn(move || {
                run_sniffer(socket, l2_len, pending);
                active_ifaces
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .remove(&ifindex);
            })?;
        active.insert(iface.index);
        log::debug!("Started SNI spoof sniffer on {name} (ifindex={ifindex}, l2_len={l2_len})");
        Ok(())
    }

    /// Connects to `remote` (IPv4 or IPv6), injects the fake ClientHello, and returns the stream.
    pub async fn connect(&self, remote: IpAddr, port: u16) -> io::Result<TcpStream> {
        let local_ip = local_ip_for(remote)?;
        let iface = interface_for_local_ip(local_ip)?;
        self.ensure_sniffer(&iface)?;

        let socket = match remote {
            IpAddr::V4(_) => TcpSocket::new_v4()?,
            IpAddr::V6(_) => TcpSocket::new_v6()?,
        };
        socket.bind(SocketAddr::new(local_ip, 0))?;
        let local_port = socket.local_addr()?.port();

        let key = ConnKey {
            local_ip,
            local_port,
            remote_ip: remote,
            remote_port: port,
        };
        let (done_tx, done_rx) = oneshot::channel();
        let handshake = Handshake::new(
            SocketAddr::new(local_ip, local_port),
            SocketAddr::new(remote, port),
            iface.l2_len,
            self.fake_record.clone(),
            self.fake_ttl,
            self.fake_bad_checksum,
        );
        self.lock_pending().insert(
            key,
            PendingConn {
                handshake,
                done: Some(done_tx),
            },
        );

        let result = async move {
            let stream = socket.connect(SocketAddr::new(remote, port)).await?;
            match timeout(FAKE_SEND_TIMEOUT, done_rx).await {
                Ok(Ok(Ok(()))) => Ok(stream),
                Ok(Ok(Err(reason))) => {
                    Err(io::Error::new(io::ErrorKind::ConnectionAborted, reason))
                }
                _ => Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "fake ClientHello was not sent",
                )),
            }
        }
        .await;
        if result.is_err() {
            self.lock_pending().remove(&key);
        }
        result
    }

    fn lock_pending(&self) -> std::sync::MutexGuard<'_, HashMap<ConnKey, PendingConn>> {
        self.pending.lock().unwrap_or_else(|e| e.into_inner())
    }
}

fn run_sniffer(socket: RawSocket, l2_len: usize, pending: Pending) {
    let mut buf = vec![0u8; 65575];
    loop {
        let n = match socket.recv(&mut buf) {
            Ok(n) => n,
            Err(e) => {
                log::error!("SNI spoof capture failed: {e}");
                if matches!(
                    e.raw_os_error(),
                    Some(libc::ENODEV | libc::ENXIO | libc::EBADF | libc::ENETDOWN)
                ) {
                    break;
                }
                continue;
            }
        };
        let frame = &buf[..n];
        let Some((k_out, k_in)) = keys_for_frame(frame, l2_len) else {
            continue;
        };
        let mut map = pending.lock().unwrap_or_else(|e| e.into_inner());
        let matched_key = if map.contains_key(&k_out) {
            k_out
        } else if map.contains_key(&k_in) {
            k_in
        } else {
            continue;
        };
        let Some(conn) = map.get_mut(&matched_key) else {
            continue;
        };
        let step = conn.handshake.handle_frame(frame);
        if step != Step::Ignore {
            log::debug!("spoof {matched_key:?}: {step:?}");
        }
        match step {
            Step::Ignore => {}
            Step::Inject(injected) => {
                log::debug!(
                    "spoof {matched_key:?}: sending fake frame of {} bytes",
                    injected.len()
                );
                let sent = socket.send(&injected);
                if let Err(e) = &sent {
                    log::error!("SNI spoof injection failed: {e}");
                }
                if let Some(done) = conn.done.take() {
                    let _ = done.send(sent.map_err(|_| "fake ClientHello could not be sent"));
                }
                map.remove(&matched_key);
            }
            Step::Done => {
                if let Some(done) = conn.done.take() {
                    let _ = done.send(Ok(()));
                }
                map.remove(&matched_key);
            }
            Step::Fail(reason) => {
                if let Some(done) = conn.done.take() {
                    let _ = done.send(Err(reason));
                }
                map.remove(&matched_key);
            }
        }
    }
}

/// Returns candidate `(outbound_key, inbound_key)` for a captured frame.
fn keys_for_frame(frame: &[u8], l2_len: usize) -> Option<(ConnKey, ConnKey)> {
    let pkt = parse_l3_tcp(frame, l2_len)?;
    let out = ConnKey {
        local_ip: pkt.src_ip,
        local_port: pkt.tcp.get_source(),
        remote_ip: pkt.dst_ip,
        remote_port: pkt.tcp.get_destination(),
    };
    let inb = ConnKey {
        local_ip: pkt.dst_ip,
        local_port: pkt.tcp.get_destination(),
        remote_ip: pkt.src_ip,
        remote_port: pkt.tcp.get_source(),
    };
    Some((out, inb))
}

/// Bit of CAP_NET_RAW in the capability masks.
const CAP_NET_RAW: u32 = 13;

/// Whether this process has CAP_NET_RAW in its effective capability set.
pub fn has_cap_net_raw() -> bool {
    std::fs::read_to_string("/proc/self/status")
        .map(|status| cap_effective_has(&status, CAP_NET_RAW))
        .unwrap_or(false)
}

/// Reads the `CapEff` mask from the text of /proc/self/status and tests one bit.
fn cap_effective_has(status: &str, bit: u32) -> bool {
    status
        .lines()
        .find_map(|line| line.strip_prefix("CapEff:"))
        .and_then(|hex| u64::from_str_radix(hex.trim(), 16).ok())
        .is_some_and(|mask| mask & (1 << bit) != 0)
}

/// Name of the interface that carries the default IPv4 route, from /proc/net/route.
fn default_route_interface() -> io::Result<String> {
    let table = std::fs::read_to_string("/proc/net/route")?;
    table
        .lines()
        .skip(1)
        .find_map(|line| {
            let mut fields = line.split_whitespace();
            let iface = fields.next()?;
            let destination = fields.next()?;
            (destination == "00000000").then(|| iface.to_string())
        })
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no default route found"))
}

/// Our source IP address for routing towards `probe` (IPv4 or IPv6). No packets are sent.
fn local_ip_for(probe: IpAddr) -> io::Result<IpAddr> {
    let bind_addr = match probe {
        IpAddr::V4(_) => "0.0.0.0:0",
        IpAddr::V6(_) => "[::]:0",
    };
    let socket = UdpSocket::bind(bind_addr)?;
    socket.connect(SocketAddr::new(probe, 9))?;
    Ok(socket.local_addr()?.ip())
}

fn interface_for_local_ip(local_ip: IpAddr) -> io::Result<InterfaceInfo> {
    match local_ip {
        IpAddr::V4(v4) => {
            if let Some(name) = ipv4_interface_name(v4)? {
                let index = interface_index(&name)?;
                let l2_len = interface_l2_len(&name);
                return Ok(InterfaceInfo {
                    name,
                    index,
                    l2_len,
                });
            }
        }
        IpAddr::V6(v6) => {
            if let Ok(table) = std::fs::read_to_string("/proc/net/if_inet6") {
                if let Some(info) = parse_if_inet6(&table, v6) {
                    return Ok(info);
                }
            }
        }
    }
    let name = default_route_interface()?;
    let index = interface_index(&name)?;
    let l2_len = interface_l2_len(&name);
    Ok(InterfaceInfo {
        name,
        index,
        l2_len,
    })
}

/// Finds the interface name holding `target` IPv4 using `SIOCGIFCONF` (works on Linux & Android API 21+).
fn ipv4_interface_name(target: Ipv4Addr) -> io::Result<Option<String>> {
    let sock = UdpSocket::bind("0.0.0.0:0")?;
    let mut buf = vec![0u8; 64 * std::mem::size_of::<libc::ifreq>()];
    // SAFETY: `ifconf` is plain old data; we initialize both `ifc_len` and `ifc_ifcu.ifcu_buf` before ioctl.
    let mut ifc: libc::ifconf = unsafe { std::mem::zeroed() };
    ifc.ifc_len = buf.len() as libc::c_int;
    ifc.ifc_ifcu.ifcu_buf = buf.as_mut_ptr() as *mut libc::c_char;
    // SAFETY: `ifc` points to a valid writable buffer of `buf.len()` bytes.
    let rc = unsafe { libc::ioctl(sock.as_raw_fd(), libc::SIOCGIFCONF as _, &mut ifc) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    let filled = (ifc.ifc_len as usize).min(buf.len());
    let entry_size = std::mem::size_of::<libc::ifreq>();
    for chunk in buf[..filled].chunks_exact(entry_size) {
        // SAFETY: `chunk` has exact size and we read unaligned `ifreq`.
        let req: libc::ifreq = unsafe { std::ptr::read_unaligned(chunk.as_ptr() as *const libc::ifreq) };
        // SAFETY: accessing sockaddr inside union; check sa_family before reading sockaddr_in.
        let family = unsafe { req.ifr_ifru.ifru_addr.sa_family };
        if family as i32 == libc::AF_INET {
            // SAFETY: sa_family == AF_INET guarantees sockaddr_in layout.
            let addr_in: libc::sockaddr_in = unsafe {
                *(&req.ifr_ifru.ifru_addr as *const libc::sockaddr as *const libc::sockaddr_in)
            };
            let ip = Ipv4Addr::from(u32::from_be(addr_in.sin_addr.s_addr));
            if ip == target {
                let name_bytes: Vec<u8> = req
                    .ifr_name
                    .iter()
                    .map(|&c| c as u8)
                    .take_while(|&b| b != 0)
                    .collect();
                if let Ok(name) = String::from_utf8(name_bytes) {
                    return Ok(Some(name));
                }
            }
        }
    }
    Ok(None)
}

fn parse_if_inet6(table: &str, target: Ipv6Addr) -> Option<InterfaceInfo> {
    for line in table.lines() {
        let mut cols = line.split_whitespace();
        let hex_ip = cols.next()?;
        let hex_idx = cols.next()?;
        let _prefix = cols.next()?;
        let _scope = cols.next()?;
        let _flags = cols.next()?;
        let name = cols.next()?;
        let Ok(raw_ip) = u128::from_str_radix(hex_ip, 16) else {
            continue;
        };
        if Ipv6Addr::from(raw_ip) == target {
            let index = i32::from_str_radix(hex_idx, 16).ok()?;
            let l2_len = interface_l2_len(name);
            return Some(InterfaceInfo {
                name: name.to_string(),
                index,
                l2_len,
            });
        }
    }
    None
}

/// Determines link-layer header length (`14` for Ethernet/loopback, `0` for raw IP / TUN).
fn interface_l2_len(name: &str) -> usize {
    if let Ok(sock) = UdpSocket::bind("0.0.0.0:0") {
        if let Ok(cname) = CString::new(name) {
            // SAFETY: zeroed `ifreq` is valid and name is copied bounded to `IFNAMSIZ`.
            let mut req: libc::ifreq = unsafe { std::mem::zeroed() };
            let bytes = cname.as_bytes_with_nul();
            let copy_len = bytes.len().min(req.ifr_name.len());
            for (dst, &src) in req.ifr_name[..copy_len].iter_mut().zip(&bytes[..copy_len]) {
                *dst = src as libc::c_char;
            }
            // SAFETY: valid ioctl `SIOCGIFHWADDR` on `ifreq`.
            if unsafe { libc::ioctl(sock.as_raw_fd(), libc::SIOCGIFHWADDR as _, &mut req) } == 0 {
                // SAFETY: `ifru_hwaddr` holds the link-layer family after `SIOCGIFHWADDR`.
                let hatype = unsafe { req.ifr_ifru.ifru_hwaddr.sa_family };
                return match hatype {
                    libc::ARPHRD_ETHER | libc::ARPHRD_LOOPBACK => ETHERNET_HEADER_LEN,
                    _ => 0,
                };
            }
        }
    }
    ETHERNET_HEADER_LEN
}

fn interface_index(name: &str) -> io::Result<i32> {
    let cname = CString::new(name).map_err(io::Error::other)?;
    // SAFETY: `cname` is a valid, NUL-terminated string for the duration of the call.
    let index = unsafe { libc::if_nametoindex(cname.as_ptr()) };
    if index == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(index as i32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pnet_packet::ethernet::MutableEthernetPacket;
    use pnet_packet::MutablePacket;

    const LOCAL_V4: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 10);
    const REMOTE_V4: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 20);
    const LOCAL_V6: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 10);
    const REMOTE_V6: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 20);
    const LPORT: u16 = 40000;
    const RPORT: u16 = 443;
    const FAKE_SNI: &str = "www.speedtest.net";

    /// Builds an Ethernet/IPv4/TCP frame with correct checksums.
    fn frame_v4(
        src: (Ipv4Addr, u16),
        dst: (Ipv4Addr, u16),
        seq: u32,
        ack: u32,
        flags: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let tcp_len = 20 + payload.len();
        let mut buf = vec![0u8; ETHERNET_HEADER_LEN + 20 + tcp_len];
        {
            let mut eth = MutableEthernetPacket::new(&mut buf).unwrap();
            eth.set_ethertype(EtherTypes::Ipv4);
        }
        {
            let mut ip = MutableIpv4Packet::new(&mut buf[ETHERNET_HEADER_LEN..]).unwrap();
            ip.set_version(4);
            ip.set_header_length(5);
            ip.set_total_length((20 + tcp_len) as u16);
            ip.set_ttl(64);
            ip.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
            ip.set_source(src.0);
            ip.set_destination(dst.0);
        }
        {
            let mut tcp = MutableTcpPacket::new(&mut buf[ETHERNET_HEADER_LEN + 20..]).unwrap();
            tcp.set_source(src.1);
            tcp.set_destination(dst.1);
            tcp.set_sequence(seq);
            tcp.set_acknowledgement(ack);
            tcp.set_data_offset(5);
            tcp.set_flags(flags);
            tcp.set_window(65535);
            tcp.payload_mut().copy_from_slice(payload);
        }
        let tcp_csum = tcp::ipv4_checksum(
            &TcpPacket::new(&buf[ETHERNET_HEADER_LEN + 20..]).unwrap(),
            &src.0,
            &dst.0,
        );
        MutableTcpPacket::new(&mut buf[ETHERNET_HEADER_LEN + 20..])
            .unwrap()
            .set_checksum(tcp_csum);
        let ip_csum = ipv4::checksum(&Ipv4Packet::new(&buf[ETHERNET_HEADER_LEN..]).unwrap());
        MutableIpv4Packet::new(&mut buf[ETHERNET_HEADER_LEN..])
            .unwrap()
            .set_checksum(ip_csum);
        buf
    }

    fn frame_v6(
        src: (Ipv6Addr, u16),
        dst: (Ipv6Addr, u16),
        seq: u32,
        ack: u32,
        flags: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let tcp_len = 20 + payload.len();
        let mut buf = vec![0u8; ETHERNET_HEADER_LEN + IPV6_HEADER_LEN + tcp_len];
        {
            let mut eth = MutableEthernetPacket::new(&mut buf).unwrap();
            eth.set_ethertype(EtherTypes::Ipv6);
        }
        {
            let mut ip = MutableIpv6Packet::new(&mut buf[ETHERNET_HEADER_LEN..]).unwrap();
            ip.set_version(6);
            ip.set_payload_length(tcp_len as u16);
            ip.set_hop_limit(64);
            ip.set_next_header(IpNextHeaderProtocols::Tcp);
            ip.set_source(src.0);
            ip.set_destination(dst.0);
        }
        {
            let mut tcp =
                MutableTcpPacket::new(&mut buf[ETHERNET_HEADER_LEN + IPV6_HEADER_LEN..]).unwrap();
            tcp.set_source(src.1);
            tcp.set_destination(dst.1);
            tcp.set_sequence(seq);
            tcp.set_acknowledgement(ack);
            tcp.set_data_offset(5);
            tcp.set_flags(flags);
            tcp.set_window(65535);
            tcp.payload_mut().copy_from_slice(payload);
        }
        let tcp_csum = tcp::ipv6_checksum(
            &TcpPacket::new(&buf[ETHERNET_HEADER_LEN + IPV6_HEADER_LEN..]).unwrap(),
            &src.0,
            &dst.0,
        );
        MutableTcpPacket::new(&mut buf[ETHERNET_HEADER_LEN + IPV6_HEADER_LEN..])
            .unwrap()
            .set_checksum(tcp_csum);
        buf
    }

    fn outbound_v4(seq: u32, ack: u32, flags: u16, payload: &[u8]) -> Vec<u8> {
        frame_v4((LOCAL_V4, LPORT), (REMOTE_V4, RPORT), seq, ack, flags, payload)
    }

    fn inbound_v4(seq: u32, ack: u32, flags: u16) -> Vec<u8> {
        frame_v4((REMOTE_V4, RPORT), (LOCAL_V4, LPORT), seq, ack, flags, &[])
    }

    fn new_handshake_v4(fake_ttl: Option<u8>, fake_bad_checksum: bool) -> Handshake {
        Handshake::new(
            SocketAddr::new(IpAddr::V4(LOCAL_V4), LPORT),
            SocketAddr::new(IpAddr::V4(REMOTE_V4), RPORT),
            ETHERNET_HEADER_LEN,
            fake_client_hello(FAKE_SNI),
            fake_ttl,
            fake_bad_checksum,
        )
    }

    fn run_to_injection_v4(hs: &mut Handshake, syn_seq: u32, server_isn: u32) -> Vec<u8> {
        assert_eq!(
            hs.handle_frame(&outbound_v4(syn_seq, 0, TcpFlags::SYN, &[])),
            Step::Ignore
        );
        assert_eq!(
            hs.handle_frame(&inbound_v4(
                server_isn,
                syn_seq + 1,
                TcpFlags::SYN | TcpFlags::ACK
            )),
            Step::Ignore
        );
        match hs.handle_frame(&outbound_v4(
            syn_seq + 1,
            server_isn + 1,
            TcpFlags::ACK,
            &[],
        )) {
            Step::Inject(injected) => injected,
            other => panic!("expected injection, got {other:?}"),
        }
    }

    #[test]
    fn cap_effective_mask_is_parsed() {
        let with_net_raw = "Name:\tchunky\nCapEff:\t0000000000002000\nCapBnd:\t0\n";
        assert!(cap_effective_has(with_net_raw, CAP_NET_RAW));
        let without = "CapEff:\t0000000000000000\n";
        assert!(!cap_effective_has(without, CAP_NET_RAW));
        assert!(!cap_effective_has("no mask here", CAP_NET_RAW));
    }

    #[test]
    fn fake_client_hello_is_a_tls_record_with_the_sni() {
        let record = fake_client_hello(FAKE_SNI);
        assert_eq!(&record[..3], &[0x16, 0x03, 0x01]);
        assert_eq!(
            u16::from_be_bytes([record[3], record[4]]) as usize,
            record.len() - 5
        );
        assert_eq!(record[5], 0x01); // ClientHello
        assert!(record
            .windows(FAKE_SNI.len())
            .any(|w| w == FAKE_SNI.as_bytes()));
    }

    #[test]
    fn injects_fake_before_the_real_stream_and_completes() {
        let mut hs = new_handshake_v4(None, false);
        let syn_seq = 1000;
        let server_isn = 5000;
        let injected = run_to_injection_v4(&mut hs, syn_seq, server_isn);

        let eth = EthernetPacket::new(&injected).unwrap();
        let ip = Ipv4Packet::new(eth.payload()).unwrap();
        let tcp = TcpPacket::new(ip.payload()).unwrap();
        let fake = fake_client_hello(FAKE_SNI);
        assert_eq!(tcp.payload().len(), fake.len());
        assert_eq!(&tcp.payload()[..3], &[0x16, 0x03, 0x01]);
        assert_eq!(tcp.get_sequence(), fake_seq_for(syn_seq, fake.len()));
        assert_eq!(tcp.get_acknowledgement(), server_isn + 1);
        assert_eq!(tcp.get_flags(), TcpFlags::ACK | TcpFlags::PSH);
        assert_eq!(ip.get_ttl(), 64);
        assert_eq!(ipv4::checksum(&ip), ip.get_checksum());
        assert_eq!(
            tcp::ipv4_checksum(&tcp, &LOCAL_V4, &REMOTE_V4),
            tcp.get_checksum()
        );

        let ack = inbound_v4(server_isn + 1, syn_seq + 1, TcpFlags::ACK);
        assert_eq!(hs.handle_frame(&ack), Step::Done);
    }

    #[test]
    fn fake_ttl_and_bad_checksum_use_in_sequence_and_modify_headers() {
        let mut hs = new_handshake_v4(Some(3), true);
        let syn_seq = 1000;
        let server_isn = 5000;
        let injected = run_to_injection_v4(&mut hs, syn_seq, server_isn);

        let eth = EthernetPacket::new(&injected).unwrap();
        let ip = Ipv4Packet::new(eth.payload()).unwrap();
        let tcp = TcpPacket::new(ip.payload()).unwrap();
        assert_eq!(ip.get_ttl(), 3);
        assert_eq!(ip.get_checksum(), ipv4::checksum(&ip));
        assert_eq!(tcp.get_sequence(), syn_seq + 1);
        assert_ne!(
            tcp.get_checksum(),
            tcp::ipv4_checksum(&tcp, &LOCAL_V4, &REMOTE_V4)
        );
    }

    #[test]
    fn ipv6_handshake_injects_with_hop_limit_and_checksum() {
        let mut hs = Handshake::new(
            SocketAddr::new(IpAddr::V6(LOCAL_V6), LPORT),
            SocketAddr::new(IpAddr::V6(REMOTE_V6), RPORT),
            ETHERNET_HEADER_LEN,
            fake_client_hello(FAKE_SNI),
            Some(4),
            false,
        );
        let syn_seq = 2000;
        let server_isn = 7000;
        assert_eq!(
            hs.handle_frame(&frame_v6(
                (LOCAL_V6, LPORT),
                (REMOTE_V6, RPORT),
                syn_seq,
                0,
                TcpFlags::SYN,
                &[],
            )),
            Step::Ignore
        );
        assert_eq!(
            hs.handle_frame(&frame_v6(
                (REMOTE_V6, RPORT),
                (LOCAL_V6, LPORT),
                server_isn,
                syn_seq + 1,
                TcpFlags::SYN | TcpFlags::ACK,
                &[],
            )),
            Step::Ignore
        );
        let injected = match hs.handle_frame(&frame_v6(
            (LOCAL_V6, LPORT),
            (REMOTE_V6, RPORT),
            syn_seq + 1,
            server_isn + 1,
            TcpFlags::ACK,
            &[],
        )) {
            Step::Inject(frame) => frame,
            other => panic!("expected injection, got {other:?}"),
        };

        let eth = EthernetPacket::new(&injected).unwrap();
        assert_eq!(eth.get_ethertype(), EtherTypes::Ipv6);
        let ip = Ipv6Packet::new(eth.payload()).unwrap();
        let tcp = TcpPacket::new(ip.payload()).unwrap();
        assert_eq!(ip.get_hop_limit(), 4);
        assert_eq!(tcp.get_sequence(), syn_seq + 1);
        assert_eq!(
            tcp.get_checksum(),
            tcp::ipv6_checksum(&tcp, &LOCAL_V6, &REMOTE_V6)
        );
    }

    #[test]
    fn raw_ip_l2_zero_works_for_tun_interfaces() {
        let mut hs = Handshake::new(
            SocketAddr::new(IpAddr::V4(LOCAL_V4), LPORT),
            SocketAddr::new(IpAddr::V4(REMOTE_V4), RPORT),
            0,
            fake_client_hello(FAKE_SNI),
            None,
            false,
        );
        let syn = &outbound_v4(1000, 0, TcpFlags::SYN, &[])[ETHERNET_HEADER_LEN..];
        let synack = &inbound_v4(5000, 1001, TcpFlags::SYN | TcpFlags::ACK)[ETHERNET_HEADER_LEN..];
        let ack = &outbound_v4(1001, 5001, TcpFlags::ACK, &[])[ETHERNET_HEADER_LEN..];
        assert_eq!(hs.handle_frame(syn), Step::Ignore);
        assert_eq!(hs.handle_frame(synack), Step::Ignore);
        let Step::Inject(injected) = hs.handle_frame(ack) else {
            panic!("expected injection");
        };
        let ip = Ipv4Packet::new(&injected).unwrap();
        assert_eq!(ip.get_version(), 4);
        assert_eq!(ipv4::checksum(&ip), ip.get_checksum());
    }

    #[test]
    fn parses_proc_net_if_inet6_entries() {
        let sample = "00000000000000000000000000000001 01 80 10 80       lo\n\
                      20010db800000000000000000000000a 03 40 00 00     eth0\n";
        let info = parse_if_inet6(sample, LOCAL_V6).unwrap();
        assert_eq!(info.name, "eth0");
        assert_eq!(info.index, 3);
    }

    #[test]
    fn wrong_ack_from_server_is_ignored() {
        let mut hs = new_handshake_v4(None, false);
        run_to_injection_v4(&mut hs, 1000, 5000);
        assert_eq!(
            hs.handle_frame(&inbound_v4(5001, 9999, TcpFlags::ACK)),
            Step::Ignore
        );
        assert_eq!(
            hs.handle_frame(&inbound_v4(5001, 1001, TcpFlags::ACK)),
            Step::Done
        );
    }

    #[test]
    fn reset_during_wait_fails() {
        let mut hs = new_handshake_v4(None, false);
        run_to_injection_v4(&mut hs, 1000, 5000);
        assert!(matches!(
            hs.handle_frame(&inbound_v4(5001, 1001, TcpFlags::RST)),
            Step::Fail(_)
        ));
    }

    #[test]
    fn reset_during_handshake_fails() {
        let mut hs = new_handshake_v4(None, false);
        assert_eq!(
            hs.handle_frame(&outbound_v4(1000, 0, TcpFlags::SYN, &[])),
            Step::Ignore
        );
        assert!(matches!(
            hs.handle_frame(&inbound_v4(0, 1001, TcpFlags::RST)),
            Step::Fail(_)
        ));
    }

    #[test]
    fn other_connections_are_ignored() {
        let mut hs = new_handshake_v4(None, false);
        let other = frame_v4(
            (LOCAL_V4, LPORT + 1),
            (REMOTE_V4, RPORT),
            1000,
            0,
            TcpFlags::SYN,
            &[],
        );
        assert_eq!(hs.handle_frame(&other), Step::Ignore);
        assert_eq!(
            hs.handle_frame(&outbound_v4(1001, 5001, TcpFlags::ACK, &[])),
            Step::Ignore
        );
    }

    #[test]
    fn sequence_number_wraps_around_zero() {
        let mut hs = new_handshake_v4(None, false);
        let injected = run_to_injection_v4(&mut hs, 10, 5000);
        let eth = EthernetPacket::new(&injected).unwrap();
        let ip = Ipv4Packet::new(eth.payload()).unwrap();
        let tcp = TcpPacket::new(ip.payload()).unwrap();
        let fake_len = fake_client_hello(FAKE_SNI).len() as u32;
        assert_eq!(tcp.get_sequence(), 11u32.wrapping_sub(fake_len));
    }
}

//! SNI spoofing. Before the real ClientHello is sent, a fake ClientHello (with a different SNI) is
//! injected with a sequence number just before the real stream. The server treats it as old data
//! and drops it, but DPI reads its SNI. The real handshake bytes are never changed, so the TLS
//! handshake stays valid.
//!
//! Packets are captured and injected with an `AF_PACKET` socket, which needs `CAP_NET_RAW`.

use std::collections::HashMap;
use std::ffi::CString;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use pnet_packet::ethernet::EthernetPacket;
use pnet_packet::ip::IpNextHeaderProtocols;
use pnet_packet::ipv4::{self, Ipv4Packet, MutableIpv4Packet};
use pnet_packet::tcp::{self, MutableTcpPacket, TcpFlags, TcpPacket};
use pnet_packet::Packet;
use tokio::net::{TcpSocket, TcpStream};
use tokio::sync::oneshot;
use tokio::time::timeout;

const ETHERNET_HEADER_LEN: usize = 14;
/// How long to wait for the fake ClientHello to be sent before giving up on the connection.
const FAKE_SEND_TIMEOUT: Duration = Duration::from_secs(2);

/// Identifies a connection from our side: our local port plus the remote endpoint.
#[derive(Hash, PartialEq, Eq, Clone, Copy, Debug)]
struct ConnKey {
    local_port: u16,
    remote_ip: Ipv4Addr,
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
    local_ip: Ipv4Addr,
    remote_ip: Ipv4Addr,
    local_port: u16,
    remote_port: u16,
    fake_record: Vec<u8>,
    syn_seq: u32,
    syn_ack_seq: u32,
    phase: Phase,
}

impl Handshake {
    pub fn new(local_ip: Ipv4Addr, remote_ip: Ipv4Addr, local_port: u16, remote_port: u16, fake_record: Vec<u8>) -> Self {
        Self {
            local_ip,
            remote_ip,
            local_port,
            remote_port,
            fake_record,
            syn_seq: 0,
            syn_ack_seq: 0,
            phase: Phase::Syn,
        }
    }

    pub fn handle_frame(&mut self, frame: &[u8]) -> Step {
        let Some(eth) = EthernetPacket::new(frame) else {
            return Step::Ignore;
        };
        let Some(ip) = Ipv4Packet::new(eth.payload()) else {
            return Step::Ignore;
        };
        let Some(tcp) = TcpPacket::new(ip.payload()) else {
            return Step::Ignore;
        };
        let Some(outbound) = self.direction(&ip, &tcp) else {
            return Step::Ignore;
        };
        let flags = tcp.get_flags();
        let is_syn = flags & TcpFlags::SYN != 0;
        let is_ack = flags & TcpFlags::ACK != 0;
        let is_rst = flags & TcpFlags::RST != 0;
        let seq = tcp.get_sequence();
        let ack = tcp.get_acknowledgement();
        let has_payload = !tcp.payload().is_empty();

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
                    let fake_seq = fake_seq_for(self.syn_seq, self.fake_record.len());
                    let fake_ack = self.syn_ack_seq.wrapping_add(1);
                    self.phase = Phase::FakeAck;
                    return match build_fake_frame(frame, &self.fake_record, fake_seq, fake_ack) {
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
}

/// Sequence number of the fake segment: it ends exactly where the real stream starts.
fn fake_seq_for(syn_seq: u32, fake_len: usize) -> u32 {
    syn_seq.wrapping_add(1).wrapping_sub(fake_len as u32)
}

impl Handshake {
    /// Returns `Some(true)` for a packet we sent on this connection, `Some(false)` for one we
    /// received, and `None` for anything else.
    fn direction(&self, ip: &Ipv4Packet, tcp: &TcpPacket) -> Option<bool> {
        let outbound = ip.get_source() == self.local_ip
            && tcp.get_source() == self.local_port
            && ip.get_destination() == self.remote_ip
            && tcp.get_destination() == self.remote_port;
        let inbound = ip.get_source() == self.remote_ip
            && tcp.get_source() == self.remote_port
            && ip.get_destination() == self.local_ip
            && tcp.get_destination() == self.local_port;
        match (outbound, inbound) {
            (true, _) => Some(true),
            (_, true) => Some(false),
            _ => None,
        }
    }
}

/// Builds the injected frame. It copies the headers of `frame` (our handshake ACK), replaces the
/// payload with `payload`, and sets the sequence and ACK numbers, the flags, and both checksums.
fn build_fake_frame(frame: &[u8], payload: &[u8], seq: u32, ack: u32) -> Option<Vec<u8>> {
    let (ip_hl, tcp_hl) = {
        let eth = EthernetPacket::new(frame)?;
        let ip = Ipv4Packet::new(eth.payload())?;
        let tcp = TcpPacket::new(ip.payload())?;
        (ip.get_header_length() as usize * 4, tcp.get_data_offset() as usize * 4)
    };
    let headers_len = ETHERNET_HEADER_LEN + ip_hl + tcp_hl;
    if frame.len() < headers_len {
        return None;
    }
    let mut buf = frame[..headers_len].to_vec();
    buf.extend_from_slice(payload);

    let (src, dst) = {
        let mut ip = MutableIpv4Packet::new(&mut buf[ETHERNET_HEADER_LEN..])?;
        ip.set_total_length((ip_hl + tcp_hl + payload.len()) as u16);
        ip.set_identification(ip.get_identification().wrapping_add(1));
        (ip.get_source(), ip.get_destination())
    };
    {
        let mut tcp = MutableTcpPacket::new(&mut buf[ETHERNET_HEADER_LEN + ip_hl..])?;
        tcp.set_sequence(seq);
        tcp.set_acknowledgement(ack);
        tcp.set_flags(tcp.get_flags() | TcpFlags::PSH);
        tcp.set_checksum(0);
    }
    let tcp_csum = tcp::ipv4_checksum(&TcpPacket::new(&buf[ETHERNET_HEADER_LEN + ip_hl..])?, &src, &dst);
    MutableTcpPacket::new(&mut buf[ETHERNET_HEADER_LEN + ip_hl..])?.set_checksum(tcp_csum);

    let ip_csum = ipv4::checksum(&Ipv4Packet::new(&buf[ETHERNET_HEADER_LEN..])?);
    MutableIpv4Packet::new(&mut buf[ETHERNET_HEADER_LEN..])?.set_checksum(ip_csum);
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
        let n = unsafe { libc::recv(self.fd.as_raw_fd(), buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
        if n < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(n as usize)
        }
    }

    fn send(&self, frame: &[u8]) -> io::Result<()> {
        // SAFETY: the pointer and length describe a valid, readable buffer.
        let n = unsafe { libc::send(self.fd.as_raw_fd(), frame.as_ptr() as *const libc::c_void, frame.len(), 0) };
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

/// Runs SNI spoofing for outgoing connections. Create one with `start`, then call `connect` in
/// place of a plain TCP connect.
pub struct Spoofer {
    local_ip: Ipv4Addr,
    fake_record: Vec<u8>,
    pending: Pending,
}

impl Spoofer {
    /// Starts the sniffer thread on the default-route interface.
    pub fn start(fake_sni: &str) -> io::Result<Self> {
        let iface = default_route_interface()?;
        let local_ip = local_ipv4_for(Ipv4Addr::new(1, 1, 1, 1))?;
        let ifindex = interface_index(&iface)?;
        let socket = RawSocket::open(ifindex)?;

        let pending: Pending = Arc::new(Mutex::new(HashMap::new()));
        let thread_pending = pending.clone();
        std::thread::Builder::new()
            .name("sni-spoof".into())
            .spawn(move || run_sniffer(socket, local_ip, thread_pending))?;

        log::info!("SNI spoofing on {iface} from {local_ip}, fake SNI {fake_sni}");
        Ok(Self {
            local_ip,
            fake_record: fake_client_hello(fake_sni),
            pending,
        })
    }

    /// Connects to `remote`, and returns once the fake ClientHello is on the wire. The server does
    /// not have to answer it: Google's servers drop the fake silently.
    pub async fn connect(&self, remote: IpAddr, port: u16) -> io::Result<TcpStream> {
        let IpAddr::V4(remote_ip) = remote else {
            return Err(io::Error::new(io::ErrorKind::Unsupported, "SNI spoofing supports IPv4 only"));
        };
        let socket = TcpSocket::new_v4()?;
        socket.bind(SocketAddr::new(IpAddr::V4(self.local_ip), 0))?;
        let local_port = socket.local_addr()?.port();

        let key = ConnKey {
            local_port,
            remote_ip,
            remote_port: port,
        };
        let (done_tx, done_rx) = oneshot::channel();
        let handshake = Handshake::new(self.local_ip, remote_ip, local_port, port, self.fake_record.clone());
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
                Ok(Ok(Err(reason))) => Err(io::Error::new(io::ErrorKind::ConnectionAborted, reason)),
                _ => Err(io::Error::new(io::ErrorKind::TimedOut, "fake ClientHello was not sent")),
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

fn run_sniffer(socket: RawSocket, local_ip: Ipv4Addr, pending: Pending) {
    let mut buf = vec![0u8; 65575];
    loop {
        let n = match socket.recv(&mut buf) {
            Ok(n) => n,
            Err(e) => {
                log::error!("SNI spoof capture failed: {e}");
                continue;
            }
        };
        let frame = &buf[..n];
        let Some(key) = key_for_frame(frame, local_ip) else {
            continue;
        };
        let mut map = pending.lock().unwrap_or_else(|e| e.into_inner());
        let Some(conn) = map.get_mut(&key) else {
            continue;
        };
        let step = conn.handshake.handle_frame(frame);
        if step != Step::Ignore {
            log::debug!("spoof {key:?}: {step:?}");
        }
        match step {
            Step::Ignore => {}
            Step::Inject(injected) => {
                log::debug!("spoof {key:?}: sending fake frame of {} bytes", injected.len());
                let sent = socket.send(&injected);
                if let Err(e) = &sent {
                    log::error!("SNI spoof injection failed: {e}");
                }
                if let Some(done) = conn.done.take() {
                    let _ = done.send(sent.map_err(|_| "fake ClientHello could not be sent"));
                }
                map.remove(&key);
            }
            Step::Done => {
                if let Some(done) = conn.done.take() {
                    let _ = done.send(Ok(()));
                }
                map.remove(&key);
            }
            Step::Fail(reason) => {
                if let Some(done) = conn.done.take() {
                    let _ = done.send(Err(reason));
                }
                map.remove(&key);
            }
        }
    }
}

/// Finds the connection a frame belongs to, from our side's point of view.
fn key_for_frame(frame: &[u8], local_ip: Ipv4Addr) -> Option<ConnKey> {
    let eth = EthernetPacket::new(frame)?;
    let ip = Ipv4Packet::new(eth.payload())?;
    if ip.get_next_level_protocol() != IpNextHeaderProtocols::Tcp {
        return None;
    }
    let tcp = TcpPacket::new(ip.payload())?;
    if ip.get_source() == local_ip {
        Some(ConnKey {
            local_port: tcp.get_source(),
            remote_ip: ip.get_destination(),
            remote_port: tcp.get_destination(),
        })
    } else if ip.get_destination() == local_ip {
        Some(ConnKey {
            local_port: tcp.get_destination(),
            remote_ip: ip.get_source(),
            remote_port: tcp.get_source(),
        })
    } else {
        None
    }
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

/// Name of the interface that carries the default route, from /proc/net/route.
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

/// Our IPv4 address for routing towards `probe`. No packets are sent.
fn local_ipv4_for(probe: Ipv4Addr) -> io::Result<Ipv4Addr> {
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.connect(SocketAddr::new(IpAddr::V4(probe), 9))?;
    match socket.local_addr()?.ip() {
        IpAddr::V4(ip) => Ok(ip),
        IpAddr::V6(_) => Err(io::Error::new(io::ErrorKind::Unsupported, "no IPv4 route")),
    }
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
    use pnet_packet::ethernet::{EtherTypes, MutableEthernetPacket};
    use pnet_packet::MutablePacket;

    const LOCAL: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 10);
    const REMOTE: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 20);
    const LPORT: u16 = 40000;
    const RPORT: u16 = 443;
    const FAKE_SNI: &str = "www.speedtest.net";

    /// Builds an Ethernet/IPv4/TCP frame with correct checksums.
    fn frame(src: (Ipv4Addr, u16), dst: (Ipv4Addr, u16), seq: u32, ack: u32, flags: u16, payload: &[u8]) -> Vec<u8> {
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
        let tcp_csum = tcp::ipv4_checksum(&TcpPacket::new(&buf[ETHERNET_HEADER_LEN + 20..]).unwrap(), &src.0, &dst.0);
        MutableTcpPacket::new(&mut buf[ETHERNET_HEADER_LEN + 20..]).unwrap().set_checksum(tcp_csum);
        let ip_csum = ipv4::checksum(&Ipv4Packet::new(&buf[ETHERNET_HEADER_LEN..]).unwrap());
        MutableIpv4Packet::new(&mut buf[ETHERNET_HEADER_LEN..]).unwrap().set_checksum(ip_csum);
        buf
    }

    fn outbound(seq: u32, ack: u32, flags: u16, payload: &[u8]) -> Vec<u8> {
        frame((LOCAL, LPORT), (REMOTE, RPORT), seq, ack, flags, payload)
    }

    fn inbound(seq: u32, ack: u32, flags: u16) -> Vec<u8> {
        frame((REMOTE, RPORT), (LOCAL, LPORT), seq, ack, flags, &[])
    }

    fn new_handshake() -> Handshake {
        Handshake::new(LOCAL, REMOTE, LPORT, RPORT, fake_client_hello(FAKE_SNI))
    }

    /// Runs the SYN, SYN-ACK, and handshake ACK steps, and returns the injected frame.
    fn run_to_injection(hs: &mut Handshake, syn_seq: u32, server_isn: u32) -> Vec<u8> {
        assert_eq!(hs.handle_frame(&outbound(syn_seq, 0, TcpFlags::SYN, &[])), Step::Ignore);
        assert_eq!(
            hs.handle_frame(&inbound(server_isn, syn_seq + 1, TcpFlags::SYN | TcpFlags::ACK)),
            Step::Ignore
        );
        match hs.handle_frame(&outbound(syn_seq + 1, server_isn + 1, TcpFlags::ACK, &[])) {
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
        assert_eq!(u16::from_be_bytes([record[3], record[4]]) as usize, record.len() - 5);
        assert_eq!(record[5], 0x01); // ClientHello
        assert!(record.windows(FAKE_SNI.len()).any(|w| w == FAKE_SNI.as_bytes()));
    }

    #[test]
    fn injects_fake_before_the_real_stream_and_completes() {
        let mut hs = new_handshake();
        let syn_seq = 1000;
        let server_isn = 5000;
        let injected = run_to_injection(&mut hs, syn_seq, server_isn);

        let eth = EthernetPacket::new(&injected).unwrap();
        let ip = Ipv4Packet::new(eth.payload()).unwrap();
        let tcp = TcpPacket::new(ip.payload()).unwrap();
        let fake = fake_client_hello(FAKE_SNI);
        // The random fields differ on every call, so check the shape rather than the bytes.
        assert_eq!(tcp.payload().len(), fake.len());
        assert_eq!(&tcp.payload()[..3], &[0x16, 0x03, 0x01]);
        assert!(tcp.payload().windows(FAKE_SNI.len()).any(|w| w == FAKE_SNI.as_bytes()));
        assert_eq!(tcp.get_sequence(), fake_seq_for(syn_seq, fake.len()));
        assert_eq!(tcp.get_acknowledgement(), server_isn + 1);
        assert_eq!(tcp.get_flags(), TcpFlags::ACK | TcpFlags::PSH);
        assert_eq!(ip.get_source(), LOCAL);
        assert_eq!(ip.get_destination(), REMOTE);
        assert_eq!(ip.get_total_length() as usize, 20 + 20 + fake.len());
        assert_eq!(ipv4::checksum(&ip), ip.get_checksum());
        assert_eq!(tcp::ipv4_checksum(&tcp, &LOCAL, &REMOTE), tcp.get_checksum());

        // The server ACKs the fake packet with its current sequence number.
        let ack = inbound(server_isn + 1, syn_seq + 1, TcpFlags::ACK);
        assert_eq!(hs.handle_frame(&ack), Step::Done);
    }

    #[test]
    fn wrong_ack_from_server_is_ignored() {
        let mut hs = new_handshake();
        run_to_injection(&mut hs, 1000, 5000);
        assert_eq!(hs.handle_frame(&inbound(5001, 9999, TcpFlags::ACK)), Step::Ignore);
        assert_eq!(hs.handle_frame(&inbound(5001, 1001, TcpFlags::ACK)), Step::Done);
    }

    #[test]
    fn reset_during_wait_fails() {
        let mut hs = new_handshake();
        run_to_injection(&mut hs, 1000, 5000);
        assert!(matches!(hs.handle_frame(&inbound(5001, 1001, TcpFlags::RST)), Step::Fail(_)));
    }

    #[test]
    fn reset_during_handshake_fails() {
        let mut hs = new_handshake();
        assert_eq!(hs.handle_frame(&outbound(1000, 0, TcpFlags::SYN, &[])), Step::Ignore);
        assert!(matches!(hs.handle_frame(&inbound(0, 1001, TcpFlags::RST)), Step::Fail(_)));
    }

    #[test]
    fn other_connections_are_ignored() {
        let mut hs = new_handshake();
        let other = frame((LOCAL, LPORT + 1), (REMOTE, RPORT), 1000, 0, TcpFlags::SYN, &[]);
        assert_eq!(hs.handle_frame(&other), Step::Ignore);
        // The SYN for our connection was not seen, so a handshake ACK does nothing.
        assert_eq!(hs.handle_frame(&outbound(1001, 5001, TcpFlags::ACK, &[])), Step::Ignore);
    }

    #[test]
    fn sequence_number_wraps_around_zero() {
        let mut hs = new_handshake();
        let injected = run_to_injection(&mut hs, 10, 5000);
        let eth = EthernetPacket::new(&injected).unwrap();
        let ip = Ipv4Packet::new(eth.payload()).unwrap();
        let tcp = TcpPacket::new(ip.payload()).unwrap();
        let fake_len = fake_client_hello(FAKE_SNI).len() as u32;
        assert_eq!(tcp.get_sequence(), fake_seq_for(10, fake_len as usize));
    }
}

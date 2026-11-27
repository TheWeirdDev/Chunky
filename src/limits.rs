//! Resource limits: file descriptor budget, connection cap, idle/handshake timeouts, and
//! resilient `accept()` handling.

use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use tokio::io::{self, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::{sleep, timeout};

pub const DEFAULT_IDLE_TIMEOUT_SECS: u64 = 300;
pub const DEFAULT_HANDSHAKE_TIMEOUT_SECS: u64 = 30;

/// File descriptors kept free for DNS, the PAC/config files, the sniffer, log output, etc.
const RESERVED_FDS: u64 = 256;
/// Worst-case descriptors per proxied connection (client + upstream + one racing connect attempt).
const FDS_PER_CONNECTION: u64 = 3;
/// Lower bound for the automatically derived connection cap.
const MIN_AUTO_MAX_CONNECTIONS: usize = 16;
/// Never ask for more than this soft limit (the usual `fs.nr_open` default on Linux).
const MAX_SOFT_LIMIT: u64 = 1 << 20;
/// macOS rejects soft limits above `OPEN_MAX`.
#[cfg(target_vendor = "apple")]
const APPLE_OPEN_MAX: u64 = 10_240;

/// Initial and maximum delay between `accept()` retries after a transient failure.
pub const ACCEPT_BACKOFF_INITIAL: Duration = Duration::from_millis(10);
pub const ACCEPT_BACKOFF_MAX: Duration = Duration::from_secs(1);

/// Per-connection limits. A zero duration disables the matching timeout.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConnectionLimits {
    /// Maximum concurrent client connections. `None` derives it from the fd limit, `Some(0)` is unlimited.
    pub max_connections: Option<usize>,
    /// A tunnel with no traffic in either direction for this long is closed.
    pub idle_timeout: Duration,
    /// Time a client has to finish its protocol handshake (SOCKS handshake / HTTP request head).
    pub handshake_timeout: Duration,
}

impl Default for ConnectionLimits {
    fn default() -> Self {
        Self {
            max_connections: None,
            idle_timeout: Duration::from_secs(DEFAULT_IDLE_TIMEOUT_SECS),
            handshake_timeout: Duration::from_secs(DEFAULT_HANDSHAKE_TIMEOUT_SECS),
        }
    }
}

impl ConnectionLimits {
    /// Resolves the connection cap given the process fd limit (`None` when unknown).
    /// Returns `None` for "unlimited".
    pub fn effective_max_connections(&self, nofile_soft: Option<u64>) -> Option<usize> {
        match self.max_connections {
            Some(0) => None,
            Some(n) => Some(n),
            None => nofile_soft.map(auto_max_connections),
        }
    }
}

/// Connection cap that leaves headroom for every connection's descriptors.
pub fn auto_max_connections(nofile_soft: u64) -> usize {
    let budget = nofile_soft.saturating_sub(RESERVED_FDS) / FDS_PER_CONNECTION;
    usize::try_from(budget)
        .unwrap_or(usize::MAX)
        .max(MIN_AUTO_MAX_CONNECTIONS)
}

/// The soft limit to request given the current `(soft, hard)` pair.
fn target_soft_limit(soft: u64, hard: u64) -> u64 {
    #[allow(unused_mut)]
    let mut cap = hard.min(MAX_SOFT_LIMIT);
    #[cfg(target_vendor = "apple")]
    {
        cap = cap.min(APPLE_OPEN_MAX);
    }
    soft.max(cap)
}

/// Raises the soft `RLIMIT_NOFILE` to the hard limit (bounded) and returns the effective soft limit.
/// Returns `None` where descriptors are not limited this way or the limit cannot be queried.
// `rlim_t` is 32-bit on some targets, so the `as u64` casts are needed there.
#[allow(clippy::unnecessary_cast)]
#[cfg(unix)]
pub fn raise_nofile_limit() -> Option<u64> {
    let mut lim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `lim` is a valid, writable rlimit struct.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) } != 0 {
        log::warn!("Could not read the open file limit: {}", io::Error::last_os_error());
        return None;
    }
    let soft = lim.rlim_cur as u64;
    let target = target_soft_limit(soft, lim.rlim_max as u64);
    if target <= soft {
        return Some(soft);
    }
    let wanted = libc::rlimit {
        rlim_cur: target as libc::rlim_t,
        rlim_max: lim.rlim_max,
    };
    // SAFETY: `wanted` is a valid rlimit struct that only raises the soft limit.
    if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &wanted) } != 0 {
        log::warn!(
            "Could not raise the open file limit from {soft} to {target}: {}",
            io::Error::last_os_error()
        );
        return Some(soft);
    }
    log::debug!("Raised the open file limit from {soft} to {target}");
    Some(target)
}

#[cfg(not(unix))]
pub fn raise_nofile_limit() -> Option<u64> {
    None
}

/// Whether an `accept()` failure is expected to clear up on its own (descriptor/memory exhaustion,
/// an aborted handshake) rather than meaning the listener is broken.
pub fn is_transient_accept_error(err: &io::Error) -> bool {
    #[cfg(unix)]
    if let Some(code) = err.raw_os_error() {
        if matches!(
            code,
            libc::EMFILE | libc::ENFILE | libc::ENOBUFS | libc::ENOMEM | libc::EINTR
        ) {
            return true;
        }
    }
    matches!(
        err.kind(),
        io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::Interrupted
            | io::ErrorKind::TimedOut
            | io::ErrorKind::WouldBlock
            | io::ErrorKind::OutOfMemory
    )
}

/// Calls `accept` until it succeeds. Transient errors are logged and retried with exponential
/// backoff (so a descriptor shortage cannot spin the loop or take the proxy down); other errors
/// are returned.
pub async fn accept_with_retry<T, F, Fut>(
    mut accept: F,
    initial_backoff: Duration,
    max_backoff: Duration,
) -> io::Result<T>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = io::Result<T>>,
{
    let mut backoff = initial_backoff;
    loop {
        match accept().await {
            Ok(conn) => return Ok(conn),
            Err(e) if is_transient_accept_error(&e) => {
                log::warn!("accept failed ({e}); retrying in {backoff:?}");
                sleep(backoff).await;
                backoff = (backoff * 2).min(max_backoff);
            }
            Err(e) => return Err(e),
        }
    }
}

/// Runs `fut` under `limit`, failing with `TimedOut` (naming `what`). A zero `limit` disables it.
pub async fn with_timeout<T>(
    limit: Duration,
    what: &str,
    fut: impl Future<Output = io::Result<T>>,
) -> io::Result<T> {
    if limit.is_zero() {
        return fut.await;
    }
    match timeout(limit, fut).await {
        Ok(res) => res,
        Err(_) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            format!("{what} timed out after {limit:?}"),
        )),
    }
}

/// Tracks the last time either direction of a tunnel moved data.
pub struct Activity {
    start: Instant,
    last_ms: AtomicU64,
}

impl Default for Activity {
    fn default() -> Self {
        Self::new()
    }
}

impl Activity {
    pub fn new() -> Self {
        Self {
            start: Instant::now(),
            last_ms: AtomicU64::new(0),
        }
    }

    pub fn touch(&self) {
        self.last_ms
            .store(self.start.elapsed().as_millis() as u64, Ordering::Relaxed);
    }

    pub fn idle_for(&self) -> Duration {
        let now = self.start.elapsed().as_millis() as u64;
        Duration::from_millis(now.saturating_sub(self.last_ms.load(Ordering::Relaxed)))
    }
}

/// Idle policy shared by both directions of one tunnel: a direction waiting for data only gives
/// up once the *whole* tunnel (both directions) has been silent for `idle`.
pub struct IdleGuard<'a> {
    pub idle: Duration,
    pub activity: &'a Activity,
}

impl IdleGuard<'_> {
    pub async fn read<R: AsyncRead + Unpin>(&self, reader: &mut R, buf: &mut [u8]) -> io::Result<usize> {
        if self.idle.is_zero() {
            return reader.read(buf).await;
        }
        loop {
            let remaining = self.idle.saturating_sub(self.activity.idle_for());
            if remaining.is_zero() {
                return Err(self.timed_out());
            }
            match timeout(remaining, reader.read(buf)).await {
                Ok(res) => {
                    let n = res?;
                    self.activity.touch();
                    return Ok(n);
                }
                Err(_) => continue,
            }
        }
    }

    /// Writes all of `data`; a peer that stops reading for `idle` fails the write.
    pub async fn write_all<W: AsyncWrite + Unpin>(&self, writer: &mut W, data: &[u8]) -> io::Result<()> {
        if self.idle.is_zero() {
            return writer.write_all(data).await;
        }
        match timeout(self.idle, writer.write_all(data)).await {
            Ok(res) => {
                res?;
                self.activity.touch();
                Ok(())
            }
            Err(_) => Err(self.timed_out()),
        }
    }

    fn timed_out(&self) -> io::Error {
        io::Error::new(
            io::ErrorKind::TimedOut,
            format!("connection idle for {:?}", self.idle),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use std::sync::Arc;

    #[test]
    fn auto_max_connections_leaves_headroom() {
        assert_eq!(auto_max_connections(1024), (1024 - 256) as usize / 3);
        assert_eq!(auto_max_connections(1_048_576), (1_048_576 - 256) as usize / 3);
    }

    #[test]
    fn auto_max_connections_has_a_floor() {
        assert_eq!(auto_max_connections(0), MIN_AUTO_MAX_CONNECTIONS);
        assert_eq!(auto_max_connections(256), MIN_AUTO_MAX_CONNECTIONS);
    }

    #[test]
    fn effective_max_connections_resolution() {
        let mut limits = ConnectionLimits::default();
        assert_eq!(limits.effective_max_connections(Some(1024)), Some(256));
        assert_eq!(limits.effective_max_connections(None), None);
        limits.max_connections = Some(0);
        assert_eq!(limits.effective_max_connections(Some(1024)), None);
        limits.max_connections = Some(7);
        assert_eq!(limits.effective_max_connections(Some(1024)), Some(7));
    }

    #[test]
    fn target_soft_limit_raises_but_never_lowers() {
        assert!(target_soft_limit(1024, 4096) > 1024);
        assert!(target_soft_limit(1024, 4096) <= 4096);
        assert_eq!(target_soft_limit(50_000, 4096), 50_000);
        assert_eq!(target_soft_limit(4096, 4096), 4096);
        assert!(target_soft_limit(1024, u64::MAX) <= MAX_SOFT_LIMIT);
    }

    #[cfg(unix)]
    #[test]
    fn raise_nofile_limit_never_lowers_the_limit() {
        let mut before = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        // SAFETY: valid, writable rlimit struct.
        assert_eq!(unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut before) }, 0);
        let after = raise_nofile_limit().expect("limit should be readable");
        #[allow(clippy::unnecessary_cast)]
        let before_soft = before.rlim_cur as u64;
        assert!(after >= before_soft);
    }

    #[cfg(unix)]
    #[test]
    fn classifies_accept_errors() {
        assert!(is_transient_accept_error(&io::Error::from_raw_os_error(libc::EMFILE)));
        assert!(is_transient_accept_error(&io::Error::from_raw_os_error(libc::ENFILE)));
        assert!(is_transient_accept_error(&io::Error::from(io::ErrorKind::ConnectionAborted)));
        assert!(!is_transient_accept_error(&io::Error::from_raw_os_error(libc::EBADF)));
        assert!(!is_transient_accept_error(&io::Error::from(io::ErrorKind::PermissionDenied)));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn accept_retries_on_emfile_then_succeeds() {
        let attempts = Arc::new(AtomicUsize::new(0));
        let counter = attempts.clone();
        let accepted = accept_with_retry(
            move || {
                let n = counter.fetch_add(1, Ordering::SeqCst);
                async move {
                    if n < 3 {
                        Err(io::Error::from_raw_os_error(libc::EMFILE))
                    } else {
                        Ok("conn")
                    }
                }
            },
            Duration::from_millis(1),
            Duration::from_millis(4),
        )
        .await
        .unwrap();
        assert_eq!(accepted, "conn");
        assert_eq!(attempts.load(Ordering::SeqCst), 4);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn accept_returns_fatal_errors() {
        let err = accept_with_retry(
            || async { Err::<(), _>(io::Error::from_raw_os_error(libc::EBADF)) },
            Duration::from_millis(1),
            Duration::from_millis(4),
        )
        .await
        .unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::EBADF));
    }

    #[tokio::test]
    async fn with_timeout_fires_and_can_be_disabled() {
        let err = with_timeout(Duration::from_millis(20), "handshake", async {
            sleep(Duration::from_secs(5)).await;
            Ok(())
        })
        .await
        .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        assert!(err.to_string().contains("handshake"));

        let value = with_timeout(Duration::ZERO, "handshake", async {
            sleep(Duration::from_millis(30)).await;
            Ok(7)
        })
        .await
        .unwrap();
        assert_eq!(value, 7);
    }

    #[tokio::test]
    async fn idle_guard_times_out_a_silent_reader() {
        let (mut a, _b) = tokio::io::duplex(64);
        let activity = Activity::new();
        let guard = IdleGuard { idle: Duration::from_millis(50), activity: &activity };
        let mut buf = [0u8; 8];
        let err = guard.read(&mut a, &mut buf).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
    }

    #[tokio::test]
    async fn idle_guard_stays_alive_while_the_other_direction_is_active() {
        let (mut a, _b) = tokio::io::duplex(64);
        let activity = Activity::new();
        let guard = IdleGuard { idle: Duration::from_millis(120), activity: &activity };
        let mut buf = [0u8; 8];
        let read = guard.read(&mut a, &mut buf);
        let keepalive = async {
            for _ in 0..6 {
                sleep(Duration::from_millis(40)).await;
                activity.touch();
            }
        };
        // The read must still be pending after ~240ms of sibling activity (> idle).
        tokio::select! {
            res = read => panic!("read ended early: {res:?}"),
            _ = keepalive => {}
        }
    }

    #[tokio::test]
    async fn idle_guard_passes_data_through() {
        use tokio::io::AsyncWriteExt;
        let (mut a, mut b) = tokio::io::duplex(64);
        let activity = Activity::new();
        let guard = IdleGuard { idle: Duration::from_secs(5), activity: &activity };
        b.write_all(b"hi").await.unwrap();
        let mut buf = [0u8; 8];
        let n = guard.read(&mut a, &mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hi");
        guard.write_all(&mut a, b"yo").await.unwrap();
    }

    #[tokio::test]
    async fn idle_guard_times_out_a_stalled_writer() {
        // A 4-byte pipe nobody reads from: the second write cannot complete.
        let (mut a, _b) = tokio::io::duplex(4);
        let activity = Activity::new();
        let guard = IdleGuard { idle: Duration::from_millis(50), activity: &activity };
        let err = guard.write_all(&mut a, &[0u8; 64]).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
    }
}

use crate::{
    broker::{Broker, Config},
    execution,
    protocol::{Reply, Request, MAX_REQUEST_BYTES},
};
use anyhow::{ensure, Context, Result};
use std::{
    fs,
    io::{BufRead, BufReader, Write},
    os::unix::{
        fs::{MetadataExt, PermissionsExt},
        io::AsRawFd,
        net::{UnixListener, UnixStream},
    },
    path::Path,
    sync::{Arc, Mutex},
    thread,
    time::Duration,
};

pub fn call(socket: &Path, request: &Request) -> Result<serde_json::Value> {
    exchange(
        UnixStream::connect(socket).context("broker unavailable")?,
        request,
    )
}
/// Authenticate the root-owned socket before sending a review reference or proof.
pub fn call_protected(socket: &Path, request: &Request) -> Result<serde_json::Value> {
    use std::os::unix::fs::FileTypeExt;
    crate::broker::protected_path(socket.parent().context("socket has no parent")?, 0)?;
    let metadata = fs::symlink_metadata(socket)?;
    ensure!(
        metadata.file_type().is_socket() && metadata.uid() == 0,
        "expected a root-owned socket"
    );
    let stream = UnixStream::connect(socket).context("broker unavailable")?;
    ensure!(peer_uid(&stream)? == 0, "broker peer must be root");
    exchange(stream, request)
}
fn exchange(mut stream: UnixStream, request: &Request) -> Result<serde_json::Value> {
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    serde_json::to_writer(&mut stream, request)?;
    stream.write_all(b"\n")?;
    let line = read_line(&mut stream, 16 * 1024 * 1024, Duration::from_secs(10))?;
    serde_json::from_slice::<Reply>(&line)?.value()
}
fn read_line(stream: &mut UnixStream, max: usize, timeout: Duration) -> Result<Vec<u8>> {
    let deadline = std::time::Instant::now() + timeout;
    let mut bytes = Vec::new();
    let mut reader = BufReader::new(stream);
    loop {
        let remaining = deadline
            .checked_duration_since(std::time::Instant::now())
            .context("message deadline exceeded")?;
        // macOS can reject timeout changes after peer close despite a buffered reply.
        let mut descriptor = libc::pollfd {
            fd: reader.get_ref().as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let milliseconds = remaining.as_millis().clamp(1, i32::MAX as u128) as i32;
        let ready = unsafe { libc::poll(&mut descriptor, 1, milliseconds) };
        if ready < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error).context("cannot wait for broker message");
        }
        ensure!(ready > 0, "message deadline exceeded");
        let available = reader.fill_buf()?;
        ensure!(!available.is_empty(), "message missing newline");
        let count = available
            .iter()
            .position(|b| *b == b'\n')
            .map_or(available.len(), |n| n + 1);
        ensure!(bytes.len() + count <= max, "message too large");
        bytes.extend_from_slice(&available[..count]);
        reader.consume(count);
        if bytes.last() == Some(&b'\n') {
            return Ok(bytes);
        }
    }
}
#[cfg(target_os = "linux")]
fn peer_uid(stream: &UnixStream) -> Result<u32> {
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut size = std::mem::size_of_val(&cred) as libc::socklen_t;
    ensure!(
        unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                &mut cred as *mut _ as *mut _,
                &mut size,
            )
        } == 0,
        "cannot identify peer"
    );
    Ok(cred.uid)
}
#[cfg(target_os = "macos")]
fn peer_uid(stream: &UnixStream) -> Result<u32> {
    let (mut uid, mut gid) = (0, 0);
    ensure!(
        unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) } == 0,
        "cannot identify peer"
    );
    Ok(uid)
}
pub fn serve(config: Config, development: bool) -> Result<()> {
    serve_mode(config, development, Dispatch::Execute)
}
#[cfg(feature = "native-receipt-lab")]
pub fn serve_receipts(config: Config, development: bool) -> Result<()> {
    serve_mode(config, development, Dispatch::ReceiptOnly)
}
enum Dispatch {
    Execute,
    #[cfg(feature = "native-receipt-lab")]
    ReceiptOnly,
}
fn serve_mode(config: Config, development: bool, dispatch: Dispatch) -> Result<()> {
    let broker = Broker::open(config.clone(), development)?;
    let parent = config.socket.parent().context("socket has no parent")?;
    if !development {
        crate::broker::protected_path(parent, 0)?;
    }
    let m = fs::metadata(parent)?;
    ensure!(
        m.mode() & 0o022 == 0,
        "socket parent must not be group/world writable"
    );
    if config.socket.exists() {
        ensure!(
            UnixStream::connect(&config.socket).is_err(),
            "broker already listening"
        );
        let m = fs::symlink_metadata(&config.socket)?;
        use std::os::unix::fs::FileTypeExt;
        ensure!(
            m.file_type().is_socket() && m.uid() == unsafe { libc::geteuid() },
            "refusing to unlink foreign socket"
        );
        fs::remove_file(&config.socket)?;
    }
    let listener = UnixListener::bind(&config.socket)?;
    if !development {
        use std::os::unix::ffi::OsStrExt;
        let path = std::ffi::CString::new(config.socket.as_os_str().as_bytes())?;
        ensure!(
            unsafe { libc::chown(path.as_ptr(), 0, config.socket_gid) } == 0,
            "could not set socket group"
        );
    }
    fs::set_permissions(&config.socket, fs::Permissions::from_mode(0o660))?;
    // No execution occurs while opening the state store. Startup recovery is committed first.
    let shared = Arc::new(Mutex::new(broker));
    for stream in listener.incoming() {
        let mut stream = stream?;
        // Requests are bounded and handled serially, so connections cannot create unbounded threads.
        let result = (|| -> Result<_> {
            stream.set_write_timeout(Some(Duration::from_secs(2)))?;
            let uid = peer_uid(&stream)?;
            ensure!(
                uid == config.agent_uid || uid == config.approver_uid,
                "peer not authorized"
            );
            let bytes = read_line(&mut stream, MAX_REQUEST_BYTES, Duration::from_secs(2))?;
            let request = serde_json::from_slice(&bytes)?;
            shared
                .lock()
                .map_err(|_| anyhow::anyhow!("broker state poisoned"))?
                .handle_current(request, uid)
        })();
        let (reply, job) = match result {
            Ok(v) => v,
            Err(e) => (Reply::error(format!("{e:#}")), None),
        };
        let (reply, job) = match &dispatch {
            Dispatch::Execute => (reply, job),
            #[cfg(feature = "native-receipt-lab")]
            Dispatch::ReceiptOnly => {
                let mut reply = reply;
                if let Reply::Ok { value, .. } = &mut reply {
                    if let Some(value) = value.as_object_mut() {
                        value.insert("receipt_only".into(), true.into());
                    }
                }
                drop(job);
                (reply, None)
            }
        };
        if let Some(job) = job {
            let state = Arc::clone(&shared);
            thread::spawn(move || {
                let id = job.envelope.id.clone();
                let details = state
                    .lock()
                    .map_err(|_| anyhow::anyhow!("broker state poisoned"))
                    .and_then(|mut broker| {
                        broker.running(&id)?;
                        Ok((broker.config.state_dir.clone(), broker.development()))
                    });
                match details {
                    Ok((dir, dev)) => {
                        let outcome =
                            execution::execute(&job.envelope, &dir, dev, job.share_output);
                        if let Ok(mut broker) = state.lock() {
                            if let Err(e) = broker.finish(&id, outcome) {
                                eprintln!("could not record completion: {e}");
                            }
                        }
                    }
                    Err(e) => eprintln!("consumed request could not start: {e}"),
                }
            });
        }
        // A disconnected caller never undoes a consumed approval.
        let _ = serde_json::to_writer(&mut stream, &reply);
        let _ = stream.write_all(b"\n");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn protected_call_rejects_user_socket_before_connecting() {
        assert_ne!(unsafe { libc::geteuid() }, 0);
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("untrusted.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        listener.set_nonblocking(true).unwrap();
        assert!(call_protected(
            &socket,
            &Request::ExecutionStatus {
                id: "test-reference".into()
            }
        )
        .is_err());
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }
    #[test]
    fn buffered_reply_survives_peer_disconnect() {
        let (mut read, mut write) = UnixStream::pair().unwrap();
        write.write_all(b"reply\n").unwrap();
        drop(write);
        assert_eq!(
            read_line(&mut read, 64, Duration::from_millis(50)).unwrap(),
            b"reply\n"
        );
    }
    #[test]
    fn framing_rejects_oversize_incomplete_and_slow_input() {
        for bytes in [b"123456\n".as_slice(), b"{}".as_slice()] {
            let (mut read, mut write) = UnixStream::pair().unwrap();
            write.write_all(bytes).unwrap();
            write.shutdown(std::net::Shutdown::Write).unwrap();
            assert!(read_line(&mut read, 5, Duration::from_millis(50)).is_err());
        }
        let (mut read, _write) = UnixStream::pair().unwrap();
        assert!(read_line(&mut read, 10, Duration::from_millis(20)).is_err());
    }
}

//! An unprivileged, loopback-only byte source for elevated MSI verification.
//!
//! The privileged process never opens a caller-owned filesystem path (including paths that can
//! race into a junction/UNC target). These public release bytes are still untrusted: the OS-side
//! policy independently authenticates them before Windows Installer sees them.

use std::io::{Read, Seek, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

pub(crate) struct Source {
    pub port: u16,
    stopped: Arc<AtomicBool>,
    worker: Option<std::thread::JoinHandle<()>>,
}

impl Source {
    pub fn new(items: &[crate::msi_batch::Item], session: &str) -> Result<Self, String> {
        let mut files = Vec::new();
        for item in items {
            let mut options = std::fs::OpenOptions::new();
            options.read(true);
            #[cfg(windows)]
            {
                use std::os::windows::fs::OpenOptionsExt as _;
                options.share_mode(1);
            }
            files.push(Some(options.open(&item.msi).map_err(|e| format!("couldn't read the downloaded MSI ({e})"))?));
        }
        let listener = TcpListener::bind(("127.0.0.1", 0)).map_err(|e| e.to_string())?;
        let port = listener.local_addr().map_err(|e| e.to_string())?.port();
        listener.set_nonblocking(true).map_err(|e| e.to_string())?;
        let stopped = Arc::new(AtomicBool::new(false));
        let done = stopped.clone();
        let session = session.to_string();
        let worker = std::thread::spawn(move || {
            while !done.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((mut client, _)) => {
                        let _ = client.set_read_timeout(Some(Duration::from_secs(2)));
                        let _ = client.set_write_timeout(Some(Duration::from_secs(2)));
                        let _ = serve(&mut client, &session, &mut files, &done);
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => std::thread::sleep(Duration::from_millis(20)),
                    Err(_) => break,
                }
            }
        });
        Ok(Self { port, stopped, worker: Some(worker) })
    }
}

impl Drop for Source {
    fn drop(&mut self) {
        self.stopped.store(true, Ordering::SeqCst);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn serve(client: &mut TcpStream, session: &str, files: &mut [Option<std::fs::File>], stopped: &AtomicBool) -> std::io::Result<()> {
    let mut header = Vec::new();
    let mut buffer = [0u8; 1024];
    while !header.ends_with(b"\r\n\r\n") {
        let n = client.read(&mut buffer)?;
        if n == 0 || header.len() + n > 8192 || stopped.load(Ordering::SeqCst) {
            return Ok(());
        }
        header.extend_from_slice(&buffer[..n]);
    }
    let line = std::str::from_utf8(&header).ok().and_then(|s| s.lines().next()).unwrap_or_default();
    let index = line
        .strip_prefix(&format!("GET /{session}/"))
        .and_then(|s| s.strip_suffix(" HTTP/1.1"))
        .filter(|s| !s.is_empty() && s.bytes().all(|c| c.is_ascii_digit()))
        .and_then(|s| s.parse::<usize>().ok());
    let Some(mut file) = index.and_then(|i| files.get_mut(i)).and_then(Option::take) else {
        return client.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    };
    let size = file.metadata()?.len();
    file.rewind()?;
    write!(client, "HTTP/1.1 200 OK\r\nContent-Length: {size}\r\nConnection: close\r\n\r\n")?;
    let mut buffer = [0u8; 65536];
    let mut remaining = size;
    while remaining > 0 && !stopped.load(Ordering::SeqCst) {
        let limit = usize::try_from(remaining.min(buffer.len() as u64)).unwrap_or(buffer.len());
        let n = file.read(&mut buffer[..limit])?;
        if n == 0 {
            break;
        }
        client.write_all(&buffer[..n])?;
        remaining = remaining.saturating_sub(n as u64);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_source_serves_only_fixed_session_indices_and_stops_on_drop() {
        let temp = tempfile::tempdir().unwrap();
        let file = temp.path().join("app.msi");
        std::fs::write(&file, b"untrusted package bytes").unwrap();
        let item = crate::msi_batch::Item {
            msi: file,
            sha256: "a".repeat(64),
            destination: None,
            release: crate::elevated::ReleaseIdentity { app: "photocraft".into(), tag: "v0.5.0".into(), asset: "photo.msi".into() },
        };
        let source = Source::new(&[item], "session").unwrap();
        let get = |path: &str| {
            let mut client = TcpStream::connect(("127.0.0.1", source.port)).unwrap();
            client.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
            write!(client, "GET /{path} HTTP/1.1\r\nHost: localhost\r\n\r\n").unwrap();
            let mut response = String::new();
            client.read_to_string(&mut response).unwrap();
            response
        };
        assert!(get("session/0").ends_with("untrusted package bytes"));
        for bad in ["wrong/0", "session/1", "session/../0", "session/0?x=1"] {
            assert!(get(bad).starts_with("HTTP/1.1 404"), "{bad}");
        }
        let port = source.port;
        drop(source);
        assert!(TcpStream::connect(("127.0.0.1", port)).is_err());
    }
}

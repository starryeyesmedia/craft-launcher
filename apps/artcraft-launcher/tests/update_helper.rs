//! The Windows update helper: the launcher started with `--finish-update` does its step and
//! exits, without opening a window or claiming the single instance.

#![cfg(windows)]

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn helper_status(arguments: &[&str]) -> std::process::ExitStatus {
    let mut helper = Command::new(env!("CARGO_BIN_EXE_artcraft-launcher"))
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if let Some(status) = helper.try_wait().unwrap() {
            break status;
        }
        if Instant::now() > deadline {
            let _ = helper.kill();
            panic!("the launcher started instead of the update helper");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn the_update_helper_exits_without_opening_the_launcher() {
    assert!(!helper_status(&["--finish-update"]).success(), "incomplete helper arguments are an error");
}

#[test]
fn the_obsolete_msi_helper_refuses_direct_invocation_without_opening_the_launcher() {
    let hash = "a".repeat(64);
    let status = helper_status(&["--install-msis", r"C:\results", r"C:\downloads", r"C:\downloads\app.msi", &hash, ""]);
    assert_eq!(status.code(), Some(2));
}

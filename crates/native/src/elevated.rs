//! The one-elevation helper for a verified batch of Windows Installer packages.
//!
//! The launcher starts itself with `RunAs` once per MSI batch. The elevated copy accepts only
//! absolute paths in the launcher's download directory, checks every file against the published
//! SHA-256 and the launcher's Authenticode publisher, holds each file open with write/rename/delete
//! sharing denied, and invokes the machine's `msiexec.exe` from its system directory. Other
//! platforms reject the helper flag.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

#[cfg(windows)]
use sha2::{Digest, Sha256};

use crate::msi_batch::Item;
#[cfg(windows)]
use crate::msi_batch::Report;
#[cfg(windows)]
use crate::paths::Paths;

pub const FLAG: &str = "--install-msis";
const MAX_ITEMS: usize = 64;
#[cfg(windows)]
const DECLINED: i32 = 1223;
const CHANGED: &str = "changed";
const UNREADABLE: &str = "unreadable";
const UNSIGNED: &str = "unsigned";
const REJECTED: &str = "rejected";
const INTERRUPTED: &str = "interrupted";

pub fn helper_args(results: &Path, downloads: &Path, items: &[Item]) -> Vec<OsString> {
    let mut args = vec![results.as_os_str().to_os_string(), downloads.as_os_str().to_os_string()];
    for item in items {
        args.push(item.msi.as_os_str().to_os_string());
        args.push(item.sha256.clone().into());
        args.push(item.destination.as_deref().map_or_else(OsString::new, |path| path.as_os_str().to_os_string()));
    }
    args
}

/// Parses the helper's fixed argument shape. Hashes are lowercase because the release parser
/// normalizes published SHA-256 values before they reach this point.
pub fn parse_args(args: &[OsString]) -> Option<(PathBuf, PathBuf, Vec<Item>)> {
    let (results, rest) = args.split_first()?;
    let (downloads, rest) = rest.split_first()?;
    let results = PathBuf::from(results);
    let downloads = PathBuf::from(downloads);
    let (triples, odd) = rest.as_chunks::<3>();
    if !results.is_absolute() || !downloads.is_absolute() || triples.is_empty() || !odd.is_empty() || triples.len() > MAX_ITEMS {
        return None;
    }
    let items = triples
        .iter()
        .map(|[msi, sha, destination]| {
            let msi = PathBuf::from(msi);
            let sha = sha.to_str()?;
            let destination = if destination.is_empty() { None } else { Some(PathBuf::from(destination)) };
            let valid_sha = sha.len() == 64 && sha.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
            (msi.is_absolute()
                && msi.extension().is_some_and(|e| e.eq_ignore_ascii_case("msi"))
                && destination.as_ref().is_none_or(|d| d.is_absolute())
                && valid_sha)
                .then_some(Item { msi, sha256: sha.to_string(), destination })
        })
        .collect::<Option<Vec<_>>>()?;
    Some((results, downloads, items))
}

pub fn parse_results(text: &str, count: usize) -> Vec<(usize, Result<(), String>)> {
    let mut seen = vec![false; count];
    text.split_inclusive('\n')
        .filter_map(|line| {
            let (index, result) = line.strip_suffix('\n')?.trim().split_once(' ')?;
            let index: usize = index.parse().ok()?;
            let seen = seen.get_mut(index).filter(|seen| !**seen)?;
            let outcome = match result {
                CHANGED => Err("the download changed after it was checked, so it wasn't installed. Try again".into()),
                UNREADABLE => Err("the download couldn't be read to install it. Try again".into()),
                UNSIGNED => Err("the download isn't signed by ArtCraft Launcher's publisher".into()),
                REJECTED => Err("the download isn't in ArtCraft Launcher's download folder".into()),
                INTERRUPTED => msi_outcome(None),
                code => msi_outcome(Some(code.parse().ok()?)),
            };
            *seen = true;
            Some((index, outcome))
        })
        .collect()
}

pub fn msi_outcome(code: Option<i32>) -> Result<(), String> {
    match code {
        Some(0 | 3010 | 1641) => Ok(()),
        Some(1602) => Err("cancelled".into()),
        Some(1618) => Err("another installation is in progress. Wait for it to finish, then try again.".into()),
        Some(1925 | 1303) => Err("Windows didn't allow the install (administrator permission is needed)".into()),
        Some(c) => Err(format!("the Windows Installer stopped with error {c}")),
        None => Err("the Windows Installer was interrupted".into()),
    }
}

/// Entry point used by the launcher binary when its first argument is [`FLAG`].
pub fn helper_main(args: &[OsString]) -> u8 {
    let Some((results, downloads, items)) = parse_args(args) else { return 2 };
    #[cfg(windows)]
    {
        let Ok(me) = std::env::current_exe() else { return 2 };
        if crate::self_update::signed_like(&me, &me).is_err() {
            return 2;
        }
        return run_batch(&results, &downloads, &items, &me);
    }
    #[cfg(not(windows))]
    {
        let _ = (results, downloads, items);
        2
    }
}

/// Starts the signed launcher once with administrator rights and reports every item as it is
/// installed. The helper itself performs the security checks after elevation.
#[cfg(windows)]
pub fn install(items: &[Item], paths: &Paths, report: &mut dyn FnMut(usize, Report)) {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;

    static RUNS: AtomicU64 = AtomicU64::new(0);
    const ELEVATE: &str = "$ErrorActionPreference = 'Stop'; try { $p = Start-Process -FilePath $env:ARTCRAFT_LAUNCHER_HELPER -ArgumentList $env:ARTCRAFT_LAUNCHER_HELPER_ARGS -Verb RunAs -WindowStyle Hidden -Wait -PassThru; exit $p.ExitCode } catch { $e = $_.Exception; while ($e) { if ($e.NativeErrorCode -eq 1223) { exit 1223 }; $e = $e.InnerException }; exit 1 }";

    let fail_all = |report: &mut dyn FnMut(usize, Report), error: String| {
        for i in 0..items.len() {
            report(i, Report::Done(Err(error.clone())));
        }
    };
    let downloads = paths.downloads();
    let results = downloads.join(format!(".msi-batch-{}-{}.results", std::process::id(), RUNS.fetch_add(1, Ordering::SeqCst)));
    let prepared = std::fs::create_dir_all(&downloads)
        .map_err(|e| format!("couldn't create {} ({e})", downloads.display()))
        .and_then(|()| std::env::current_exe().map_err(|e| format!("couldn't find ArtCraft Launcher's program ({e})")))
        .and_then(|exe| argument_line(&results, &downloads, &exe, items));
    let (exe, args) = match prepared {
        Ok(p) => p,
        Err(e) => return fail_all(report, e),
    };
    let _ = std::fs::remove_file(&results);
    for i in 0..items.len() {
        report(i, Report::Phase(artcraft_launcher_core::protocol::JobPhase::Permission));
    }
    let mut command = crate::process::command(system_powershell());
    command
        .args(["-NoProfile", "-NonInteractive", "-Command", ELEVATE])
        .env("ARTCRAFT_LAUNCHER_HELPER", &exe)
        .env("ARTCRAFT_LAUNCHER_HELPER_ARGS", &args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(e) => return fail_all(report, format!("couldn't ask Windows for permission ({e})")),
    };
    let code = loop {
        let exited = match child.try_wait() {
            Ok(status) => status.map(|status| status.code()),
            Err(_) => Some(None),
        };
        if let Some(code) = exited {
            break code;
        }
        std::thread::sleep(Duration::from_millis(150));
    };
    let mut done = vec![false; items.len()];
    // The results path is user-writable, so do not trust a file an unprivileged process created
    // while UAC was open. The helper holds the file exclusively against writes/deletes and a
    // successful exit proves it created and completed that file.
    if code == Some(0) {
        if let Ok(text) = std::fs::read_to_string(&results) {
            for i in 0..items.len() {
                report(i, Report::Phase(artcraft_launcher_core::protocol::JobPhase::Installing));
            }
            for (i, outcome) in parse_results(&text, items.len()) {
                if let Some(finished) = done.get_mut(i).filter(|finished| !**finished) {
                    *finished = true;
                    report(i, Report::Done(outcome));
                }
            }
        }
    }
    let _ = std::fs::remove_file(&results);
    let missing = match code {
        Some(DECLINED) => artcraft_launcher_core::protocol::CANCELLED.to_string(),
        Some(0) => "the Windows Installer stopped before reporting its result".into(),
        _ => "the Windows Installer stopped before installing it".into(),
    };
    for (i, finished) in done.iter().enumerate().filter(|(_, finished)| !**finished) {
        report(i, Report::Done(Err(missing.clone())));
    }
}

#[cfg(windows)]
fn argument_line(results: &Path, downloads: &Path, exe: &Path, items: &[Item]) -> Result<(PathBuf, String), String> {
    let mut line = String::new();
    for arg in helper_args(results, downloads, items) {
        let arg = arg.to_str().ok_or("a download's path has characters Windows can't pass on")?;
        if !line.is_empty() {
            line.push(' ');
        }
        line.push_str(&windows_quote(arg));
    }
    Ok((exe.to_path_buf(), line))
}

#[cfg(windows)]
fn windows_quote(arg: &str) -> String {
    let mut out = String::from('"');
    let mut backslashes = 0;
    for c in arg.chars() {
        match c {
            '\\' => backslashes += 1,
            '"' => {
                out.extend(std::iter::repeat_n('\\', backslashes * 2 + 1));
                out.push('"');
                backslashes = 0;
            }
            _ => {
                out.extend(std::iter::repeat_n('\\', backslashes));
                out.push(c);
                backslashes = 0;
            }
        }
    }
    out.extend(std::iter::repeat_n('\\', backslashes * 2));
    out.push('"');
    out
}

#[cfg(windows)]
fn system_powershell() -> PathBuf {
    system_directory().join(r"WindowsPowerShell\v1.0\powershell.exe")
}

#[cfg(windows)]
fn system_directory() -> PathBuf {
    winsafe::GetSystemDirectory().map(PathBuf::from).unwrap_or_else(|_| PathBuf::from(r"C:\Windows\System32"))
}

#[cfg(windows)]
fn run_batch(results: &Path, downloads: &Path, items: &[Item], reference: &Path) -> u8 {
    use std::io::Write as _;

    let Ok(downloads) = safe_directory(downloads) else { return 2 };
    if !same_directory(results, &downloads) || std::fs::symlink_metadata(results).is_ok() {
        return 2;
    }
    use std::os::windows::fs::OpenOptionsExt;
    let Ok(mut out) = std::fs::OpenOptions::new().write(true).create_new(true).share_mode(0x1).open(results) else { return 3 };
    for (index, item) in items.iter().enumerate() {
        let result = install_one(item, &downloads, reference);
        if writeln!(out, "{index} {result}").and_then(|()| out.flush()).is_err() {
            return 3;
        }
    }
    0
}

#[cfg(windows)]
fn safe_directory(path: &Path) -> Result<PathBuf, ()> {
    let metadata = std::fs::symlink_metadata(path).map_err(|_| ())?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(());
    }
    dunce::canonicalize(path).map_err(|_| ())
}

#[cfg(windows)]
fn same_directory(path: &Path, directory: &Path) -> bool {
    path.parent().and_then(|parent| dunce::canonicalize(parent).ok()).is_some_and(|parent| parent == directory)
}

#[cfg(windows)]
fn install_one(item: &Item, downloads: &Path, reference: &Path) -> String {
    let Ok(metadata) = std::fs::symlink_metadata(&item.msi) else { return UNREADABLE.into() };
    if !metadata.is_file() || metadata.file_type().is_symlink() || !same_directory(&item.msi, downloads) {
        return REJECTED.into();
    }
    let Ok(file) = open_for_reading_only(&item.msi) else { return UNREADABLE.into() };
    let mut hasher = Sha256::new();
    if std::io::copy(&mut &file, &mut hasher).is_err() {
        return UNREADABLE.into();
    }
    if crate::http::hex(&hasher.finalize()) != item.sha256 {
        return CHANGED.into();
    }
    if crate::self_update::signed_like(reference, &item.msi).is_err() {
        return UNSIGNED.into();
    }
    let code = run_msiexec(item);
    drop(file);
    code.map_or_else(|| INTERRUPTED.to_string(), |code| code.to_string())
}

#[cfg(windows)]
fn open_for_reading_only(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::windows::fs::OpenOptionsExt;
    std::fs::OpenOptions::new().read(true).share_mode(0x1).open(path)
}

#[cfg(windows)]
fn run_msiexec(item: &Item) -> Option<i32> {
    use std::os::windows::process::CommandExt;
    let msi = crate::install::msi_path(&item.msi).ok()?;
    let mut command = crate::process::command(system_msiexec());
    // Explicitly request a per-machine install. The helper runs under the administrator who
    // accepted UAC; without this public property an otherwise valid per-user MSI could land in
    // that administrator's profile instead of updating the user's installed app.
    // Do not let elevated Windows Installer write beside a user-owned MSI: a pre-created
    // junction or symlink there could redirect the log to an administrator-owned file.
    command.arg("/i").arg(&msi).args(["/qn", "/norestart", "ALLUSERS=1", "/l*v", "NUL"]);
    if let Some(destination) = &item.destination {
        command.raw_arg(crate::install::msi_folder_argument(destination).ok()?);
    }
    command.status().ok()?.code()
}

#[cfg(windows)]
fn system_msiexec() -> PathBuf {
    system_directory().join("msiexec.exe")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn downloads() -> PathBuf {
        #[cfg(windows)]
        return PathBuf::from(r"C:\Users\Ann Lee\ArtCraft Launcher\cache\downloads");
        #[cfg(not(windows))]
        return PathBuf::from("/tmp/ArtCraft Launcher/cache/downloads");
    }

    fn item(name: &str) -> Item {
        Item { msi: downloads().join(name), sha256: "a".repeat(64), destination: None }
    }

    fn destination() -> PathBuf {
        #[cfg(windows)]
        return PathBuf::from(r"C:\Program Files\PhotoCraft");
        #[cfg(not(windows))]
        return PathBuf::from("/opt/PhotoCraft");
    }

    #[test]
    fn arguments_round_trip_and_unexpected_shapes_are_refused() {
        let results = downloads().join(".batch.results");
        let downloads = results.parent().unwrap().to_path_buf();
        let items = vec![item("Photo Craft.msi"), Item { destination: Some(destination()), ..item("Other.msi") }];
        assert_eq!(parse_args(&helper_args(&results, &downloads, &items)), Some((results.clone(), downloads.clone(), items)));
        for bad in [
            vec![results.clone().into_os_string()],
            vec![results.clone().into_os_string(), downloads.clone().into_os_string()],
            vec![
                PathBuf::from("relative").into_os_string(),
                downloads.clone().into_os_string(),
                item("a.msi").msi.into_os_string(),
                "a".repeat(64).into(),
                OsString::new(),
            ],
            vec![
                results.clone().into_os_string(),
                downloads.clone().into_os_string(),
                PathBuf::from(r"C:\x.exe").into_os_string(),
                "a".repeat(64).into(),
                OsString::new(),
            ],
            vec![
                results.clone().into_os_string(),
                downloads.into_os_string(),
                item("a.msi").msi.into_os_string(),
                "A".repeat(64).into(),
                OsString::new(),
            ],
        ] {
            assert_eq!(parse_args(&bad), None, "{bad:?}");
        }
    }

    #[test]
    fn results_are_parsed_incrementally_and_only_once() {
        let parsed = parse_results("0 0\n2 3010\n1 changed\n1 0\n3 nonsense\n4 unreadable\n5 unsigned\n6 rejected\n7 interrupted\n", 8);
        assert_eq!(parsed[0], (0, Ok(())));
        assert_eq!(parsed[1], (2, Ok(())));
        assert!(parsed.iter().any(|(i, result)| *i == 1 && result.is_err()));
        assert_eq!(parsed.len(), 7);
    }

    #[test]
    fn installer_codes_preserve_cancellation_and_reboot_success() {
        assert_eq!(msi_outcome(Some(0)), Ok(()));
        assert_eq!(msi_outcome(Some(3010)), Ok(()));
        assert_eq!(msi_outcome(Some(1602)), Err("cancelled".into()));
        assert!(msi_outcome(Some(1618)).unwrap_err().contains("another installation"));
        assert_eq!(msi_outcome(None), Err("the Windows Installer was interrupted".into()));
    }
}

//! Destructive, ignored integration test: the manual workflow alone opts in on a fresh hosted
//! Windows runner. All package authorization and installation code is production code.
use super::*;
use std::path::Path;

fn run_script(root: &Path, phase: &str) -> Result<(), String> {
    use base64::Engine as _;
    use std::io::Write as _;
    let code = format!("{}\n$phase = '{}'\n{}", crate::elevated::POLICY, phase, include_str!("../../../../../tests/windows-msi-e2e/runner.ps1"));
    let encoded = base64::engine::general_purpose::STANDARD.encode(code.encode_utf16().flat_map(u16::to_le_bytes).collect::<Vec<_>>());
    let mut child = std::process::Command::new(crate::elevated::system_powershell()?)
        .args(["-NoProfile", "-NonInteractive", "-Command", "-"])
        .env("ARTCRAFT_MSI_E2E_ROOT", root)
        .stdin(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| e.to_string())?;
    writeln!(
        child.stdin.take().ok_or("missing script input")?,
        "& ([ScriptBlock]::Create([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('{encoded}'))))"
    )
    .map_err(|e| e.to_string())?;
    if child.wait().map_err(|e| e.to_string())?.success() { Ok(()) } else { Err(format!("Windows E2E {phase} failed; see sanitized report")) }
}

fn wait_for_jobs(backend: &mut NativeBackend) -> Result<serde_json::Value, String> {
    let start = Instant::now();
    let mut results = serde_json::Map::new();
    let mut phases = Vec::new();
    while results.len() < 2 {
        for event in backend.poll() {
            match event {
                Event::JobFinished { app, result } => {
                    // Backend errors can contain cache paths/network exception data. Evidence
                    // records success per app; fixed protected-policy codes diagnose failures.
                    results.insert(app, serde_json::json!({"success": result.is_ok()}));
                }
                Event::Progress { app, phase } if !matches!(phase, JobPhase::Downloading { .. } | JobPhase::Reconnecting { .. }) => {
                    phases.push(serde_json::json!({"app": app, "phase": format!("{phase:?}")}));
                }
                _ => {}
            }
        }
        if start.elapsed() > Duration::from_secs(20 * 60) {
            return Err("timed out waiting for InstallAll results".into());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Ok(serde_json::json!({"results": results, "phases": phases}))
}

fn batch(root: &Path) -> Result<(), String> {
    let shared = shared();
    for (id, tag) in [("photocraft", "v0.14.0"), ("vectorcraft", "v0.16.0")] {
        let app = CraftApp::by_id(id).ok_or("missing catalog app")?;
        // Real pinned GitHub release metadata saved by preflight; never a fabricated release
        // source or download mirror. The backend downloads/verifies the official MSI again.
        let json = std::fs::read_to_string(root.join(format!("{id}-{tag}.json"))).map_err(|e| e.to_string())?;
        let release = artcraft_launcher_core::release::parse_github_release(&json, app.repo)?;
        if release.tag != tag {
            return Err("official release tag changed".into());
        }
        shared.latest.lock().unwrap().insert(id.into(), release);
        let entries = crate::detect::windows::msi_installs(app);
        if entries.len() != 1 {
            return Err(format!("expected exactly one installed {id} MSI"));
        }
        let installed = crate::detect::detect(app, &Manifest::default(), &crate::detect::Snapshot::take()).ok_or("baseline not detected")?;
        shared.installed.lock().unwrap().insert(id.into(), installed);
    }
    shared.options.lock().unwrap().kinds = vec![PackageKind::Msi];
    let mut backend = NativeBackend {
        shared: Arc::new(shared),
        paths: Paths::under(&root.join("launcher")),
        http: Some(Http::new()?),
        source: None,
        platform: Some(Platform { os: Os::Windows, arch: Arch::X64 }),
    };
    crate::elevated::hosted_test::ACTIVE.store(true, Ordering::SeqCst);
    backend.send(Command::InstallAll { apps: vec!["photocraft".into(), "vectorcraft".into()] });
    let observed = wait_for_jobs(&mut backend)?;
    std::fs::write(root.join("batch.json"), serde_json::to_vec_pretty(&observed).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
    let sessions = crate::elevated::hosted_test::SESSIONS.lock().unwrap().clone();
    std::fs::write(root.join("sessions.json"), serde_json::to_vec(&sessions).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
    if sessions.len() != 1 || !["photocraft", "vectorcraft"].iter().all(|app| observed["results"][app]["success"] == true) {
        return Err("InstallAll did not complete both apps in exactly one protected policy invocation".into());
    }

    // Real protected policy must reject a caller-forged hash and altered package bytes.
    let file = root.join("photocraft-0.14.0-windows-x64.msi");
    let sha = crate::http::sha256_file(&file)?;
    let changed = root.join("changed.msi");
    let mut bytes = std::fs::read(&file).map_err(|e| e.to_string())?;
    *bytes.first_mut().ok_or("empty official package")? ^= 1;
    std::fs::write(&changed, bytes).map_err(|e| e.to_string())?;
    let item = crate::msi_batch::Item {
        msi: file,
        sha256: "0".repeat(64),
        destination: None,
        release: crate::elevated::ReleaseIdentity {
            app: "photocraft".into(),
            tag: "v0.14.0".into(),
            asset: "photocraft-0.14.0-windows-x64.msi".into(),
        },
    };
    let mut corrupt = item.clone();
    corrupt.sha256 = sha;
    corrupt.msi = changed;
    let mut failures = Vec::new();
    crate::elevated::install(&[item, corrupt], &mut |index, report| {
        if let crate::msi_batch::Report::Done(result) = report {
            failures.push(serde_json::json!({"index": index, "rejected": result.is_err(), "message": result.err()}));
        }
    });
    std::fs::write(
        root.join("sessions.json"),
        serde_json::to_vec(&*crate::elevated::hosted_test::SESSIONS.lock().unwrap()).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    std::fs::write(root.join("negative.json"), serde_json::to_vec_pretty(&failures).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
    if failures.len() != 2 || failures.iter().any(|f| f["rejected"] != true) {
        return Err("protected policy accepted a forged checksum or changed package".into());
    }
    run_script(root, "verify")
}

#[test]
#[ignore = "installs real MSIs; opt in only via the manual disposable GitHub-hosted Windows workflow"]
fn official_msi_batch_e2e() -> Result<(), String> {
    if std::env::var("GITHUB_ACTIONS").as_deref() != Ok("true")
        || std::env::var("RUNNER_ENVIRONMENT").as_deref() != Ok("github-hosted")
        || std::env::var("GITHUB_REPOSITORY").as_deref() != Ok("starryeyesmedia/craft-launcher")
        || std::env::var("GITHUB_EVENT_NAME").as_deref() != Ok("workflow_dispatch")
        || std::env::var("GITHUB_REF").as_deref() != Ok("refs/heads/fix/windows-batched-uac")
    {
        return Err("refusing real MSI installs outside the dedicated hosted workflow".into());
    }
    let root = std::path::PathBuf::from(std::env::var_os("ARTCRAFT_MSI_E2E_ROOT").ok_or("missing dedicated test root")?);
    run_script(&root, "prepare")?;
    let result = batch(&root);
    crate::elevated::hosted_test::ACTIVE.store(false, Ordering::SeqCst);
    result
}

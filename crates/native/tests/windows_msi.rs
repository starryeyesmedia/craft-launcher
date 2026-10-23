//! Windows-native tests use real PowerShell/.NET and read-only Windows Installer databases.
//! They never install a package, request UAC, mock signature success, or add certificate trust.
#![cfg(windows)]

use artcraft_launcher_native::elevated::{POLICY, system_powershell};
use base64::Engine as _;

fn run_policy(test: &str) {
    let script = format!("{POLICY}\n{test}");
    let encoded = base64::engine::general_purpose::STANDARD.encode(script.encode_utf16().flat_map(u16::to_le_bytes).collect::<Vec<_>>());
    // Use stdin to avoid cmd.exe and Windows command-line limits.
    let mut child = std::process::Command::new(system_powershell().unwrap())
        .args(["-NoProfile", "-NonInteractive", "-Command", "-"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let command = format!(
        "$ErrorActionPreference='Stop'; try {{ & ([ScriptBlock]::Create([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('{encoded}')))); exit 0 }} catch {{ [Console]::Error.WriteLine($_); exit 1 }}\n"
    );
    std::io::Write::write_all(&mut child.stdin.take().unwrap(), command.as_bytes()).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success(), "stdout: {}\nstderr: {}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
}

#[test]
fn policy_rejects_unsafe_paths_unsigned_files_and_forged_release_identity() {
    run_policy(
        r#"
function Must-Fail($work) {
    $failed = $false
    try { & $work } catch { $failed = $true }
    if (-not $failed) { throw 'Policy accepted invalid input' }
}
# This tests only the exact publisher-name filter, not certificate-chain success.
# Real Authenticode success is exercised exclusively with official MSIs in the E2E workflow.
Assert-AuthenticodePublisher 'Learning Machines Inc'
foreach ($publisher in @('', 'Learning Machines LLC', 'Microsoft Corporation',
    'learning machines inc', 'Learning Machines Inc ', 'Learning Machines Inc Evil', '*Learning Machines Inc*')) {
    Must-Fail { Assert-AuthenticodePublisher $publisher }
}
Must-Fail { Assert-LocalPath '\\attacker\share\package.msi' }
Must-Fail { Assert-LocalPath 'C:\x.msi:stream' }
Must-Fail { Assert-LocalPath 'C:\x" ALLUSERS=2' }
Must-Fail { Assert-LocalPath 'relative.msi' }
Must-Fail { New-ProtectedRun '..\escape' }
Must-Fail { Assert-OfficialSignature ([IO.Path]::Combine([Environment]::SystemDirectory, 'not-an-artcraft.msi')) }
Must-Fail { Assert-OfficialSignature ([IO.Path]::Combine([Environment]::SystemDirectory, 'cmd.exe')) }
$catalog = @([pscustomobject]@{ id='photocraft'; repo='storytold/photocraft'; names=@('PhotoCraft'); stems=@('photocraft') })
$item = [pscustomobject]@{ release=[pscustomobject]@{ app='attacker'; tag='v0.5.0'; asset='photocraft-0.5.0-windows-x64.msi' }; sha256=('a'*64) }
Must-Fail { Get-ReleaseAuthorization $item $catalog }
$item.release.app='photocraft'
$item.release.tag='../escape'
Must-Fail { Get-ReleaseAuthorization $item $catalog }
$item.release.tag='v0.5.0'
$item.release.asset='filmcraft-0.5.0-windows-x64.msi'
Must-Fail { Get-ReleaseAuthorization $item $catalog }
$sha='a'*64
if ((Get-PublishedHash "$sha  photo.msi" 'photo.msi') -cne $sha) { throw 'Checksum parser failed' }
Must-Fail { Get-PublishedHash "$sha  other.msi" 'photo.msi' }
$duplicate="$sha  photo.msi" + [char]10 + "$sha  photo.msi"
Must-Fail { Get-PublishedHash $duplicate 'photo.msi' }
"#,
    );
}

#[test]
fn installer_database_scope_identity_and_file_locking_are_checked_without_installing() {
    run_policy(
        r#"
function Must-Fail($work) {
    $failed = $false
    try { & $work } catch { $failed = $true }
    if (-not $failed) { throw 'Policy accepted invalid MSI scope/identity' }
}
$folder = [IO.Path]::Combine([IO.Path]::GetTempPath(), [Guid]::NewGuid().ToString('N'))
$null=[IO.Directory]::CreateDirectory($folder)
$file=[IO.Path]::Combine($folder, 'fixture.msi')
$installer=New-Object -ComObject WindowsInstaller.Installer
try {
    $db=$installer.OpenDatabase($file, 3)
    try {
        $view=$db.OpenView('CREATE TABLE Property (Property CHAR(72) NOT NULL, Value CHAR(0) LOCALIZABLE PRIMARY KEY Property)')
        $view.Execute(); $view.Close()
        $null=[Runtime.InteropServices.Marshal]::FinalReleaseComObject($view)
        foreach ($pair in @(@('ALLUSERS','1'), @('Manufacturer','Learning Machines LLC'), @('ProductName','PhotoCraft'), @('ProductVersion','0.5.0'))) {
            $view=$db.OpenView("INSERT INTO Property (Property, Value) VALUES ('$($pair[0])', '$($pair[1])')")
            $view.Execute(); $view.Close()
            $null=[Runtime.InteropServices.Marshal]::FinalReleaseComObject($view)
        }
        $db.Commit()
    } finally { $null=[Runtime.InteropServices.Marshal]::FinalReleaseComObject($db) }
    $app=[pscustomobject]@{ names=@('PhotoCraft'); stems=@('photocraft') }
    Assert-MsiIdentity $file $app '0.5.0'
    Must-Fail { Assert-OfficialSignature $file }
    Must-Fail { Assert-MsiIdentity $file $app '0.6.0' }
    Must-Fail { Assert-MsiIdentity $file ([pscustomobject]@{names=@('FilmCraft')}) '0.5.0' }
    # The authorized certificate publisher is NOT an authorized MSI Manufacturer.
    $db=$installer.OpenDatabase($file, 1)
    try {
        $view=$db.OpenView("UPDATE Property SET Value='Learning Machines Inc' WHERE Property='Manufacturer'")
        $view.Execute(); $view.Close()
        $null=[Runtime.InteropServices.Marshal]::FinalReleaseComObject($view)
        $db.Commit()
    } finally { $null=[Runtime.InteropServices.Marshal]::FinalReleaseComObject($db) }
    Must-Fail { Assert-MsiIdentity $file $app '0.5.0' }
    $db=$installer.OpenDatabase($file, 1)
    try {
        $view=$db.OpenView("UPDATE Property SET Value='Learning Machines LLC' WHERE Property='Manufacturer'")
        $view.Execute(); $view.Close()
        $null=[Runtime.InteropServices.Marshal]::FinalReleaseComObject($view)
        $db.Commit()
    } finally { $null=[Runtime.InteropServices.Marshal]::FinalReleaseComObject($db) }
    Assert-MsiIdentity $file $app '0.5.0'
    foreach ($scope in @('2', '')) {
        $db=$installer.OpenDatabase($file, 1)
        try {
            $view=$db.OpenView("UPDATE Property SET Value='$scope' WHERE Property='ALLUSERS'")
            $view.Execute(); $view.Close()
            $null=[Runtime.InteropServices.Marshal]::FinalReleaseComObject($view)
            $db.Commit()
        } finally { $null=[Runtime.InteropServices.Marshal]::FinalReleaseComObject($db) }
        Must-Fail { Assert-MsiIdentity $file $app '0.5.0' }
    }
    $db=$installer.OpenDatabase($file, 1)
    try {
        foreach ($sql in @("UPDATE Property SET Value='1' WHERE Property='ALLUSERS'", "INSERT INTO Property (Property, Value) VALUES ('MSIINSTALLPERUSER', '1')")) {
            $view=$db.OpenView($sql)
            $view.Execute(); $view.Close()
            $null=[Runtime.InteropServices.Marshal]::FinalReleaseComObject($view)
        }
        $db.Commit()
    } finally { $null=[Runtime.InteropServices.Marshal]::FinalReleaseComObject($db) }
    Must-Fail { Assert-MsiIdentity $file $app '0.5.0' }
    $locked=[IO.File]::Open($file, 'Open', 'Read', 'Read')
    try {
        Must-Fail { $f=[IO.File]::Open($file, 'Open', 'Write', 'ReadWrite'); $f.Dispose() }
        Must-Fail { [IO.File]::Delete($file) }
    } finally { $locked.Dispose() }
} finally {
    $null=[Runtime.InteropServices.Marshal]::FinalReleaseComObject($installer)
    [IO.Directory]::Delete($folder, $true)
}
"#,
    );
}

#[test]
fn protected_results_have_no_unprivileged_write_or_delete_permissions() {
    // Hosted Windows runners have administrator tokens. Fail explicitly if that changes.
    run_policy(
        r#"
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
$principal=[Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Protected-results test requires an administrator test shell (no UAC is requested)'
}
$session=[Guid]::NewGuid().ToString('N')
$root=New-ProtectedRun $session
try {
    if ((Assert-InstallDestination $root) -cne $root) { throw 'Protected destination was refused' }
    $file=[IO.Path]::Combine($root,'results')
    $handle=New-ProtectedFile $file $true
    try {
        $bytes=[Text.Encoding]::UTF8.GetBytes("0 0" + [char]10)
        $handle.Write($bytes,0,$bytes.Length)
    } finally { $handle.Dispose() }
    foreach ($path in @($root,$file)) {
        $acl=Get-Acl -LiteralPath $path
        $owner=$acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
        if ($owner -notin @('S-1-5-32-544','S-1-5-18')) { throw 'Unexpected owner' }
        foreach ($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
            if ($rule.AccessControlType -eq 'Allow' -and $rule.IdentityReference.Value -notin @('S-1-5-32-544','S-1-5-18')) {
                if (([int]$rule.FileSystemRights -band 0x000d0156) -ne 0) { throw 'Unprivileged result mutation allowed' }
            }
        }
    }
    $failed=$false
    try { New-ProtectedRun $session } catch { $failed=$true }
    if (-not $failed) { throw 'Existing session was adopted' }
} finally { [IO.Directory]::Delete($root,$true) }
"#,
    );
}

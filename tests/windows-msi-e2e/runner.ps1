# Invoked with production POLICY already loaded by the ignored Rust test (prepare/verify),
# or directly by the workflow (finish). Never upload the raw download/staging directory.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2
$root = $env:ARTCRAFT_MSI_E2E_ROOT
if ($env:GITHUB_ACTIONS -cne 'true' -or $env:RUNNER_ENVIRONMENT -cne 'github-hosted' -or
    $env:GITHUB_REPOSITORY -cne 'starryeyesmedia/craft-launcher' -or
    $env:GITHUB_EVENT_NAME -cne 'workflow_dispatch' -or
    $env:GITHUB_REF -cne 'refs/heads/fix/windows-batched-uac' -or -not $root) {
    throw 'Refusing MSI test outside the manual disposable hosted workflow'
}
$null = New-Item -ItemType Directory -Force -Path $root
$reportPath = Join-Path $root 'report.json'
$diagnostics = Join-Path $root 'diagnostics'
$null = New-Item -ItemType Directory -Force -Path $diagnostics

function Get-AppEntries([string]$name) {
    foreach ($hive in @([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryHive]::CurrentUser)) {
        foreach ($view in @([Microsoft.Win32.RegistryView]::Registry64, [Microsoft.Win32.RegistryView]::Registry32)) {
            $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey($hive, $view)
            try {
                $uninstall = $base.OpenSubKey('SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall')
                if ($null -eq $uninstall) { continue }
                try {
                    foreach ($code in $uninstall.GetSubKeyNames()) {
                        $key = $uninstall.OpenSubKey($code)
                        try {
                            if ([string]$key.GetValue('DisplayName') -ceq $name) {
                                [pscustomobject]@{
                                    app = $name
                                    hive = [string]$hive; view = [string]$view; code = $code
                                    version = [string]$key.GetValue('DisplayVersion')
                                    publisher = [string]$key.GetValue('Publisher')
                                    windowsInstaller = $key.GetValue('WindowsInstaller')
                                }
                            }
                        } finally { $key.Dispose() }
                    }
                } finally { $uninstall.Dispose() }
            } finally { $base.Dispose() }
        }
    }
}

function Assert-Version([string]$name, [string]$version) {
    $entries = @(Get-AppEntries $name)
    if ($entries.Count -ne 1 -or $entries[0].hive -cne 'LocalMachine' -or
        $entries[0].view -cne 'Registry64' -or $entries[0].version -cne $version -or
        $entries[0].publisher -cne 'Learning Machines LLC' -or $entries[0].windowsInstaller -ne 1) {
        throw 'Unexpected installed version, publisher, architecture or MSI scope'
    }
    return $entries[0]
}

if (Test-Path $reportPath) { $report = Get-Content $reportPath -Raw | ConvertFrom-Json }
else {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $admin = ([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    $report = [pscustomobject]@{
        status = 'not-run'; stage = 'initialization'; commit = $env:GITHUB_SHA
        windows = [Environment]::OSVersion.VersionString; imageVersion = $env:ImageVersion
        administrator = $admin; packages = @(); before = @(); after = @(); baselineExits = @()
        batch = $null; negative = $null; protectedResults = @(); cleanup = @(); error = $null
        unavailable = @('Interactive UAC approval/count/cancellation and secure desktop',
            'Unelevated-to-admin boundary on a UAC-enabled VM', 'GUI rendering and running-app end-to-end scenarios')
        execution = 'Existing administrator context; identical protected policy; UAC is NOT tested'
        baselineStarted = $false
    }
}

try {
    if ($phase -eq 'prepare') {
        $report.stage = 'fresh-runner guard'
        if (-not $report.administrator -or -not [Environment]::Is64BitProcess) { throw 'Expected existing x64 administrator context' }
        foreach ($name in @('PhotoCraft', 'VectorCraft')) {
            if (@(Get-AppEntries $name).Count -ne 0) { throw 'Refusing to modify a pre-existing application' }
        }
        $report.stage = 'official package preflight'
        foreach ($spec in @(
            @('photocraft', 'PhotoCraft', '0.13.0'), @('photocraft', 'PhotoCraft', '0.14.0'),
            @('vectorcraft', 'VectorCraft', '0.15.0'), @('vectorcraft', 'VectorCraft', '0.16.0'))) {
            $id, $name, $version = $spec
            $asset = "$id-$version-windows-x64.msi"
            $package = [pscustomobject]@{
                app = $id; version = $version; asset = $asset; checksum = 'not-run'; signature = 'not-run'
                publisher = $null; identityScope = 'not-run'; productCode = $null; error = $null
            }
            $report.packages += $package
            try {
                $url = "https://github.com/storytold/$id/releases/download/v$version"
                $sums = Read-OfficialChecksums "$url/SHA256SUMS.txt"
                $sha = Get-PublishedHash $sums $asset
                [IO.File]::WriteAllText((Join-Path $root "$asset.SHA256SUMS.txt"), $sums)
                $file = Join-Path $root $asset
                Invoke-WebRequest "$url/$asset" -OutFile $file -UseBasicParsing -UserAgent 'ArtCraft-Launcher/MSI-E2E'
                if ((Get-FileHash $file -Algorithm SHA256).Hash.ToLowerInvariant() -cne $sha) { throw 'Official checksum mismatch' }
                $package.checksum = $sha
                $sig = Microsoft.PowerShell.Security\Get-AuthenticodeSignature -LiteralPath $file
                $package.signature = [string]$sig.Status
                if ($null -ne $sig.SignerCertificate) {
                    $package.publisher = $sig.SignerCertificate.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false)
                }
                Assert-OfficialSignature $file
                Assert-MsiIdentity $file ([pscustomobject]@{names=@($name)}) $version
                $package.identityScope = 'passed: ALLUSERS=1; MSIINSTALLPERUSER absent/0; official name/manufacturer/version'
                $api = New-MsiApi
                $msiArgs = [object[]]@($file, [IntPtr]::Zero, [uint32]0)
                if ($api.GetMethod('MsiOpenDatabaseW').Invoke($null, $msiArgs) -ne 0) { throw 'Cannot read ProductCode' }
                try { $package.productCode = Get-MsiProperty $api ([uint32]$msiArgs[2]) 'ProductCode' }
                finally { $null = $api.GetMethod('MsiCloseHandle').Invoke($null, [object[]]@([uint32]$msiArgs[2])) }
                if ($package.productCode -cnotmatch '^\{[A-Fa-f0-9-]{36}\}$') { throw 'Invalid ProductCode' }
                # Save the real GitHub API release answer for the Rust backend's pinned update.
                Invoke-WebRequest "https://api.github.com/repos/storytold/$id/releases/tags/v$version" `
                    -OutFile (Join-Path $root "$id-v$version.json") -UseBasicParsing -UserAgent 'ArtCraft-Launcher/MSI-E2E'
            } catch {
                $package.error = 'Official package preflight incompatible: checksum, signature, MSI identity/scope or release metadata'
            }
        }
        if (@($report.packages | Where-Object { $null -ne $_.error }).Count -ne 0) { throw 'Official package preflight failed; no MSI was installed' }
        $report.stage = 'baseline installation'
        # Persist the cleanup allowlist BEFORE installing. Only verified official ProductCodes
        # on a previously empty hosted runner can ever be uninstalled by this test.
        $report.baselineStarted = $true
        $report | ConvertTo-Json -Depth 12 | Set-Content $reportPath
        foreach ($spec in @(@('photocraft', 'PhotoCraft', '0.13.0'), @('vectorcraft', 'VectorCraft', '0.15.0'))) {
            $id, $name, $version = $spec
            $file = Join-Path $root "$id-$version-windows-x64.msi"
            $log = Join-Path $root "$id-baseline.log"
            $process = Start-Process ([IO.Path]::Combine([Environment]::SystemDirectory, 'msiexec.exe')) `
                -ArgumentList "/i `"$file`" /qn /norestart ALLUSERS=1 /l*v `"$log`"" -Wait -PassThru
            $report.baselineExits += [pscustomobject]@{app=$id; exitCode=$process.ExitCode}
            if ($process.ExitCode -notin @(0,3010)) { throw 'Baseline MSI installation failed' }
            $report.before += Assert-Version $name $version
        }
        $report.stage = 'InstallAll ready'
        $report.status = 'baseline-installed'
    } elseif ($phase -eq 'verify') {
        $report.stage = 'post-update installation records'
        $report.after = @((Assert-Version 'PhotoCraft' '0.14.0'), (Assert-Version 'VectorCraft' '0.16.0'))
        $report.status = 'passed'
    } elseif ($phase -eq 'finish') {
        # Capture partial upgrades as well as fully successful runs before cleanup.
        $report.after = @((Get-AppEntries 'PhotoCraft'); (Get-AppEntries 'VectorCraft'))
        if (Test-Path (Join-Path $root 'batch.json')) { $report.batch = Get-Content (Join-Path $root 'batch.json') -Raw | ConvertFrom-Json }
        if (Test-Path (Join-Path $root 'negative.json')) { $report.negative = @(Get-Content (Join-Path $root 'negative.json') -Raw | ConvertFrom-Json) }
        if (Test-Path (Join-Path $root 'sessions.json')) {
            $sessions = @(Get-Content (Join-Path $root 'sessions.json') -Raw | ConvertFrom-Json)
            foreach ($session in $sessions) {
                if ($session -cnotmatch '^[a-f0-9]{32}$') { throw 'Invalid diagnostic session' }
                $run = [IO.Path]::Combine([Environment]::SystemDirectory, "ArtCraft-MSI-$session")
                $results = [IO.Path]::Combine($run, 'results')
                if (Test-Path $results) {
                    $codes = @(Get-Content $results | Where-Object { $_ -cmatch '^\d+ (\d+|rejected|running)$' })
                    $report.protectedResults += [pscustomobject]@{session=$session; results=$codes}
                    Get-ChildItem $run -Filter '*.log' | Copy-Item -Destination $root
                }
            }
        }
        if ($report.baselineStarted) {
            foreach ($package in $report.packages) {
                if ($null -eq $package.error -and $package.productCode -cmatch '^\{[A-Fa-f0-9-]{36}\}$') {
                    $name = if ($package.app -eq 'photocraft') { 'PhotoCraft' } else { 'VectorCraft' }
                    if (@(Get-AppEntries $name | Where-Object { $_.code -ceq $package.productCode }).Count -gt 0) {
                        $log = Join-Path $root "$($package.app)-cleanup.log"
                        $process = Start-Process ([IO.Path]::Combine([Environment]::SystemDirectory, 'msiexec.exe')) `
                            -ArgumentList "/x $($package.productCode) /qn /norestart /l*v `"$log`"" -Wait -PassThru
                        $report.cleanup += [pscustomobject]@{app=$package.app; exitCode=$process.ExitCode}
                        if ($process.ExitCode -notin @(0,3010,1605)) { throw 'Cleanup MSI failed' }
                    }
                }
            }
        }
        # MSI logs contain usernames, paths, environment and possibly custom action data.
        # Export only recognized action identifiers/numeric returns and installer exit codes.
        foreach ($log in Get-ChildItem $root -Filter '*.log') {
            $safe = @(foreach ($line in Get-Content $log.FullName) {
                if ($line -match 'MainEngineThread is returning (\d+)') { "installerExit=$($Matches[1])" }
                elseif ($line -match '^Action ended [0-9: ]+: ([A-Za-z0-9_.]+)\. Return value (\d+)\.') {
                    "action=$($Matches[1]); return=$($Matches[2])"
                }
            })
            $safe | Set-Content (Join-Path $diagnostics "$($log.BaseName)-sanitized.txt")
        }
        if ($report.status -ne 'passed') { throw 'Integration did not pass all installation and failure scenarios' }
    } else { throw 'Unknown E2E phase' }
} catch {
    $report.status = 'failed'
    $report.error = "Failed at $($report.stage); see package verification and installer results"
} finally {
    $report | ConvertTo-Json -Depth 12 | Set-Content $reportPath
    Copy-Item $reportPath (Join-Path $diagnostics 'report.json') -Force
    if ($phase -eq 'finish') {
        # Fixed fields only: make decisive results visible even if cloud artifact downloads are blocked.
        $brief = [ordered]@{status=$report.status; stage=$report.stage; before=@($report.before | ForEach-Object {$_.version});
            after=@($report.after | ForEach-Object {$_.version}); signatures=@($report.packages | ForEach-Object {"$($_.asset):$($_.signature):$($_.publisher)"});
            baselineExits=$report.baselineExits; protectedResults=$report.protectedResults}
        $summary = $brief | ConvertTo-Json -Depth 8 -Compress
        Write-Output "::notice title=Windows MSI E2E results::$summary"
        if ($env:GITHUB_STEP_SUMMARY) { $report | ConvertTo-Json -Depth 12 | Add-Content $env:GITHUB_STEP_SUMMARY }
    }
}
if ($report.status -eq 'failed') { exit 1 }
exit 0

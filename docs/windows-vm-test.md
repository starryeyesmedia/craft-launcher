# Windows x64 VM test build

The manually triggered **Windows MSI security** workflow, with `package_vm=true` on
`fix/windows-batched-uac`, tests Windows MSVC code and then builds the actual release-profile
ArtCraft Launcher using the existing Windows packaging recipe. Download its
`artcraft-launcher-windows-x64-vm-<commit>` Actions artifact (GitHub sign-in may be required).
It expires after 14 days; rerun the workflow to create a fresh artifact.

The artifact contains the executable, `portable.txt`, licenses, documentation, build identity
and SHA-256 hashes. Fonts/icons are embedded and the C runtime is statically linked, matching
the production portable layout. Windows supplies the graphics and system DLLs. No external
helper executable, developer certificate, or Visual C++ redistributable is required.

This is an **unsigned development launcher**, not a release. No signing secrets are used or
production signing rules changed. The GUI remains unelevated. The system-hosted elevated
policy still independently requires official published checksums, a valid Authenticode
signature from Learning Machines LLC, and a per-machine MSI database. Do not disable UAC,
signature checks, antivirus, or certificate validation to make a test pass. If VM policy
blocks the unsigned GUI, use a disposable VM whose policy permits unsigned development
applications; do not weaken the official MSI policy or distribute the build as signed.

## Manual test

1. Snapshot a disposable, fully updated Windows 10/11 x64 VM with UAC enabled and internet
   access. Use a normal unelevated desktop session with access to administrator credentials.
   Close any other launcher instance. Keep production data out of the VM.
2. Download two older official x64 installers and each release's `SHA256SUMS.txt`:
   [PhotoCraft v0.13.0](https://github.com/storytold/photocraft/releases/tag/v0.13.0)
   (`photocraft-0.13.0-windows-x64.msi`) and
   [VectorCraft v0.15.0](https://github.com/storytold/vectorcraft/releases/tag/v0.15.0)
   (`vectorcraft-0.15.0-windows-x64.msi`). Newer releases existed when this recipe was written.
   Before running either MSI, compare `Get-FileHash <file> -Algorithm SHA256` with its exact
   published checksum entry. Run `Get-AuthenticodeSignature <file> | Format-List Status,SignerCertificate`:
   require `Valid` and signer Learning Machines LLC. These release assets were identified
   through official release metadata; their Windows signatures must be checked in the VM.
   Stop if either verification fails; do not re-sign or substitute an unsigned MSI.
3. Install both older apps normally, accepting their individual setup prompts. Use their
   default per-machine installation locations. Confirm both launch, then close them.
   These initial setup prompts are separate from the batch update being tested.
4. Extract the **entire** Actions artifact into a writable VM directory. Keep `portable.txt`
   beside `artcraft-launcher.exe`. Check `BUILD-INFO.txt` for the intended commit and compare
   the executable hash with the bundled `SHA256SUMS.txt`. Run the launcher normally, without
   **Run as administrator**. Settings/cache live in `ArtCraftLauncherData` beside the exe.
5. Check for updates, confirm both apps have newer versions, then choose **Update all**.
   After downloading, expect **one UAC approval for Windows PowerShell** for the batch,
   followed by both verified MSI updates. Check both versions and launch both apps.
   No UAC prompt, multiple prompts, a hang, or an MSI verification failure is a test failure
   to investigate, not a reason to relax validation.
6. Restore the snapshot for cancellation and failure cases: cancel UAC and confirm failure
   reporting; leave an app running and confirm its update is blocked; try an uninstall while
   a batch is active and confirm installer operations are serialized. Close/restart the
   launcher to check portable settings and app detection.

Retain `ArtCraftLauncherData` diagnostics and the administrator-readable logs in
`%SystemRoot%\System32\ArtCraft-MSI-*` when reporting failures. Remove protected staging
directories only as an administrator after testing, or discard the VM.

Hosted CI checks compilation, tests and executable startup with `--version`; it cannot verify
the interactive UAC desktop, real app update success, or rendering on your VM graphics driver.
See [the security design](windows-msi-security.md) for the remaining manual security scenarios.

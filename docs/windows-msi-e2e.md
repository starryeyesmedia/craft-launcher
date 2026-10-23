# Real Windows MSI integration

The **Windows real MSI batch integration** workflow is manual only, restricted to
`starryeyesmedia/craft-launcher`, `fix/windows-batched-uac`, and a disposable GitHub-hosted
`windows-latest` runner. No secrets, certificates, trust-store changes, or local mirrors are
used. Never run its ignored test against a workstation or persistent/self-hosted runner.

Until this workflow exists on the default branch, GitHub cannot dispatch it directly by name.
Dispatch the existing **Windows MSI security** workflow on `fix/windows-batched-uac` with
`real_msi_e2e=true` (`package_vm=false`). Its explicitly manual-only job calls this dedicated
workflow. Push and pull-request runs cannot select that job. For example:

```sh
gh workflow run windows-msi.yml --repo starryeyesmedia/craft-launcher \
  --ref fix/windows-batched-uac -f real_msi_e2e=true
```

The ignored Windows unit test `backend::tests::windows_e2e::official_msi_batch_e2e`:

1. Refuses existing PhotoCraft/VectorCraft installations. Downloads official x64 MSIs and
   checksum files for PhotoCraft 0.13.0/0.14.0 and VectorCraft 0.15.0/0.16.0. Uses the production
   policy's checksum parser, Authenticode publisher validation, read-only MSI identity and
   per-machine scope checks. **All four packages must pass before any installation starts.**
2. Installs the older verified packages with the system MSI engine and their normal
   per-machine defaults. Checks HKLM 64-bit uninstall records, exact versions/publisher and
   WindowsInstaller registration. Does not use `Win32_Product`, which can trigger repairs.
3. Seeds the backend with the actual pinned GitHub release metadata and detected baseline
   installations, then sends the real `Command::InstallAll`. Backend workers download and
   verify the official update packages again, reserve/join the real shared MSI coordinator,
   and invoke the unchanged protected policy and local byte source. The test requires one
   policy invocation for both apps and individual successful backend results.
4. Requires the exact new versions in machine-wide installation records. Exercises real
   protected-policy rejection of a forged caller checksum and corrupted official MSI bytes,
   with two individual errors; rechecks installed versions afterwards.

The runner already has an administrator token. Only in a `cfg(test)` build, an internal flag
set by this ignored test selects direct system PowerShell execution of the **identical encoded
policy**, instead of the production `Start-Process -Verb RunAs` wrapper. The flag and branch
are absent from shipped binaries. The compiled catalog, independently fetched published
checksums, Authenticode, identity/scope checks, protected ACLs, staging, results, and real
`msiexec` execution are retained. No successful signature verification is mocked.

**Automated installation success is not verification of one interactive UAC approval.** The
hosted test cannot verify consent count, secure desktop behavior, credential entry,
cancellation of UAC, or the unelevated/admin boundary. GUI/running-app end-to-end behavior
also remains a [disposable VM task](windows-vm-test.md); unit tests separately cover the
coordinator's cancellation and installer serialization.

The always-run finalizer captures verification states, before/after records, per-app backend
results, protected policy result codes, baseline/cleanup MSI exit codes, Windows version,
and unavailable scenarios. It removes only verified test ProductCodes on the initially empty
runner; GitHub discards the VM afterwards. A failure before installation never enables
cleanup. Raw MSI logs, package files, and GitHub API answers stay private to the disposable
runner. The diagnostic artifact contains JSON and **allowlisted numeric MSI returns/action
identifiers only**, excluding raw property/environment dumps, credentials and personal paths.
An annotation and job summary expose decisive results when artifact downloads are unavailable.

If upstream releases lack a valid official signature, published checksum or compatible
per-machine metadata, the workflow fails clearly during preflight. Do not change production
verification to obtain a green integration run. Such incompatibility is a release prerequisite
to resolve with the official publisher.

## Verified signing and manufacturer identities

The initial October 23, 2026 run exposed an incorrect assumption: the certificate publisher
is **Learning Machines Inc**, while the authored MSI Manufacturer is **Learning Machines LLC**.
All four official packages were downloaded again and independently inspected with `msiinfo`
and Authenticode CMS extraction. [The recorded evidence](windows-msi-identities.json) includes
the full certificate subject, issuer, thumbprint, each published SHA-256 and actual MSI table
values. All four specify `ALLUSERS=1` and omit `MSIINSTALLPERUSER`; ProductName and ProductVersion
match the requested applications/releases. Source templates were not used as a substitute
for inspecting the actual MSI databases.

The production signer check now accepts exactly **Learning Machines Inc**, after Windows
reports a `Valid` Authenticode signature. The independent Manufacturer check remains exactly
**Learning Machines LLC**. No publisher alias, wildcard, certificate-chain bypass, trust-store
change or per-machine scope relaxation was introduced. The unit tests distinguish these two
identities; the E2E must additionally validate the real packages and actual installations.
Public certificate details and read-only MSI properties are also captured on the Windows
runner. Protected-policy result indices are mapped to app IDs in test-only instrumentation,
so per-app MSI exit codes remain attributable even when concurrent downloads finish in a
different order.

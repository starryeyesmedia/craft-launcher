# Windows MSI batch security review

Reviewed commit: 5fbb405348bb3bd18a6a1da2d4b62b0283b14f46.
The findings below are corrected by the follow-up on fix/windows-batched-uac.

## Findings

1. **High — per-user GUI executable elevated.** Authenticode verification in main cannot
   protect code that runs before main: imported DLLs and runtime initialization have already
   loaded. Per-user installations, portable directories, and inherited working directories
   are unsuitable elevated loading locations. This matches the DLL-planting objection in
   [upstream PR #68](https://github.com/storytold/craft-launcher/pull/68).
2. **High — caller-controlled authorization.** The old helper accepted both the purported
   downloads root and hash. A direct invocation could choose any directory/hash; comparing the
   executable's signature with itself did not pin ArtCraft's publisher, and a matching publisher
   alone did not prove that the MSI was an authorized app release. Also, the old argument builder
   omitted --install-msis, so normal elevation did not actually enter the helper.
3. **High — result substitution and privileged path races.** The old helper released its result
   handle before the parent reopened a user-owned path. Success exit status did not authenticate
   the subsequently opened file. Checking a path for reparse points before using it was also
   insufficient against ancestor replacement. Forged success could cause deletion of a cached
   update even when installation failed.
4. **Medium — independent installer locks.** The batch coordinator did not acquire INSTALLER.
   MSI uninstall and batch install could overlap and fail with 1618. The old ALLUSERS command
   argument also did not verify the MSI's authored installation scope.

## Elevation and authorization

The GUI never elevates itself. The legacy --install-msis entry point always refuses requests.
The unelevated launcher starts the OS PowerShell executable obtained through GetSystemDirectory,
with an OS working directory, no profiles, and a cleared environment. That process asks UAC once
to run the same system PowerShell host with the fixed batch policy. No executable, DLL, script
file, or module from the launcher's installation/cache directory is loaded with elevation.
PowerShell modules are resolved explicitly from the system host's module directory.
The batch is gzip/base64-encoded in memory to fit Windows' command-line limit; encoding is
transport, not an authorization mechanism. Oversized commands fail before asking for UAC.

This is the system-hosted installer-chain alternative suggested in PR #68, with an added
verification/staging policy. A bare elevated msiexec /i chain cannot itself authenticate a
batch, inspect scope before installation, or protect caller-owned package paths. There is no
permanent LocalSystem service (PR #311), and portable ZIP installs (PR #345) keep their existing
path. UAC remains enabled; declining its one prompt cancels the whole pending batch.

The elevated policy derives repositories, accepted app names and executable stems from the
compiled catalog. Request fields identify an app, tag and artifact, never a trusted URL.
Tags and filenames must agree; only Windows MSI assets from that app are accepted.
The policy independently fetches SHA256SUMS.txt over Windows-validated HTTPS from the pinned
storytold repository/tag, caps the response, restricts HTTPS redirect hosts and requires exactly
one checksum entry. The caller's hash must agree with this independently obtained publication.

Source bytes come from a short-lived, unelevated loopback server bound only to 127.0.0.1. It
serves fixed, one-use file indices under a random session path, with bounded HTTP headers and
socket timeouts. No source filesystem path crosses the privilege boundary. This avoids elevated
file opens racing through caller-owned junctions into SMB paths and leaking administrator
network credentials. The elevated loopback client uses no proxy, credentials or redirects.
The stream is length-capped and copied into an administrator-owned directory under
the OS system directory. The policy hashes the copy against the official publication, verifies a valid
Authenticode signature whose certificate simple name is exactly Learning Machines Inc, and opens the
MSI database read-only through the absolute system msi.dll. Managed P/Invoke declarations are
emitted in memory; privileged COM activation and user-owned temporary assemblies are avoided.
It independently requires ProductName to match the catalog, Manufacturer to equal
Learning Machines LLC, ProductVersion to match the release, ALLUSERS=1, and MSIINSTALLPERUSER
absent or zero. The certificate signer and MSI Manufacturer are separate identities; neither
is inferred from the other. There is no wildcard or legacy-publisher alias. Certificate subject,
issuer and thumbprints for the four verified official packages are recorded in
[the inspection evidence](windows-msi-identities.json), along with actual MSI properties and
published hashes. The common signer subject is
`CN=Learning Machines Inc,O=Learning Machines Inc,L=Atlanta,ST=Georgia,C=US`; its issuer is
`CN=Microsoft ID Verified CS AOC CA 03,O=Microsoft Corporation,C=US` and SHA-1 certificate
thumbprint is `0F52B93A635EFA09AF6036A4DD4977683B4FB7E2`.
Thumbprints identify the inspected certificate, not a new trust anchor or a permanent pin:
Microsoft's short-lived signing certificates rotate. Windows must still return `Valid`,
including its certificate-chain and timestamp validation, for every package. No root or leaf
certificates are imported. Linux extraction records certificate data and independently reads
the MSI database; it does not replace the Windows trust decision.
Only the staged, authenticated package goes to the system msiexec. A local source replacement
or a hostile loopback peer cannot authorize different bytes: verification and installation use the
protected copy. The staged file is read-locked against writes/deletion during checks and install.

There is no caller-supplied MSI transform, command, URL, log path, extra installer argument or
arbitrary helper executable. A custom INSTALLFOLDER must be a local path without reparse points.
Its closest existing directory must be owned and writable only by SYSTEM/Administrators or
TrustedInstaller, and every ancestor must forbid unprivileged replacement and ACL/owner changes.
This also closes destination junction races; unsafe user-owned custom folders now fail closed.
The property is quoted with Windows trailing-separator escaping. Published MSI custom actions remain trusted publisher
code and are not sandboxed. Installation uses /qn /norestart ALLUSERS=1 only after inspecting
scope, and checks for running app processes immediately before each MSI.

## Results, permissions and serialization

Each run uses a cryptographically random 128-bit session under the OS system directory, a parent
standard users cannot write. The directory is created with a protected ACL: SYSTEM and
Administrators get full control; Users get read/execute only; Administrators own the directory.
Each staged MSI, log and result file also gets an explicit Administrators owner and protected
ACL atomically at creation. Only the fixed-code results allow Users read access; verbose logs
and staged packages remain administrator-only. Ownership does not inherit, and a default account SID owner could
otherwise let the same account's unelevated processes change the file's ACL.
Existing sessions and reparse paths are refused. Results are created once and held against
writes/deletes while published incrementally. The parent reads this fixed, protected path,
rather than trusting a child exit code or a path in its user-writable cache. A standard user
cannot replace the file/directory before, during or after the child exits. File size and parser
indices are bounded. MSI verbose logs also go only into the protected run directory.
Logs/results are retained there for administrator diagnosis; they may be removed by an
administrator. The unelevated launcher does not attempt privileged cleanup.

The MSI batch obtains an RAII permit from the same Queue used by MSI uninstall, individual
MSI install, and self-update reinstall. Admission is closed for every explicit Update all action,
including one started while another operation is active. Jobs remain cancellable while waiting
for downloads or the shared queue. Once the UAC/installer call starts, its jobs see it through.
One failed MSI reports its own error and does not prevent the other authorized packages running.
External installers and other launcher processes are still serialized by Windows Installer,
and an external 1618 is reported normally.

## Validation and unsigned development builds

The Windows MSI security workflow runs on windows-latest with stable-x86_64-pc-windows-msvc
on development-branch pushes and relevant pull requests. It explicitly checks compilation,
runs strict clippy, and runs workspace unit/integration tests. Windows-native tests invoke
the real system PowerShell, create/read MSI Property tables without installing them, test
scope/identity/signature rejection, test deny-write/delete file sharing, inspect protected
result ACLs and test session collision refusal. A separate test streams real cached bytes over
the production loopback server into
the protected staging directory and confirms rejection of unsigned and hash-mismatched data.
The GUI integration test also checks that the obsolete helper exits with refusal status 2.
The ACL and staging tests require an already elevated test shell (the hosted Windows runner
supplies one); they do not request UAC.

Unsigned GUI development builds can run these policy tests and can request installation of
officially published/signed app releases. The GUI signature is no longer a trust input.
Unsigned MSI fixtures must continue to fail the production signature gate. Their scope,
argument, parser and queue behavior can be tested independently without mocking production
signature success or adding a development certificate to a production trust store.
No debug-build flag, environment variable or Cargo feature disables the elevated checks.

Manual testing in a disposable Windows VM is still required for real secure-desktop UAC,
standard-user credentials for a different administrator, enterprise PowerShell policy,
publisher certificate compatibility, a complete multi-app install, running-app races,
declined UAC, failure/reboot return codes and hostile attempts to replace junctions/results.
Hosted runners commonly have UAC disabled/already elevated, so green CI cannot prove one
interactive approval. No Windows-native test is represented as having run on Linux.

## Remaining trust and operational limits

Windows' protected system directory, administrators, TLS root store, official GitHub release
publication and the publisher's signing identity are trust anchors. Another administrator
can alter results, OS binaries or trust roots and is outside the standard-user threat model.
Checksums require network access after elevation and fail closed offline. A compromised
official publisher/release can distribute malicious custom actions; this is not a sandbox.
The certificate name is fixed; publisher changes require a reviewed policy change.
Enterprise policy may forbid PowerShell or dynamic script blocks; report failure rather than
bypass it. Strict destination checks reject junction-based or user-writable custom install locations.
Per-run logs consume administrator-owned storage until removed. The policy reads declared
MSI scope, but a trusted MSI custom action could subsequently change properties; release
package testing remains necessary. An app can start after its final process check; Windows
Installer's own files-in-use rules remain the final guard.


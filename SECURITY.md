# UNKNWN security architecture and limitations

## Release authenticity

Packaged releases use the existing Ed25519-signed manifest. The executable
contains the release public key; the private signing key must remain outside
the application package and under release-operator control. The startup
decision is made at module startup before selecting a persisted data location
or loading the vault configuration. A modified, unsigned, incomplete, or
unverifiable enforced release skips profile/configuration loading and blocks
normal startup before application event hooks, hotkey registration, and
temporary file cleanup are started. Invalid saved location metadata also
fails closed into the acknowledged startup-error screen instead of aborting
before the graphical interface can be created.

This early decision covers release integrity and the supported runtime trust
probes; it is not a claim that profile configuration or every recovery journal
has already been evaluated. The Intro reports the actual persisted-location,
configuration, and destructive-cleanup-journal outcomes available before it
starts. It explicitly marks profile/storage recovery as deferred until profile
selection or authentication. A pending or invalid cleanup journal is shown as
recovery-required/failed, never as a successful recovery. Storage-move recovery
and the authenticated settings snapshot are evaluated in the authenticated
sign-in flow. Their individual failure paths block the affected operation
rather than granting access on an unverified result.

The manifest contains hashes and package paths. It is authenticity metadata,
not a secret. Encrypting it with a key embedded in the executable would not
provide meaningful confidentiality. No encryption layer is claimed for this
public metadata. The release check is offline.

## Startup and vault access

The startup gate state is authoritative; the Intro is presentation only and
cannot grant access. A failed mandatory check skips normal profile, login, and
vault flow. The Intro reports package integrity separately from runtime
trust and the final gate decision, so a debugger finding is not mislabeled as
a package-integrity failure. The blocked screen includes a persistent animated
failure indicator created only by the mandatory failure path and waits for a
non-repeating key press,
the Quit action, or window close before exiting. It does not provide a bypass
or initiate data deletion.

Failure screens show a non-sensitive diagnostic category. On gate failure,
in-memory vault configuration and index state are cleared, supported worker
dialogs receive cancellation requests, and normal UI transitions and hotkeys
are blocked. Acknowledgment is idempotent; if an operation is still draining,
shutdown waits rather than closing its UI objects underneath it. This is
best-effort process-local coordination and cannot survive forced termination
or a compromised operating system.

The destructive-cleanup journal is checked before the profile chooser.
Profile/key-rotation recovery occurs after a profile is selected; storage-move
and storage-transaction recovery occur after credential authentication and
before the vault session is opened. The encrypted vault index is loaded only
after authentication. These stages use the existing vault-key architecture
and authenticated encryption, and are not all part of the early package/runtime
gate.

## Runtime checks

For enforced packaged builds, startup checks Python tracing/profiling and the
Windows debugger indicators exposed by `IsDebuggerPresent` and
`CheckRemoteDebuggerPresent` before selecting persisted profile state or
loading vault configuration. A positive result, or failure to perform the
required Windows check, blocks startup. The same check is required before
sensitive actions and periodically during an active session. Development and
source runs do not enforce this policy so they remain debuggable. The existing
user-configurable debugger setting remains an additional sensitive-action
warning in development runs.

These are limited indicators, not proof of compromise and not protection
against instrumentation that these APIs do not report. A transient API failure
in an enforced build is treated as unavailable and fails closed; this can
prevent startup on an unsupported or damaged Windows runtime. No scan of
unrelated personal files or processes is performed. The Intro reports whether
the check passed, was not enforced, or blocked startup; it does not authorize
the application.

Release integrity is spot-checked during an authenticated session against
hashes retained from the full startup verification. This depends on the
integrity of the running verifier and process. A fully compromised operating
system or process can falsify in-process checks.

## Plaintext and data handling

Vault payloads and the authenticated security-settings snapshot use the
application's existing authenticated-encryption and key-derivation paths.
The config and profile-location files are not confidential containers: they
include application settings, profile locations, and password/recovery key
wrappers, but not the plaintext master password or vault key. The security
settings snapshot detects changes; it does not encrypt every setting in the
config file. The signed release manifest is intentionally public authenticity
metadata and is not decrypted to a plaintext temporary file.

Video/audio disk playback is an explicit low-memory mode because the
multimedia backend consumes a local file URL; memory mode supplies a Qt buffer
and may use substantial RAM. Disk-mode plaintext is created under the
application temp directory and is removed after authentication failure,
playback setup/error, viewer close, application close, or a subsequent normal
startup sweep. A trusted package also sweeps owned media temp files when a
non-package startup gate fails. Cleanup is best-effort: forced termination,
power loss, OS file locks, storage snapshots, and flash wear-levelling can
prevent or outlive deletion. When package integrity itself fails, cleanup code
is not trusted and the app does not run it against persisted files. No
guarantee is made that plaintext never exists on disk when disk playback is
selected.

The local `error.log` remains useful for triage but now records a diagnostic
identifier, a validated exception class, and bounded function/line locations;
it omits exception messages, source lines, local variables, and full paths to
avoid persisting values that could contain secrets or private filenames. The
Diagnostics view sanitizes legacy log content when displaying it; already
written raw tracebacks are not retroactively rewritten. Security-event logs
remain local and redact recognized sensitive fields, but arbitrary caller
text is not guaranteed to be safe. These behaviors do not satisfy a blanket
requirement for no plaintext temporary or log artifacts. The application
does not claim that plaintext in process memory can never be observed, that
operating-system paging cannot persist memory, or that file deletion
guarantees physical erasure.

Diagnostics and the Intro must not display vault keys, recovery material, or
plaintext protected data. UNKNWN does not require network access or telemetry
for these checks.

## File intake and shortcut notice

File and folder drops are accepted only in an unlocked, writable vault and
are routed through the existing reviewed, preflighted, background sealing
flows. The drop path rejects non-local items, links, reparse points, and
non-regular file/folder roots; the sealing pipelines validate inputs again
before processing. Dropping does not remove source data unless the existing
explicit source-shredding option is enabled and sealing succeeds.

The panic-shortcut notice is an optional informational dialog. Disabling it
does not disable the shortcut, change its configured action, bypass existing
destructive-action checks, or suppress mandatory security-failure screens.
The preference is included in the authenticated security-settings snapshot.

## Test environment and release verification status

Manifest verification reads the public signed authenticity metadata in memory;
it does not decrypt the manifest or create a plaintext copy. Verification does
not create staging, backup, or cache files. Tests cover authentication,
parsing, inventory failures, injected interruptions, and process termination
without adding files to the package directory. The manifest remains public and
is not encrypted with a key embedded in the executable.

Symlink security tests are retained and skip only when the current account,
filesystem, or platform cannot create the required link. On Windows, run them
with Developer Mode enabled or an account permitted to create symbolic links;
the tests run automatically when link creation succeeds.

The release process provides manifest/signature verification and archive
verification tooling. A production package must be built and independently
audited before making claims about its shipped contents or Authenticode
signature. The production-package audit remains blocked until a real signed
distribution and owner-controlled signing environment are available. No
production package audit is implied by this document.

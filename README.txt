# UNKNWN

**UNKNWN** is an offline, encrypted, burn-after-reading vault for Windows.

> *the known for you will be unknown for others*

UNKNWN is designed around local privacy, authenticated encrypted storage, crash-safe operations, and controlled destruction of vault data. It does not require network access for normal operation.

## Features

### 🔐 Encrypted Vault

- AES-256-GCM authenticated encryption.
- Encrypted and authenticated vault metadata.
- Password and recovery-word based authentication.
- Streaming decryption for large files.
- File and folder sealing with authenticated encrypted storage.
- View-count and burn-after-reading support.
- Optional read-only operation mode.
- Vault profile support with independent master passwords.

### 🛡️ Integrity & Security

- Signed release manifest and installation integrity verification.
- Modified, missing, or unlisted packaged files can cause the release integrity check to fail.
- Crash-safe configuration and vault-index updates.
- Authenticated recovery and transaction state.
- Security and diagnostic checks run locally.
- No network requests are required for normal vault operation.
- Sensitive authentication data is not stored in diagnostic or activity history.

UNKNWN is designed to reduce accidental data exposure, but it cannot guarantee physical data erasure. SSDs, backups, snapshots, failing hardware, and filesystem or driver behavior may retain data outside the application's control.

### 💥 Panic Wipe & Self-Destruct

UNKNWN provides destructive cleanup features with explicit confirmation and recovery-aware cleanup handling.

- **Panic Wipe** clears supported UNKNWN-managed vault and profile data.
- **Full Self-Destruct** can additionally remove a verified packaged installation.
- Interrupted cleanup can resume after restart.
- Modified or unverifiable installations are protected from full self-destruct.
- Destructive operations do not follow symbolic links outside their target.
- Cleanup failures are reported instead of being silently treated as successful.

These features are not a guarantee of forensic or physical data destruction.

### 📊 Vault Management

- Search vault items by visible name, type, size, or item ID.
- Sort and inspect authenticated metadata.
- Vault statistics and duplicate detection.
- Background operations with progress and cancellation.
- Operation and activity monitoring.
- Crash-safe data-folder movement.
- Vault profile import/export.
- Vault-key rotation with re-encryption and verification.

### 👁️ Built-in Viewers

UNKNWN can preview supported content without extracting archive members or executing programs.

Supported preview capabilities include:

- PDF
- Images
- Text
- ZIP / 7z / RAR member listings
- DOCX / XLSX / PPTX / EPUB text extraction
- ISO-9660 directory listings
- Windows PE metadata
- MIDI metadata
- Bounded hexadecimal previews
- Audio/video playback

Large media can use disk-backed streaming to reduce RAM usage. Temporary plaintext media files may remain after an unexpected crash until startup cleanup runs.

### 🎨 Look Studio

UNKNWN includes a customizable terminal-inspired interface with:

- Multiple themes.
- Animated and still backgrounds.
- Live preview.
- Animation speed and density controls.
- Terminal-style interface options.
- CRT scanlines.
- Reduced-motion support.
- Custom background photos.

## Diagnostics

UNKNWN includes local diagnostic and health checks that can:

- Verify release integrity.
- Authenticate the encrypted vault index.
- Verify indexed encrypted items.
- Inspect bounded local security and crash logs.
- Report missing or malformed diagnostic sources.
- Redact sensitive fields and path-like identifiers.

Diagnostics do not require network access and do not install external packages.

## Requirements

- Windows
- Python 3
- Dependencies listed in `requirements.txt`

For development:

```powershell
pip install -r requirements.txt
python unknwn.py
```

## Development Build

To run the development build pipeline:

```powershell
.\build.ps1 -Dev
```

Development builds are intended for testing and are not equivalent to signed production releases.

## Release Build

The release pipeline performs the project's tests, packaging, signing, manifest generation, integrity verification, and release artifact generation.

```powershell
.\build.ps1
```

A production release requires the appropriate Windows signing environment and release credentials.

**Never commit private signing keys, passwords, certificates, or other secrets to the repository.**

The public release key may be included in the repository where required for release verification.

## Tests

The project uses Python's `unittest` framework.

Examples:

```powershell
python -m unittest tests.test_core
python -m unittest tests.test_diagnostics
python -m unittest tests.test_vault_management
python -m unittest tests.test_vault_management_move
```

The complete test suite is available under `tests/`.

## Project Structure

```text
UNKNWN/
├── assets/
├── tests/
├── tools/
├── build.ps1
├── easter_egg.py
├── easter_egg_messages.py
├── operation_engine.py
├── requirements.txt
├── release_pubkey.txt
├── SECURITY.md
├── UNKNWN.ico
├── unknwn.py
├── unknwn_integrity.py
├── unknwn_media.py
├── verify_install.ps1
└── warden_art.py
```

## Security Notes

UNKNWN is intended to provide application-level protection for locally stored encrypted data.

It does **not** claim to provide:

- Guaranteed physical erasure.
- Protection against compromised hardware or operating systems.
- Protection against filesystem or driver failures.
- Protection against every form of reverse engineering.
- Protection against offline password guessing when an attacker possesses a copied vault.

Use a strong, unique password and keep recovery words private.

For important originals, maintain independent backups.

## License

See the repository for the applicable project licensing information.

## Status

UNKNWN is an actively developed project. Some security and reliability mechanisms may continue to evolve as additional testing and failure-injection coverage are added.

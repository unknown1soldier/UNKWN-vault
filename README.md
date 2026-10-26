# UNKNWN

### The known for you will be unknown for others.

**UNKNWN** is an offline encrypted vault for Windows, built for private files, controlled access, and burn-after-reading workflows.

It is designed around one simple idea:

> **Your private data should stay yours.**

UNKNWN does not require an online account, cloud storage, telemetry, or network access for normal operation.

---

## 🔐 What is UNKNWN?

UNKNWN is a local encrypted vault that lets you securely store, view, manage, and destroy sensitive files while keeping the entire workflow on your own device.

It combines:

- Authenticated encryption
- Crash-safe storage
- Release integrity verification
- Local diagnostics
- Burn-after-reading controls
- Vault profiles
- Secure file handling
- Built-in file viewers
- Privacy-focused settings
- Offline operation

The application is designed to fail closed when important security checks cannot be verified rather than silently continuing with an uncertain state.

---

# ✨ Features

## 🔒 Encrypted Vault

- AES-256-GCM authenticated encryption
- Encrypted and authenticated vault metadata
- Password-based vault protection
- Recovery-word authentication
- Streaming decryption for large files
- File and folder sealing
- View-count and burn-after-reading support
- Read-only mode
- Multiple independent vault profiles
- Vault key rotation with re-encryption and verification

Files are processed through authenticated encryption rather than being stored as ordinary plaintext inside the vault.

---

## 💥 Burn & Destructive Controls

UNKNWN includes controlled destructive operations for users who need them.

### Panic Wipe

Clears supported UNKNWN-managed vault and profile data while using recovery-aware cleanup handling.

### Full Self-Destruct

A stronger destructive mode available to verified packaged installations.

It can remove supported application data and the verified UNKNWN installation after the required confirmations and security checks succeed.

Interrupted cleanup is designed to remain recoverable instead of silently pretending that everything was deleted.

> **Important:** No software can guarantee physical destruction of every copy of data. SSD wear-leveling, backups, snapshots, filesystem behavior, hardware failure, and forced termination can all prevent guaranteed physical erasure.

---

# 🛡️ Security

UNKNWN uses several independent layers rather than relying on a single password screen.

### Release Integrity

Packaged releases use a signed manifest and an embedded public verification key.

A modified, incomplete, unsigned, or unverifiable enforced package can be blocked before normal vault access begins. The private signing key remains outside the application package.

### Runtime Trust Checks

Enforced packaged builds perform runtime checks for supported Windows debugger and tracing indicators.

These checks are deliberately limited. They are indicators, not proof that a system is compromised, and they cannot protect against a completely compromised operating system.

### Crash-Safe Storage

Vault operations use authenticated transaction and recovery mechanisms so interrupted writes, burns, and other storage operations can be detected and recovered instead of silently producing an inconsistent vault.

### Local Only

UNKNWN does not require network access or telemetry for its security and diagnostic checks.

---

# 📁 Vault Management

UNKNWN provides tools for managing larger vaults without leaving the application.

### Search & Organization

Search vault items by:

- Name
- File type
- Size
- Item ID

Items can also be sorted and inspected through authenticated metadata.

### Statistics & Duplicates

Vault statistics provide authenticated metadata totals and duplicate analysis without automatically deleting anything.

### Operation Center

Long-running operations can display:

- Progress
- Elapsed time
- Cancellation
- Recovery state
- Failure state

### Data Location

The vault data folder can be moved using a verified, background migration process.

The original location is retained as a backup rather than being automatically deleted.

---

# 📦 Import & Export

Vault profiles can be exported and imported as encrypted packages.

Import verification checks the package before activating the imported profile.

Each profile maintains its own master-password protection.

---

# 👁️ Built-in Viewers

UNKNWN includes built-in previews for several common file types.

Supported functionality includes:

- Images
- PDF
- Text
- ZIP / 7z / RAR listings
- DOCX
- XLSX
- PPTX
- EPUB
- ISO-9660 directory listings
- Windows PE metadata
- MIDI metadata
- Bounded hexadecimal previews
- Audio and video

Archive members are browsed without extracting them to disk, and programs are never executed as part of archive preview.

Large audio/video files can use disk-backed streaming to reduce memory usage.

When disk-backed playback is enabled, temporary plaintext media may exist locally during playback. Cleanup is best-effort and cannot guarantee physical erasure.

---

# 🎨 Look Studio

UNKNWN is not trying to look like another spreadsheet from 2007.

Look Studio provides a customizable terminal-inspired interface with:

- Multiple themes
- Animated backgrounds
- Still backgrounds
- Live preview
- Animation speed controls
- Density controls
- Terminal styling
- CRT scanlines
- Reduced-motion options
- Custom background images

The visual system is designed to make the application feel like a dedicated privacy tool rather than a generic file manager.

---

# 🧭 Privacy & Accessibility

UNKNWN includes several controls designed to reduce unnecessary exposure:

- Optional Windows account-name privacy
- Read-only mode
- Reduced-motion mode
- Configurable shortcuts
- Activity history controls
- Ghost Mode
- Local diagnostics
- Contextual help
- Profile switching

Security-sensitive actions remain subject to their required confirmation and authorization rules.

---

# 🩺 Diagnostics & Vault Health

UNKNWN includes local health and diagnostic tools that can verify:

- Release integrity
- Vault index integrity
- Encrypted vault items
- Local security events
- Crash/error information
- Configuration-related issues

Diagnostics are bounded and designed to avoid displaying vault keys, recovery material, or protected plaintext data.

---

# 🖥️ Requirements

### Supported platform

- Windows

### Development requirements

- Python 3
- Dependencies listed in `requirements.txt`

Install dependencies:

```powershell
pip install -r requirements.txt
```

Run the application:

```powershell
python unknwn.py
```

---

# 🧪 Development & Testing

UNKNWN includes an automated test suite covering areas such as:

- Cryptography
- Authentication
- Crash recovery
- Vault management
- Storage movement
- Diagnostics
- Integrity verification
- Viewer flows
- Release verification

Run individual test groups with:

```powershell
python -m unittest tests.test_core
python -m unittest tests.test_diagnostics
python -m unittest tests.test_vault_management
python -m unittest tests.test_vault_management_move
```

Development builds can be tested with:

```powershell
.\build.ps1 -Dev
```

---

# 📦 Release Verification

Production releases use a signed integrity manifest and Windows code-signing infrastructure.

The release process verifies the packaged contents before distribution.

**Private signing keys must never be committed to this repository.**

The public release key may be distributed with the project for verification.

---

# ⚠️ Security Limitations

UNKNWN is designed to provide strong application-level protection, but it does not make impossible promises.

It does **not** guarantee:

- Physical destruction of data
- Protection against a fully compromised operating system
- Protection against failing storage hardware
- Protection against filesystem or driver bugs
- Protection against every form of reverse engineering
- That plaintext can never exist in memory or OS-managed storage
- That an attacker with a copied vault cannot attempt offline password guessing

For important data, use a strong unique password, protect your recovery words, and maintain independent backups where appropriate.

Full-disk encryption is also recommended for protection against device theft.

---

# 📂 Project Structure

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

---

# 📜 Security Documentation

For the deeper security architecture, limitations, release-integrity model, runtime checks, plaintext handling, and release verification details, see:

**[`SECURITY.md`](SECURITY.md)**

---

# 🚧 Project Status

UNKNWN is an actively developed project.

Security and reliability mechanisms continue to receive testing, auditing, and failure-injection coverage as development progresses.

The project intentionally documents its limitations rather than claiming that software can magically defeat hardware, operating systems, backups, or physics.

---

## Contact

For project-related contact:

**Discord:** `unknown1soldier`

---

### UNKNWN

**Private by design.  
Offline by default.  
Known only to you.**

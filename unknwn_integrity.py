"""UNKNWN release-integrity and settings-snapshot helpers. No Qt, no network, no secrets.

Trust model: RELEASE_PUBKEY (Ed25519, public half only) is compiled into the signed executable by the build.
A release ships `unknwn.manifest` (JSON: relative path -> SHA-256) and `unknwn.manifest.sig` (Ed25519 signature over those exact bytes).
The private key never leaves the release machine. This only has teeth when the executable itself is Authenticode-signed and installed
where ordinary users cannot write: anyone who can rewrite the verifier can also rewrite the key it trusts.
"""
import os, sys, ctypes, json, base64, random, hashlib, hmac
from pathlib import Path
from typing import Any, Literal, Union, cast
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

RELEASE_PUBKEY = "19c55d3b5ef160d443d54242ec75490990e9d634ee234ae4786960aef97b6ef4"   # 64 hex chars; written by `tools/release.py embed` at build time. Empty = unsigned development build.
MAN, SIG, DATA_DIR = "unknwn.manifest", "unknwn.manifest.sig", "UNKNWN_data"
EXEC_EXT = {".exe", ".dll", ".pyd", ".so", ".py", ".pyc", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".sys", ".msi", ".scr", ".com"}
_verified_files: dict[str, Path] = {}
_verified_hashes: dict[str, str] = {}

GateStatus = Literal["ok", "dev", "fail"]
GateError = Literal[
    "",
    "release_integrity",
    "runtime_debugger_detected",
    "runtime_check_unavailable",
    "package_integrity_changed",
    "startup_state_unavailable",
]


def security_decision(
    enforce: bool,
    integrity: Literal["ok", "dev", "fail"],
    runtime: Literal["clear", "debugger", "unavailable", "not_enforced", "not_run"],
) -> tuple[GateStatus, GateError]:
    """Return the authoritative startup decision and a safe diagnostic category."""
    if not enforce:
        return "dev", ""
    if integrity != "ok":
        return "fail", "release_integrity"
    if runtime == "clear":
        return "ok", ""
    if runtime == "debugger":
        return "fail", "runtime_debugger_detected"
    return "fail", "runtime_check_unavailable"


def sha256_file(p: Union[os.PathLike[str], str]) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""): h.update(b)
    return h.hexdigest()


def listing(d: Union[os.PathLike[str], str]) -> dict[str, Path]:
    """Every file a release consists of (relative posix path -> Path). The manifest files and the portable data folder are not part of it."""
    d = Path(d); out: dict[str, Path] = {}
    for p in d.rglob("*"):
        if not p.is_file(): continue
        rel = p.relative_to(d).as_posix()
        if rel in (MAN, SIG) or rel.split("/")[0] == DATA_DIR: continue
        out[rel] = p
    return out


def load_manifest(d: Union[os.PathLike[str], str], pub_hex: str) -> dict[str, Any]:
    """Return the manifest dict if its signature verifies against pub_hex, else raise."""
    d = Path(d); raw = (d / MAN).read_bytes(); sig = (d / SIG).read_bytes()
    Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex)).verify(sig, raw)   # raises InvalidSignature
    manifest: dict[str, Any] = json.loads(raw)
    files: Any = manifest.get("files")
    if (type(manifest.get("v")) is not int or manifest.get("v") != 1
            or not isinstance(files, dict) or not files):
        raise ValueError("bad manifest")
    return manifest


def verify_dir(d: Union[os.PathLike[str], str], pub_hex: str) -> bool:
    """Full check: signature, every listed file's hash, and no unlisted executable content. Returns True/False, never raises."""
    try:
        d = Path(d).resolve(); manifest = load_manifest(d, pub_hex); files: dict[str, Path] = {}
        manifest_files: dict[str, Any] = manifest["files"]
        for rel, want in manifest_files.items():
            p = (d / rel).resolve()
            if d not in p.parents or not p.is_file(): return False        # missing, or a path that escapes the release folder
            if not hmac.compare_digest(sha256_file(p), str(want)): return False
            files[rel] = p
        for rel in listing(d):
            if rel not in files: return False   # ANY file not in the signed manifest is rejected, whatever its extension
        global _verified_files, _verified_hashes
        _verified_files = files
        _verified_hashes = {rel: str(digest) for rel, digest in manifest_files.items()}
        return True
    except Exception:
        return False


def verify_partial_dir(d: Union[os.PathLike[str], str], pub_hex: str) -> bool:
    """Check an authorized interrupted removal: only signed package files may remain, or only empty directories and manifest files."""
    try:
        d = Path(d).resolve()
        manifest = d / MAN
        signature = d / SIG
        if manifest.is_file() and signature.is_file():
            signed: dict[str, Any] = load_manifest(d, pub_hex)["files"]
            for rel, path in listing(d).items():
                resolved = path.resolve()
                if (rel not in signed or d not in resolved.parents or not resolved.is_file()
                        or not hmac.compare_digest(sha256_file(resolved), str(signed[rel]))):
                    return False
            return True
        for current, dirs, files in os.walk(d, followlinks=False):
            if dirs:
                return False
            for name in files:
                path = Path(current) / name
                rel = path.relative_to(d).as_posix()
                info = path.lstat()
                if (rel not in (MAN, SIG) or not path.is_file() or path.is_symlink()
                        or getattr(info, "st_file_attributes", 0) & 0x400):
                    return False
        return True
    except Exception:
        return False


def spot(n: int = 1) -> bool:
    """Re-hash n random files against the hashes verified at startup (cheap, repeatable). False = changed after the full check passed."""
    try:
        if not _verified_files: return False
        return all(
            hmac.compare_digest(
                sha256_file(_verified_files[rel]), _verified_hashes[rel]
            )
            for rel in random.sample(
                sorted(_verified_files), min(n, len(_verified_files))
            )
        )
    except Exception:
        return False


def state(
    app_dir: Union[os.PathLike[str], str],
    enforce: bool,
) -> Literal["ok", "dev", "fail"]:
    """'ok' verified release, 'dev' unsigned development run (not enforced), 'fail' enforced but not verifiable."""
    if not enforce: return "dev"
    if not RELEASE_PUBKEY: return "fail"
    return "ok" if verify_dir(app_dir, RELEASE_PUBKEY) else "fail"


def runtime_trust() -> Literal["clear", "debugger", "unavailable"]:
    """Report supported debugger indicators; unavailable is not a trusted result."""
    try:
        if sys.gettrace() is not None or sys.getprofile() is not None:
            return "debugger"
        if sys.platform != "win32":
            return "unavailable"
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.GetCurrentProcess.restype = ctypes.c_void_p
        kernel32.IsDebuggerPresent.restype = ctypes.c_bool
        kernel32.CheckRemoteDebuggerPresent.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_int),
        ]
        kernel32.CheckRemoteDebuggerPresent.restype = ctypes.c_bool
        if kernel32.IsDebuggerPresent():
            return "debugger"
        remote_debugger = ctypes.c_int(0)
        if not kernel32.CheckRemoteDebuggerPresent(
            kernel32.GetCurrentProcess(), ctypes.byref(remote_debugger)
        ):
            return "unavailable"
        return "debugger" if remote_debugger.value else "clear"
    except (AttributeError, ctypes.ArgumentError, OSError, TypeError, ValueError):
        return "unavailable"


# ---------- authenticated snapshot of security-relevant settings (sealed with a key derived from the vault key) ----------
def _k(dek: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=b"unknwn-cfg", info=b"unknwn-file").derive(dek)


def snap_make(dek: bytes, d: dict[str, Any]) -> str:
    iv = os.urandom(12)
    return base64.b64encode(iv + AESGCM(_k(dek)).encrypt(iv, json.dumps(d, sort_keys=True).encode(), b"cfg1")).decode()


def snap_check(
    dek: bytes,
    blob: Union[str, None],
    cur: dict[str, Any],
) -> tuple[Literal["new", "ok", "changed", "bad"], dict[str, Any], list[str]]:
    """-> (status, good, changed). status: 'new' (no snapshot yet), 'ok', 'changed' (edited outside the app; `good` holds the sealed
    values), 'bad' (a snapshot exists but cannot be authenticated)."""
    if not blob: return "new", dict(cur), []
    try:
        raw = base64.b64decode(blob)
        parsed: Any = json.loads(
            AESGCM(_k(dek)).decrypt(raw[:12], raw[12:], b"cfg1")
        )
        if not isinstance(parsed, dict): raise ValueError
        good = cast(dict[str, Any], parsed)
    except Exception:
        return "bad", dict(cur), []
    ch = sorted(k for k in good if k in cur and good[k] != cur[k])
    return ("changed" if ch else "ok"), good, ch

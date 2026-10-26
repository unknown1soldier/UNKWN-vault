"""UNKNWN release tool.   keygen | embed | manifest | verify | validate-key | verify-archive
    (build.ps1 calls these for you; run from the project folder)
Private key: release_key.pem (encrypted with your passphrase). Keep it OFFLINE and backed up. Public key: release_pubkey.txt (safe to share).
Set UNKNWN_KEY_PASS to skip the passphrase prompts in automated builds."""
import sys, os, re, json, getpass, argparse, zipfile, hashlib, hmac, tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import unknwn_integrity as IG
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def passphrase(prompt: str) -> str: return os.environ.get("UNKNWN_KEY_PASS") or getpass.getpass(prompt)


def keygen(a: argparse.Namespace) -> None:
    kp, pp = Path(a.key), Path(a.pub)
    if kp.exists() or pp.exists(): sys.exit("Refusing to overwrite an existing release key. Delete both files yourself only if you want a new identity (older releases will stop verifying).")
    p1 = passphrase("Choose a passphrase for the release key (12+ characters): ")
    if len(p1) < 12: sys.exit("Use at least 12 characters.")
    if not os.environ.get("UNKNWN_KEY_PASS") and getpass.getpass("Repeat it: ") != p1: sys.exit("The passphrases differ.")
    k = Ed25519PrivateKey.generate()
    kp.write_bytes(k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.BestAvailableEncryption(p1.encode())))
    pp.write_text(k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex() + "\n")
    print(f"Created {kp} (PRIVATE: keep offline, back it up) and {pp}.")


def embed(a: argparse.Namespace) -> None:
    pub = Path(a.pub).read_text().strip()
    if not re.fullmatch(r"[0-9a-f]{64}", pub): sys.exit("Bad public key file.")
    m = Path(a.module); t = m.read_text(encoding="utf-8"); n, c = re.subn(r'(?m)^RELEASE_PUBKEY = "[0-9a-fA-F]*"', f'RELEASE_PUBKEY = "{pub}"', t)
    if c != 1: sys.exit("RELEASE_PUBKEY line not found in " + str(m))
    m.write_text(n, encoding="utf-8"); print("Embedded the public key into", m)

def verify_embedded_key(a: argparse.Namespace) -> None:
    pub = Path(a.pub).read_text().strip().lower()
    if not re.fullmatch(r"[0-9a-f]{64}", pub): sys.exit("Bad public key file.")
    binary = Path(a.exe).read_bytes()
    if pub.encode("ascii") not in binary:
        sys.exit("The compiled executable does not contain the configured release public key.")
    print("Compiled executable contains the configured release public key.")


def manifest(a: argparse.Namespace) -> None:
    d = Path(a.dist).resolve(); k = serialization.load_pem_private_key(Path(a.key).read_bytes(), passphrase("Release key passphrase: ").encode())
    if not isinstance(k, Ed25519PrivateKey): sys.exit("The release private key is not Ed25519.")
    files = {rel: IG.sha256_file(p) for rel, p in sorted(IG.listing(d).items())}
    if not files: sys.exit("Nothing to sign in " + str(d))
    raw = json.dumps({"v": 1, "build": a.build, "files": files}, sort_keys=True, indent=1).encode()
    (d / IG.MAN).write_bytes(raw); (d / IG.SIG).write_bytes(k.sign(raw)); print(f"Signed {len(files)} files (build {a.build}).")


def verify(a: argparse.Namespace) -> None:
    ok = IG.verify_dir(a.dist, Path(a.pub).read_text().strip()); print("VERIFY", "OK" if ok else "FAILED"); sys.exit(0 if ok else 1)

def validate_key(a: argparse.Namespace) -> None:
    pub = Path(a.pub).read_text().strip().lower()
    if not re.fullmatch(r"[0-9a-f]{64}", pub): sys.exit("Bad public key file.")
    try:
        key = serialization.load_pem_private_key(Path(a.key).read_bytes(), passphrase("Release key passphrase: ").encode())
    except (TypeError, ValueError) as exc:
        sys.exit(f"Could not unlock the release key ({type(exc).__name__}). Check the ReleaseKey passphrase and protected key file.")
    if not isinstance(key, Ed25519PrivateKey): sys.exit("The release private key is not Ed25519.")
    actual = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    if not hmac.compare_digest(actual, pub): sys.exit("The private and public release keys do not match.")
    print("Release private/public keys verified.")

def change_passphrase(a: argparse.Namespace) -> None:
    pub = Path(a.pub).read_text().strip().lower()
    if not re.fullmatch(r"[0-9a-f]{64}", pub): sys.exit("Bad public key file.")
    key_path = Path(a.key)
    try:
        key = serialization.load_pem_private_key(key_path.read_bytes(), passphrase("Current release key passphrase: ").encode())
    except (TypeError, ValueError) as exc:
        sys.exit(f"Could not unlock the release key ({type(exc).__name__}). Check the current passphrase and protected key file.")
    if not isinstance(key, Ed25519PrivateKey): sys.exit("The release private key is not Ed25519.")
    actual = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    if not hmac.compare_digest(actual, pub): sys.exit("The private and public release keys do not match; key file was not changed.")
    new_pass = getpass.getpass("New release key passphrase (12+ characters): ")
    if len(new_pass) < 12: sys.exit("Use at least 12 characters.")
    if getpass.getpass("Repeat new passphrase: ") != new_pass: sys.exit("The passphrases differ.")
    encoded = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.BestAvailableEncryption(new_pass.encode()))
    fd, temporary = tempfile.mkstemp(prefix=key_path.name + ".", suffix=".tmp", dir=key_path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(encoded); stream.flush(); os.fsync(stream.fileno())
        os.replace(temporary, key_path)
    except BaseException:
        try: os.unlink(temporary)
        except OSError: pass
        raise
    print("Release key passphrase updated; the Ed25519 identity and public key are unchanged.")

def verify_archive(a: argparse.Namespace) -> None:
    dist = Path(a.dist).resolve()
    public_key = Path(a.pub).read_text().strip()
    if not IG.verify_dir(dist, public_key): sys.exit("Distribution integrity verification failed.")
    manifest_path = dist / IG.MAN
    signature_path = dist / IG.SIG
    manifest_raw = manifest_path.read_bytes()
    signature_raw = signature_path.read_bytes()
    manifest = IG.load_manifest(dist, public_key)
    expected = set(manifest["files"]) | {IG.MAN, IG.SIG}
    try:
        with zipfile.ZipFile(a.archive) as archive:
            names = [name for name in archive.namelist() if not name.endswith("/")]
            if len(names) != len(set(names)) or set(names) != expected:
                sys.exit("Archive file list does not exactly match the signed release manifest.")
            if archive.testzip() is not None: sys.exit("Archive CRC validation failed.")
            if archive.read(IG.MAN) != manifest_raw or archive.read(IG.SIG) != signature_raw:
                sys.exit("Archive manifest or signature differs from the verified distribution.")
            for name, expected_hash in manifest["files"].items():
                digest = hashlib.sha256()
                with archive.open(name) as stream:
                    for block in iter(lambda: stream.read(1 << 20), b""): digest.update(block)
                if not hmac.compare_digest(digest.hexdigest(), str(expected_hash)):
                    sys.exit(f"Archive file differs from the signed manifest: {name}")
    except (OSError, ValueError, zipfile.BadZipFile, KeyError) as exc:
        sys.exit(f"Could not verify release archive ({type(exc).__name__}).")
    print("ARCHIVE VERIFY OK")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(); sp = ap.add_subparsers(dest="cmd", required=True)
    g = sp.add_parser("keygen"); g.add_argument("--key", default="release_key.pem"); g.add_argument("--pub", default="release_pubkey.txt"); g.set_defaults(f=keygen)
    g = sp.add_parser("embed"); g.add_argument("--module", required=True); g.add_argument("--pub", default="release_pubkey.txt"); g.set_defaults(f=embed)
    g = sp.add_parser("verify-embedded-key"); g.add_argument("--exe", required=True); g.add_argument("--pub", default="release_pubkey.txt"); g.set_defaults(f=verify_embedded_key)
    g = sp.add_parser("manifest"); g.add_argument("--dist", required=True); g.add_argument("--key", default="release_key.pem"); g.add_argument("--build", type=int, default=1); g.set_defaults(f=manifest)
    g = sp.add_parser("verify"); g.add_argument("--dist", required=True); g.add_argument("--pub", default="release_pubkey.txt"); g.set_defaults(f=verify)
    g = sp.add_parser("validate-key"); g.add_argument("--key", default="release_key.pem"); g.add_argument("--pub", default="release_pubkey.txt"); g.set_defaults(f=validate_key)
    g = sp.add_parser("change-passphrase"); g.add_argument("--key", default="release_key.pem"); g.add_argument("--pub", default="release_pubkey.txt"); g.set_defaults(f=change_passphrase)
    g = sp.add_parser("verify-archive"); g.add_argument("--archive", required=True); g.add_argument("--dist", required=True); g.add_argument("--pub", default="release_pubkey.txt"); g.set_defaults(f=verify_archive)
    a = ap.parse_args(); a.f(a)

"""Release-tool key and archive verification regression tests."""
import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from typing import Any
from unittest import mock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from tools import release as release_tool
RELEASE_TOOL = ROOT / "tools" / "release.py"
PASSPHRASE = "Release-Test-Key-Passphrase!"


class TestReleaseTool(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="release test ")
        self.root = Path(self.temp.name) / "project with spaces"
        self.root.mkdir()
        self.key = Ed25519PrivateKey.generate()
        self.private_path = self.root / "release key.pem"
        self.public_path = self.root / "release pubkey.txt"
        self.private_path.write_bytes(self.key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(PASSPHRASE.encode()),
        ))
        public_hex = self.key.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        ).hex()
        self.public_path.write_text(public_hex + "\n", encoding="ascii")
        self.env = os.environ.copy()
        self.env["UNKNWN_KEY_PASS"] = PASSPHRASE

    def tearDown(self):
        self.temp.cleanup()

    def run_release(
        self,
        *args: object,
        passphrase: str = PASSPHRASE,
    ) -> subprocess.CompletedProcess[str]:
        env = self.env.copy()
        env["UNKNWN_KEY_PASS"] = passphrase
        return subprocess.run(
            [sys.executable, str(RELEASE_TOOL), *map(str, args)],
            cwd=self.root,
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )

    def test_validate_key_checks_passphrase_and_matching_public_key(self):
        result = self.run_release(
            "validate-key", "--key", self.private_path, "--pub", self.public_path,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("verified", result.stdout)

        wrong = self.run_release(
            "validate-key", "--key", self.private_path, "--pub", self.public_path,
            passphrase="Wrong-Release-Passphrase",
        )
        self.assertNotEqual(wrong.returncode, 0)
        self.assertNotIn("Wrong-Release-Passphrase", wrong.stdout + wrong.stderr)

    def test_embed_updates_staged_module_and_checks_compiled_binary_key(self):
        staged_module = self.root / "staged" / "unknwn_integrity.py"
        staged_module.parent.mkdir()
        staged_module.write_text('RELEASE_PUBKEY = "' + ("0" * 64) + '"\n', encoding="utf-8")
        release_tool.embed(argparse.Namespace(module=staged_module, pub=self.public_path))
        embedded_source = staged_module.read_text(encoding="utf-8")
        public_hex = self.public_path.read_text(encoding="ascii").strip()
        self.assertIn('RELEASE_PUBKEY = "' + public_hex + '"', embedded_source)

        executable = self.root / "compiled.exe"
        executable.write_bytes(b"compiled constants:" + public_hex.encode("ascii"))
        release_tool.verify_embedded_key(argparse.Namespace(exe=executable, pub=self.public_path))
        executable.write_bytes(b"compiled constants:" + (b"0" * 64))
        with self.assertRaises(SystemExit):
            release_tool.verify_embedded_key(argparse.Namespace(exe=executable, pub=self.public_path))

    def test_change_passphrase_reencrypts_same_release_identity(self):
        new_pass = "New-Release-Test-Passphrase!"
        with mock.patch.dict(os.environ, {"UNKNWN_KEY_PASS": PASSPHRASE}), \
             mock.patch.object(release_tool.getpass, "getpass", side_effect=[new_pass, new_pass]):
            release_tool.change_passphrase(argparse.Namespace(key=self.private_path, pub=self.public_path))
        original_public = self.public_path.read_text(encoding="ascii")
        updated = serialization.load_pem_private_key(
            self.private_path.read_bytes(), password=new_pass.encode(),
        )
        self.assertEqual(
            updated.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw,
            ).hex() + "\n",
            original_public,
        )
        with self.assertRaises(ValueError):
            serialization.load_pem_private_key(
                self.private_path.read_bytes(), password=PASSPHRASE.encode(),
            )

    def test_manifest_rejects_non_ed25519_private_keys(self):
        other_key = X25519PrivateKey.generate()
        self.private_path.write_bytes(other_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(PASSPHRASE.encode()),
        ))
        dist = self.root / "release distribution"
        dist.mkdir()
        with mock.patch.object(release_tool, "passphrase", return_value=PASSPHRASE):
            with self.assertRaisesRegex(SystemExit, "not Ed25519"):
                release_tool.manifest(
                    argparse.Namespace(dist=dist, key=self.private_path, build=1)
                )
        self.assertFalse((dist / "unknwn.manifest").exists())

    def test_signed_manifest_rejects_boolean_version(self):
        dist = self.root / "release distribution"
        dist.mkdir()
        manifest_raw = json.dumps(
            {"v": True, "files": {"UNKNWN.exe": "0" * 64}},
            sort_keys=True,
        ).encode()
        (dist / "unknwn.manifest").write_bytes(manifest_raw)
        (dist / "unknwn.manifest.sig").write_bytes(self.key.sign(manifest_raw))
        public_hex = self.key.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        ).hex()
        with self.assertRaisesRegex(ValueError, "bad manifest"):
            release_tool.IG.load_manifest(dist, public_hex)

    def test_manifest_processing_interruption_never_creates_plaintext_artifacts(self):
        integrity = release_tool.IG
        dist = self.root / "signed package"
        dist.mkdir()
        payloads = {"UNKNWN.exe": b"trusted package fixture"}
        for name, content in payloads.items():
            (dist / name).write_bytes(content)
        manifest_raw = json.dumps(
            {
                "v": 1,
                "build": 1,
                "files": {
                    name: hashlib.sha256(content).hexdigest()
                    for name, content in payloads.items()
                },
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        manifest_path = dist / integrity.MAN
        signature_path = dist / integrity.SIG
        manifest_path.write_bytes(manifest_raw)
        signature_path.write_bytes(self.key.sign(manifest_raw))
        public_hex = self.public_path.read_text(encoding="ascii").strip()
        original_files = {path.relative_to(dist).as_posix() for path in dist.rglob("*") if path.is_file()}

        interruptions = (
            mock.patch.object(
                integrity.Ed25519PublicKey,
                "from_public_bytes",
                side_effect=KeyboardInterrupt("authentication interruption"),
            ),
            mock.patch.object(
                integrity.json,
                "loads",
                side_effect=KeyboardInterrupt("parsing interruption"),
            ),
            mock.patch.object(
                integrity,
                "sha256_file",
                side_effect=KeyboardInterrupt("verification interruption"),
            ),
        )
        for stage, interruption in zip(
            ("authentication", "parsing", "file hashing"),
            interruptions,
        ):
            with self.subTest(stage=stage), interruption, self.assertRaises(KeyboardInterrupt):
                integrity.verify_dir(dist, public_hex)
            current_files = {
                path.relative_to(dist).as_posix()
                for path in dist.rglob("*")
                if path.is_file()
            }
            self.assertEqual(current_files, original_files)
            self.assertTrue(integrity.verify_dir(dist, public_hex))

        for _ in range(2):
            result = subprocess.run(
                [
                    sys.executable,
                    "-c",
                    "import os,sys; "
                    "sys.path.insert(0, sys.argv[1]); import unknwn_integrity as I; "
                    "I.sha256_file = lambda path: os._exit(73); "
                    "I.verify_dir(sys.argv[2], sys.argv[3]);",
                    str(ROOT),
                    str(dist),
                    public_hex,
                ],
                cwd=dist,
                capture_output=True,
                check=False,
            )
            self.assertEqual(result.returncode, 73)
            self.assertEqual(
                {
                    path.relative_to(dist).as_posix()
                    for path in dist.rglob("*")
                    if path.is_file()
                },
                original_files,
            )
        self.assertEqual(
            original_files,
            {"UNKNWN.exe", integrity.MAN, integrity.SIG},
            "Package verification must not create temporary, staging, backup, cache, or plaintext metadata files.",
        )

    def test_manifest_authentication_parse_and_inventory_failures_do_not_write_artifacts(self):
        integrity = release_tool.IG
        dist = self.root / "invalid package"
        dist.mkdir()
        executable = dist / "UNKNWN.exe"
        executable.write_bytes(b"package fixture")
        public_hex = self.public_path.read_text(encoding="ascii").strip()

        manifest_path = dist / integrity.MAN
        signature_path = dist / integrity.SIG
        good_manifest = json.dumps(
            {
                "v": 1,
                "build": 2,
                "files": {"UNKNWN.exe": hashlib.sha256(executable.read_bytes()).hexdigest()},
            },
            sort_keys=True,
        ).encode()
        manifest_path.write_bytes(good_manifest)
        signature_path.write_bytes(self.key.sign(good_manifest))

        cases = (
            ("authentication", good_manifest, b"invalid signature"),
            ("parsing", b"{not valid json", self.key.sign(b"{not valid json")),
            ("inventory", good_manifest, self.key.sign(good_manifest)),
        )
        for case, manifest, signature in cases:
            with self.subTest(case=case):
                manifest_path.write_bytes(manifest)
                signature_path.write_bytes(signature)
                if case == "inventory":
                    executable.write_bytes(b"modified package fixture")
                self.assertFalse(integrity.verify_dir(dist, public_hex))
                self.assertEqual(
                    {path.name for path in dist.iterdir() if path.is_file()},
                    {"UNKNWN.exe", integrity.MAN, integrity.SIG},
                )
                if case == "inventory":
                    executable.write_bytes(b"package fixture")

    def test_verify_archive_checks_signed_distribution_contents(self):
        dist = self.root / "release distribution"
        dist.mkdir()
        files = {
            "UNKNWN.exe": b"compiled executable",
            "runtime/module.pyd": b"runtime module",
        }
        for name, content in files.items():
            target = dist / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)
        manifest: dict[str, Any] = {
            "v": 1,
            "build": 4,
            "files": {
                name: hashlib.sha256(content).hexdigest()
                for name, content in sorted(files.items())
            },
        }
        manifest_raw = json.dumps(manifest, sort_keys=True, indent=1).encode()
        (dist / "unknwn.manifest").write_bytes(manifest_raw)
        (dist / "unknwn.manifest.sig").write_bytes(self.key.sign(manifest_raw))
        archive_path = self.root / "release package.zip"
        with zipfile.ZipFile(archive_path, "w", zipfile.ZIP_DEFLATED) as archive:
            for name, content in files.items():
                archive.writestr(name, content)
            archive.writestr("unknwn.manifest", manifest_raw)
            archive.writestr("unknwn.manifest.sig", (dist / "unknwn.manifest.sig").read_bytes())

        args = (
            "verify-archive", "--archive", archive_path, "--dist", dist,
            "--pub", self.public_path,
        )
        result = self.run_release(*args)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("ARCHIVE VERIFY OK", result.stdout)

        with zipfile.ZipFile(archive_path, "w", zipfile.ZIP_DEFLATED) as archive:
            for name, content in files.items():
                archive.writestr(name, b"tampered" if name == "UNKNWN.exe" else content)
            archive.writestr("unknwn.manifest", manifest_raw)
            archive.writestr("unknwn.manifest.sig", (dist / "unknwn.manifest.sig").read_bytes())
        tampered = self.run_release(*args)
        self.assertNotEqual(tampered.returncode, 0)


if __name__ == "__main__":
    unittest.main()

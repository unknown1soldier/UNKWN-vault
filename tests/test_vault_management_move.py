"""Crash-safe vault-management transfer and authenticated recovery tests."""
# pyright: reportConstantRedefinition=false, reportUnknownParameterType=false, reportMissingParameterType=false
# pyright: reportUnknownArgumentType=false, reportUnknownMemberType=false, reportUnknownVariableType=false
# pyright: reportSelfClsParameterName=false, reportPrivateUsage=false, reportUnknownLambdaType=false
# pyright: reportCallIssue=false, reportArgumentType=false, reportIndexIssue=false, reportAssignmentType=false
# pyright: reportUnusedVariable=false, reportOptionalSubscript=false, reportAttributeAccessIssue=false, reportOptionalCall=false
# pyright: reportGeneralTypeIssues=false
import os
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import unknwn as U


class TestDataMoveTransaction(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="unknwn_move_")
        self.root_dir = Path(self.temp.name)
        self.profile = self.root_dir / "profile"
        self.profile.mkdir()
        self.source = self.profile / ".unknwn"
        self.source.mkdir()
        self.target_parent = self.root_dir / "app"
        self.target_parent.mkdir()
        self.target = self.target_parent / "UNKNWN_data"
        self.root = os.urandom(32)
        self.old_home = U.HOME
        self.old_port = U.PORT
        self.home_patch = mock.patch.object(Path, "home", return_value=self.profile)
        self.home_patch.start()
        U.PORT = self.target
        U.set_home(self.source)
        (self.source / "vault").mkdir()
        (self.source / "vault" / "item.cdr").write_bytes(os.urandom(2048))
        (self.source / "config.json").write_bytes(b'{"encrypted":"configuration"}')

    def tearDown(self):
        self.home_patch.stop()
        U.PORT = self.old_port
        U.set_home(self.old_home)
        self.temp.cleanup()

    def move(self, **kwargs):
        return U.copy_data_tree_transaction(self.source, self.target, self.root, **kwargs)

    def test_verified_copy_preserves_encrypted_bytes_and_original_source(self):
        original = {path.relative_to(self.source): path.read_bytes()
                    for path in self.source.rglob("*") if path.is_file()}
        result = self.move()
        self.assertEqual(result["status"], "completed")
        self.assertTrue(result["retained_backup"])
        self.assertEqual({path.relative_to(self.target): path.read_bytes()
                          for path in self.target.rglob("*") if path.is_file()}, original)
        self.assertEqual({path.relative_to(self.source): path.read_bytes()
                          for path in self.source.rglob("*") if path.is_file()}, original)

    def test_portable_backup_does_not_override_persisted_profile_location(self):
        profile_backup = self.profile / "previous-profile"
        self.source.rename(profile_backup)
        self.target.mkdir()
        (self.target / "config.json").write_bytes(b"portable source")
        (self.target / "vault").mkdir()
        (self.target / "vault" / "item.cdr").write_bytes(b"portable ciphertext")
        U.set_home(self.target)

        result = U.copy_data_tree_transaction(self.target, self.source, self.root)

        self.assertEqual(result["status"], "completed")
        self.assertTrue(self.target.is_dir(), "the original portable source remains as a backup")
        selected = U.select_active_home(
            self.target, self.source, self.profile / ".unknwn-location", argv=[]
        )
        self.assertEqual(selected, self.source)
        self.assertEqual((selected / "config.json").read_bytes(), b"portable source")
        self.assertEqual((self.target / "config.json").read_bytes(), b"portable source")

    def test_existing_destination_is_never_merged_or_overwritten(self):
        self.target.mkdir()
        sentinel = self.target / "keep.txt"
        sentinel.write_text("pre-existing")
        with self.assertRaises(FileExistsError):
            self.move()
        self.assertEqual(sentinel.read_text(), "pre-existing")
        self.assertTrue(self.source.is_dir())

    def test_destination_lock_blocks_a_concurrent_worker(self):
        outcomes = []

        def attempt_lock():
            try:
                with U._MoveDestinationLock(self.target):
                    outcomes.append("acquired")
            except U.MoveDataError:
                outcomes.append("blocked")

        with U._MoveDestinationLock(self.target):
            thread = threading.Thread(target=attempt_lock)
            thread.start()
            thread.join(timeout=5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(outcomes, ["blocked"])

    def test_insufficient_space_stops_before_journaling(self):
        with mock.patch.object(U, "storage_preflight", return_value={"status": "insufficient"}):
            with self.assertRaises(OSError):
                self.move()
        self.assertTrue(self.source.is_dir())
        self.assertFalse(self.target.exists())
        self.assertFalse((self.source / U.MOVE_JOURNAL).exists())

    def test_cancellation_during_copy_cleans_stage_and_preserves_source(self):
        cancel = threading.Event()

        def progress(event):
            label, _done, _total = event
            if label == "Copying encrypted data":
                cancel.set()

        with self.assertRaises(U.MoveDataCancelled):
            self.move(cancel=cancel, progress=progress)
        self.assertTrue(self.source.is_dir())
        self.assertFalse(self.target.exists())
        self.assertFalse((self.source / U.MOVE_JOURNAL).exists())
        self.assertFalse(list(self.target_parent.glob("*.staging")))

    def test_verification_failure_does_not_activate_destination(self):
        with mock.patch.object(U, "_verify_move_tree", side_effect=U.MoveDataError("injected verification failure")):
            with self.assertRaises(U.MoveDataError):
                self.move()
        self.assertTrue(self.source.is_dir())
        self.assertFalse(self.target.exists())
        self.assertFalse((self.source / U.MOVE_JOURNAL).exists())

    def test_source_change_before_activation_preserves_both_original_and_changed_data(self):
        real_copy = U._copy_move_tree

        def copy_then_change(*args, **kwargs):
            result = real_copy(*args, **kwargs)
            (self.source / "config.json").write_bytes(b"changed during operation")
            return result

        with mock.patch.object(U, "_copy_move_tree", side_effect=copy_then_change):
            with self.assertRaises(U.MoveDataError):
                self.move()
        self.assertEqual((self.source / "config.json").read_bytes(), b"changed during operation")
        self.assertFalse(self.target.exists())
        self.assertFalse((self.source / U.MOVE_JOURNAL).exists())

    def test_source_root_symlink_is_rejected_before_resolution(self):
        link = self.root_dir / "source-link"
        try:
            link.symlink_to(self.source, target_is_directory=True)
        except (OSError, NotImplementedError) as exc:
            if os.name == "nt":
                env = os.environ.copy()
                env["UNKNWN_TEST_LINK"] = str(link)
                env["UNKNWN_TEST_TARGET"] = str(self.source)
                junction = subprocess.run(
                    ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
                     "$ErrorActionPreference='Stop'; New-Item -ItemType Junction -Path $env:UNKNWN_TEST_LINK -Target $env:UNKNWN_TEST_TARGET | Out-Null"],
                    capture_output=True, text=True, env=env
                )
                if junction.returncode:
                    self.skipTest(f"source symlink and junction creation are unavailable: {exc}; {junction.stderr.strip()}")
            else:
                self.skipTest(f"source-directory symlink creation is unavailable: {exc}")
        destination = self.target_parent / "linked-data"
        with self.assertRaises(U.MoveDataError):
            U.copy_data_tree_transaction(link, destination, self.root)
        self.assertFalse(destination.exists())
        self.assertTrue(self.source.is_dir())

    def test_partial_write_failure_cleans_only_created_stage_and_keeps_source(self):
        real_fsync = U.os.fsync
        calls = 0

        def fail_copy_fsync(fd):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError("injected disk write failure")
            return real_fsync(fd)

        with mock.patch.object(U.os, "fsync", side_effect=fail_copy_fsync):
            with self.assertRaises(OSError):
                self.move()
        self.assertTrue(self.source.is_dir())
        self.assertFalse(self.target.exists())
        self.assertFalse((self.source / U.MOVE_JOURNAL).exists())
        self.assertFalse(list(self.target_parent.glob("*.staging")))

    def test_cleanup_failure_leaves_authenticated_recovery_record_and_stage(self):
        def fail_after_partial_stage(_source, stage, *_args, **_kwargs):
            stage.mkdir()
            (stage / "partial").write_bytes(b"partial")
            raise OSError("injected cleanup failure")

        with mock.patch.object(U, "_cleanup_created_move_tree", return_value=[self.target_parent / "partial"]):
            with mock.patch.object(U, "_copy_move_tree", side_effect=fail_after_partial_stage):
                with self.assertRaises(U.MoveDataError):
                    self.move()
        self.assertTrue(self.source.is_dir())
        self.assertTrue((self.source / U.MOVE_JOURNAL).exists())
        record = U._read_move_journal(self.source, self.root)
        self.assertEqual(record["phase"], "copying")
        self.assertTrue(Path(record["stage"]).is_dir())

    def test_ambiguous_copying_journal_is_reported_without_auto_resume(self):
        def interrupt_after_partial_stage(_source, stage, *_args, **_kwargs):
            stage.mkdir()
            (stage / "partial").write_bytes(b"partial")
            raise SystemExit("simulated abrupt process exit")

        with mock.patch.object(U, "_copy_move_tree", side_effect=interrupt_after_partial_stage):
            with self.assertRaises(SystemExit):
                self.move()
        first = U.recover_data_move(self.root)
        second = U.recover_data_move(self.root)
        self.assertEqual(first["status"], "interrupted")
        self.assertEqual(second, first)
        self.assertTrue(self.source.is_dir())
        self.assertFalse(self.target.exists())
        self.assertTrue(Path(first["stage"]).is_dir())

    def test_verified_interrupted_copy_recovers_idempotently_after_restart(self):
        real_write = U._write_move_journal

        def crash_after_verified(source, root, record):
            real_write(source, root, record)
            if record["phase"] == "verified":
                raise RuntimeError("simulated process interruption")

        with mock.patch.object(U, "_write_move_journal", side_effect=crash_after_verified):
            with self.assertRaises(RuntimeError):
                self.move()
        self.assertTrue(self.source.is_dir())
        record = U._read_move_journal(self.source, self.root)
        self.assertEqual(record["phase"], "verified")
        U.set_home(self.source)
        result = U.recover_data_move(self.root)
        self.assertEqual(result["status"], "completed")
        self.assertTrue(self.target.is_dir())
        self.assertTrue(self.source.is_dir())
        self.assertIsNone(U.recover_data_move(self.root))
        self.assertEqual((self.target / "config.json").read_bytes(), b'{"encrypted":"configuration"}')

    def test_verified_move_recovers_in_fresh_process_and_selects_active_target(self):
        profile_backup = self.profile / "previous-profile"
        self.source.rename(profile_backup)
        self.target.mkdir()
        (self.target / "vault").mkdir()
        payload = os.urandom(2048)
        (self.target / "vault" / "item.cdr").write_bytes(payload)
        (self.target / "config.json").write_bytes(b"portable config")
        U.set_home(self.target)
        key_path = self.root_dir / "move-key.bin"
        key_path.write_bytes(self.root)

        env = os.environ.copy()
        env["HOME"] = str(self.profile)
        env["USERPROFILE"] = str(self.profile)
        env["QT_QPA_PLATFORM"] = "offscreen"
        env["PYTHONPATH"] = str(ROOT) + os.pathsep + env.get("PYTHONPATH", "")
        writer_script = """
import os, sys
from pathlib import Path
import unknwn as U
portable, profile, key_file = map(Path, sys.argv[1:])
U.PORT = portable
U.set_home(portable)
real_write = U._write_move_journal
def stop_after_verified(source, root, record):
    real_write(source, root, record)
    if record["phase"] == "verified":
        os._exit(73)
U._write_move_journal = stop_after_verified
U.copy_data_tree_transaction(portable, profile / ".unknwn", key_file.read_bytes())
raise SystemExit("move unexpectedly completed without the controlled process exit")
"""
        interrupted = subprocess.run(
            [sys.executable, "-c", writer_script, str(self.target), str(self.profile), str(key_path)],
            capture_output=True, text=True, env=env, timeout=60
        )
        self.assertEqual(interrupted.returncode, 73, interrupted.stdout + interrupted.stderr)
        journal = U._read_move_journal(self.target, self.root)
        self.assertEqual(journal["phase"], "verified")
        self.assertTrue(Path(journal["stage"]).is_dir())

        script = """
import sys
from pathlib import Path
import unknwn as U
portable, profile, marker, key_file = map(Path, sys.argv[1:])
U.PORT = portable
U.set_home(U.select_active_home(portable, profile / ".unknwn", marker, argv=[]))
assert U.HOME == portable
result = U.resolve_data_move_before_signin(key_file.read_bytes())
assert result["status"] == "completed"
assert U.HOME == profile / ".unknwn"
assert U.resolve_data_move_before_signin(key_file.read_bytes()) is None
print("process-boundary recovery passed")
"""
        completed = subprocess.run(
            [sys.executable, "-c", script, str(self.target), str(self.profile),
             str(self.profile / ".unknwn-location"), str(key_path)],
            capture_output=True, text=True, env=env, timeout=60
        )
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        self.assertIn("process-boundary recovery passed", completed.stdout)
        self.assertEqual((self.source / "vault" / "item.cdr").read_bytes(), payload)
        self.assertEqual((self.target / "vault" / "item.cdr").read_bytes(), payload)
        self.assertTrue(self.target.is_dir(), "the portable source is retained")
        self.assertEqual(
            U.select_active_home(self.target, self.source, self.profile / ".unknwn-location", argv=[]),
            self.source
        )
        self.assertFalse((self.target / U.MOVE_JOURNAL).exists())

    def test_signin_recovers_verified_move_before_burning_exhausted_item(self):
        profile_backup = self.profile / "previous-profile"
        self.source.rename(profile_backup)
        self.target.mkdir()
        (self.target / "vault").mkdir()
        rid = os.urandom(6).hex()
        item_path = self.target / "vault" / f"{rid}.cdr"
        item_path.write_bytes(os.urandom(128))
        dek = self.root
        salt = os.urandom(16)
        file_key = U.file_key(dek, salt)
        metadata = {
            "s": U.b64e(salt),
            "nm": U.b64e(U.seal(file_key, b"last-view.bin")),
            "size": 1,
            "exp": None,
            "views": 0,
        }
        (self.target / "config.json").write_text("{}", encoding="utf-8")
        U.set_home(self.target)
        U.idx.clear()
        U.idx[rid] = metadata
        U.save_idx(dek, U.idx)
        source_index = (self.target / "index.json").read_bytes()

        real_write = U._write_move_journal

        def stop_after_verified(source, root, record):
            real_write(source, root, record)
            if record["phase"] == "verified":
                raise RuntimeError("simulated interruption before stage activation")

        with mock.patch.object(U, "_write_move_journal", side_effect=stop_after_verified):
            with self.assertRaises(RuntimeError):
                U.copy_data_tree_transaction(self.target, self.source, dek)

        old_cfg = dict(U.cfg)
        U.cfg.clear()
        U.cfg.update({"set": {"intro": 1, "log": 0}})
        self.addCleanup(lambda: (U.cfg.clear(), U.cfg.update(old_cfg)))

        class SigninState:
            root = dek
            ro = False
            relocked = False
            session_started = None
            def logs(self):
                return []

        with mock.patch.object(U.App, "prepare_settings_snapshot", return_value=True), \
                mock.patch.object(U.App, "record_session_event"):
            self.assertTrue(U.App.signin(SigninState(), "password"))

        self.assertEqual(U.HOME, self.source)
        self.assertNotIn(rid, U.load_idx(dek))
        self.assertFalse((self.source / "vault" / f"{rid}.cdr").exists())
        self.assertEqual((self.target / "index.json").read_bytes(), source_index)
        self.assertTrue((self.target / "vault" / f"{rid}.cdr").exists())

    def test_signin_blocks_ambiguous_move_before_any_mutation(self):
        def interrupt_after_partial_stage(_source, stage, *_args, **_kwargs):
            stage.mkdir()
            (stage / "partial").write_bytes(b"partial")
            raise SystemExit("simulated abrupt process exit")

        with mock.patch.object(U, "_copy_move_tree", side_effect=interrupt_after_partial_stage):
            with self.assertRaises(SystemExit):
                self.move()
        source_before = {
            path.relative_to(self.source): path.read_bytes()
            for path in self.source.rglob("*") if path.is_file()
        }

        class SigninState:
            ro = False

        state = SigninState()
        state.root = self.root
        with mock.patch.object(U.App, "prepare_settings_snapshot") as prepare, \
                mock.patch.object(U, "burn_exhausted_view_items") as burn, \
                mock.patch.object(U.QMessageBox, "warning"):
            self.assertFalse(U.App.signin(state, "password"))
        prepare.assert_not_called()
        burn.assert_not_called()
        self.assertEqual(source_before, {
            path.relative_to(self.source): path.read_bytes()
            for path in self.source.rglob("*") if path.is_file()
        })

if __name__ == "__main__":
    unittest.main()

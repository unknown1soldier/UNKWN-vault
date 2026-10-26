"""Core tests: crypto, crash-safe saves, vault-key rotation (incl. simulated crashes), release integrity, password policy, and a smoke test of the
new UI code paths. Run:  python -m unittest tests.test_core"""
# pyright: reportConstantRedefinition=false, reportUnknownParameterType=false, reportMissingParameterType=false
# pyright: reportUnknownArgumentType=false, reportUnknownMemberType=false, reportUnknownVariableType=false
# pyright: reportSelfClsParameterName=false, reportPrivateUsage=false, reportUnknownLambdaType=false
# pyright: reportCallIssue=false, reportArgumentType=false, reportIndexIssue=false, reportAssignmentType=false
# pyright: reportUnusedVariable=false, reportOptionalSubscript=false, reportAttributeAccessIssue=false, reportOptionalCall=false
# pyright: reportConstantRedefinition=false, reportUnknownParameterType=false, reportMissingParameterType=false, reportUnknownArgumentType=false, reportUnknownMemberType=false, reportUnknownVariableType=false, reportSelfClsParameterName=false, reportPrivateUsage=false, reportUnknownLambdaType=false, reportCallIssue=false, reportArgumentType=false, reportIndexIssue=false, reportAssignmentType=false, reportUnusedVariable=false, reportOptionalSubscript=false, reportAttributeAccessIssue=false, reportOptionalCall=false
import hashlib, os, sys, json, shutil, struct, subprocess, tempfile, time, threading, unittest
from pathlib import Path
from typing import cast
from unittest import mock
ROOT = Path(__file__).resolve().parent.parent; sys.path.insert(0, str(ROOT)); sys.path.insert(0, str(Path(__file__).parent))
from qt_test_support import flush_deferred_deletes
_H = tempfile.mkdtemp(prefix="unknwn_home_"); os.environ["HOME"] = _H; os.environ["USERPROFILE"] = _H
def _has_real_qt():
    import importlib
    try:
        spec = importlib.util.find_spec("PyQt5.QtWidgets")
        return spec is not None
    except Exception:
        try:
            spec = importlib.util.find_spec("qtstub")
            return spec is None
        except Exception:
            return True

REAL_QT = _has_real_qt()
import unknwn as U, unknwn_integrity as IG
from cryptography.exceptions import InvalidTag
PW = "Corr3ct-Horse-Battery!"
_QT_TEST_APP = None

def qt_test_application():
    global _QT_TEST_APP
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    if _QT_TEST_APP is None:
        _QT_TEST_APP = U.QApplication.instance() or U.QApplication([])
    return _QT_TEST_APP

def make_signed_package(directory, files):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    for relative, content in files.items():
        path = directory / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    manifest = json.dumps(
        {"v": 1, "build": 1,
         "files": {name: hashlib.sha256(content).hexdigest() for name, content in files.items()}},
        sort_keys=True, separators=(",", ":")).encode()
    (directory / IG.MAN).write_bytes(manifest)
    (directory / IG.SIG).write_bytes(private_key.sign(manifest))
    return directory, public_key

class Base(unittest.TestCase):
    def setUp(s):
        s.addCleanup(flush_deferred_deletes)
        s.d = Path(tempfile.mkdtemp(prefix="unknwn_t_")); U.set_home(s.d); U.cfg.clear(); U.idx.clear(); U.SELF_DESTRUCT_RUNTIME_KEY = os.urandom(32)
        try: U.destruct_journal_path().unlink(missing_ok=True)
        except OSError: pass
    def tearDown(s):
        try: U.destruct_journal_path().unlink(missing_ok=True)
        except OSError: pass
        shutil.rmtree(s.d, ignore_errors=True)
    def vault(s, sizes=(300_000, 0, 1 << 20, 2_500_000, 1000)):
        """Mirrors App._create() + add_files() with the app's own functions. Returns dek, phrase, {rid: (plain, name)}."""
        dek = os.urandom(32); phrase = " ".join(__import__("random").SystemRandom().sample(U.WORDS, U.NW)); s1, s2 = os.urandom(16), os.urandom(16)
        U.cfg.update(n=17, s1=U.b64e(s1), s2=U.b64e(s2), wp=U.b64e(U.seal(U.kdf(PW, s1), dek)), wr=U.b64e(U.seal(U.kdf(phrase, s2), dek)), f=0, lock=0, last=time.time(), fails=[], set=dict(U.DEF))
        U.cfg["sc"] = IG.snap_make(dek, U.secset()); U.VAULT.mkdir(parents=True, exist_ok=True); files = {}
        for i, n in enumerate(sizes):
            data = os.urandom(n); src = s.d / f"in{i}.bin"; src.write_bytes(data); salt = os.urandom(16); k = U.file_key(dek, salt); rid = os.urandom(6).hex(); name = f"file{i}.bin"
            U.enc_file(src, U.VAULT / f"{rid}.cdr", k, lambda a, b: None); src.unlink()
            U.idx[rid] = {"s": U.b64e(salt), "nm": U.b64e(U.seal(k, name.encode())), "size": n, "exp": None, "views": None}; files[rid] = (data, name)
        U.LOG.write_bytes(U.seal(U.file_key(dek, b"unknwn-log"), json.dumps([{"t": 1, "ok": True}]).encode())); U.jsave(U.CFG, U.cfg); U.save_idx(dek, U.idx); return dek, phrase, files
    def reload(s):
        U.rotate_commit(); c = U.jload(U.CFG, {}); U.cfg.clear(); U.cfg.update(c)
        dek = U.unseal(U.kdf(PW, U.b64d(c["s1"])), U.b64d(c["wp"]))
        U.idx.clear(); U.idx.update(U.load_idx(dek))
    def check_all(s, dek, files):
        for rid, (data, name) in files.items():
            m = U.idx[rid]; k = U.file_key(dek, U.b64d(m["s"]))
            s.assertEqual(U.dec_file(U.VAULT / f"{rid}.cdr", k), data); s.assertEqual(U.unseal(k, U.b64d(m["nm"])).decode(), name)

class TestCrypto(Base):
    def test_encryption_cancel_before_start_preserves_source_and_creates_no_stage(s):
        U.VAULT.mkdir(parents=True, exist_ok=True)
        source = s.d / "source.bin"; source.write_bytes(b"source remains unchanged")
        staged = U.VAULT / "cancel-before.cdr.txn"; cancel = threading.Event(); cancel.set()
        with s.assertRaises(U.MoveDataCancelled):
            U.enc_file(source, staged, os.urandom(32), lambda *_: None, cancel)
        s.assertEqual(source.read_bytes(), b"source remains unchanged")
        s.assertFalse(staged.exists())

    def test_encryption_cancel_at_chunk_boundary_removes_incomplete_stage(s):
        U.VAULT.mkdir(parents=True, exist_ok=True)
        source = s.d / "source.bin"; content = os.urandom(2 * U.CH + 9); source.write_bytes(content)
        staged = U.VAULT / "cancel-during.cdr.txn"; cancel = threading.Event()
        def progress(done, _total):
            if done >= U.CH: cancel.set()
        with s.assertRaises(U.MoveDataCancelled):
            U.enc_file(source, staged, os.urandom(32), progress, cancel)
        s.assertEqual(source.read_bytes(), content)
        s.assertFalse(staged.exists())

    def test_encryption_cancel_at_final_callback_removes_complete_but_uncommitted_stage(s):
        U.VAULT.mkdir(parents=True, exist_ok=True)
        source = s.d / "source.bin"; content = os.urandom(U.CH + 17); source.write_bytes(content)
        staged = U.VAULT / "cancel-final.cdr.txn"; cancel = threading.Event()
        def progress(done, total):
            if done == total: cancel.set()
        with s.assertRaises(U.MoveDataCancelled):
            U.enc_file(source, staged, os.urandom(32), progress, cancel)
        s.assertEqual(source.read_bytes(), content)
        s.assertFalse(staged.exists())

    def test_encryption_pause_resumes_at_an_authenticated_chunk_boundary(s):
        U.VAULT.mkdir(parents=True, exist_ok=True)
        source = s.d / "pause-source.bin"; content = os.urandom(U.CH + 17); source.write_bytes(content)
        staged = U.VAULT / "pause-resume.cdr"; key = os.urandom(32)
        resume = threading.Event(); resume.set()
        paused_at = []
        release = threading.Timer(0.08, resume.set)

        def progress(done, _total):
            if done >= U.CH and not paused_at:
                paused_at.append(time.monotonic())
                resume.clear()
                release.start()

        started = time.monotonic()
        U.enc_file(source, staged, key, progress, resume=resume)
        s.assertGreaterEqual(time.monotonic() - started, 0.07)
        s.assertEqual(U.dec_file(staged, key), content)
        s.assertEqual(source.read_bytes(), content)

    def test_encryption_cancel_while_paused_removes_stage_and_preserves_source(s):
        U.VAULT.mkdir(parents=True, exist_ok=True)
        source = s.d / "paused-cancel-source.bin"
        content = os.urandom(U.CH + 17); source.write_bytes(content)
        staged = U.VAULT / "paused-cancel.cdr.txn"
        cancel = threading.Event(); resume = threading.Event(); resume.set()
        release_cancel = threading.Timer(0.02, cancel.set)

        def progress(done, _total):
            if done >= U.CH and not release_cancel.is_alive():
                resume.clear()
                release_cancel.start()

        with s.assertRaises(U.MoveDataCancelled):
            U.enc_file(source, staged, os.urandom(32), progress, cancel, resume=resume)
        release_cancel.join()
        s.assertEqual(source.read_bytes(), content)
        s.assertFalse(staged.exists())

    def test_encryption_never_overwrites_an_existing_stage(s):
        source = s.d / "source.bin"; source.write_bytes(b"source")
        staged = s.d / "existing.cdr.txn"; staged.write_bytes(b"keep")
        with s.assertRaises(FileExistsError):
            U.enc_file(source, staged, os.urandom(32), lambda *_: None)
        s.assertEqual(staged.read_bytes(), b"keep")

    def test_seal_worker_commits_complete_encrypted_output_off_the_ui_path(s):
        root = os.urandom(32); source = s.d / "worker-source.bin"; content = os.urandom(4097)
        source.write_bytes(content); info = source.lstat()
        sources = ((source, info.st_size, info.st_mtime_ns, info.st_dev, info.st_ino),)
        worker = U._SealWorker(sources, root, {}, 0, 0, False, 0, True)
        result = []
        worker.signals.finished.connect(result.append)
        worker.run()
        s.assertEqual(result[0]["status"], "completed")
        s.assertEqual(result[0]["completed"], 1)
        s.assertEqual(source.read_bytes(), content)
        s.assertFalse(U._seal_stage_journal_path().exists())
        rid = result[0]["records"][0]["rid"]
        metadata = U.load_idx(root)[rid]
        key = U.file_key(root, U.b64d(metadata["s"]))
        s.assertEqual(U.dec_file(U.VAULT / f"{rid}.cdr", key), content)
        s.assertEqual(U.unseal(key, U.b64d(metadata["nm"])), source.name.encode())

    def test_seal_worker_cancellation_cleans_stage_and_preserves_original(s):
        root = os.urandom(32); source = s.d / "worker-source.bin"
        content = os.urandom(2 * U.CH + 17); source.write_bytes(content); info = source.lstat()
        sources = ((source, info.st_size, info.st_mtime_ns, info.st_dev, info.st_ino),)
        worker = U._SealWorker(sources, root, {}, 0, 0, False, 0, True)
        original_enc_file = U.enc_file
        def cancel_after_first_chunk(src, dst, key, callback, cancel, on_stage_created=None, resume=None):
            def progress(done, total):
                callback(done, total)
                if done >= U.CH:
                    cancel.set()
            return original_enc_file(src, dst, key, progress, cancel, on_stage_created, resume)
        result = []
        worker.signals.finished.connect(result.append)
        with mock.patch.object(U, "enc_file", side_effect=cancel_after_first_chunk):
            worker.run()
        s.assertEqual(result[0]["status"], "cancelled")
        s.assertEqual(worker.operation.snapshot.state, U.OperationState.CANCELED)
        s.assertEqual(source.read_bytes(), content)
        s.assertEqual(list(U.VAULT.glob("*.cdr")), [])
        s.assertFalse(U._seal_stage_journal_path().exists())

    def test_seal_stage_recovery_removes_only_authenticated_owned_stage(s):
        root = os.urandom(32); operation_id = os.urandom(16).hex()
        U.VAULT.mkdir(parents=True, exist_ok=True)
        U._create_seal_stage_journal(root, "012345abcdef", operation_id)
        staged = U.VAULT / "012345abcdef.cdr.txn"; staged.write_bytes(b"partial ciphertext")
        info = staged.lstat()
        U._write_seal_stage_identity(root, "012345abcdef", operation_id, (info.st_dev, info.st_ino))
        unrelated = U.VAULT / "notes.txt"; unrelated.write_text("preserve", encoding="utf-8")
        result = U.recover_orphan_seal_stage(root)
        s.assertEqual(result, {"rid": "012345abcdef", "removed": True})
        s.assertFalse(staged.exists()); s.assertFalse(U._seal_stage_journal_path().exists())
        s.assertEqual(unrelated.read_text(encoding="utf-8"), "preserve")

    def test_seal_stage_journal_rejects_boolean_version(s):
        root = os.urandom(32); operation_id = os.urandom(16).hex()
        body = {
            "version": True,
            "rid": "012345abcdef",
            "operation_id": operation_id,
            "stage_identity": None,
        }
        record = {
            "body": body,
            "sig": U.b64e(U._seal_stage_signature(root, body)),
        }
        U._seal_stage_journal_path().write_bytes(U.canonical_json(record))
        with s.assertRaisesRegex(ValueError, "unsupported format"):
            U._read_seal_stage_journal(root)

    def test_seal_stage_recovery_preserves_stage_without_recorded_identity(s):
        root = os.urandom(32); operation_id = os.urandom(16).hex()
        U.VAULT.mkdir(parents=True, exist_ok=True)
        U._create_seal_stage_journal(root, "012345abcdef", operation_id)
        staged = U.VAULT / "012345abcdef.cdr.txn"; staged.write_bytes(b"unverified stage")
        with s.assertRaises(ValueError):
            U.recover_orphan_seal_stage(root)
        s.assertTrue(staged.exists())
        s.assertTrue(U._seal_stage_journal_path().exists())

    def test_unjournaled_seal_stage_is_preserved_for_diagnosis(s):
        U.VAULT.mkdir(parents=True, exist_ok=True)
        staged = U.VAULT / "012345abcdef.cdr.txn"; staged.write_bytes(b"unowned")
        s.assertIsNone(U.recover_orphan_seal_stage(os.urandom(32)))
        s.assertEqual(staged.read_bytes(), b"unowned")

    def test_folder_is_zip_streamed_directly_into_authenticated_encryption(s):
        import io, zipfile
        source = s.d / "bundle"; (source / "nested" / "empty").mkdir(parents=True)
        (source / "readme.txt").write_text("folder secret marker", encoding="utf-8")
        (source / "nested" / "payload.bin").write_bytes(os.urandom(2_200_000))
        dest = U.VAULT / "folder.cdr"; key = os.urandom(32); progress = []
        root, entries, size = U.enc_folder(source, dest, key, lambda done, total: progress.append((done, total)))
        s.assertEqual(root, source.resolve())
        encrypted = dest.read_bytes(); s.assertNotIn(b"folder secret marker", encrypted)
        payload = b"".join(part for part, _, _, _ in U.iter_dec(dest, key))
        s.assertEqual(size, len(payload))
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            s.assertEqual(set(archive.namelist()), {"bundle/nested/", "bundle/nested/empty/", "bundle/readme.txt", "bundle/nested/payload.bin"})
            s.assertEqual(archive.read("bundle/readme.txt"), b"folder secret marker")
        total = sum(snapshot[2] for _, _, is_dir, snapshot in entries if not is_dir)
        s.assertEqual(progress[-1], (total, total))
    def test_add_files_starts_background_work_without_waiting(s):
        source = s.d / "large-source.bin"
        source.write_bytes(os.urandom(4096))
        app = mock.MagicMock()
        app.ro = False
        app.root = os.urandom(32)
        app.hold = 0
        app.dying = set()
        app.sec_ok = mock.Mock(return_value=True)
        app.ex = mock.Mock(); app.vw = mock.Mock(); app.rm = mock.Mock()
        app.ex.currentData.return_value = 0
        app.vw.currentData.return_value = 0
        app.rm.isChecked.return_value = False
        queued = []
        with mock.patch.object(U, "terminal_confirm", return_value=True) as confirm, \
             mock.patch.object(U, "storage_preflight", return_value={"status": "pass", "free": 1 << 30}), \
             mock.patch.object(U.App, "other_working", return_value=False), \
             mock.patch.object(app, "_queue_seal_job", side_effect=lambda *_args: queued.append(_args)):
            U.App.add_files(app, [source])

        s.assertTrue(confirm.called)
        s.assertEqual(len(queued), 1)
        s.assertEqual(queued[0][0], "Seal 1 file(s)")
        worker = queued[0][2]()
        s.assertIsInstance(worker, U._SealWorker)
        s.assertEqual(app.hold, 0)
        s.assertTrue(source.exists())

    def test_folder_archive_skips_recompression_for_already_compressed_types(s):
        import io, zipfile
        source = s.d / "compression-check"; source.mkdir()
        (source / "photo.jpg").write_bytes(os.urandom(4096))
        (source / "notes.txt").write_text("repeatable text " * 200, encoding="utf-8")
        key = os.urandom(32)
        destination = U.VAULT / "compression.cdr"
        U.enc_folder(source, destination, key, lambda *_: None)
        with zipfile.ZipFile(io.BytesIO(U.dec_file(destination, key))) as archive:
            s.assertEqual(archive.getinfo("compression-check/photo.jpg").compress_type, zipfile.ZIP_STORED)
            s.assertEqual(archive.getinfo("compression-check/notes.txt").compress_type, zipfile.ZIP_DEFLATED)
    def test_folder_symlink_files_are_not_followed(s):
        source = s.d / "bundle"; source.mkdir(); outside = s.d / "outside.txt"; outside.write_text("do not seal")
        link = source / "linked.txt"
        try: link.symlink_to(outside)
        except (OSError, NotImplementedError): s.skipTest("symlink creation is not available")
        root, entries = U.folder_entries(source)
        s.assertEqual(entries, [])
        dest = U.VAULT / "folder.cdr"; U.enc_folder(source, dest, os.urandom(32), lambda *_: None)
        s.assertTrue(outside.exists()); s.assertEqual(outside.read_text(), "do not seal")
    def test_folder_source_cleanup_removes_only_unchanged_snapshot_files(s):
        source = s.d / "bundle"; source.mkdir(); keep = source / "keep.txt"; changed = source / "changed.txt"
        keep.write_text("remove"); changed.write_text("replace")
        root, entries = U.folder_entries(source); changed.write_text("new user content")
        U.remove_folder_sources(root, entries, 0)
        s.assertFalse(keep.exists()); s.assertEqual(changed.read_text(), "new user content"); s.assertTrue(root.exists())
    def test_empty_folder_seals_as_valid_empty_zip(s):
        import io, zipfile
        source = s.d / "empty-folder"; source.mkdir(); dest = U.VAULT / "empty.cdr"; key = os.urandom(32)
        _, entries, _ = U.enc_folder(source, dest, key, lambda *_: None)
        s.assertEqual(entries, [])
        payload = U.dec_file(dest, key)
        with zipfile.ZipFile(io.BytesIO(payload)) as archive: s.assertEqual(archive.namelist(), [])
    def test_add_folder_flow_seals_one_vault_item(s):
        qt_test_application()
        import zipfile
        source = s.d / "sample-folder"; (source / "nested").mkdir(parents=True)
        (source / "nested" / "note.txt").write_text("folder workflow secret", encoding="utf-8")
        dummy = U.App.__new__(U.App); U.QWidget.__init__(dummy)
        s.addCleanup(dummy.deleteLater)
        dummy.mode = "vault"; dummy.ro = False; dummy.hold = 0; dummy.root = os.urandom(32)
        dummy.dying = set(); dummy._seal_queue = []; dummy._seal_queue_active = False
        dummy._seal_active_cleanup = None; dummy.seal_dialog = None; dummy._pending_seal_action = None
        dummy.sec_ok = mock.Mock(return_value=True)
        dummy.ex = mock.Mock(); dummy.ex.currentData.return_value = 0
        dummy.ex.currentText.return_value = "Never"
        dummy.vw = mock.Mock(); dummy.vw.currentData.return_value = 0
        dummy.vw.currentText.return_value = "Unlimited"
        dummy.rm = mock.Mock()
        dummy.rm.isChecked.return_value = True
        dummy.cards = {}; dummy.cds = {}; dummy.refresh_vault_item_actions = mock.Mock()
        dummy.add_card = mock.Mock(); dummy.apply_vault_sort = mock.Mock()
        dummy.record_session_event = mock.Mock(); dummy.run_pending_seal_action = mock.Mock()
        dummy.lock = mock.Mock()
        dummy.finish_folder_seal_operation = lambda result: U.App.finish_folder_seal_operation(dummy, result)
        class ImmediateDialog:
            def __init__(self, _app, worker, on_finished, **_kwargs):
                self.worker = worker
                self.on_finished = on_finished
                self._running = True
                self.result = []
                worker.signals.finished.connect(self.finish)
            def set_queued_count(self, _count):
                pass
            def show(self):
                self.visible = True
            def finish(self, result):
                self._running = False
                self.result.append(result)
                self.on_finished(result)
        confirmation = mock.Mock(return_value=True)
        with mock.patch.object(U.QFileDialog, "getExistingDirectory", return_value=str(source)), \
             mock.patch.object(U, "terminal_confirm", confirmation), \
             mock.patch.object(U, "storage_preflight", return_value={"status": "pass", "free": 1 << 30}), \
             mock.patch.object(U, "_SealProgressDialog", ImmediateDialog), \
             mock.patch.object(U, "_start_qrunnable", side_effect=lambda worker: worker.run()):
            U.App.add_folder(dummy)
        s.assertEqual(dummy.hold, 0); dummy.add_card.assert_called_once()
        review = "\n".join(confirmation.call_args.args[3])
        s.assertIn("Folder inventory: 1 file, 1 folder", review)
        s.assertIn("Documents", review)
        s.assertFalse(source.exists())
        rid = dummy.add_card.call_args.args[0]; metadata = U.idx[rid]
        key = U.file_key(dummy.root, U.b64d(metadata["s"]))
        archive_data = U.dec_file(U.VAULT / f"{rid}.cdr", key)
        with zipfile.ZipFile(__import__("io").BytesIO(archive_data)) as archive:
            s.assertEqual(archive.namelist(), ["sample-folder/nested/", "sample-folder/nested/note.txt"])
            s.assertEqual(archive.read(archive.namelist()[1]), b"folder workflow secret")

    def test_folder_seal_worker_cancellation_removes_only_its_owned_stage(s):
        source = s.d / "cancel-folder"; source.mkdir()
        content = os.urandom(2 * U.CH + 17)
        (source / "payload.bin").write_bytes(content)
        _root, entries = U.folder_entries(source)
        worker = U._FolderSealWorker(source, entries, os.urandom(32), {}, 0, 0, False, 0, True)
        original_enc_folder = U.enc_folder
        def cancel_after_first_chunk(folder, destination, key, callback, cancel, on_stage_created=None, resume=None):
            def progress(done, total):
                callback(done, total)
                if done >= U.CH:
                    cancel.set()
            return original_enc_folder(
                folder, destination, key, progress, cancel, on_stage_created, resume)
        result = []
        worker.signals.finished.connect(result.append)
        with mock.patch.object(U, "enc_folder", side_effect=cancel_after_first_chunk):
            worker.run()
        s.assertEqual(result[0]["status"], "cancelled")
        s.assertEqual(worker.operation.snapshot.state, U.OperationState.CANCELED)
        s.assertEqual((source / "payload.bin").read_bytes(), content)
        s.assertEqual(list(U.VAULT.glob("*.cdr")), [])
        s.assertFalse(U._seal_stage_journal_path().exists())

    def test_vault_analysis_reports_only_authenticated_exact_content_duplicates(s):
        root = os.urandom(32)
        U.VAULT.mkdir(parents=True, exist_ok=True)
        index = {}
        ids = {}
        contents = {
            "first.txt": b"same payload",
            "copy.txt": b"same payload",
            "different.txt": b"else payload",
            "tampered.txt": b"fake payload",
        }
        for name, content in contents.items():
            rid = os.urandom(6).hex()
            salt = os.urandom(16)
            key = U.file_key(root, salt)
            encrypted = U.VAULT / f"{rid}.cdr"
            source = s.d / name
            source.write_bytes(content)
            U.enc_file(source, encrypted, key, lambda *_: None)
            index[rid] = {
                "s": U.b64e(salt),
                "nm": U.b64e(U.seal(key, name.encode())),
                "size": len(content),
                "exp": None,
                "views": None,
            }
            ids[name] = rid
        tampered_path = U.VAULT / f"{ids['tampered.txt']}.cdr"
        payload = bytearray(tampered_path.read_bytes())
        payload[-1] ^= 1
        tampered_path.write_bytes(payload)

        worker = U._VaultAnalysisWorker(root, index, False)
        result = []
        worker.signals.finished.connect(result.append)
        worker.run()

        self_result = result[0]
        s.assertEqual(self_result["status"], "failed")
        s.assertEqual(len(self_result["duplicates"]), 1)
        s.assertEqual(set(self_result["duplicates"][0]), {"first.txt", "copy.txt"})
        duplicate_records = self_result["duplicate_records"]
        s.assertEqual(
            {item["rid"] for item in duplicate_records[0]},
            {ids["first.txt"], ids["copy.txt"]},
        )
        s.assertEqual(self_result["stats"]["candidate_count"], 4)
        s.assertEqual(self_result["stats"]["file_count"], 4)
        s.assertEqual(len(self_result["failures"]), 1)
        s.assertEqual(self_result["failures"][0]["name"], "tampered.txt")
    def test_authenticated_index_keeps_backward_compatibility_and_validates_virtual_groups(s):
        rid = os.urandom(6).hex()
        metadata = {"s": "salt", "nm": "name", "size": 0, "exp": None, "views": None}
        s.assertNotIn("group", U._validated_idx({rid: metadata})[rid])
        grouped = dict(metadata, group="Archive")
        validated_group = cast(dict[str, object], U._validated_idx({rid: grouped})[rid])
        s.assertEqual(validated_group["group"], "Archive")
        with s.assertRaisesRegex(ValueError, "invalid vault item group"):
            U._validated_idx({rid: dict(metadata, group=["not", "text"])})
    def test_roundtrip_and_progress(s):
        dek, ph, files = s.vault(); seen = []
        rid, (data, _) = list(files.items())[3]; k = U.file_key(dek, U.b64d(U.idx[rid]["s"]))
        s.assertEqual(U.dec_file(U.VAULT / f"{rid}.cdr", k, lambda a, b: seen.append(a / b)), data); s.assertAlmostEqual(seen[-1], 1.0); s.check_all(dek, files)
    def test_stream_decrypt_writes_authenticated_plaintext_directly_to_temp_file(s):
        dek, _, files = s.vault(sizes=(2_500_000,))
        rid, (data, name) = next(iter(files.items()))
        path, size = U.dec_file_to_temp(U.VAULT / f"{rid}.cdr", U.file_key(dek, U.b64d(U.idx[rid]["s"])), name)
        s.assertEqual(size, len(data)); s.assertEqual(path.read_bytes(), data)
        s.assertEqual(path.parent, U.HOME / "tmp")
        U.tmp_wipe(path)
        s.assertFalse(path.exists())
    def test_authenticated_temp_media_can_be_exported_without_accepting_changed_temp_data(s):
        dek, _, files = s.vault(sizes=(256,))
        rid, (data, name) = next(iter(files.items()))
        path, size, digest = U.dec_file_to_temp(
            U.VAULT / f"{rid}.cdr", U.file_key(dek, U.b64d(U.idx[rid]["s"])), name, with_digest=True)
        output = s.d / "export.mp4"
        s.assertEqual(size, len(data))
        U.save_verified_temp_copy(path, output, digest)
        s.assertEqual(output.read_bytes(), data)
        path.write_bytes(b"x" * len(data))
        changed_output = s.d / "changed.mp4"
        with s.assertRaisesRegex(ValueError, "source changed"):
            U.save_verified_temp_copy(path, changed_output, digest)
        s.assertFalse(changed_output.exists())
        U.tmp_wipe(path)
    def test_stream_decrypt_removes_partial_plaintext_when_authentication_fails(s):
        dek, _, files = s.vault(sizes=(128,))
        rid, (data, name) = next(iter(files.items()))
        source = U.VAULT / f"{rid}.cdr"; source.write_bytes(source.read_bytes()[:-1] + b"x")
        target = U.HOME / "tmp" / "failed.mp4"
        target.parent.mkdir(parents=True, exist_ok=True)
        with mock.patch.object(U, "tmp_media_path", return_value=target), s.assertRaises(InvalidTag):
            U.dec_file_to_temp(source, U.file_key(dek, U.b64d(U.idx[rid]["s"])), name)
        s.assertFalse(target.exists())
    def test_password_and_recovery_unwrap_same_key(s):
        dek, ph, _ = s.vault()
        s.assertEqual(U.unseal(U.kdf(PW, U.b64d(U.cfg["s1"])), U.b64d(U.cfg["wp"])), dek); s.assertEqual(U.unseal(U.kdf(ph, U.b64d(U.cfg["s2"])), U.b64d(U.cfg["wr"])), dek)
        with s.assertRaises(InvalidTag): U.unseal(U.kdf("Wrong-Password-123!", U.b64d(U.cfg["s1"])), U.b64d(U.cfg["wp"]))
    def test_copied_vault_offline_guess_and_metadata_privacy(s):
        dek, _, files = s.vault(sizes=(128,))
        rid = next(iter(files)); U.idx[rid].update(exp=1_900_000_000, views=3); U.save_idx(dek, U.idx)
        copied = Path(tempfile.mkdtemp(prefix="unknwn_copy_")); s.addCleanup(shutil.rmtree, copied, True); shutil.copytree(U.HOME, copied, dirs_exist_ok=True)
        original_home = U.HOME
        try:
            U.set_home(copied); copied_cfg = U.jload(U.CFG, {})
            blob = U.IDX.read_text(encoding="utf-8")
            for secret in ('"size"', '"views"', '"exp"', "file0.bin"):
                s.assertNotIn(secret, blob)
            guesses = ("password", "Definitely-Wrong-123!", "definitely-not-the-password")
            opened = None
            for guess in guesses:
                try:
                    candidate = U.unseal(U.kdf(guess, U.b64d(copied_cfg["s1"])), U.b64d(copied_cfg["wp"]))
                    opened = candidate; break
                except InvalidTag:
                    pass
            s.assertIsNone(opened, "the simulated offline dictionary guesses must not unwrap the copied vault")
            opened = U.unseal(U.kdf(PW, U.b64d(copied_cfg["s1"])), U.b64d(copied_cfg["wp"]))
            s.assertEqual(opened, dek, "the correct password must open the copied vault")
            copied_index = U.load_idx(opened)
            s.assertEqual(copied_index[rid]["views"], 3)
            copied_file_key = U.file_key(opened, U.b64d(copied_index[rid]["s"]))
            s.assertEqual(U.dec_file(U.VAULT / f"{rid}.cdr", copied_file_key), files[rid][0])
        finally:
            U.set_home(original_home)
    def test_encrypted_index_tampering_is_rejected_or_recovers_authenticated_backup(s):
        dek, _, _ = s.vault(sizes=(32,))
        raw = json.loads(U.IDX.read_text(encoding="utf-8")); raw["data"] = U.b64e(os.urandom(len(U.b64d(raw["data"]))))
        U.IDX.write_text(json.dumps(raw), encoding="utf-8")
        with s.assertRaises(InvalidTag):
            U.load_idx(dek)
        U.save_idx(dek, U.idx)
        U.save_idx(dek, U.idx)
        tampered = json.loads(U.IDX.read_text(encoding="utf-8")); tampered["data"] = U.b64e(os.urandom(len(U.b64d(tampered["data"]))))
        U.IDX.write_text(json.dumps(tampered), encoding="utf-8")
        s.assertEqual(U.load_idx(dek), U.idx)
    def test_legacy_plaintext_index_migrates_to_encrypted_format(s):
        dek, _, _ = s.vault(sizes=(64,))
        plain = dict(U.idx)
        U.jsave(U.IDX, plain)
        loaded, legacy = U.load_idx(dek, with_legacy=True)
        s.assertTrue(legacy); s.assertEqual(loaded, plain)
        U.save_idx(dek, loaded)
        s.assertEqual(json.loads(U.IDX.read_text(encoding="utf-8"))["format"], "UNKNWN-INDEX-2")
        s.assertNotIn('"size"', U.IDX.read_text(encoding="utf-8"))
    def test_password_kdf_rejects_manipulated_work_factors(s):
        for work_factor in (True, 0, 16, 18, 1000, "17"):
            U.cfg["n"] = work_factor
            with s.subTest(work_factor=work_factor), s.assertRaises(ValueError):
                U.kdf("test password", os.urandom(16))
        U.cfg["n"] = 17
        s.assertEqual(len(U.kdf("test password", os.urandom(16))), 32)
    def test_tampering_is_rejected(s):
        dek, ph, files = s.vault(); rid = list(files)[3]; k = U.file_key(dek, U.b64d(U.idx[rid]["s"])); p = U.VAULT / f"{rid}.cdr"; raw = p.read_bytes(); cs = []; pos = 0
        while pos < len(raw): L = struct.unpack(">I", raw[pos:pos + 4])[0]; cs.append(raw[pos:pos + 4 + L]); pos += 4 + L
        for label, bad in {"bitflip": raw[:60] + bytes([raw[60] ^ 1]) + raw[61:], "drop last": b"".join(cs[:-1]), "swap": cs[1] + cs[0] + b"".join(cs[2:]), "dup": cs[0] + cs[0] + b"".join(cs[1:]),
                           "junk": raw + os.urandom(50), "empty": b""}.items():
            p.write_bytes(bad)
            with s.assertRaises(Exception, msg=label): U.dec_file(p, k)
    def test_empty_ciphertext_rejected(s):
        e = s.d / "e.cdr"; e.write_bytes(b"")
        with s.assertRaises(InvalidTag): U.dec_file(e, os.urandom(32))
    def test_shred_progress_and_delete(s):
        p = s.d / "x.bin"; p.write_bytes(os.urandom(2_500_000)); seen = []; U.shred(p, 3, lambda a, b: seen.append(a / b)); s.assertFalse(p.exists()); s.assertAlmostEqual(seen[-1], 1.0)
    def test_wipe_unlinks_symlinks_without_touching_their_targets(s):
        root = s.d / "wipe"; root.mkdir()
        target = s.d / "outside.txt"; target.write_text("keep this")
        link = root / "linked.txt"
        try: link.symlink_to(target)
        except (OSError, NotImplementedError): s.skipTest("symlink creation is not available")
        outside_dir = s.d / "outside_dir"; outside_dir.mkdir()
        (outside_dir / "keep.txt").write_text("keep directory contents")
        dir_link = root / "linked-dir"
        try: dir_link.symlink_to(outside_dir, target_is_directory=True)
        except (OSError, NotImplementedError): s.skipTest("directory symlink creation is not available")
        U.wipe(root, False)
        s.assertFalse(link.exists()); s.assertFalse(link.is_symlink())
        s.assertFalse(dir_link.exists()); s.assertFalse(dir_link.is_symlink())
        s.assertEqual(target.read_text(), "keep this")
        s.assertEqual((outside_dir / "keep.txt").read_text(), "keep directory contents")
    def test_wipe_refuses_hardlinks_to_preserve_outside_file_contents(s):
        root = s.d / "wipe"; root.mkdir()
        outside = s.d / "outside.txt"; outside.write_text("unrelated file")
        linked = root / "owned-looking.txt"
        try: os.link(outside, linked)
        except OSError: s.skipTest("hard links are not available")
        with s.assertRaisesRegex(ValueError, "multiply-linked"):
            U.wipe(root, False, 1)
        s.assertEqual(outside.read_text(), "unrelated file")
    def test_shred_surfaces_when_overwrite_and_delete_fail(s):
        path = s.d / "locked.bin"; path.write_bytes(b"still present")
        with mock.patch("builtins.open", side_effect=PermissionError("locked")), \
             mock.patch.object(U, "_durable_unlink", side_effect=PermissionError("locked")), \
             s.assertRaises(OSError):
            U.shred(path)
        s.assertEqual(path.read_bytes(), b"still present")
    def test_recursive_wipe_surfaces_directory_removal_errors(s):
        root = s.d / "wipe"; root.mkdir(); (root / "item.bin").write_bytes(b"removed first")
        with mock.patch.object(Path, "rmdir", side_effect=OSError("directory locked")), s.assertRaises(OSError):
            U.wipe(root, True)
        s.assertTrue(root.exists())
    def test_panic_wipe_clears_interrupted_transaction_artifacts(s):
        staged = U.VAULT / "012345abcdef.cdr.txn"; staged.parent.mkdir(parents=True, exist_ok=True)
        staged.write_bytes(b"staged ciphertext")
        journal = U.storage_txn_path(); journal.write_text('{"operation":"seal"}')
        U.wipe(U.HOME, False, 1)
        s.assertFalse(staged.exists())
        s.assertFalse(journal.exists())
        s.assertTrue(U.HOME.exists())
    def test_recovery_phrase_strength(s):
        import math; s.assertGreater(sum(math.log2(len(U.WORDS) - i) for i in range(U.NW)), 65)

class TestCrashSafety(Base):
    def test_fresh_start_routes_to_setup_after_empty_config_defaults_are_added(s):
        U.cfg.clear(); U.cfg.update(f=0, tf=0, lock=0, fails=[])
        dummy = mock.MagicMock()
        U.App.route_startup_config(dummy)
        dummy.setup_screen.assert_called_once()
        dummy.login_screen.assert_not_called()
        dummy.damaged_screen.assert_not_called()
    def test_startup_routes_to_login_only_with_all_required_config_fields(s):
        U.cfg.clear()
        U.cfg.update({key: 1 for key in U.REQUIRED_CFG_KEYS})
        dummy = mock.MagicMock()
        with mock.patch.object(U.QTimer, "singleShot") as single_shot:
            U.App.route_startup_config(dummy)
        dummy.login_screen.assert_called_once()
        dummy.setup_screen.assert_not_called()
        dummy.damaged_screen.assert_not_called()
        single_shot.assert_not_called()
    def test_unlock_reports_missing_wrapper_fields_as_configuration_damage(s):
        for missing in ("s1", "wp"):
            with s.subTest(missing=missing):
                U.cfg.clear(); U.cfg.update(lock=0, set={})
                U.cfg["wp" if missing == "s1" else "s1"] = U.b64e(os.urandom(32 if missing == "s1" else 16))
                class Dummy:
                    pw = mock.MagicMock(); ub = mock.MagicMock(); rob = mock.MagicMock()
                    root = b"old"; ro = True
                    def sec_ok(self): return True
                    def login_screen(self): pass
                    fail = mock.MagicMock()
                dummy = Dummy(); dummy.pw.text.return_value = "correct horse"
                with mock.patch.object(U, "kdf", return_value=os.urandom(32)), \
                     mock.patch.object(U.QApplication, "processEvents"), \
                     mock.patch.object(U.QMessageBox, "warning") as warning, \
                     mock.patch.object(U, "log_security_event") as log:
                    U.App.try_login(dummy)
                s.assertEqual(warning.call_args.args[1], "Vault configuration incomplete")
                s.assertIn(missing, warning.call_args.args[2])
                s.assertNotIn("low on memory", warning.call_args.args[2])
                s.assertIsNone(dummy.root); s.assertFalse(dummy.ro)
                dummy.fail.assert_not_called()
                log.assert_called_once_with("unlock_configuration_incomplete", field=missing)
    def test_unlock_reports_memory_error_without_claiming_config_is_damaged(s):
        U.cfg.clear(); U.cfg.update(lock=0, set={}, s1=U.b64e(os.urandom(16)), wp=U.b64e(os.urandom(60)))
        class Dummy:
            pw = mock.MagicMock(); ub = mock.MagicMock(); rob = mock.MagicMock()
            root = b"old"; ro = True
            def sec_ok(self): return True
            def login_screen(self): pass
            fail = mock.MagicMock()
        dummy = Dummy(); dummy.pw.text.return_value = "correct horse"
        with mock.patch.object(U, "kdf", side_effect=MemoryError), \
             mock.patch.object(U.QApplication, "processEvents"), \
             mock.patch.object(U.QMessageBox, "warning") as warning, \
             mock.patch.object(U, "log_security_event") as log:
            U.App.try_login(dummy)
        s.assertEqual(warning.call_args.args[1], "Not enough memory to unlock")
        s.assertIn("128 MiB", warning.call_args.args[2])
        s.assertNotIn("configuration", warning.call_args.args[2].lower())
        dummy.fail.assert_not_called()
        log.assert_called_once_with("unlock_resource_exhausted", error="MemoryError")

    def test_cancelled_manual_burn_does_not_start_deletion(s):
        class Dummy:
            root = b"authenticated-root"
            dying = set()
            cards = {"012345abcdef": object()}
            mode = "vault"
            def sec_ok(self, *_args): return True
            def _simulate_vault_action(self, *_args, **_kwargs):
                return mock.Mock(valid=True, affected_count=1, conflicts=())
        dummy = Dummy()
        with mock.patch.object(U, "idx", {"012345abcdef": {}}), \
             mock.patch.object(U, "terminal_confirm", return_value=False) as confirm:
            U.App.burn(dummy, "012345abcdef")
        confirm.assert_called_once()
        s.assertNotIn("012345abcdef", dummy.dying)

    def test_panic_wipe_minimizes_then_restores_to_profile_chooser(s):
        order = []
        dummy = mock.MagicMock()
        dummy.cards = {}; dummy.cds = {}; dummy.dying = set(); dummy.busy = True; dummy.ro = True
        dummy.windowState.return_value = U.Qt.WindowMaximized
        dummy.showMinimized.side_effect = lambda: order.append("minimize")
        dummy.fl.deleteLater.side_effect = lambda: order.append("remove outro")
        dummy.setWindowState.side_effect = lambda state: order.append(("window state", state))
        dummy.show.side_effect = lambda: order.append("show")
        dummy.raise_.side_effect = lambda: order.append("raise")
        dummy.restore_wipe_window.side_effect = lambda state: U.App.restore_wipe_window(dummy, state)
        dummy.profile_chooser.side_effect = lambda: order.append("profiles")
        scheduled = []
        with mock.patch.object(U, "resume_destructive_cleanup", side_effect=lambda *args: (order.append("wipe") or {"operation": "panic-wipe", "phase": "data-cleared"})), \
             mock.patch.object(U, "read_destruct_journal", return_value=None), \
             mock.patch.object(U, "begin_destructive_cleanup", return_value={"operation": "panic-wipe"}), \
             mock.patch.object(U, "clear_destruct_journal"), \
             mock.patch.object(U.QApplication, "processEvents", side_effect=lambda: order.append("process events")), \
             mock.patch.object(U.QTimer, "singleShot", side_effect=lambda delay, callback: scheduled.append(callback)):
            U.App.wipe_all(dummy)
        s.assertEqual(order, ["minimize", "process events", "wipe", "remove outro", "profiles"])
        s.assertEqual(len(scheduled), 1)
        scheduled[0]()
        s.assertEqual(order[-3:], [("window state", U.Qt.WindowMaximized), "show", "raise"])
        dummy.showNormal.assert_not_called(); dummy.activateWindow.assert_not_called()
        s.assertFalse(dummy.busy); s.assertFalse(dummy.ro)
        s.assertEqual(U.cfg, {}); s.assertEqual(U.idx, {})

    def test_windows_device_fingerprint_ignores_hostname_and_adapter_mac(s):
        class RegistryKey:
            def __enter__(self): return self
            def __exit__(self, *_args): return False

        registry = mock.Mock()
        registry.KEY_READ = 0x20019
        registry.KEY_WOW64_64KEY = 0x0100
        registry.HKEY_LOCAL_MACHINE = object()
        registry.REG_SZ = 1
        registry.OpenKey.return_value = RegistryKey()
        registry.QueryValueEx.return_value = ("{01234567-89ab-cdef-0123-456789abcdef}", 1)
        with mock.patch.dict(sys.modules, {"winreg": registry}), \
             mock.patch.object(U.platform, "node", side_effect=["pc-before", "pc-after"]), \
             mock.patch.object(U.uuid, "getnode", side_effect=[1, 2]):
            first = U.fp()
            second = U.fp()
        s.assertEqual(first, second)
        registry.QueryValueEx.assert_called_with(mock.ANY, "MachineGuid")

    def test_device_binding_accepts_legacy_fingerprint_for_existing_vaults(s):
        stable = "a" * 64
        legacy = "b" * 64
        with mock.patch.object(U, "fp", return_value=stable), \
             mock.patch.object(U, "_legacy_fp", return_value=legacy):
            s.assertTrue(U._device_binding_matches(stable))
            s.assertTrue(U._device_binding_matches(legacy))
            s.assertFalse(U._device_binding_matches("c" * 64))
            s.assertFalse(U._device_binding_matches("malformed"))

    def test_panic_wipe_restores_app_and_reports_failure(s):
        dummy = mock.MagicMock()
        dummy.cards = {}; dummy.cds = {}; dummy.dying = set(); dummy.busy = True; dummy.ro = True
        dummy.destructive_recovery_screen.side_effect = lambda error: setattr(dummy, "failure", error)
        with mock.patch.object(U, "resume_destructive_cleanup", side_effect=OSError("disk error")), \
             mock.patch.object(U.QApplication, "processEvents"), \
             mock.patch.object(U, "read_destruct_journal", return_value={"operation": "panic-wipe"}):
            U.App.wipe_all(dummy)
        dummy.showMinimized.assert_called_once()
        dummy.destructive_recovery_screen.assert_called_once()
        s.assertFalse(dummy.busy); s.assertFalse(dummy.ro)
        s.assertEqual(dummy.failure.args[0], "disk error")

    def test_panic_wipe_restores_a_window_that_was_already_minimized(s):
        app = mock.MagicMock(); app.cards = {}; app.cds = {}; app.dying = set(); app.busy = True; app.ro = False
        app.windowState.return_value = U.Qt.WindowMinimized
        app.restore_wipe_window.side_effect = lambda state: U.App.restore_wipe_window(app, state)
        scheduled = []
        with mock.patch.object(U, "resume_destructive_cleanup", return_value={"operation": "panic-wipe", "phase": "data-cleared"}), \
             mock.patch.object(U, "read_destruct_journal", return_value={"operation": "panic-wipe"}), \
             mock.patch.object(U, "clear_destruct_journal"), mock.patch.object(U.QApplication, "processEvents"), \
             mock.patch.object(U.QTimer, "singleShot", side_effect=lambda delay, callback: scheduled.append(callback)):
            U.App.wipe_all(app)
        scheduled[0]()
        app.setWindowState.assert_called_once_with(U.Qt.WindowNoState)
        app.show.assert_called_once()

    def test_setting_a_panic_shortcut_does_not_confirm_execution(s):
        app = mock.MagicMock(); combo = mock.MagicMock(); combo.currentData.return_value = "wipe"
        with mock.patch.object(U.QMessageBox, "warning") as warning:
            U.App.set_act(app, combo)
        app.put.assert_called_once_with("hk_act", "wipe")
        warning.assert_not_called()

    def test_manual_panic_wipe_still_requires_confirmation(s):
        app = mock.MagicMock(); app.busy = False; app.confirm_panic.return_value = False
        app.defer_seal_action.return_value = False
        U.App.panic(app, True)
        app.confirm_panic.assert_called_once_with()
        app.PanicSequence.assert_not_called()
        s.assertFalse(app.busy)
    def test_panic_hotkey_wipe_uses_existing_direct_wipe_action(s):
        app = mock.MagicMock(); app.busy = False
        with mock.patch.object(U, "S", side_effect=lambda key: {
                "hk_act": "wipe", "hk_notice": True}.get(key, False)), \
             mock.patch.object(U.QMessageBox, "information") as notice:
            U.App.hotkey(app)
        notice.assert_called_once()
        app.panic.assert_called_once_with(False)
        app.destruct.assert_not_called()
    def test_self_destruct_hotkey_requires_explicit_confirmation(s):
        app = mock.MagicMock(); app.busy = False
        with mock.patch.object(U, "S", side_effect=lambda key: {
                "hk_act": "destruct", "hk_notice": True}.get(key, False)), \
             mock.patch.object(U.QMessageBox, "information") as notice:
            U.App.hotkey(app)
        notice.assert_called_once()
        app.destruct.assert_called_once_with(True)
        app.panic.assert_not_called()
    def test_source_run_full_self_destruct_fails_closed_before_confirmation(s):
        app = mock.MagicMock(); app.targets.return_value = []
        with mock.patch.object(U.QMessageBox, "warning") as warning, \
             mock.patch.object(U, "terminal_confirm") as confirm:
            s.assertFalse(U.App.confirm_destruct(app))
        warning.assert_called_once()
        confirm.assert_not_called()
    def test_non_windows_full_self_destruct_is_refused_before_data_cleanup(s):
        app = mock.MagicMock(); app.busy = False; app.hold = 0
        app.working.return_value = False
        app.defer_seal_action.return_value = False
        app.targets.return_value = [s.d / "UNKNWN_fixture"]
        with mock.patch.object(U.sys, "platform", "linux"), \
             mock.patch.dict(os.environ, {"UNKNWN_DRYRUN": ""}), \
             mock.patch.object(U.QMessageBox, "warning") as warning, \
             mock.patch.object(U, "begin_destructive_cleanup") as begin:
            U.App.destruct(app, ask=False)
        warning.assert_called_once()
        begin.assert_not_called()
    def test_cancelled_self_destruct_does_not_create_a_cleanup_journal(s):
        app = mock.MagicMock(); app.busy = False; app.confirm_destruct.return_value = False
        app.working.return_value = False; app.hold = 0
        app.defer_seal_action.return_value = False
        U.App.destruct(app, True)
        app.confirm_destruct.assert_called_once_with()
        s.assertIsNone(U.read_destruct_journal())
    def test_self_destruct_targets_a_dedicated_package_directory(s):
        package, public_key = make_signed_package(
            Path(tempfile.mkdtemp(prefix="UNKNWN_package_")),
            {"UNKNWN.exe": b"signed fixture"},
        )
        s.addCleanup(shutil.rmtree, package, True)
        executable = package / "UNKNWN.exe"
        with mock.patch.object(U, "APP", executable), mock.patch.object(U, "PACKAGED", True), \
             mock.patch.object(U.IG, "RELEASE_PUBKEY", public_key):
            s.assertEqual(U.App.targets(None), [package.resolve()])
    def test_self_destruct_rejects_unlisted_files_in_packaged_install(s):
        package, public_key = make_signed_package(
            Path(tempfile.mkdtemp(prefix="UNKNWN_signed_package_")),
            {"UNKNWN.exe": b"signed fixture"},
        )
        s.addCleanup(shutil.rmtree, package, True)
        executable = package / "UNKNWN.exe"
        with mock.patch.object(U, "APP", executable), mock.patch.object(U, "PACKAGED", True), \
             mock.patch.object(U.IG, "RELEASE_PUBKEY", public_key):
            s.assertEqual(U.App.targets(None), [package.resolve()])
            (package / "unlisted-user-file.txt").write_text("not in the signed installation")
            with s.assertRaises(ValueError):
                U.App.targets(None)
            s.assertTrue((package / "unlisted-user-file.txt").exists())
    def test_restart_recovery_accepts_only_the_remaining_signed_install_files(s):
        package = s.d / "UNKNWN_partial"
        package, public_key = make_signed_package(package, {"UNKNWN.exe": b"signed fixture"})
        executable = package / "UNKNWN.exe"
        with mock.patch.object(U.IG, "RELEASE_PUBKEY", public_key):
            U.begin_destructive_cleanup("self-destruct", package)
            record = U.read_destruct_journal()
            record["phase"] = "data-cleared"
            U.write_destruct_journal(record)
            executable.unlink()
            s.assertEqual(U.read_destruct_journal()["phase"], "data-cleared")
            system_root = s.d / "windows"
            powershell = system_root / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
            powershell.parent.mkdir(parents=True)
            powershell.touch()
            with mock.patch.object(U.sys, "platform", "win32"), \
                 mock.patch.dict(os.environ, {"SystemRoot": str(system_root)}):
                command = U.windows_cleanup_command(
                    package, Path.home() / ".unknwn", os.getpid(), restart=False,
                    journal_path=U.destruct_journal_path())
            script = U._decode_cleanup_command(command[-1])
            s.assertIn("Remove-InstallTree $target", script)
            s.assertNotIn("Remove-Item -LiteralPath $target -Recurse", script)
            s.assertNotIn("rd /s /q", script)
            (package / IG.MAN).unlink()
            s.assertEqual(U.read_destruct_journal()["phase"], "data-cleared")
            (package / IG.SIG).unlink()
            s.assertEqual(U.read_destruct_journal()["phase"], "data-cleared")
            unlisted = package / "unlisted-user-file.txt"
            unlisted.write_text("must not be removed")
            with s.assertRaisesRegex(ValueError, "signed UNKNWN package"):
                U.read_destruct_journal()
            s.assertTrue(unlisted.exists())
    def test_self_destruct_never_targets_the_source_workspace(s):
        source = ROOT / "unknwn.py"
        with mock.patch.object(U, "APP", source), mock.patch.object(U, "PACKAGED", False):
            s.assertEqual(U.App.targets(None), [])
    def test_self_destruct_does_not_target_an_unmarked_source_directory(s):
        source_dir = s.d / "UNKNWN_unmarked"
        source_dir.mkdir()
        source = source_dir / "unknwn.py"; source.touch()
        with mock.patch.object(U, "APP", source), mock.patch.object(U, "PACKAGED", False):
            s.assertEqual(U.App.targets(None), [])
    def test_windows_restart_helper_requires_successful_removal_and_does_not_force_close_apps(s):
        if sys.platform != "win32": s.skipTest("Windows PowerShell cleanup is platform-specific")
        package, public_key = make_signed_package(
            s.d / "UNKNWN_release", {"UNKNWN.exe": b"fixture executable"})
        profile = s.d / "profile"; profile.mkdir()
        system_root = s.d / "windows"
        powershell = system_root / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
        powershell.parent.mkdir(parents=True); powershell.touch()
        env = {"USERPROFILE": str(profile), "SystemRoot": str(system_root)}
        with mock.patch.dict(os.environ, env), mock.patch.object(U.IG, "RELEASE_PUBKEY", public_key):
            command = U.windows_cleanup_command(package, profile / ".unknwn", 123, restart=True)
        script = U._decode_cleanup_command(command[-1])
        removal_failure_check = script.index("if (-not $removed)")
        restart_request = script.index("Start-Process -FilePath")
        data_guard = script.index("if ($requestedDataRemain -or $knownDataRemain)")
        install_removal = script.index("if (Test-Path -LiteralPath $target) { Remove-InstallTree $target }")
        journal_removal = script.index("Remove-Item -LiteralPath $journal")
        s.assertLess(data_guard, install_removal)
        s.assertLess(removal_failure_check, restart_request)
        s.assertLess(script.index("Stop-Recovery 15"), restart_request)
        s.assertLess(script.index("The self-destruct verification marker"), restart_request)
        s.assertLess(restart_request, journal_removal)
        s.assertIn(".unknwn-profiles.json.*.tmp", script)
        s.assertIn(".unknwn-location.*.tmp", script)
        s.assertIn("@('/r', '/t', '10')", script)
        self_destruct_note = script.index("$noteBytes = [System.Text.UTF8Encoding]::new($false).GetBytes('meow')")
        s.assertIn("bWVvdw==", script)
        s.assertNotIn("cleanup-debug.log", script)
        s.assertNotIn("Log-Debug", script)
        s.assertNotIn("persistentLogDir", script)
        s.assertNotIn("C:\\Users\\youss\\Desktop\\UNKNWN", script)
        s.assertNotIn("'/f'", script)
        s.assertLess(self_destruct_note, script.index("[IO.File]::Delete($recoveryScript)"))
        s.assertLess(self_destruct_note, script.index("Remove-Item -LiteralPath $journal"))
        s.assertLess(self_destruct_note, script.index("Start-Process -FilePath"))
    def test_recovery_stages_helper_before_exiting_without_restarting_early(s):
        app = mock.MagicMock()
        install = s.d / "UNKNWN_missing"
        record = {"operation": "self-destruct", "phase": "data-cleared",
                  "install_target": str(install)}
        events = []
        with mock.patch.object(U.sys, "platform", "win32"), \
             mock.patch.object(U, "_validate_packaged_install_target", return_value=install), \
             mock.patch.object(U, "_safe_recovery_script", return_value=True), \
             mock.patch.object(U, "destruct_runonce_command", return_value=["powershell.exe", "-File", "helper.ps1"]), \
             mock.patch.object(U.subprocess, "Popen",
                               side_effect=lambda *_a, **_k: events.append("helper-started")) as popen, \
             mock.patch.object(U.os, "_exit") as exit_process:
            U.App.finalize_destructive_cleanup(app, record)
        s.assertEqual(events, ["helper-started"])
        popen.assert_called_once()
        exit_process.assert_called_once_with(0)
    def test_source_self_destruct_is_not_reported_as_success(s):
        app = mock.MagicMock()
        record = {"operation": "self-destruct", "phase": "data-cleared",
                  "install_target": None}
        with mock.patch.object(U.sys, "platform", "win32"), \
             mock.patch.object(U.subprocess, "Popen") as popen, \
             mock.patch.object(U.os, "_exit") as exit_process:
            U.App.finalize_destructive_cleanup(app, record)
        app.destructive_recovery_screen.assert_called_once()
        popen.assert_not_called()
        exit_process.assert_not_called()
    def test_recovered_panic_wipe_returns_to_profile_chooser(s):
        app = mock.MagicMock()
        record = {"operation": "panic-wipe", "phase": "data-cleared"}
        with mock.patch.object(U, "clear_destruct_journal"):
            U.App.finalize_destructive_cleanup(app, record)
        app.profile_chooser.assert_called_once_with()
        app.setup_screen.assert_not_called()
    def test_windows_self_cleanup_waits_for_process_then_removes_only_install_and_data(s):
        if sys.platform != "win32": s.skipTest("Windows PowerShell cleanup is platform-specific")
        parent = s.d / "UNKNWN_release_parent"; package = parent / "UNKNWN_release"; sibling = parent / "UNKNWN_release_backup"
        profile = s.d / "profile"; home = profile / ".unknwn"
        sibling.mkdir(parents=True); home.mkdir(parents=True)
        package, public_key = make_signed_package(
            package, {"UNKNWN.exe": b"fixture executable",
                      "nested/deeper/payload.dat": b"nested fixture"})
        exe = package / "UNKNWN.exe"
        (sibling / "keep.txt").write_text("not the target")
        marker = parent / "keep-parent.txt"; marker.write_text("parent survives")
        (home / "config.json").write_text("app data")
        child_code = ("import ctypes,sys,time; k=ctypes.windll.kernel32; "
                      "k.CreateFileW.restype=ctypes.c_void_p; "
                      "h=k.CreateFileW(sys.argv[1],0x80000000,1,None,3,0x80,None); "
                      "assert h not in (None,0,ctypes.c_void_p(-1).value); "
                      "time.sleep(1.5); k.CloseHandle(h)")
        env = os.environ.copy(); env["USERPROFILE"] = str(profile)
        child = subprocess.Popen([sys.executable, "-c", child_code, str(exe)], env=env)
        with mock.patch.dict(os.environ, {"USERPROFILE": str(profile)}), \
             mock.patch.object(U.IG, "RELEASE_PUBKEY", public_key):
            try: command = U.windows_cleanup_command(package, home, child.pid, restart=False)
            except FileNotFoundError:
                child.terminate(); child.wait(timeout=5)
                s.skipTest("Windows PowerShell is unavailable")
        s.assertLess(len(subprocess.list2cmdline(command)), 32767)
        cleanup = subprocess.Popen(command, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        time.sleep(.35)
        s.assertTrue(package.exists(), "cleanup must wait while the process holds the executable")
        out, err = cleanup.communicate(timeout=60)
        child.wait(timeout=5)
        s.assertEqual(cleanup.returncode, 0, (out.decode(errors="replace"), err.decode(errors="replace")))
        s.assertFalse(package.exists())
        s.assertFalse(home.exists())
        s.assertTrue(sibling.joinpath("keep.txt").exists())
        s.assertTrue(marker.exists())
        s.assertTrue(profile.exists())
    def test_windows_package_cleanup_creates_exact_marker_before_suppressed_restart(s):
        if sys.platform != "win32": s.skipTest("Windows PowerShell cleanup is platform-specific")
        profile = s.d / "profile"
        profile.mkdir()
        home = profile / ".unknwn"
        home.mkdir()
        (home / "config.json").write_text("owned data")
        package, public_key = make_signed_package(
            s.d / "UNKNWN_release", {"UNKNWN.exe": b"fixture executable"})
        env = os.environ.copy()
        env["USERPROFILE"] = str(profile)
        with mock.patch.dict(os.environ, env), \
             mock.patch.object(U.IG, "RELEASE_PUBKEY", public_key):
            command = U.windows_cleanup_command(package, home, 0, restart=True)
        script = U._decode_cleanup_command(command[-1])
        restart = ("Start-Process -FilePath $shutdownPath -ArgumentList @('/r', '/t', '10') `\n"
                   "            -WindowStyle Hidden -ErrorAction Stop")
        s.assertIn(restart, script)
        script = script.replace(restart, "Write-Output 'RESTART_SUPPRESSED_FOR_TEST'", 1)
        command[-1] = U._encode_cleanup_command(script)
        result = subprocess.run(command, env=env, capture_output=True, text=True, timeout=60)
        s.assertEqual(result.returncode, 0, (result.stdout, result.stderr))
        s.assertIn("RESTART_SUPPRESSED_FOR_TEST", result.stdout)
        s.assertFalse(package.exists())
        s.assertFalse(home.exists())
        s.assertEqual((profile / "Downloads" / "meow.txt").read_bytes(), b"meow")
    def test_windows_self_cleanup_rejects_similarly_named_non_install_directory(s):
        if sys.platform != "win32": s.skipTest("Windows PowerShell cleanup is platform-specific")
        profile = s.d / "profile"; other = s.d / "UNKNWN_release_backup"; profile.mkdir(); other.mkdir()
        (other / "keep.txt").write_text("not an installation")
        with mock.patch.dict(os.environ, {"USERPROFILE": str(profile)}):
            with s.assertRaises(ValueError):
                U.windows_cleanup_command(other, profile / ".unknwn", 1, restart=False)
        s.assertTrue(other.joinpath("keep.txt").exists())
    def test_windows_self_cleanup_rejects_source_workspace(s):
        if sys.platform != "win32": s.skipTest("Windows PowerShell cleanup is platform-specific")
        parent = s.d / "UNKNWN_source_parent"; source = parent / "UNKNWN_source"
        profile = s.d / "profile"
        (source / ".venv").mkdir(parents=True); (source / "tests").mkdir()
        profile.mkdir()
        (source / "unknwn.py").write_text("source")
        (source / "unknwn_integrity.py").write_text("integrity")
        (source / ".venv" / "environment.txt").write_text("developer data")
        (source / "tests" / "test.txt").write_text("developer data")
        marker = parent / "keep-parent.txt"; marker.write_text("parent survives")
        with mock.patch.dict(os.environ, {"USERPROFILE": str(profile)}), s.assertRaises(ValueError):
            U.windows_cleanup_command(source, None, 1, restart=False)
        s.assertTrue(source.exists())
        s.assertTrue(marker.exists())

    def test_legacy_plaintext_playback_default_migrates_and_is_authenticated(s):
        dek, _, _ = s.vault(sizes=())
        U.cfg["set"]["vmode"] = "file"
        legacy = {k: v for k, v in U.secset().items() if k != "vmode"}
        U.cfg["sc"] = IG.snap_make(dek, legacy)
        class Dummy:
            root = dek; ro = False; fixed = None; prev = None; nf = 0
            def logs(self): return []
        dummy = Dummy()
        U.App.signin(dummy, "password")
        s.assertEqual(U.cfg["set"]["vmode"], "file")
        status, good, _ = IG.snap_check(dek, U.cfg["sc"], U.secset())
        s.assertEqual(status, "ok"); s.assertEqual(good["vmode"], "file")
        U.cfg["set"]["vmode"] = "mem"
        U.App.signin(dummy, "password")
        s.assertEqual(U.cfg["set"]["vmode"], "file", "hand-edited playback settings must not change the authenticated setting")

    def test_disk_playback_is_the_default_and_memory_mode_is_available(s):
        s.assertEqual(U.DEF["vmode"], "file")
    def test_app_view_streams_media_to_disk_without_materializing_bytes(s):
        dek = os.urandom(32); salt = os.urandom(16); key = U.file_key(dek, salt)
        rid = "fedcba987652"; name = "clip.mp4"; data = b"\0\0\0\x18ftypisom" + b"x" * 64
        U.VAULT.mkdir(parents=True, exist_ok=True)
        source = s.d / name; source.write_bytes(data)
        encrypted = U.VAULT / f"{rid}.cdr"; U.enc_file(source, encrypted, key, lambda *_: None)
        U.idx[rid] = {"s": U.b64e(salt), "nm": U.b64e(U.seal(key, name.encode())),
                      "size": len(data), "exp": None, "views": None}
        class Card:
            def __init__(self, card_name):
                self.name = card_name; self.vl = mock.MagicMock()
        card = Card(name)
        opened = {}
        class DiskViewer:
            def __init__(self, name, payload, last, parent, media_path=None):
                opened.update(name=name, payload=payload, media_path=media_path)
                self.tmp = media_path
            def exec_(self): U.tmp_wipe(self.tmp)
        class Dummy:
            root = dek; ro = True; hold = 0; cards = {rid: card}; dlg = None
            def sec_ok(self, *_args): return True
            def record_session_event(self, *args, **kwargs): pass
            def tick(self): pass
            _vault_file_state_key = U.App._vault_file_state_key
            _simulate_vault_action = U.App._simulate_vault_action
            _begin_vault_file_operation = U.App._begin_vault_file_operation
            _finish_vault_file_operation = U.App._finish_vault_file_operation
        dummy = Dummy()
        card._file_state_revision = U.FILE_STATE_MANAGER.register(
            dummy._vault_file_state_key(rid)).revision
        with mock.patch.object(U, "S", side_effect=lambda k: {"vmode": "file", "ghost": False, "reauth": False, "mask": False}.get(k, U.DEF.get(k))), \
             mock.patch.object(U, "Viewer", DiskViewer), \
             mock.patch.object(U, "dec_file", side_effect=AssertionError("disk playback must not collect plaintext in RAM")):
            U.App.view(dummy, rid)
        s.assertIsNone(opened["payload"])
        s.assertEqual(opened["name"], name)
        s.assertTrue(opened["media_path"])
        s.assertFalse(opened["media_path"].exists())

    def test_app_file_action_uses_authoritative_state_and_rejects_stale_card(s):
        rid = "ui-state-" + os.urandom(8).hex()
        key = "ui-test:" + rid
        class Card:
            _file_state_revision = 0
        class Dummy:
            cards = {rid: Card()}
            def _vault_file_state_key(self, _rid): return key
            _simulate_vault_action = U.App._simulate_vault_action
        dummy = Dummy()
        state = U.FILE_STATE_MANAGER.register(key)
        dummy.cards[rid]._file_state_revision = state.revision

        before = (
            U.copy.deepcopy(U.cfg), U.copy.deepcopy(U.idx),
            U.OPERATION_MANAGER.snapshots(), U.OPERATION_MANAGER.reports,
            U.storage_txn_path().read_bytes() if U.storage_txn_path().exists() else None,
            tuple(sorted((path.name, U.file_digest(path))
                         for path in U.VAULT.glob("*.cdr"))),
        )
        preview = U.App._simulate_vault_action(dummy, (rid,), "test_file_action")
        s.assertTrue(preview.valid)
        after = (
            U.copy.deepcopy(U.cfg), U.copy.deepcopy(U.idx),
            U.OPERATION_MANAGER.snapshots(), U.OPERATION_MANAGER.reports,
            U.storage_txn_path().read_bytes() if U.storage_txn_path().exists() else None,
            tuple(sorted((path.name, U.file_digest(path))
                         for path in U.VAULT.glob("*.cdr"))),
        )
        s.assertEqual(after, before)

        operation, revision = U.App._begin_vault_file_operation(
            dummy, rid, "test_file_action", preview)
        s.assertEqual(
            U.FILE_STATE_MANAGER.snapshot(key).state, U.FileState.PROCESSING)
        plan = U.App._simulate_vault_action(dummy, (rid,), "test_file_action")
        s.assertFalse(plan.valid)
        U.App._finish_vault_file_operation(
            dummy, rid, operation, revision, verified=True)
        s.assertEqual(operation.snapshot.state, U.OperationState.COMPLETED)
        available = U.FILE_STATE_MANAGER.snapshot(key)
        s.assertEqual(available.state, U.FileState.AVAILABLE)
        dummy.cards[rid]._file_state_revision = available.revision
        with s.assertRaises(U.StaleSimulationPlan):
            U.App._begin_vault_file_operation(
                dummy, rid, "test_file_action", preview)

        U.FILE_STATE_MANAGER.lock_available(key, available.revision)
        with s.assertRaises(U.StaleFileState):
            U.App._begin_vault_file_operation(
                dummy, rid, "stale_file_action",
                U.App._simulate_vault_action(dummy, (rid,), "stale_file_action"))

    def test_invalid_settings_snapshot_blocks_signin_without_changes(s):
        dek, _, _ = s.vault(sizes=())
        U.cfg["set"].update(export=False, reauth=True, title="Custom title")
        U.cfg["sc"] = "tampered snapshot"
        before = (dict(U.cfg["set"]), U.cfg["sc"])
        class Dummy:
            root = dek; ro = False
        with mock.patch.object(U, "terminal_confirm", return_value=False) as confirm:
            s.assertFalse(U.App.signin(Dummy(), "password"))
        confirm.assert_called_once()
        s.assertEqual((U.cfg["set"], U.cfg["sc"]), before)

    def test_missing_settings_snapshot_requires_explicit_repair(s):
        dek, _, _ = s.vault(sizes=())
        U.cfg["set"]["export"] = False
        U.cfg["sc"] = None
        before = (dict(U.cfg["set"]), U.cfg["sc"])
        class Dummy:
            pass
        with mock.patch.object(U, "terminal_confirm", return_value=False) as confirm:
            s.assertFalse(U.App.prepare_settings_snapshot(Dummy(), dek))
        confirm.assert_called_once()
        s.assertEqual((U.cfg["set"], U.cfg["sc"]), before)

    def test_confirmed_invalid_snapshot_resets_protected_settings_only(s):
        dek, _, _ = s.vault(sizes=())
        U.cfg["set"].update(export=False, reauth=True, title="Keep this appearance")
        U.cfg["sc"] = "tampered snapshot"
        class Dummy:
            root = dek; ro = False; fixed = None; prev = None; nf = 0
            def logs(self): return []
        with mock.patch.object(U, "terminal_confirm", return_value=True) as confirm:
            s.assertTrue(U.App.signin(Dummy(), "password"))
        confirm.assert_called_once()
        for key in U.SECKEYS:
            s.assertEqual(U.cfg["set"][key], U.DEF[key], key)
        s.assertEqual(U.cfg["set"]["title"], "Keep this appearance")
        status, _, _ = IG.snap_check(dek, U.cfg["sc"], U.secset())
        s.assertEqual(status, "ok")

    def test_valid_legacy_snapshot_defaults_every_missing_protected_key(s):
        dek, _, _ = s.vault(sizes=())
        legacy = U.secset()
        legacy.pop("vmode")
        legacy.pop("export")
        U.cfg["sc"] = IG.snap_make(dek, legacy)
        U.cfg["set"]["vmode"] = "file"
        U.cfg["set"]["export"] = False
        class Dummy:
            root = dek; ro = False; fixed = None; prev = None; nf = 0
            def logs(self): return []
        U.App.signin(Dummy(), "password")
        s.assertEqual(U.cfg["set"]["vmode"], U.DEF["vmode"])
        s.assertEqual(U.cfg["set"]["export"], U.DEF["export"])
        status, good, _ = IG.snap_check(dek, U.cfg["sc"], U.secset())
        s.assertEqual(status, "ok")
        s.assertEqual(good["export"], U.DEF["export"])

    def test_viewer_close_removes_real_decrypted_media_file(s):
        from test_viewer_flow import make
        g, V = make(vmode="file")
        g.update(tmp_media=U.tmp_media, tmp_wipe=U.tmp_wipe, log_security_event=U.log_security_event)
        v = V("video.mp4", b"\0\0\0\x18ftypisom" + b"x" * 40, False, None)
        temp_file = v.tmp
        s.assertTrue(temp_file.is_file())
        v.closeEvent(mock.MagicMock())
        s.assertFalse(temp_file.exists(), "closing the viewer must remove the real decrypted temp file")
    def test_temp_media_wipe_retries_failed_delete_and_rejects_outside_paths(s):
        p = U.tmp_media("video.mp4", b"decrypted video")
        outside = s.d / "outside.mp4"; outside.write_bytes(b"do not delete")
        scheduled = []
        with mock.patch.object(U, "shred", return_value=None), mock.patch.object(U.QTimer, "singleShot", side_effect=lambda delay, cb: scheduled.append((delay, cb))):
            U.tmp_wipe(p)
            U.tmp_wipe(outside)
        s.assertTrue(p.exists(), "simulated Windows media lock keeps the temp file present")
        s.assertEqual(len(scheduled), 1, "a still-present temp file must be retried")
        scheduled[0][1]()
        s.assertFalse(p.exists(), "the scheduled retry must remove the released temp file")
        U.tmp_wipe(outside)
        s.assertTrue(outside.exists(), "cleanup must never wipe a file outside the app temp directory")
    def test_temp_media_collision_does_not_delete_existing_file(s):
        d = U.HOME / "tmp"; d.mkdir(parents=True, exist_ok=True)
        p = d / ("a" * 32 + ".mp4"); p.write_bytes(b"existing content")
        with mock.patch.object(U.secrets, "token_hex", return_value="a" * 32), s.assertRaises(FileExistsError):
            U.tmp_media("video.mp4", b"new content")
        s.assertEqual(p.read_bytes(), b"existing content")
    def test_config_transaction_publishes_only_after_crash_safe_save(s):
        U.cfg.clear()
        U.cfg.update(set={"th": "matrix"}, extension={"keep": True})
        previous = U.copy.deepcopy(U.cfg)
        candidate = U.copy.deepcopy(previous)
        candidate["set"]["th"] = "ice"
        observed = []

        def fail_save(_path, _candidate):
            observed.append(U.copy.deepcopy(U.cfg))
            raise OSError("simulated config write failure")

        with mock.patch.object(U, "jsave", side_effect=fail_save), s.assertRaises(OSError):
            U.commit_config_transaction(candidate)

        s.assertEqual(observed, [previous])
        s.assertEqual(U.cfg, previous)

    def test_config_transaction_preserves_extension_keys_and_commits_live_snapshot(s):
        U.cfg.clear()
        U.cfg.update(set={"th": "matrix"}, extension={"keep": True})
        candidate = U.copy.deepcopy(U.cfg)
        candidate["set"]["th"] = "ice"

        U.commit_config_transaction(candidate)

        s.assertEqual(U.cfg, candidate)
        s.assertEqual(U.jload(U.CFG, {}), candidate)

    def test_settings_password_creation_keeps_live_lock_unmodified_if_save_fails(s):
        U.cfg.clear()
        U.cfg.update(set={"th": "matrix"}, extension={"keep": True})
        previous = U.copy.deepcopy(U.cfg)

        class AppState:
            root = b"r" * 32
            owner = False
            tab = mock.Mock()

        with mock.patch.object(U.QInputDialog, "getText",
                               side_effect=[("long enough password", True),
                                            ("long enough password", True)]), \
             mock.patch.object(U, "slk_hash", return_value=b"h" * 32), \
             mock.patch.object(U, "jsave", side_effect=OSError("simulated disk failure")), \
             mock.patch.object(U.QMessageBox, "warning") as warning:
            U.App.lock_set(AppState())

        s.assertEqual(U.cfg, previous)
        s.assertFalse(AppState.owner)
        AppState.tab.assert_not_called()
        warning.assert_called_once()
        s.assertIn("No settings-lock change was applied.", warning.call_args.args[2])

    def test_settings_password_removal_keeps_live_lock_if_save_fails(s):
        U.cfg.clear()
        U.cfg.update(set={"th": "matrix"}, slk={"s": "salt", "h": "hash"}, slc="sealed")
        previous = U.copy.deepcopy(U.cfg)

        class AppState:
            owner = True
            tab = mock.Mock()

        with mock.patch.object(U.QMessageBox, "question",
                               return_value=U.QMessageBox.StandardButton.Yes), \
             mock.patch.object(U, "jsave", side_effect=OSError("simulated disk failure")), \
             mock.patch.object(U.QMessageBox, "warning") as warning:
            U.App.lock_drop(AppState())

        s.assertEqual(U.cfg, previous)
        s.assertTrue(AppState.owner)
        AppState.tab.assert_not_called()
        warning.assert_called_once()
        s.assertIn("The existing settings lock remains active.", warning.call_args.args[2])

    def test_master_password_change_does_not_accept_when_save_fails(s):
        U.cfg.clear()
        U.cfg.update(set={"th": "matrix"}, s1="salt", wp="old-wrapper")
        previous = U.copy.deepcopy(U.cfg)
        callbacks = []
        fields = [mock.Mock(), mock.Mock(), mock.Mock()]
        for field, value in zip(fields, ("current password", "New-Password-2048!", "New-Password-2048!")):
            field.text.return_value = value

        class Signal:
            def connect(self, callback): callbacks.append(callback)
        class Button:
            clicked = Signal()
        dialog = mock.Mock()

        class LineEdit:
            EchoMode = U.QLineEdit.EchoMode
            def __init__(self): self.field = fields.pop(0)
            def setEchoMode(self, _mode): pass
            def setPlaceholderText(self, _text): pass
            def text(self): return self.field.text()

        class Layout:
            def __init__(self, _dialog): pass
            def addWidget(self, _widget): pass

        class Dialog:
            def __new__(cls, _parent): return dialog

        with mock.patch.object(U, "QDialog", Dialog), \
             mock.patch.object(U, "QVBoxLayout", Layout), \
             mock.patch.object(U, "QLineEdit", LineEdit), \
             mock.patch.object(U, "lbl", return_value=mock.Mock()), \
             mock.patch.object(U, "btn", return_value=Button()), \
             mock.patch.object(U, "b64d", return_value=b"s" * 16), \
             mock.patch.object(U, "kdf", return_value=b"k" * 32), \
             mock.patch.object(U, "unseal", return_value=b"r" * 32), \
             mock.patch.object(U, "check_pw", return_value=(1, "")), \
             mock.patch.object(U, "seal", return_value=b"new-wrapper"), \
             mock.patch.object(U, "jsave", side_effect=OSError("simulated disk failure")):
            U.App.chpw(mock.Mock())
            s.assertEqual(len(callbacks), 1)
            callbacks[0]()

        s.assertEqual(U.cfg, previous)
        dialog.accept.assert_not_called()

    def test_recovery_words_remain_active_if_new_words_cannot_be_saved(s):
        U.cfg.clear()
        U.cfg.update(set={"th": "matrix"}, s2="old-salt", wr="old-wrapper")
        previous = U.copy.deepcopy(U.cfg)

        class AppState:
            root = b"r" * 32
            recovery_screen = mock.Mock()

        with mock.patch.object(U.QMessageBox, "question",
                               return_value=U.QMessageBox.StandardButton.Yes), \
             mock.patch.object(U.random, "SystemRandom") as system_random, \
             mock.patch.object(system_random.return_value, "sample",
                               return_value=["word"] * U.NW), \
             mock.patch.object(U, "kdf", return_value=b"k" * 32), \
             mock.patch.object(U, "seal", return_value=b"new-wrapper"), \
             mock.patch.object(U, "jsave", side_effect=OSError("simulated disk failure")), \
             mock.patch.object(U.QMessageBox, "warning") as warning:
            U.App.newrec(AppState())

        s.assertEqual(U.cfg, previous)
        AppState.recovery_screen.assert_not_called()
        warning.assert_called_once()
        s.assertIn("The existing recovery words remain active.", warning.call_args.args[2])

    def test_recovery_does_not_open_vault_if_new_password_save_fails(s):
        U.cfg.clear()
        U.cfg.update(set={"th": "matrix"}, s2="recovery-salt", wr="recovery-wrapper",
                     s1="old-salt", wp="old-wrapper")
        previous = U.copy.deepcopy(U.cfg)

        class AppState:
            p1 = mock.Mock()
            p2 = mock.Mock()
            rw = mock.Mock()
            btn = mock.Mock()
            msg = mock.Mock()
            root = None
            ro = True
            sec_ok = mock.Mock(return_value=True)
            show_storage_recovery_preview = mock.Mock()
            load_vault_index = mock.Mock(return_value=True)
            prepare_settings_snapshot = mock.Mock(return_value=True)
            signin = mock.Mock(return_value=True)
            enter_vault = mock.Mock()
            login_screen = mock.Mock()

        AppState.p1.text.return_value = "New-Password-2048!"
        AppState.p2.text.return_value = "New-Password-2048!"
        AppState.rw.text.return_value = "recovery words"
        with mock.patch.object(U, "check_pw", return_value=(1, "")), \
             mock.patch.object(U.QApplication, "processEvents"), \
             mock.patch.object(U, "b64d", return_value=b"s" * 16), \
             mock.patch.object(U, "kdf", return_value=b"k" * 32), \
             mock.patch.object(U, "unseal", return_value=b"r" * 32), \
             mock.patch.object(U, "resolve_data_move_before_signin", return_value=None), \
             mock.patch.object(U, "storage_recovery_preview", return_value={}), \
             mock.patch.object(U, "recover_storage_transaction", return_value=None), \
             mock.patch.object(U, "recover_orphan_seal_stage", return_value=None), \
             mock.patch.object(U, "commit_config_transaction",
                               side_effect=OSError("simulated disk failure")), \
             mock.patch.object(U.QMessageBox, "warning") as warning:
            app = AppState()
            U.App.do_recover(app)

        s.assertEqual(U.cfg, previous)
        s.assertIsNone(app.root)
        AppState.signin.assert_not_called()
        AppState.enter_vault.assert_not_called()
        warning.assert_called_once()
        s.assertIn("The existing password remains active", warning.call_args.args[2])

    def test_config_transaction_rejects_conflicting_ghost_dependencies_without_writes(s):
        U.cfg.clear()
        U.cfg.update(set={"ghost": False, "vmode": "file", "log": True})
        previous = U.copy.deepcopy(U.cfg)
        U.jsave(U.CFG, previous)
        candidate = U.copy.deepcopy(previous)
        candidate["set"]["ghost"] = True

        with s.assertRaisesRegex(ValueError, "dependency advisor"):
            U.commit_config_transaction(candidate)

        s.assertEqual(U.cfg, previous)
        s.assertEqual(U.jload(U.CFG, {}), previous)

    def test_config_loader_reports_backup_recovery_without_mutating_files(s):
        primary = U.CFG
        backup = primary.with_name(primary.name + ".bak")
        backup_value = {
            "s1": U.b64e(os.urandom(16)),
            "s2": U.b64e(os.urandom(16)),
            "wp": U.b64e(os.urandom(48)),
            "wr": U.b64e(os.urandom(48)),
            "f": 0,
            "lock": 0,
            "last": time.time(),
        }
        primary.write_text("{ damaged", encoding="utf-8")
        U.jsave(backup, backup_value)
        primary_before = primary.read_bytes()
        backup_before = backup.read_bytes()

        loaded, source = U.load_config_snapshot(primary, U.REQUIRED_CFG_KEYS)
        diagnostic = U.config_recovery_diagnostic(primary, U.REQUIRED_CFG_KEYS)

        s.assertEqual(source, "backup")
        s.assertEqual(loaded, backup_value)
        s.assertEqual(diagnostic["state"], "warning")
        s.assertIn("valid local backup is available", diagnostic["detail"])
        s.assertEqual(primary.read_bytes(), primary_before)
        s.assertEqual(backup.read_bytes(), backup_before)

    def test_config_loader_distinguishes_empty_and_unrecoverable_state(s):
        s.assertEqual(U.load_config_snapshot(U.CFG, U.REQUIRED_CFG_KEYS), ({}, "empty"))
        U.CFG.write_text("not json", encoding="utf-8")

        loaded, source = U.load_config_snapshot(U.CFG, U.REQUIRED_CFG_KEYS)

        s.assertEqual(loaded, {})
        s.assertEqual(source, "damaged")
        s.assertEqual(
            U.config_recovery_diagnostic(U.CFG, U.REQUIRED_CFG_KEYS)["state"], "fail")

    def test_temp_sweep_removes_files_left_by_previous_process(s):
        p = U.tmp_media("video.mp4", b"leftover decrypted data")
        U.tmp_sweep()
        s.assertFalse(p.exists())
    def test_jload_falls_back_to_backup(s):
        p = s.d / "index.json"; U.jsave(p, {"a": 1}); U.jsave(p, {"a": 2}); p.write_text(""); s.assertEqual(U.jload(p, {}), {"a": 1}); p.write_text('{"a": '); s.assertEqual(U.jload(p, {}), {"a": 1})
        s.assertFalse((s.d / "index.json.tmp").exists())
    def test_atomic_json_save_keeps_old_value_when_replace_fails(s):
        p = s.d / "atomic.json"; U.jsave(p, {"value": "old"})
        with mock.patch.object(U, "durable_replace", side_effect=OSError("simulated power loss")), s.assertRaises(OSError):
            U.jsave(p, {"value": "new"})
        s.assertEqual(U.jload(p, {}), {"value": "old"})
    def test_storage_seal_rolls_forward_after_ciphertext_promotion(s):
        dek, _, _ = s.vault(sizes=(64,))
        rid = "fedcba987654"; data = b"newly sealed payload"; source = s.d / "source.bin"; source.write_bytes(data)
        salt = os.urandom(16); key = U.file_key(dek, salt); staged = U.VAULT / f"{rid}.cdr.txn"
        U.enc_file(source, staged, key, lambda *_: None)
        candidate = dict(U.idx); candidate[rid] = {"s": U.b64e(salt), "nm": U.b64e(U.seal(key, b"new.bin")),
                                                    "size": len(data), "exp": None, "views": None}
        with mock.patch.object(U, "write_idx_blob", side_effect=RuntimeError("simulated power loss")), s.assertRaises(RuntimeError):
            U.commit_storage_transaction(dek, "seal", rid, candidate, staged)
        final = U.VAULT / f"{rid}.cdr"
        s.assertTrue(final.exists()); s.assertTrue(U.storage_txn_path().exists())
        recovered = U.recover_storage_transaction(dek)
        s.assertEqual(recovered, {"operation": "seal", "rid": rid})
        s.assertEqual(U.load_idx(dek), candidate); s.assertEqual(U.dec_file(final, key), data)
        s.assertFalse(U.storage_txn_path().exists())
    def test_storage_seal_recovers_staged_file_after_commit_record(s):
        dek, _, _ = s.vault(sizes=(64,))
        rid = "abcdef012345"; data = b"staged and authenticated"; source = s.d / "source.bin"; source.write_bytes(data)
        salt = os.urandom(16); key = U.file_key(dek, salt); staged = U.VAULT / f"{rid}.cdr.txn"
        U.enc_file(source, staged, key, lambda *_: None)
        candidate = dict(U.idx); candidate[rid] = {"s": U.b64e(salt), "nm": U.b64e(U.seal(key, b"staged.bin")),
                                                    "size": len(data), "exp": None, "views": None}
        with mock.patch.object(U, "_apply_storage_transaction", side_effect=RuntimeError("power cut after journal")), s.assertRaises(RuntimeError):
            U.commit_storage_transaction(dek, "seal", rid, candidate, staged)
        s.assertTrue(U.storage_txn_path().exists()); s.assertTrue(staged.exists())
        U.recover_storage_transaction(dek)
        s.assertEqual(U.load_idx(dek), candidate)
        s.assertEqual(U.dec_file(U.VAULT / f"{rid}.cdr", key), data)
    def test_storage_transaction_rejects_stale_vault_snapshot(s):
        dek, _, _ = s.vault(sizes=(64, 128))
        original = dict(U.idx)
        first_rid, second_rid = tuple(original)
        first_candidate = dict(original)
        first_candidate[first_rid] = {**original[first_rid], "views": 2}
        second_candidate = dict(original)
        second_candidate[second_rid] = {**original[second_rid], "views": 3}

        U.commit_storage_transaction(
            dek, "index", first_rid, first_candidate, expected_index=original)
        with s.assertRaises(InvalidTag):
            U.commit_storage_transaction(
                dek, "index", second_rid, second_candidate, expected_index=original)

        s.assertEqual(U.load_idx(dek), first_candidate)
        s.assertFalse(U.storage_txn_path().exists())

    def test_storage_transaction_verifies_commit_and_retains_journal_on_failure(s):
        dek, _, _ = s.vault(sizes=(64,))
        rid = next(iter(U.idx))
        original = dict(U.idx)
        candidate = dict(original)
        candidate[rid] = {**original[rid], "views": 4}

        with mock.patch.object(U, "write_idx_blob"), s.assertRaises(InvalidTag):
            U.commit_storage_transaction(
                dek, "index", rid, candidate, expected_index=original)
        s.assertTrue(U.storage_txn_path().exists())
        s.assertEqual(U.load_idx(dek), original)

        U.recover_storage_transaction(dek)
        s.assertEqual(U.load_idx(dek), candidate)
        s.assertFalse(U.storage_txn_path().exists())

    def test_storage_transaction_preflight_failure_has_no_persistent_effect(s):
        dek, _, _ = s.vault(sizes=(64,))
        rid = next(iter(U.idx))
        original = dict(U.idx)
        candidate = dict(original)
        candidate[rid] = {**original[rid], "views": 4}

        with mock.patch.object(
                U, "storage_preflight",
                return_value={"status": "insufficient", "required": 1 << 20, "free": 0}), \
                s.assertRaisesRegex(OSError, "preflight failed"):
            U.commit_storage_transaction(
                dek, "index", rid, candidate, expected_index=original)

        s.assertFalse(U.storage_txn_path().exists())
        s.assertEqual(U.load_idx(dek), original)

    def test_storage_recovery_preview_counts_consistency_without_mutating_files(s):
        dek, _, files = s.vault(sizes=(64, 128))
        missing_rid = next(iter(files))
        (U.VAULT / f"{missing_rid}.cdr").unlink()
        orphan = U.VAULT / "fedcba987654.cdr"
        staged = U.VAULT / "abcdef012345.cdr.txn"
        orphan.write_bytes(b"preserve unindexed encrypted file")
        staged.write_bytes(b"preserve staged encrypted file")
        before_orphan = orphan.read_bytes()
        before_staged = staged.read_bytes()

        preview = U.storage_recovery_preview(dek)

        s.assertEqual(preview["indexed_items"], 2)
        s.assertEqual(preview["missing_objects"], 1)
        s.assertEqual(preview["orphan_objects"], 1)
        s.assertEqual(preview["staged_objects"], 1)
        s.assertEqual(preview["unsafe_objects"], 0)
        s.assertIsNone(preview["pending_transaction"])
        s.assertFalse(preview["pending_seal_stage"])
        s.assertEqual(orphan.read_bytes(), before_orphan)
        s.assertEqual(staged.read_bytes(), before_staged)
        s.assertFalse((U.VAULT / f"{missing_rid}.cdr").exists())

    def test_storage_recovery_preview_authenticates_pending_transaction_read_only(s):
        dek, _, _ = s.vault(sizes=(64,))
        rid = next(iter(U.idx))
        original = dict(U.idx)
        candidate = dict(original)
        candidate[rid] = {**original[rid], "views": 2}
        with mock.patch.object(U, "_apply_storage_transaction",
                              side_effect=RuntimeError("power cut")), s.assertRaises(RuntimeError):
            U.commit_storage_transaction(
                dek, "index", rid, candidate, expected_index=original)
        journal_path = U.storage_txn_path()
        journal_before = journal_path.read_bytes()
        index_before = U.IDX.read_bytes()

        preview = U.storage_recovery_preview(dek)

        s.assertEqual(preview["pending_transaction"], "index")
        s.assertEqual(journal_path.read_bytes(), journal_before)
        s.assertEqual(U.IDX.read_bytes(), index_before)
        journal = json.loads(journal_before)
        journal["rid"] = "fedcba987654"
        journal_path.write_text(json.dumps(journal), encoding="utf-8")
        with s.assertRaises(InvalidTag):
            U.storage_recovery_preview(dek)
        s.assertEqual(U.IDX.read_bytes(), index_before)

    def test_storage_recovery_preview_ui_does_not_expose_file_identifiers(s):
        dummy = object()
        preview = {
            "indexed_items": 2,
            "missing_objects": 1,
            "orphan_objects": 1,
            "staged_objects": 1,
            "unsafe_objects": 0,
            "pending_transaction": "seal",
            "pending_seal_stage": True,
        }
        with mock.patch.object(U.QMessageBox, "information") as information:
            U.App.show_storage_recovery_preview(dummy, preview)

        message = information.call_args.args[2]
        s.assertIn("interrupted seal operation", message)
        s.assertIn("automatically", message)
        s.assertNotIn("fedcba987654", message)
        s.assertNotIn(".cdr", message)

    def test_seal_authentication_failure_does_not_commit_index(s):
        dek, _, _ = s.vault(sizes=(64,))
        rid = "aabbccddeeff"
        source = s.d / "source.bin"
        source.write_bytes(b"staged ciphertext must authenticate")
        salt = os.urandom(16)
        key = U.file_key(dek, salt)
        staged = U.VAULT / f"{rid}.cdr.txn"
        U.enc_file(source, staged, key, lambda *_: None)
        corrupted = bytearray(staged.read_bytes())
        corrupted[-1] ^= 1
        staged.write_bytes(corrupted)
        candidate = dict(U.idx)
        candidate[rid] = {
            "s": U.b64e(salt),
            "nm": U.b64e(U.seal(key, b"corrupted.bin")),
            "size": source.stat().st_size,
            "exp": None,
            "views": None,
        }
        original = dict(U.idx)

        with s.assertRaises(InvalidTag):
            U.commit_storage_transaction(
                dek, "seal", rid, candidate, staged, expected_index=original)

        s.assertEqual(U.load_idx(dek), original)
        s.assertTrue(U.storage_txn_path().exists())
        s.assertTrue((U.VAULT / f"{rid}.cdr").exists())

    def test_concurrent_storage_commits_serialize_and_reject_stale_second_snapshot(s):
        dek, _, _ = s.vault(sizes=(64, 128))
        original = dict(U.idx)
        first_rid, second_rid = tuple(original)
        candidates = []
        for rid, views in ((first_rid, 2), (second_rid, 3)):
            candidate = dict(original)
            candidate[rid] = {**original[rid], "views": views}
            candidates.append((rid, candidate))

        barrier = threading.Barrier(3)
        successes = []
        stale_rejections = []
        unexpected = []

        def commit(rid, candidate):
            barrier.wait()
            try:
                result = U.commit_storage_transaction(
                    dek, "index", rid, candidate, expected_index=original)
                successes.append(result["rid"])
            except InvalidTag:
                stale_rejections.append(rid)
            except Exception as exc:
                unexpected.append(type(exc).__name__)

        workers = [
            threading.Thread(target=commit, args=(rid, candidate))
            for rid, candidate in candidates
        ]
        for worker in workers:
            worker.start()
        barrier.wait()
        for worker in workers:
            worker.join(timeout=15)
            s.assertFalse(worker.is_alive())

        s.assertEqual(len(successes), 1)
        s.assertEqual(len(stale_rejections), 1)
        s.assertEqual(unexpected, [])
        s.assertFalse(U.storage_txn_path().exists())
    def test_storage_transaction_rejects_tampered_journal_without_mutating_vault(s):
        dek, _, files = s.vault(sizes=(64,))
        rid = "123456abcdef"; data = b"keep the staged bytes"; source = s.d / "source.bin"; source.write_bytes(data)
        salt = os.urandom(16); key = U.file_key(dek, salt); staged = U.VAULT / f"{rid}.cdr.txn"
        U.enc_file(source, staged, key, lambda *_: None)
        candidate = dict(U.idx); candidate[rid] = {"s": U.b64e(salt), "nm": U.b64e(U.seal(key, b"new.bin")),
                                                    "size": len(data), "exp": None, "views": None}
        with mock.patch.object(U, "_apply_storage_transaction", side_effect=RuntimeError("power cut")), s.assertRaises(RuntimeError):
            U.commit_storage_transaction(dek, "seal", rid, candidate, staged)
        before = U.IDX.read_bytes(); journal = json.loads(U.storage_txn_path().read_text())
        journal["rid"] = "../../outside"
        U.storage_txn_path().write_text(json.dumps(journal))
        with s.assertRaises(InvalidTag): U.recover_storage_transaction(dek)
        s.assertEqual(U.IDX.read_bytes(), before); s.assertTrue(staged.exists()); s.assertFalse((U.VAULT / f"{rid}.cdr").exists())
        s.assertTrue(files)
    def test_storage_transaction_refuses_to_overwrite_a_newer_index(s):
        dek, _, _ = s.vault(sizes=(64,))
        rid = "fedcba987650"; data = b"index conflict"; source = s.d / "source.bin"; source.write_bytes(data)
        salt = os.urandom(16); key = U.file_key(dek, salt); staged = U.VAULT / f"{rid}.cdr.txn"
        U.enc_file(source, staged, key, lambda *_: None)
        candidate = dict(U.idx); candidate[rid] = {"s": U.b64e(salt), "nm": U.b64e(U.seal(key, b"new.bin")),
                                                    "size": len(data), "exp": None, "views": None}
        with mock.patch.object(U, "_apply_storage_transaction", side_effect=RuntimeError("power cut")), s.assertRaises(RuntimeError):
            U.commit_storage_transaction(dek, "seal", rid, candidate, staged)
        changed = dict(U.idx); next(iter(changed.values()))["views"] = 3; U.save_idx(dek, changed)
        with s.assertRaises(InvalidTag): U.recover_storage_transaction(dek)
        s.assertFalse((U.VAULT / f"{rid}.cdr").exists())
        s.assertTrue(staged.exists()); s.assertEqual(U.load_idx(dek), changed)
    def test_wrong_password_key_cannot_replay_a_pending_storage_change(s):
        dek, _, _ = s.vault(sizes=(64,))
        rid = "fedcba987651"; data = b"root-key protected"; source = s.d / "source.bin"; source.write_bytes(data)
        salt = os.urandom(16); key = U.file_key(dek, salt); staged = U.VAULT / f"{rid}.cdr.txn"
        U.enc_file(source, staged, key, lambda *_: None)
        candidate = dict(U.idx); candidate[rid] = {"s": U.b64e(salt), "nm": U.b64e(U.seal(key, b"new.bin")),
                                                    "size": len(data), "exp": None, "views": None}
        with mock.patch.object(U, "_apply_storage_transaction", side_effect=RuntimeError("power cut")), s.assertRaises(RuntimeError):
            U.commit_storage_transaction(dek, "seal", rid, candidate, staged)
        with s.assertRaises(InvalidTag): U.recover_storage_transaction(os.urandom(32))
        s.assertFalse((U.VAULT / f"{rid}.cdr").exists()); s.assertTrue(staged.exists())
    def test_interrupted_view_count_update_commits_exactly_once(s):
        dek, _, files = s.vault(sizes=(64,))
        rid = next(iter(files)); updated = dict(U.idx[rid]); updated["views"] = 2; candidate = dict(U.idx); candidate[rid] = updated
        with mock.patch.object(U, "_apply_storage_transaction", side_effect=RuntimeError("power cut")), s.assertRaises(RuntimeError):
            U.commit_storage_transaction(dek, "index", rid, candidate)
        U.recover_storage_transaction(dek); U.recover_storage_transaction(dek)
        s.assertEqual(U.load_idx(dek)[rid]["views"], 2)
    def test_consumed_last_view_is_burned_after_restart(s):
        dek, _, files = s.vault(sizes=(64,))
        rid = next(iter(files))
        U.idx[rid]["views"] = 1
        U.save_idx(dek, U.idx)
        name = files[rid][1]
        class Card:
            def __init__(self):
                self.name = name
                self.vl = mock.MagicMock()
        card = Card()
        opened = {}
        class Viewer:
            def __init__(self, _name, _data, last, _parent, media_path=None):
                opened["last"] = last
                self.tmp = media_path
            def exec_(self): pass
        class Dummy:
            root = dek; ro = False; hold = 0; cards = {rid: card}; dlg = None
            def sec_ok(self, *_args): return True
            def record_session_event(self, *_args, **_kwargs): pass
            def tick(self): pass
            def card_details(self, metadata, card_name): return U.App.card_details(self, metadata, card_name)
            _vault_file_state_key = U.App._vault_file_state_key
            _simulate_vault_action = U.App._simulate_vault_action
            _begin_vault_file_operation = U.App._begin_vault_file_operation
            _finish_vault_file_operation = U.App._finish_vault_file_operation

        dummy = Dummy()
        card._file_state_revision = U.FILE_STATE_MANAGER.register(
            dummy._vault_file_state_key(rid)).revision
        with mock.patch.object(U, "Viewer", Viewer):
            U.App.view(dummy, rid)
        s.assertTrue(opened["last"])
        s.assertEqual(U.load_idx(dek)[rid]["views"], 0)
        self_path = U.VAULT / f"{rid}.cdr"
        s.assertTrue(self_path.exists())

        U.idx.clear()
        U.idx.update(U.load_idx(dek))
        s.assertEqual(U.burn_exhausted_view_items(dek), [rid])
        s.assertNotIn(rid, U.idx)
        s.assertNotIn(rid, U.load_idx(dek))
        s.assertFalse(self_path.exists())
        s.assertEqual(U.burn_exhausted_view_items(dek), [])
    def test_storage_burn_resumes_after_interruption_and_updates_index(s):
        dek, _, files = s.vault(sizes=(64,))
        rid = next(iter(files)); candidate = dict(U.idx); candidate.pop(rid)
        with mock.patch.object(U, "shred", side_effect=RuntimeError("power loss")), s.assertRaises(RuntimeError):
            U.commit_storage_transaction(dek, "burn", rid, candidate, passes=1)
        s.assertTrue(U.storage_txn_path().exists()); s.assertTrue((U.VAULT / f"{rid}.cdr").exists())
        U.recover_storage_transaction(dek)
        s.assertNotIn(rid, U.load_idx(dek)); s.assertFalse((U.VAULT / f"{rid}.cdr").exists())
        s.assertFalse(U.storage_txn_path().exists())
    def test_storage_burn_replays_after_ciphertext_removed_before_index(s):
        dek, _, files = s.vault(sizes=(64,))
        rid = next(iter(files)); candidate = dict(U.idx); candidate.pop(rid)
        with mock.patch.object(U, "write_idx_blob", side_effect=RuntimeError("power loss")), s.assertRaises(RuntimeError):
            U.commit_storage_transaction(dek, "burn", rid, candidate, passes=1)
        s.assertFalse((U.VAULT / f"{rid}.cdr").exists()); s.assertTrue(U.storage_txn_path().exists())
        U.recover_storage_transaction(dek)
        s.assertNotIn(rid, U.load_idx(dek)); s.assertFalse(U.storage_txn_path().exists())
    def test_bad_ids_filtered_and_orphans_not_shredded_by_source(s):
        dek, _, _ = s.vault(sizes=(1,))
        orphan = U.VAULT / "999999999999.cdr"
        orphan.write_bytes(b"preserve for recovery")
        app = mock.MagicMock()
        with mock.patch.object(U, "log_security_event"):
            s.assertTrue(U.App.load_vault_index(app, dek))
        s.assertFalse(orphan.exists())
        s.assertEqual(orphan.with_suffix(".orphan").read_bytes(), b"preserve for recovery")
        with s.assertRaises(ValueError):
            U.validate_rid("../../x")

        damaged_app = mock.MagicMock()
        config_path = mock.Mock()
        config_path.exists.return_value = True
        vault_path = mock.Mock()
        vault_path.glob.return_value = iter(())
        with mock.patch.object(U, "read_destruct_journal", return_value=None), \
             mock.patch.object(U, "has_vault_config", return_value=False), \
             mock.patch.object(U, "CFG", config_path), \
             mock.patch.object(U, "VAULT", vault_path):
            U.App.route_startup_config(damaged_app)
        damaged_app.damaged_screen.assert_called_once_with()
        damaged_app.setup_screen.assert_not_called()
    def test_index_storage_mismatch_blocks_load_without_rewriting_evidence(s):
        dek, _, files = s.vault(sizes=(64,))
        rid = next(iter(files))
        item_path = U.VAULT / f"{rid}.cdr"
        orphan = U.VAULT / "fedcba987654.cdr"
        orphan_bytes = b"preserve unindexed encrypted object"
        orphan.write_bytes(orphan_bytes)
        index_bytes = U.IDX.read_bytes()
        live_index = U.copy.deepcopy(U.idx)
        app = mock.MagicMock()

        item_path.unlink()
        with mock.patch.object(U, "save_idx") as save_index, \
             mock.patch.object(U, "log_security_event") as log_event:
            s.assertFalse(U.App.load_vault_index(app, dek))
        save_index.assert_not_called()
        s.assertEqual(U.IDX.read_bytes(), index_bytes)
        s.assertEqual(U.idx, live_index)
        s.assertTrue(orphan.exists())
        s.assertEqual(orphan.read_bytes(), orphan_bytes)
        log_event.assert_any_call(
            "vault_index_storage_mismatch", affected_items=1)

        item_path.mkdir()
        with mock.patch.object(U, "save_idx") as save_index, \
             mock.patch.object(U, "log_security_event") as log_event:
            s.assertFalse(U.App.load_vault_index(app, dek))
        save_index.assert_not_called()
        s.assertEqual(U.IDX.read_bytes(), index_bytes)
        s.assertEqual(U.idx, live_index)
        s.assertTrue(item_path.is_dir())
        s.assertTrue(orphan.exists())
    def test_lock_stays_on_if_hash_removed(s):
        U.cfg.update(slc="x"); s.assertTrue(U.lock_on())
    def test_invalid_index_record_and_self_destruct_state_are_rejected(s):
        root = b"rootkey"; bad = {"../../x": {"s": "", "nm": "", "size": 1, "exp": None, "views": None}}
        U.IDX.write_text(json.dumps(bad), encoding="utf-8")
        with s.assertRaises(InvalidTag):
            U.load_idx(root)
        with s.assertRaises(InvalidTag): U.verify_self_destruct_state(root, {"state": "pending", "deadline": "bad", "sig": ""})
        good = U._signed_self_destruct_state(root, "pending", 123.0)
        s.assertEqual(U.verify_self_destruct_state(root, good)["state"], "pending")
        tampered = dict(good)
        tampered["deadline"] = 999.0
        with s.assertRaises(InvalidTag):
            U.verify_self_destruct_state(root, tampered)
    def test_self_destruct_countdown_is_runtime_authenticated_and_not_restartable(s):
        root = U.SELF_DESTRUCT_RUNTIME_KEY; deadline = time.time() + 600.0
        U.cfg.update(set={"lv": 2}, f=0, lock=0)
        U.cfg["sd"] = U._signed_self_destruct_state(root, "pending", deadline)
        s.assertAlmostEqual(U.pending_self_destruct_deadline(), deadline, places=3)
        U.cfg["sd"] = U._signed_self_destruct_state(root, "cleared", deadline)
        s.assertEqual(U.pending_self_destruct_deadline(), 0.0)
        U.cfg["sd"] = U._signed_self_destruct_state(b"", "pending", deadline)
        s.assertEqual(U.pending_self_destruct_deadline(), 0.0)
        class Dummy:
            def login_screen(self, shake=False):
                pass
        dummy = Dummy()
        U.cfg.update(set={"lv": 2}, f=2, lock=0)
        U.App.fail(dummy)
        s.assertEqual(U.cfg["sd"]["state"], "pending")
        s.assertGreater(U.cfg["lock"], time.time())
        s.assertFalse(U.CFG.exists(), "a process-only destructive order must not persist to config.json")
        state = dict(U.cfg["sd"]); U.SELF_DESTRUCT_RUNTIME_KEY = os.urandom(32)
        s.assertEqual(U.pending_self_destruct_deadline(), 0.0, "a new process must reject the old process signature")
        U.SELF_DESTRUCT_RUNTIME_KEY = root
        U.cfg["sd"] = state
    def test_remembered_password_button_enables_entry_without_cancelling_countdown(s):
        deadline = time.time() + 600.0; root = U.SELF_DESTRUCT_RUNTIME_KEY
        U.cfg.update(set={"lv": 2}, lock=deadline)
        U.cfg["sd"] = U._signed_self_destruct_state(root, "pending", deadline)
        persisted_state = dict(U.cfg["sd"])
        class Dummy:
            pending_password_ack = False
            pw = mock.MagicMock()
            ub = mock.MagicMock()
            kp = mock.MagicMock()
            lk = mock.MagicMock()
            def panic(self, ask=False):
                self.panicked = True
        dummy = Dummy()
        U.App.acknowledge_pending_password(dummy)
        s.assertTrue(dummy.pending_password_ack)
        dummy.pw.setEnabled.assert_called_once_with(True)
        dummy.ub.setEnabled.assert_called_once_with(True)
        dummy.lk.setText.assert_called_once()
        s.assertEqual(U.cfg["lock"], deadline)
        s.assertEqual(U.cfg["sd"], persisted_state)
        s.assertAlmostEqual(U.pending_self_destruct_deadline(), deadline, places=3)
    def test_successful_signin_does_not_clear_pending_countdown(s):
        deadline = time.time() + 600.0; U.cfg.update(set={"lv": 2, "log": False, "intro": 1}, lock=deadline, f=3, fails=[time.time()])
        original_state = U._signed_self_destruct_state(U.SELF_DESTRUCT_RUNTIME_KEY, "pending", deadline)
        U.cfg["sd"] = original_state
        class Dummy:
            root = b"decrypted vault key"
            ro = False
            def logs(self): return []
        with mock.patch.object(U.IG, "snap_check", return_value=("ok", {}, [])):
            U.App.signin(Dummy(), "password")
        s.assertEqual(U.cfg["sd"], original_state)
        s.assertAlmostEqual(U.pending_self_destruct_deadline(), deadline, places=3)
        s.assertEqual(U.cfg["lock"], 0)
    def test_pending_login_screen_shows_and_wires_remembered_password_button(s):
        s.app = qt_test_application()
        app = U.App.__new__(U.App)
        U.QWidget.__init__(app)
        s.addCleanup(app.deleteLater)
        app.root = None
        app.integ_ok = mock.Mock(return_value=True)
        app.show_w = mock.Mock()
        app.tick = mock.Mock()
        app.clock_label = mock.Mock(return_value=mock.Mock())
        app.login_greeting = mock.Mock(return_value=mock.Mock())
        app.panel = mock.Mock(return_value=mock.Mock())
        app.profile_chooser = mock.Mock()
        buttons = {}

        def make_button(text, *_args):
            button = mock.MagicMock()
            buttons[text] = button
            return button

        deadline = time.time() + 600
        old_profile_id = U.active_profile_id
        U.active_profile_id = "active-profile"
        try:
            with mock.patch.object(U, "pending_self_destruct_deadline", return_value=deadline), \
                 mock.patch.object(U, "storage_txn_path", return_value=s.d / "missing-transaction.json"), \
                 mock.patch.object(U, "S", return_value=False), \
                 mock.patch.object(U, "cdt", return_value="10:00"), \
                 mock.patch.object(U, "btn", side_effect=make_button), \
                 mock.patch.object(U, "lbl", return_value=mock.MagicMock()), \
                 mock.patch.object(U, "tlbl", return_value=mock.MagicMock()), \
                 mock.patch.object(U, "QLineEdit", return_value=mock.MagicMock()), \
                 mock.patch.object(U, "QCheckBox", return_value=mock.MagicMock()), \
                 mock.patch.object(U, "QFrame", return_value=mock.MagicMock()), \
                 mock.patch.object(U, "QVBoxLayout", return_value=mock.MagicMock()), \
                 mock.patch.object(U, "QHBoxLayout", return_value=mock.MagicMock()):
                U.App.login_screen(app)
                remember = buttons["I REMEMBER THE PASSWORD"]
                remember.clicked.connect.assert_called_once_with(app.acknowledge_pending_password)
                app.pw.setEnabled.assert_called_with(False)
                handler = remember.clicked.connect.call_args[0][0]
                handler()
                back_handler = buttons["< Back to profiles"].clicked.connect.call_args[0][0]
                back_handler()
        finally:
            U.active_profile_id = old_profile_id
        s.assertTrue(app.pending_password_ack)
        app.pw.setEnabled.assert_called_with(True)
        app.ub.setEnabled.assert_called_with(True)
        app.profile_chooser.assert_called_once_with()
    def test_failed_attempt_during_pending_state_does_not_extend_deadline(s):
        deadline = time.time() + 600.0; U.cfg.update(set={"lv": 2}, f=3, lock=deadline, tf=0, fails=[])
        U.cfg["sd"] = U._signed_self_destruct_state(U.SELF_DESTRUCT_RUNTIME_KEY, "pending", deadline)
        class Dummy:
            def login_screen(self, shake=False): pass
        U.App.fail(Dummy())
        s.assertAlmostEqual(U.pending_self_destruct_deadline(), deadline, places=3)
        s.assertEqual(U.cfg["lock"], deadline)
    def test_expired_pending_state_wipes_instead_of_restarting_on_failed_attempt(s):
        deadline = time.time() - 1; U.cfg.update(set={"lv": 2}, f=3, lock=deadline, tf=0, fails=[])
        original_state = U._signed_self_destruct_state(U.SELF_DESTRUCT_RUNTIME_KEY, "pending", deadline)
        U.cfg["sd"] = original_state
        class Dummy:
            panic = mock.MagicMock()
            login_screen = mock.MagicMock()
        dummy = Dummy()
        U.App.fail(dummy)
        dummy.panic.assert_called_once_with(False)
        dummy.login_screen.assert_not_called()
        s.assertEqual(U.cfg["sd"], original_state)
    def test_forged_persisted_expired_state_never_wipes_before_authentication(s):
        deadline = time.time() - 1; U.cfg.update(set={"lv": 2}, lock=deadline)
        U.cfg["sd"] = U._signed_self_destruct_state(b"", "pending", deadline)
        class Dummy:
            pw = mock.MagicMock()
            panic = mock.MagicMock()
            def sec_ok(self): return False
        dummy = Dummy()
        U.App.try_login(dummy)
        dummy.panic.assert_not_called()
    def test_pending_countdown_continues_after_unlock_and_wipes_at_deadline(s):
        deadline = time.time() + 600.0; U.cfg.update(set={"lv": 2}, lock=0)
        U.cfg["sd"] = U._signed_self_destruct_state(U.SELF_DESTRUCT_RUNTIME_KEY, "pending", deadline)
        class Dummy:
            busy = working = ro = False
            root = b"decrypted vault key"
            mode = "vault"; tc = 0; cds = {}
            sd_timer = mock.MagicMock()
            panic = mock.MagicMock()
            def working(self): return False
            def integ_ok(self): return True
        dummy = Dummy()
        U.App.tick(dummy)
        dummy.sd_timer.setText.assert_called_once()
        dummy.panic.assert_not_called()
        with mock.patch.object(U.time, "time", return_value=deadline + 1):
            U.App.tick(dummy)
        dummy.panic.assert_called_once_with(False)

class TestRotation(Base):
    def test_rotate_success(s):
        old, phrase, files = s.vault(); oldcfg = json.loads(U.CFG.read_text()); seen = []
        new, nphrase = U.rotate_vault(old, PW, lambda f, t: seen.append(f))
        s.assertNotEqual(new, old); s.assertAlmostEqual(seen[-1], 1.0, places=1); s.check_all(new, files)
        s.assertEqual(U.unseal(U.kdf(PW, U.b64d(U.cfg["s1"])), U.b64d(U.cfg["wp"])), new); s.assertEqual(U.unseal(U.kdf(nphrase, U.b64d(U.cfg["s2"])), U.b64d(U.cfg["wr"])), new)
        with s.assertRaises(InvalidTag): U.unseal(U.kdf(phrase, U.b64d(U.cfg["s2"])), U.b64d(U.cfg["wr"]))            # old words dead on the live config
        for rid in files:                                                                                         # the OLD key (from an old backup) no longer opens ANY file
            with s.assertRaises(InvalidTag): U.dec_file(U.VAULT / f"{rid}.cdr", U.file_key(old, U.b64d(U.idx[rid]["s"])))
        s.assertEqual(json.loads(U.unseal(U.file_key(new, b"unknwn-log"), U.LOG.read_bytes()))[0]["ok"], True)
        st, good, ch = IG.snap_check(new, U.cfg["sc"], U.secset()); s.assertEqual(st, "ok")
        s.assertFalse((U.HOME / "rotate.json").exists()); s.assertEqual(list(U.VAULT.glob("*.new")), []); s.assertEqual(len(list(U.VAULT.glob("*.cdr"))), len(files)); s.assertEqual(oldcfg["wp"] != U.cfg["wp"], True)
    def test_rotation_preserves_encrypted_session_logs(s):
        old, _, _ = s.vault(sizes=())
        history = json.loads(U.unseal(U.file_key(old, b"unknwn-log"), U.LOG.read_bytes()))
        history.append({"type": "session", "sid": "a" * 32, "t": time.time(),
                        "events": [{"t": time.time(), "kind": "vault_unlocked", "method": "password"}]})
        U.LOG.write_bytes(U.seal(U.file_key(old, b"unknwn-log"), json.dumps(history).encode()))
        new, _ = U.rotate_vault(old, PW)
        restored = json.loads(U.unseal(U.file_key(new, b"unknwn-log"), U.LOG.read_bytes()))
        session = next(entry for entry in restored if entry.get("type") == "session")
        s.assertEqual(session["sid"], "a" * 32)
        s.assertEqual(session["events"][0]["kind"], "vault_unlocked")
    def test_crash_before_commit_changes_nothing(s):
        old, phrase, files = s.vault(); before = (U.CFG.read_text(), U.IDX.read_text(), {p.name: p.read_bytes() for p in U.VAULT.glob("*.cdr")}); n = [0]; real = U.recrypt
        def boom(*a, **k):
            n[0] += 1
            if n[0] == 3: raise OSError("disk full")
            return real(*a, **k)
        with mock.patch.object(U, "recrypt", boom), s.assertRaises(OSError): U.rotate_vault(old, PW)
        s.assertEqual((U.CFG.read_text(), U.IDX.read_text(), {p.name: p.read_bytes() for p in U.VAULT.glob("*.cdr")}), before); s.assertEqual(list(U.VAULT.glob("*.new")), [])
        s.reload(); s.check_all(old, files)
    def test_crash_right_after_journal_is_rolled_forward(s):
        old, phrase, files = s.vault()
        with mock.patch.object(U, "rotate_commit", side_effect=RuntimeError("power cut")), s.assertRaises(RuntimeError): U.rotate_vault(old, PW)
        s.assertTrue((U.HOME / "rotate.json").exists()); j = json.loads((U.HOME / "rotate.json").read_text()); s.reload()   # = next app start
        new = U.unseal(U.kdf(PW, U.b64d(U.cfg["s1"])), U.b64d(U.cfg["wp"])); s.assertNotEqual(new, old); s.check_all(new, files); s.assertFalse((U.HOME / "rotate.json").exists())
    def test_crash_in_the_middle_of_commit_is_rolled_forward(s):
        old, phrase, files = s.vault(); calls = [0]; real = os.replace
        def flaky(a, b):
            calls[0] += 1
            if calls[0] == 3: raise OSError("power cut")
            return real(a, b)
        with mock.patch.object(U, "rotate_commit", side_effect=RuntimeError("x")), s.assertRaises(RuntimeError): U.rotate_vault(old, PW)
        with mock.patch("os.replace", flaky), s.assertRaises(OSError): U.rotate_commit()          # dies after replacing 2 of 5 files: a MIXED state on disk
        s.assertTrue((U.HOME / "rotate.json").exists()); s.reload()                                  # next start finishes the job
        new = U.unseal(U.kdf(PW, U.b64d(U.cfg["s1"])), U.b64d(U.cfg["wp"])); s.check_all(new, files)
    def test_corrupt_source_file_aborts_rotation(s):
        old, phrase, files = s.vault(); rid = list(files)[3]; p = U.VAULT / f"{rid}.cdr"; raw = p.read_bytes(); p.write_bytes(raw[:80] + bytes([raw[80] ^ 1]) + raw[81:]); cfg0 = U.CFG.read_text()
        with s.assertRaises(InvalidTag): U.rotate_vault(old, PW)
        s.assertEqual(U.CFG.read_text(), cfg0); s.assertEqual(list(U.VAULT.glob("*.new")), [])
    def test_stray_new_files_cleaned_at_start(s):
        old, phrase, files = s.vault(); (U.VAULT / "abcdefabcdef.cdr.new").write_bytes(b"junk"); U.rotate_commit(); s.assertEqual(list(U.VAULT.glob("*.new")), [])

class TestVaultProfiles(Base):
    def setUp(s):
        super().setUp()
        s.old_profile_registry = U.PROFILE_REGISTRY
        s.user_home = s.d / "user"
        s.user_home.mkdir()
        s.home_patch = mock.patch.object(Path, "home", return_value=s.user_home)
        s.home_patch.start()
        U.PROFILE_REGISTRY = s.user_home / ".unknwn-profiles.json"
        s.managed = s.user_home / ".unknwn-profiles"
        s.managed.mkdir()
    def tearDown(s):
        try: U.destruct_journal_path().unlink(missing_ok=True)
        except OSError: pass
        U.PROFILE_REGISTRY = s.old_profile_registry
        s.home_patch.stop()
        super().tearDown()
    def test_profile_registry_rejects_boolean_version(s):
        U.PROFILE_REGISTRY.write_text(
            json.dumps({"version": True, "profiles": []}),
            encoding="utf-8",
        )
        with s.assertRaisesRegex(ValueError, "unsupported format"):
            U._read_profiles()
    def test_profile_rename_updates_only_the_selected_profile_metadata(s):
        first = U._register_profile("Personal", s.managed / "first")
        second = U._register_profile("Work", s.managed / "second")
        renamed = U._rename_profile(first["id"], "Personal Vault")
        s.assertEqual(renamed["path"], first["path"])
        profiles = U._read_profiles()
        s.assertEqual(profiles, [renamed, second])
        with s.assertRaisesRegex(FileExistsError, "already uses that name"):
            U._rename_profile(first["id"], "work")
        with s.assertRaisesRegex(ValueError, "printable characters"):
            U._rename_profile(first["id"], "Bad\nName")
        s.assertEqual(U._read_profiles(), [renamed, second])
    def test_setting_a_preferred_profile_reorders_only_the_registry_entries(s):
        first = U._register_profile("Personal", s.managed / "first")
        second = U._register_profile("Work", s.managed / "second")
        preferred = U._set_default_profile(second["id"])
        s.assertEqual(preferred, second)
        s.assertEqual(U._read_profiles(), [second, first])
        s.assertEqual(U._set_default_profile(second["id"]), second)
        with s.assertRaisesRegex(ValueError, "no longer registered"):
            U._set_default_profile("0" * 32)
    def test_active_profile_rename_dialog_updates_the_current_profile(s):
        profile = U._register_profile("Before", s.managed / "active")
        app = mock.MagicMock()
        app.ro = False; app.root = b"unlocked-vault-key"; app.sec_ok.return_value = True
        app.sp = mock.Mock(); app.changes = mock.Mock()
        with mock.patch.object(U, "active_profile_id", profile["id"]), \
             mock.patch.object(U, "active_profile_name", "Before"), \
             mock.patch.object(U.QInputDialog, "getText", return_value=("After", True)):
            U.App.rename_profile_dialog(app)
            s.assertEqual(U.active_profile_name, "After")
        app.sp.setWidget.assert_called_once()
        app.changes.setWidget.assert_called_once()
        s.assertEqual(U._read_profiles()[0]["name"], "After")
    def test_empty_data_location_does_not_create_a_default_profile(s):
        old_home = U.HOME
        old_active = (U.active_profile_id, U.active_profile_name)
        old_cfg = dict(U.cfg)
        empty_home = s.d / "empty-home"
        try:
            U.set_home(empty_home); U.cfg.clear()
            s.assertEqual(U._ensure_initial_profile(), [])
            s.assertFalse(U.PROFILE_REGISTRY.exists())
            s.assertIsNone(U.active_profile_id)
            s.assertIsNone(U.active_profile_name)
        finally:
            U.set_home(old_home); U.cfg.clear(); U.cfg.update(old_cfg)
            U.active_profile_id, U.active_profile_name = old_active
    def test_panic_wipe_removes_named_profile_data_and_registry(s):
        old_port = U.PORT
        portable = s.d / "portable"
        portable.mkdir()
        U.PORT = portable
        U.set_home(portable)
        profile_default = s.user_home / ".unknwn"
        profile_default.mkdir()
        imported_id = __import__("uuid").uuid4().hex
        imported = s.managed / imported_id
        imported.mkdir()
        for folder in (portable, profile_default, imported):
            (folder / "vault").mkdir(exist_ok=True)
            (folder / "vault" / "sealed.cdr").write_bytes(b"sealed")
        U._register_profile("Portable vault", portable, __import__("uuid").uuid4().hex)
        U._register_profile("Default vault", profile_default, __import__("uuid").uuid4().hex)
        U._register_profile("Imported vault", imported, imported_id)
        U.persist_active_location(profile_default)
        try:
            U.wipe_all_vault_data(U.HOME, 1)
            s.assertFalse(U.PROFILE_REGISTRY.exists())
            s.assertFalse(U._active_location_state_path().exists())
            s.assertFalse(s.managed.exists())
            s.assertTrue(profile_default.exists())
            s.assertTrue(portable.exists())
            s.assertFalse((portable / "vault" / "sealed.cdr").exists())
            s.assertFalse((profile_default / "vault" / "sealed.cdr").exists())
            s.assertNotIn("Imported vault", [item["name"] for item in U._read_profiles()])
        finally:
            U.PORT = old_port
    def test_panic_wipe_refuses_unregistered_active_path(s):
        old_port = U.PORT
        outside = s.d / "outside"
        outside.mkdir()
        marker = outside / "keep.txt"
        marker.write_text("unrelated user data", encoding="utf-8")
        U.PORT = s.d / "portable"
        U.PORT.mkdir()
        try:
            with s.assertRaisesRegex(OSError, "unrecognized active vault location"):
                U.wipe_all_vault_data(outside, 1)
            s.assertTrue(marker.exists())
            s.assertFalse(U.PROFILE_REGISTRY.exists())
        finally:
            U.PORT = old_port
    def test_self_destruct_does_not_restart_after_profile_wipe_failure(s):
        app = mock.MagicMock()
        app._destruct_wipe_error = OSError("locked")
        app.destructive_recovery_screen.side_effect = lambda error: setattr(app, "failure", error)
        package, public_key = make_signed_package(
            s.d / "UNKNWN_fixture", {"UNKNWN.exe": b"signed fixture"})
        with mock.patch.object(U.IG, "RELEASE_PUBKEY", public_key):
            U.begin_destructive_cleanup("self-destruct", package)
        with mock.patch.object(U.subprocess, "Popen") as popen, \
             mock.patch.object(U.os, "_exit") as exit_process:
            U.App.finish_destruct(app, False)
        app.login_screen.assert_not_called()
        app.destructive_recovery_screen.assert_called_once()
        popen.assert_not_called()
        exit_process.assert_not_called()
    def test_self_destruct_dry_run_returns_to_login_without_reading_journal(s):
        app = mock.MagicMock()
        with mock.patch.object(U.QMessageBox, "information"), \
             mock.patch.object(U, "read_destruct_journal") as read_journal:
            U.App.finish_destruct(app, True)
        read_journal.assert_not_called()
        app.login_screen.assert_called_once()
        app.finalize_destructive_cleanup.assert_not_called()
    def test_incomplete_panic_wipe_retains_profile_registry(s):
        old_port = U.PORT
        U.PORT = s.d / "portable"
        U.PORT.mkdir()
        profile_id = __import__("uuid").uuid4().hex
        profile_dir = s.managed / profile_id
        profile_dir.mkdir()
        U._register_profile("Recoverable vault", profile_dir, profile_id)
        try:
            with mock.patch.object(U, "wipe", side_effect=OSError("locked")), \
                 s.assertRaisesRegex(OSError, "wipe incomplete"):
                U.wipe_all_vault_data(U.HOME, 1)
            s.assertTrue(U.PROFILE_REGISTRY.exists())
            s.assertEqual(U._read_profiles()[0]["name"], "Recoverable vault")
        finally:
            U.PORT = old_port
    def test_corrupt_import_recovery_record_does_not_break_profile_chooser(s):
        app = mock.MagicMock()
        with mock.patch.object(U, "_ensure_initial_profile", return_value=[]), \
             mock.patch.object(U, "_pending_profile_imports", side_effect=ValueError("invalid record")), \
             mock.patch.object(U, "btn", return_value=mock.MagicMock()), \
             mock.patch.object(U, "lbl", return_value=mock.MagicMock()), \
             mock.patch.object(U, "tlbl", return_value=mock.MagicMock()):
            U.App.profile_chooser(app)
        app.show_w.assert_called_once()
        s.assertEqual(app.show_w.call_args.args[1], "profiles")
    def test_empty_profile_chooser_offers_only_new_and_import_actions(s):
        app = mock.MagicMock()
        with mock.patch.object(U, "_ensure_initial_profile", return_value=[]), \
             mock.patch.object(U, "_pending_profile_imports", return_value=[]), \
             mock.patch.object(U, "btn", return_value=mock.MagicMock()) as make_button, \
             mock.patch.object(U, "lbl", return_value=mock.MagicMock()), \
             mock.patch.object(U, "tlbl", return_value=mock.MagicMock()):
            U.App.profile_chooser(app)
        labels = [call.args[0] for call in make_button.call_args_list]
        s.assertEqual(labels, ["Import vault", "New vault"])
        s.assertNotIn("Open  /  Default", labels)
        app.show_w.assert_called_once()
    def test_import_profile_button_discards_qt_checked_argument(s):
        app = mock.MagicMock()
        buttons = []
        def make_button(*_args, **_kwargs):
            button = mock.MagicMock()
            buttons.append(button)
            return button
        with mock.patch.object(U, "_ensure_initial_profile", return_value=[]), \
             mock.patch.object(U, "_pending_profile_imports", return_value=[]), \
             mock.patch.object(U, "btn", side_effect=make_button), \
             mock.patch.object(U, "lbl", return_value=mock.MagicMock()), \
             mock.patch.object(U, "tlbl", return_value=mock.MagicMock()):
            U.App.profile_chooser(app)
        import_button = buttons[0]
        callback = import_button.clicked.connect.call_args.args[0]
        callback(False)
        app.import_profile_dialog.assert_called_once_with()
    def test_profile_action_buttons_discard_checked_argument_for_import_and_export(s):
        callbacks = [mock.Mock(), mock.Mock()]
        for callback in callbacks:
            button = mock.MagicMock()
            with mock.patch.object(U, "btn", return_value=button):
                result = U.profile_action_button("Profile action", callback)
            s.assertIs(result, button)
            signal_callback = button.clicked.connect.call_args.args[0]
            signal_callback(False)
            callback.assert_called_once_with()
    def export_and_import(s, custom_password=None, resume=False):
        dek, _, files = s.vault(sizes=(4096,))
        package = s.d / "vault.unknwn"
        original_cfg = U.CFG.read_bytes()
        result = U.export_vault_package(dek, package, package_password=custom_password)
        s.assertEqual(result["status"], "completed")
        profile_id = __import__("uuid").uuid4().hex
        destination = s.managed / profile_id
        if resume:
            interrupted = s.managed / f".import-{profile_id}.stage"
            interrupted.mkdir()
            (interrupted / ".import-owned.json").write_text(
                json.dumps({"profile_id": profile_id}), encoding="utf-8")
            (interrupted / "partial").write_bytes(b"partial")
        imported = U.import_vault_package(custom_password or PW, package, destination,
                                          profile_name="Imported archive", profile_id=profile_id,
                                          resume=resume)
        s.assertEqual(imported["status"], "completed")
        s.assertEqual(imported["password_mode"], "new-master" if custom_password else "existing-master")
        s.assertEqual(U.CFG.read_bytes(), original_cfg, "export must not change the source vault config")
        s.assertTrue(package.exists(), "import must preserve the package")
        imported_cfg = json.loads((destination / "config.json").read_text(encoding="utf-8"))
        imported_root = U.unseal(U._derive_profile_password(custom_password or PW,
                                                            U.b64d(imported_cfg["s1"])),
                                 U.b64d(imported_cfg["wp"]))
        s.assertEqual(imported_root, dek)
        with s.assertRaises(InvalidTag):
            U.unseal(U._derive_profile_password("Wrong-Password-!2026",
                                                U.b64d(imported_cfg["s1"])),
                     U.b64d(imported_cfg["wp"]))
        imported_index = U.decode_idx_blob(imported_root,
                                            json.loads((destination / "index.json").read_text(encoding="utf-8")))
        s.assertEqual(set(imported_index), set(files))
        for rid, (data, _) in files.items():
            meta = imported_index[rid]
            authenticated = b"".join(part for part, _last, _read, _total in
                                     U.iter_dec(destination / "vault" / f"{rid}.cdr",
                                                U.file_key(imported_root, U.b64d(meta["s"]))))
            s.assertEqual(len(authenticated), len(data))
        return dek, package, destination, profile_id
    def test_existing_master_password_import_creates_separate_profile(s):
        _, package, destination, profile_id = s.export_and_import()
        profile = U._register_profile("Imported archive", destination, profile_id)
        s.assertEqual(U._read_profiles(), [profile])
        s.assertTrue(package.exists())
        s.assertEqual(destination.parent, s.managed)
    def test_custom_export_password_becomes_imported_profile_master(s):
        password = "New-Vault-Password!2026"
        _, package, destination, profile_id = s.export_and_import(password)
        profile = U._register_profile("Imported archive", destination, profile_id)
        s.assertEqual(profile["name"], "Imported archive")
        s.assertTrue(package.exists())
    def test_resume_restarts_from_package_and_cleans_only_owned_stage(s):
        _, _, destination, _ = s.export_and_import(resume=True)
        s.assertTrue(destination.is_dir())
        s.assertFalse((s.managed / f".import-{destination.name}.stage").exists())
    def test_wrong_import_password_preserves_source_and_package(s):
        dek, _, files = s.vault(sizes=(64,))
        package = s.d / "wrong-password.unknwn"
        U.export_vault_package(dek, package)
        destination = s.managed / __import__("uuid").uuid4().hex
        with s.assertRaises(InvalidTag):
            U.import_vault_package("wrong-password", package, destination,
                                   profile_name="Rejected", profile_id=destination.name)
        s.assertFalse(destination.exists())
        s.assertFalse(list(s.managed.glob(".import-*.stage")))
        s.assertTrue(package.exists())
        s.assertEqual(set(U.idx), set(files))
    def test_import_rejects_package_symlink(s):
        dek, _, _ = s.vault(sizes=(64,))
        package = s.d / "vault.unknwn"
        U.export_vault_package(dek, package)
        link = s.d / "linked.unknwn"
        try:
            link.symlink_to(package)
        except (OSError, NotImplementedError):
            s.skipTest("symlink creation is not available")
        destination = s.managed / __import__("uuid").uuid4().hex
        with s.assertRaisesRegex(ValueError, "safe regular file"):
            U.import_vault_package(PW, link, destination, profile_name="Linked", profile_id=destination.name)
        s.assertFalse(destination.exists())
        s.assertFalse(list(s.managed.glob(".import-*.stage")))
    def test_import_rejects_profile_identity_mismatch(s):
        dek, _, _ = s.vault(sizes=(64,))
        package = s.d / "vault.unknwn"
        U.export_vault_package(dek, package)
        destination = s.managed / __import__("uuid").uuid4().hex
        with s.assertRaisesRegex(ValueError, "identity or name"):
            U.import_vault_package(PW, package, destination, profile_name="Mismatch",
                                   profile_id=__import__("uuid").uuid4().hex)
        s.assertFalse(destination.exists())


class FakeRegistryKey:
    def __init__(self, registry, path):
        self.registry = registry
        self.path = path
    def __enter__(self):
        return self
    def __exit__(self, *_args):
        return False
    def Close(self):
        return None

class FakeWinreg:
    HKEY_CURRENT_USER = object()
    KEY_QUERY_VALUE = 1
    KEY_SET_VALUE = 2
    REG_SZ = 1
    def __init__(self):
        self.values = {}
        self.keys = set()
    def CreateKeyEx(self, _hive, path, _reserved, _access):
        self.keys.add(path)
        return FakeRegistryKey(self, path)
    def OpenKey(self, _hive, path, _reserved=0, _access=0):
        if path not in self.keys:
            raise FileNotFoundError(path)
        return FakeRegistryKey(self, path)
    def QueryValueEx(self, key, name):
        try:
            return self.values[(key.path, name)]
        except KeyError as exc:
            raise FileNotFoundError(name) from exc
    def SetValueEx(self, key, name, _reserved, value_type, value):
        self.values[(key.path, name)] = (value, value_type)
    def DeleteValue(self, key, name):
        try:
            del self.values[(key.path, name)]
        except KeyError as exc:
            raise FileNotFoundError(name) from exc

class TestDestructiveCleanup(Base):
    def setUp(s):
        super().setUp()
        s.old_home, s.old_port, s.old_registry = U.HOME, U.PORT, U.PROFILE_REGISTRY
        s.user_home = s.d / "user"; s.user_home.mkdir()
        s.home_patch = mock.patch.object(Path, "home", return_value=s.user_home)
        s.home_patch.start()
        U.PROFILE_REGISTRY = s.user_home / ".unknwn-profiles.json"
        U.PORT = s.d / "portable"
        U.set_home(s.d / "active")
    def tearDown(s):
        try: U.destruct_journal_path().unlink(missing_ok=True)
        except OSError: pass
        U.PROFILE_REGISTRY = s.old_registry; U.PORT = s.old_port
        U.set_home(s.old_home); s.home_patch.stop()
        super().tearDown()
    def test_completion_note_uses_downloads_and_preserves_existing_files(s):
        script = s.cleanup_script()
        removed = script.index("if (-not $removed)")
        marker = script.index("$notePath = Join-Path $downloads 'meow.txt'")
        s.assertLess(removed, marker)
        s.assertIn("[System.Text.UTF8Encoding]::new($false).GetBytes('meow')", script)
        s.assertIn("[IO.FileMode]::CreateNew", script)
        s.assertIn("[Convert]::ToBase64String([IO.File]::ReadAllBytes($notePath)) -cne 'bWVvdw=='", script)

    def test_completion_note_preserves_conflicting_existing_file(s):
        script = s.cleanup_script()
        conflict = script.index("exists with different content and was preserved")
        create = script.index("[IO.FileMode]::CreateNew", conflict)
        s.assertLess(conflict, create)
        s.assertIn("if (Test-Path -LiteralPath $notePath)", script)
        s.assertIn("The self-destruct verification marker could not be verified.", script)

    def cleanup_script(s):
        package, public_key = make_signed_package(
            s.d / "UNKNWN_cleanup_note_test", {"UNKNWN.exe": b"signed fixture"})
        system_root = s.d / "windows"
        powershell = system_root / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
        powershell.parent.mkdir(parents=True)
        powershell.touch()
        with mock.patch.object(U.sys, "platform", "win32"), \
             mock.patch.object(U.IG, "RELEASE_PUBKEY", public_key), \
             mock.patch.dict(os.environ, {"SystemRoot": str(system_root)}):
            command = U.windows_cleanup_command(
                package, None, os.getpid(), restart=True)
        return U._decode_cleanup_command(command[-1])
    def test_cleanup_journal_survives_interruption_and_resumes(s):
        U.begin_destructive_cleanup("panic-wipe")
        with mock.patch.object(U, "wipe_all_vault_data", side_effect=[PermissionError("private path"), None]) as wipe:
            with s.assertRaises(PermissionError):
                U.resume_destructive_cleanup(U.HOME, 1)
            pending = U.read_destruct_journal()
            s.assertEqual(pending["phase"], "pending")
            s.assertEqual(pending["failures"], ["PermissionError"])
            completed = U.resume_destructive_cleanup(U.HOME, 1)
        s.assertEqual(wipe.call_count, 2)
        s.assertEqual(completed["phase"], "data-cleared")
        U.clear_destruct_journal()
        s.assertIsNone(U.read_destruct_journal())
    def test_cleanup_journal_rejects_mistyped_schema_values(s):
        path = U.destruct_journal_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        base = {"version": 1, "operation": "panic-wipe", "phase": "pending",
                "install_target": None, "failures": []}
        invalid_records = (
            {**base, "version": True},
            {**base, "operation": []},
            {**base, "phase": {}},
            {**base, "updated": "now"},
        )
        for record in invalid_records:
            with s.subTest(record=record):
                path.write_text(json.dumps(record), encoding="utf-8")
                with s.assertRaises(ValueError):
                    U.read_destruct_journal()
        path.unlink(missing_ok=True)
    def test_full_self_destruct_journal_requires_a_verified_install_target(s):
        with s.assertRaisesRegex(ValueError, "validated signed installation"):
            U.begin_destructive_cleanup("self-destruct")
        s.assertIsNone(U.read_destruct_journal())
    def test_completed_cleanup_is_idempotent(s):
        U.begin_destructive_cleanup("panic-wipe")
        with mock.patch.object(U, "wipe_all_vault_data") as wipe:
            record = U.resume_destructive_cleanup(U.HOME, 1)
            second = U.resume_destructive_cleanup(U.HOME, 1)
        wipe.assert_called_once_with(U.HOME, 1)
        s.assertEqual({k: v for k, v in record.items() if k != "updated"},
                      {k: v for k, v in second.items() if k != "updated"})
        s.assertEqual(second["phase"], "data-cleared")
    def test_profile_vault_temp_logs_and_application_state_are_removed(s):
        U.PORT.mkdir()
        default = s.user_home / ".unknwn"
        U.set_home(default)
        profile_id = __import__("uuid").uuid4().hex
        managed = s.user_home / ".unknwn-profiles" / profile_id
        roots = tuple(dict.fromkeys((U.HOME, U.PORT, default, managed)))
        for root in roots:
            (root / "vault").mkdir(parents=True)
            (root / "vault" / "sealed.cdr").write_bytes(b"ciphertext")
            (root / "tmp").mkdir()
            (root / "tmp" / "decrypted.bin").write_bytes(b"plaintext")
            (root / "security-2026-10-13.log").write_text("event")
            (root / "error.log").write_text("crash")
        U._register_profile("Portable", U.PORT)
        U._register_profile("Default", default)
        U._register_profile("Managed", managed, profile_id)
        U.persist_active_location(default)
        unrelated = s.user_home / "keep.txt"; unrelated.write_text("not UNKNWN data")
        outside = s.d / "outside.txt"; outside.write_text("unrelated data")
        U.begin_destructive_cleanup("panic-wipe")
        U.resume_destructive_cleanup(U.HOME, 1)
        for root in roots:
            s.assertFalse(any(path.is_file() for path in root.rglob("*")), str(root))
        s.assertFalse(U.PROFILE_REGISTRY.exists())
        s.assertFalse(U._active_location_state_path().exists())
        s.assertFalse((s.user_home / ".unknwn-profiles").exists())
        s.assertTrue(unrelated.exists())
        s.assertTrue(outside.exists())
    def test_self_destruct_removes_owned_roots_but_preserves_source_and_unrelated_data(s):
        default = s.user_home / ".unknwn"
        U.set_home(default)
        U.PORT.mkdir()
        managed_root = s.user_home / ".unknwn-profiles"
        profiles = [managed_root / __import__("uuid").uuid4().hex for _ in range(2)]
        roots = [default, U.PORT, *profiles]
        for root in roots:
            (root / "vault").mkdir(parents=True)
            (root / "vault" / "sealed.cdr").write_bytes(b"ciphertext")
            (root / "tmp").mkdir()
            (root / "tmp" / "decrypted.bin").write_bytes(b"plaintext")
            (root / "index.json").write_text("metadata")
            (root / "error.log").write_text("application log")
        U._register_profile("Default", default)
        U._register_profile("Portable", U.PORT)
        for index, profile in enumerate(profiles):
            U._register_profile(f"Imported {index}", profile, profile.name)
        U.persist_active_location(default)
        unrelated = s.user_home / "keep.txt"
        unrelated.write_text("unrelated user data")
        source_project = s.d / "UNKNWN-source-project"
        source_project.mkdir()
        (source_project / "unknwn.py").write_text("development source")
        (source_project / "release-key.pem").write_text("development signing material")
        (U.PROFILE_REGISTRY.with_name(U.PROFILE_REGISTRY.name + ".crash.tmp")).write_text("partial state")
        (s.user_home / ".unknwn-location.crash.tmp").write_text("partial state")
        package, public_key = make_signed_package(
            s.d / "UNKNWN_fixture", {"UNKNWN.exe": b"signed fixture"})
        with mock.patch.object(U.IG, "RELEASE_PUBKEY", public_key):
            U.begin_destructive_cleanup("self-destruct", package)
        (U.destruct_journal_path().with_name(U.DESTRUCT_JOURNAL + ".crash.tmp")).write_text("partial journal")
        with mock.patch.object(U.IG, "RELEASE_PUBKEY", public_key), \
             mock.patch.object(U, "wipe_all_vault_data", wraps=U.wipe_all_vault_data) as wipe:
            first = U.resume_destructive_cleanup(default, 1)
            second = U.resume_destructive_cleanup(default, 1)
        s.assertEqual(first["phase"], "data-cleared")
        s.assertEqual(second["phase"], first["phase"])
        s.assertEqual(second["operation"], first["operation"])
        wipe.assert_called_once_with(default, 1, remove_roots=True)
        for root in roots:
            s.assertFalse(root.exists(), str(root))
        s.assertFalse(managed_root.exists())
        s.assertFalse(U.PROFILE_REGISTRY.exists())
        s.assertFalse(U._active_location_state_path().exists())
        s.assertEqual(list(s.user_home.glob(".unknwn-profiles.json.*.tmp")), [])
        s.assertEqual(list(s.user_home.glob(".unknwn-location.*.tmp")), [])
        s.assertEqual(list(s.user_home.glob(U.DESTRUCT_JOURNAL + ".*.tmp")), [])
        s.assertTrue(unrelated.exists())
        s.assertTrue((package / "UNKNWN.exe").exists())
        s.assertEqual((source_project / "unknwn.py").read_text(), "development source")
        s.assertTrue((source_project / "release-key.pem").exists())
    def test_failed_root_removal_keeps_journal_pending_and_never_claims_completion(s):
        default = s.user_home / ".unknwn"
        U.set_home(default)
        default.mkdir()
        marker = default / "vault.cdr"
        marker.write_bytes(b"vault")
        package, public_key = make_signed_package(
            s.d / "UNKNWN_fixture", {"UNKNWN.exe": b"signed fixture"})
        with mock.patch.object(U.IG, "RELEASE_PUBKEY", public_key):
            U.begin_destructive_cleanup("self-destruct", package)
        with mock.patch.object(U.IG, "RELEASE_PUBKEY", public_key), \
             mock.patch.object(U, "wipe", side_effect=PermissionError("locked")), \
             s.assertRaisesRegex(OSError, "wipe incomplete"):
            U.resume_destructive_cleanup(default, 1)
        s.assertTrue(marker.exists())
        with mock.patch.object(U.IG, "RELEASE_PUBKEY", public_key):
            s.assertEqual(U.read_destruct_journal()["phase"], "pending")
    def test_cleanup_rejects_linked_journal_without_touching_target(s):
        outside = s.d / "outside"; outside.mkdir(); marker = outside / "keep.txt"
        marker.write_text("preserve")
        journal = U.destruct_journal_path()
        try:
            journal.symlink_to(marker)
        except (OSError, NotImplementedError):
            s.skipTest("symlink creation is not available")
        with s.assertRaises(ValueError):
            U.read_destruct_journal()
        s.assertEqual(marker.read_text(), "preserve")
    def test_invalid_cleanup_target_is_rejected(s):
        unrelated = s.d / "UNKNWN_source"
        unrelated.mkdir()
        (unrelated / "unknwn.py").write_text("source")
        (unrelated / "unknwn_integrity.py").write_text("integrity")
        with s.assertRaises(ValueError):
            U.begin_destructive_cleanup("self-destruct", unrelated)
        s.assertTrue((unrelated / "unknwn.py").exists())
        s.assertIsNone(U.read_destruct_journal())
    def test_windows_cleanup_rejects_data_roots_outside_supported_locations(s):
        package, public_key = s.signed_install()
        outside = s.d / "unrelated-data"
        outside.mkdir()
        with mock.patch.object(U.IG, "RELEASE_PUBKEY", public_key), \
             mock.patch.object(U.sys, "platform", "win32"), \
             s.assertRaisesRegex(ValueError, "unexpected data directory"):
            U.windows_cleanup_command(package, outside, 1, restart=False)
        s.assertTrue(outside.exists())
        s.assertEqual(list(outside.iterdir()), [])

    def signed_install(s):
        package = s.d / "UNKNWN_recovery_fixture"
        return make_signed_package(
            package, {"UNKNWN.exe": b"fixture executable", "runtime/core.dll": b"fixture runtime"})

    def test_runonce_helper_is_scoped_signed_retryable_and_removable(s):
        package, public_key = s.signed_install()
        (package / "UNKNWN_data").mkdir()
        (package / "UNKNWN_data" / "vault.db").write_bytes(b"owned data")
        system_root = s.d / "windows"
        powershell = system_root / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
        powershell.parent.mkdir(parents=True); powershell.touch()
        registry = FakeWinreg()
        registry.keys.add(U.DESTRUCT_RUNONCE_KEY)
        registry.values[(U.DESTRUCT_RUNONCE_KEY, "UnrelatedStartup")] = ("keep", registry.REG_SZ)
        real_root = Path(os.environ.get("SystemRoot", r"C:\Windows"))
        real_powershell = real_root / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
        env = {"SystemRoot": str(system_root), "USERPROFILE": str(s.user_home)}
        with mock.patch.object(U.IG, "RELEASE_PUBKEY", public_key), \
             mock.patch.object(U.sys, "platform", "win32"), mock.patch.dict(os.environ, env), \
             mock.patch.dict(sys.modules, {"winreg": registry}):
            U.begin_destructive_cleanup("self-destruct", package)
            helper = U.register_destruct_runonce(package, None, U.destruct_journal_path())
            s.assertEqual(list(s.user_home.glob("unknwn_cleanup_*.ps1")), [])
            expected = U._destruct_runonce_command(helper)
            retry_expected = U._destruct_runonce_command(helper, U.DESTRUCT_RUNONCE_RETRY_VALUE)
            script = helper.read_text(encoding="utf-8")
            command = U.destruct_runonce_command(4321)
            s.assertEqual(registry.values[(U.DESTRUCT_RUNONCE_KEY, U.DESTRUCT_RUNONCE_VALUE)],
                          (expected, registry.REG_SZ))
            s.assertIn("param([int]$WaitPid = 0, [string]$RunOnceName = '')", script)
            s.assertIn("configuredRetryRunOnceName", script)
            s.assertIn("if ($pidToWait -eq 0", script)
            s.assertIn("SetValue($retryRunOnceName, $retryRunOnceCommand", script)
            s.assertIn("GetValue($retryRunOnceName", script)
            s.assertIn("DeleteValue($retryRunOnceName", script)
            s.assertIn("GetValueKind($runOnceName)", script)
            s.assertIn("$registeredRetryKind -ne", script)
            s.assertIn("Test-SignedPackageRemainder", script)
            s.assertIn("Remove-InstallTree $target", script)
            s.assertNotIn("Remove-Item -LiteralPath $target -Recurse", script)
            s.assertNotIn("rd /s /q", script)
            s.assertIn("runtime/core.dll", script)
            s.assertIn("UNKNWN_data", script)
            s.assertIn("Stop-Recovery 15", script)
            s.assertIn("@('/r', '/t', '10')", script)
            s.assertIn("$notePath = Join-Path $downloads 'meow.txt'", script)
            s.assertIn("bWVvdw==", script)
            s.assertNotIn("cleanup-debug.log", script)
            s.assertNotIn("Log-Debug", script)
            s.assertNotIn("persistentLogDir", script)
            s.assertIn("@('pending', 'data-cleared')", script)
            s.assertIn("[IO.FileAttributes]::ReparsePoint", script)
            helper.write_bytes(helper.read_bytes() + b"\n# unexpected content")
            with s.assertRaisesRegex(ValueError, "content does not match"):
                U.destruct_runonce_command(4321)
            helper.write_bytes(script.encode("utf-8"))
            s.assertIn("-WaitPid", command)
            s.assertIn(U.DESTRUCT_RUNONCE_VALUE, command)
            marker_create = script.index("$notePath = Join-Path $downloads 'meow.txt'")
            marker_verify = script.index("The self-destruct verification marker")
            helper_remove = script.index("[IO.File]::Delete($recoveryScript)")
            restart = script.index("Start-Process -FilePath")
            s.assertLess(script.index("if ($requestedDataRemain -or $knownDataRemain)"), marker_create)
            s.assertLess(script.index("Remove-InstallTree $target"), marker_create)
            s.assertLess(marker_create, marker_verify)
            s.assertLess(marker_verify, helper_remove)
            s.assertLess(helper_remove, restart)
            s.assertLess(restart, script.index("Remove-Item -LiteralPath $journal"))
            s.assertIn("catch { Stop-Recovery 29 }", script)
            s.assertLess(script.index("DeleteValue($runOnceName"),
                          restart)
            s.assertEqual(registry.values[(U.DESTRUCT_RUNONCE_KEY, "UnrelatedStartup")],
                          ("keep", registry.REG_SZ))
            registry.DeleteValue(
                FakeRegistryKey(registry, U.DESTRUCT_RUNONCE_KEY),
                U.DESTRUCT_RUNONCE_VALUE,
            )
            registry.SetValueEx(
                FakeRegistryKey(registry, U.DESTRUCT_RUNONCE_KEY),
                U.DESTRUCT_RUNONCE_RETRY_VALUE, 0, registry.REG_SZ, retry_expected,
            )
            retry_command = U.destruct_runonce_command(4321)
            s.assertIn(U.DESTRUCT_RUNONCE_RETRY_VALUE, retry_command)
            registry.SetValueEx(
                FakeRegistryKey(registry, U.DESTRUCT_RUNONCE_KEY),
                U.DESTRUCT_RUNONCE_VALUE, 0, registry.REG_SZ, expected,
            )
            if real_powershell.is_file():
                parser_env = os.environ.copy()
                parser_env["SystemRoot"] = str(real_root)
                try:
                    probe = subprocess.run(
                        [str(real_powershell), "-NoProfile", "-NonInteractive", "-Command", "$PSVersionTable.PSVersion.Major"],
                        capture_output=True, env=parser_env, timeout=30)
                except subprocess.TimeoutExpired:
                    s.skipTest("Windows PowerShell did not initialize within the 30-second parser-test limit.")
                if probe.returncode != 0:
                    s.skipTest("Windows PowerShell could not initialize its managed runtime.")
                parse = (
                    "$tokens=$null; $errors=$null; "
                    f"[System.Management.Automation.Language.Parser]::ParseFile('{helper}',[ref]$tokens,[ref]$errors) > $null; "
                    "if ($errors.Count) { $errors | ForEach-Object { Write-Error $_.Message }; exit 1 }"
                )
                result = subprocess.run(
                    [str(real_powershell), "-NoProfile", "-NonInteractive", "-Command", parse],
                    capture_output=True, text=True, env=parser_env, timeout=60)
                s.assertEqual(result.returncode, 0, result.stderr)
            U.clear_destruct_runonce()
            s.assertFalse(helper.exists())
            s.assertNotIn((U.DESTRUCT_RUNONCE_KEY, U.DESTRUCT_RUNONCE_VALUE), registry.values)
            s.assertNotIn((U.DESTRUCT_RUNONCE_KEY, U.DESTRUCT_RUNONCE_RETRY_VALUE), registry.values)
            s.assertEqual(registry.values[(U.DESTRUCT_RUNONCE_KEY, "UnrelatedStartup")],
                          ("keep", registry.REG_SZ))

    def test_runonce_cleanup_preserves_unregistered_helper_collision(s):
        helper = s.user_home / U.DESTRUCT_RECOVERY_SCRIPT
        helper.write_text("unrelated helper", encoding="utf-8")
        with mock.patch.object(U, "_read_destruct_runonce", return_value=None), \
             s.assertRaisesRegex(ValueError, "no matching RunOnce entry"):
            U.clear_destruct_runonce()
        s.assertEqual(helper.read_text(encoding="utf-8"), "unrelated helper")

    def test_runonce_permission_failure_does_not_leave_a_helper_file(s):
        package, public_key = s.signed_install()
        system_root = s.d / "windows"
        powershell = system_root / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
        powershell.parent.mkdir(parents=True); powershell.touch()
        registry = FakeWinreg()
        registry.SetValueEx = mock.Mock(side_effect=PermissionError("registry denied"))
        with mock.patch.object(U.IG, "RELEASE_PUBKEY", public_key), \
             mock.patch.object(U.sys, "platform", "win32"), \
             mock.patch.dict(os.environ, {"SystemRoot": str(system_root), "USERPROFILE": str(s.user_home)}), \
             mock.patch.dict(sys.modules, {"winreg": registry}):
            U.begin_destructive_cleanup("self-destruct", package)
            with s.assertRaises(PermissionError):
                U.register_destruct_runonce(package, None, U.destruct_journal_path())
        s.assertFalse((s.user_home / U.DESTRUCT_RECOVERY_SCRIPT).exists())
        s.assertEqual(json.loads(U.destruct_journal_path().read_text())["phase"], "pending")

    def test_runonce_registration_refuses_to_replace_an_unrelated_value(s):
        package, public_key = s.signed_install()
        system_root = s.d / "windows"
        powershell = system_root / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
        powershell.parent.mkdir(parents=True); powershell.touch()
        registry = FakeWinreg()
        registry.keys.add(U.DESTRUCT_RUNONCE_KEY)
        registry.values[(U.DESTRUCT_RUNONCE_KEY, U.DESTRUCT_RUNONCE_VALUE)] = (
            "unrelated command", registry.REG_SZ)
        with mock.patch.object(U.IG, "RELEASE_PUBKEY", public_key), \
             mock.patch.object(U.sys, "platform", "win32"), \
             mock.patch.dict(os.environ, {"SystemRoot": str(system_root), "USERPROFILE": str(s.user_home)}), \
             mock.patch.dict(sys.modules, {"winreg": registry}):
            U.begin_destructive_cleanup("self-destruct", package)
            with s.assertRaisesRegex(FileExistsError, "already owned"):
                U.register_destruct_runonce(package, None, U.destruct_journal_path())
        s.assertEqual(registry.values[(U.DESTRUCT_RUNONCE_KEY, U.DESTRUCT_RUNONCE_VALUE)],
                      ("unrelated command", registry.REG_SZ))
        s.assertFalse((s.user_home / U.DESTRUCT_RECOVERY_SCRIPT).exists())
        s.assertEqual(json.loads(U.destruct_journal_path().read_text())["phase"], "pending")

    def test_runonce_registration_refuses_to_replace_an_unrelated_retry_value(s):
        package, public_key = s.signed_install()
        system_root = s.d / "windows"
        powershell = system_root / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
        powershell.parent.mkdir(parents=True); powershell.touch()
        registry = FakeWinreg()
        registry.keys.add(U.DESTRUCT_RUNONCE_KEY)
        retry_key = (U.DESTRUCT_RUNONCE_KEY, U.DESTRUCT_RUNONCE_RETRY_VALUE)
        registry.values[retry_key] = ("unrelated retry command", registry.REG_SZ)
        with mock.patch.object(U.IG, "RELEASE_PUBKEY", public_key), \
             mock.patch.object(U.sys, "platform", "win32"), \
             mock.patch.dict(os.environ, {"SystemRoot": str(system_root), "USERPROFILE": str(s.user_home)}), \
             mock.patch.dict(sys.modules, {"winreg": registry}):
            U.begin_destructive_cleanup("self-destruct", package)
            with s.assertRaisesRegex(FileExistsError, "already owned"):
                U.register_destruct_runonce(package, None, U.destruct_journal_path())
        s.assertEqual(registry.values[retry_key], ("unrelated retry command", registry.REG_SZ))
        s.assertNotIn((U.DESTRUCT_RUNONCE_KEY, U.DESTRUCT_RUNONCE_VALUE), registry.values)
        s.assertFalse((s.user_home / U.DESTRUCT_RECOVERY_SCRIPT).exists())
        s.assertEqual(json.loads(U.destruct_journal_path().read_text())["phase"], "pending")

    def test_confirmed_selfdestruct_registers_recovery_before_scheduling_wipe(s):
        app = mock.MagicMock()
        app.busy = False; app.hold = 0; app.dlg = None
        app.working.return_value = False
        app.defer_seal_action.return_value = False
        app.confirm_destruct.return_value = True
        target = s.d / "UNKNWN_fixture"; app.targets.return_value = [target]
        events = []
        with mock.patch.object(U.sys, "platform", "win32"), \
             mock.patch.object(U, "begin_destructive_cleanup",
                               side_effect=lambda *_a: events.append("journal")), \
             mock.patch.object(U, "register_destruct_runonce",
                               side_effect=lambda *_a: events.append("runonce")), \
             mock.patch.object(U, "Inferno", return_value=mock.MagicMock()), \
             mock.patch.object(U, "QLabel", return_value=mock.MagicMock()), \
             mock.patch.object(U, "S", return_value="short"), \
             mock.patch.object(U.QTimer, "singleShot",
                               side_effect=lambda *_a: events.append("scheduled")):
            U.App.destruct(app, True)
        s.assertEqual(events[:2], ["journal", "runonce"])
        s.assertEqual(events[2:], ["scheduled"] * 7)
        app.confirm_destruct.assert_called_once_with()

    def test_startup_registers_missing_recovery_before_resuming_selfdestruct(s):
        package = s.d / "UNKNWN_recovery_fixture"
        package.mkdir()
        record = {"operation": "self-destruct", "phase": "pending",
                  "install_target": str(package)}
        app = mock.MagicMock()
        app.finalize_destructive_cleanup.side_effect = lambda _record: events.append("finalize")
        events = []
        with mock.patch.object(U, "read_destruct_journal", return_value=record), \
             mock.patch.object(U, "destruct_runonce_command",
                               side_effect=FileNotFoundError("not registered")), \
             mock.patch.object(U, "register_destruct_runonce",
                               side_effect=lambda *_a: events.append("register")), \
             mock.patch.object(U, "resume_destructive_cleanup",
                               side_effect=lambda *_a: (events.append("wipe") or record)), \
             mock.patch.object(U, "S", return_value="short"):
            U.App.recover_destructive_cleanup(app)
        s.assertEqual(events, ["register", "wipe", "finalize"])
    def test_startup_resumes_cleanup_before_opening_profile_chooser(s):
        app = mock.MagicMock()
        record = {"operation": "panic-wipe", "phase": "pending"}
        with mock.patch.object(U, "read_destruct_journal", return_value=record):
            U.App.route_startup_config(app)
        app.recover_destructive_cleanup.assert_called_once_with()
        app.profile_chooser.assert_not_called()
        app.login_screen.assert_not_called()


class TestIntegrity(Base):
    def test_failed_gate_skips_module_level_profile_and_config_loading(s):
        home = s.d / "isolated-home"
        home.mkdir()
        (home / ".unknwn-location").write_bytes(b"invalid")
        (home / ".unknwn-profiles.json").write_text("not valid profile metadata", encoding="utf-8")
        vault = home / ".unknwn"
        vault.mkdir()
        (vault / "config.json").write_text('{"marker":"must-not-load"}', encoding="utf-8")
        env = os.environ.copy()
        env["HOME"] = str(home)
        env["USERPROFILE"] = str(home)
        code = (
            "import sys; sys.path.insert(0, sys.argv[1]); "
            "import unknwn_integrity as IG; IG.state = lambda *_: 'fail'; "
            "import importlib.util; from pathlib import Path; "
            "spec = importlib.util.spec_from_file_location('unknwn', Path(sys.argv[1]) / 'unknwn.py'); "
            "U = importlib.util.module_from_spec(spec); U.__compiled__ = True; "
            "sys.modules['unknwn'] = U; spec.loader.exec_module(U); "
            "assert U.INTEG[0] == 'fail'; "
            "assert U.cfg.get('marker') is None, 'persisted config was loaded'; "
            "assert U.HOME == Path.home() / '.unknwn', 'persisted location was selected'; "
            "print('failed-gate-blocked-profile-and-config-load')"
        )
        result = subprocess.run(
            [sys.executable, "-c", code, str(ROOT)],
            cwd=home,
            env=env,
            capture_output=True,
            text=True,
            timeout=90,
        )
        s.assertEqual(result.returncode, 0, result.stderr)
        s.assertIn("failed-gate-blocked-profile-and-config-load", result.stdout)

    def test_debugger_gate_blocks_before_profile_and_config_loading(s):
        home = s.d / "debugger-gate-home"
        home.mkdir()
        (home / ".unknwn-location").write_bytes(b"invalid")
        (home / ".unknwn-profiles.json").write_text("invalid", encoding="utf-8")
        vault = home / ".unknwn"
        vault.mkdir()
        (vault / "config.json").write_text('{"marker":"must-not-load"}', encoding="utf-8")
        env = dict(os.environ, HOME=str(home), USERPROFILE=str(home))
        code = (
            "import sys; sys.path.insert(0, sys.argv[1]); "
            "import unknwn_integrity as IG; "
            "IG.state = lambda *_: 'ok'; IG.runtime_trust = lambda: 'debugger'; "
            "import importlib.util; from pathlib import Path; "
            "spec = importlib.util.spec_from_file_location('unknwn', Path(sys.argv[1]) / 'unknwn.py'); "
            "U = importlib.util.module_from_spec(spec); U.__compiled__ = True; "
            "sys.modules['unknwn'] = U; spec.loader.exec_module(U); "
            "assert U.INTEG[0] == 'fail'; "
            "assert U.integ_error == 'runtime_debugger_detected'; "
            "assert U.cfg.get('marker') is None; "
            "assert U.HOME == Path.home() / '.unknwn'; "
            "print('debugger-gate-blocked-profile-and-config-load')"
        )
        result = subprocess.run(
            [sys.executable, "-c", code, str(ROOT)],
            cwd=home,
            env=env,
            capture_output=True,
            text=True,
            timeout=90,
        )
        s.assertEqual(result.returncode, 0, result.stderr)
        s.assertIn("debugger-gate-blocked-profile-and-config-load", result.stdout)

    def test_invalid_saved_location_uses_acknowledged_gate_instead_of_import_crash(s):
        home = s.d / "invalid-location-home"
        home.mkdir()
        (home / ".unknwn-location").write_bytes(b"invalid")
        vault = home / ".unknwn"
        vault.mkdir()
        (vault / "config.json").write_text('{"marker":"must-not-load"}', encoding="utf-8")
        env = dict(os.environ, HOME=str(home), USERPROFILE=str(home))
        code = (
            "import sys; sys.path.insert(0, sys.argv[1]); "
            "import unknwn_integrity as IG; "
            "IG.state = lambda *_: 'ok'; IG.runtime_trust = lambda: 'clear'; "
            "import importlib.util; from pathlib import Path; "
            "spec = importlib.util.spec_from_file_location('unknwn', Path(sys.argv[1]) / 'unknwn.py'); "
            "U = importlib.util.module_from_spec(spec); U.__compiled__ = True; "
            "sys.modules['unknwn'] = U; spec.loader.exec_module(U); "
            "assert U.INTEG[0] == 'fail'; "
            "assert U.integ_error == 'startup_state_unavailable'; "
            "assert U.cfg.get('marker') is None; "
            "assert U.HOME == Path.home() / '.unknwn'; "
            "print('invalid-location-blocked-before-config-load')"
        )
        result = subprocess.run(
            [sys.executable, "-c", code, str(ROOT)],
            cwd=home,
            env=env,
            capture_output=True,
            text=True,
            timeout=90,
        )
        s.assertEqual(result.returncode, 0, result.stderr)
        s.assertIn("invalid-location-blocked-before-config-load", result.stdout)

    def test_allow_list_release_check(s):
        env = dict(os.environ, UNKNWN_KEY_PASS="a-long-test-passphrase-123"); kd = s.d / "k"; kd.mkdir(); rt = str(ROOT / "tools" / "release.py")
        sh = lambda *a: subprocess.run([sys.executable, rt, *a], env=env, capture_output=True, text=True, cwd=kd)
        sh("keygen"); pub = (kd / "release_pubkey.txt").read_text().strip(); dist = s.d / "dist"; (dist / "sub").mkdir(parents=True); (dist / "UNKNWN.exe").write_bytes(os.urandom(999)); (dist / "sub" / "p.dll").write_bytes(os.urandom(99))
        sh("manifest", "--dist", str(dist), "--key", str(kd / "release_key.pem"), "--build", "1"); s.assertTrue(IG.verify_dir(dist, pub)); s.assertTrue(IG.spot(2))
        for f in ("qt.conf", "UNKNWN.exe.manifest", "UNKNWN.exe.local", "evil.pyw", "evil.lnk", "evil.dll", "__pycache__/mupdf.cpython-313.pyc"):
            path = dist / f; path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("x"); s.assertFalse(IG.verify_dir(dist, pub), f); path.unlink()
        (dist / "UNKNWN.exe").write_bytes(b"patched"); s.assertFalse(IG.verify_dir(dist, pub)); s.assertFalse(IG.spot(2))

    def test_debugger_probe_detects_python_tracing(s):
        with mock.patch.object(U.sys, "gettrace", return_value=object()), \
             mock.patch.object(U.sys, "getprofile", return_value=None):
            s.assertTrue(U.dbg_now())

    def test_runtime_trust_reports_python_tracing(s):
        with mock.patch.object(IG.sys, "gettrace", return_value=object()), \
             mock.patch.object(IG.sys, "getprofile", return_value=None):
            s.assertEqual(IG.runtime_trust(), "debugger")

    def test_runtime_trust_reports_windows_debugger_indicators(s):
        kernel32 = mock.MagicMock()
        kernel32.IsDebuggerPresent.return_value = False
        kernel32.GetCurrentProcess.return_value = 1
        def remote_debugger(_process, result):
            IG.ctypes.cast(result, IG.ctypes.POINTER(IG.ctypes.c_int)).contents.value = 1
            return True
        kernel32.CheckRemoteDebuggerPresent.side_effect = remote_debugger
        with mock.patch.object(IG.sys, "gettrace", return_value=None), \
             mock.patch.object(IG.sys, "getprofile", return_value=None), \
             mock.patch.object(IG.sys, "platform", "win32"), \
             mock.patch.object(IG.ctypes, "WinDLL", return_value=kernel32):
            s.assertEqual(IG.runtime_trust(), "debugger")

    def test_runtime_trust_fails_closed_when_windows_probe_unavailable(s):
        with mock.patch.object(IG.sys, "gettrace", return_value=None), \
             mock.patch.object(IG.sys, "getprofile", return_value=None), \
             mock.patch.object(IG.sys, "platform", "win32"), \
             mock.patch.object(IG.ctypes, "WinDLL", side_effect=OSError("unavailable")):
            s.assertEqual(IG.runtime_trust(), "unavailable")

    def test_enforced_gate_accepts_only_verified_release_and_clear_runtime(s):
        s.assertEqual(IG.security_decision(True, "ok", "clear"), ("ok", ""))
        s.assertEqual(IG.security_decision(True, "fail", "clear"), ("fail", "release_integrity"))
        s.assertEqual(
            IG.security_decision(True, "ok", "debugger"),
            ("fail", "runtime_debugger_detected"),
        )
        s.assertEqual(
            IG.security_decision(True, "ok", "unavailable"),
            ("fail", "runtime_check_unavailable"),
        )
        s.assertEqual(
            IG.security_decision(True, "fail", "debugger"),
            ("fail", "release_integrity"),
        )
        s.assertEqual(IG.security_decision(False, "dev", "not_enforced"), ("dev", ""))

    def test_intro_distinguishes_runtime_failure_from_package_failure(s):
        prior_integrity = U.INTEG[0]
        prior_release = U.release_integrity_state
        prior_runtime = U.runtime_trust_state
        prior_error = U.integ_error
        try:
            U.INTEG[0] = "fail"
            U.release_integrity_state = "ok"
            U.runtime_trust_state = "debugger"
            U.integ_error = "runtime_debugger_detected"
            text = "\n".join(line for line, _, _, _ in U.startup_script(1))
            s.assertIn("signed package signature/inventory verified", text)
            s.assertIn("authenticated, parsed; inventory verified", text)
            s.assertIn("verified", text)
            s.assertIn("debugger/tracer detected", text)
            s.assertIn("FAILED - startup blocked (runtime_debugger_detected)", text)
            s.assertNotIn("package untrusted", text)
        finally:
            U.INTEG[0] = prior_integrity
            U.release_integrity_state = prior_release
            U.runtime_trust_state = prior_runtime
            U.integ_error = prior_error

    def test_debugger_setting_blocks_sensitive_action(s):
        app = mock.MagicMock()
        app.integ_ok.return_value = True
        with mock.patch.object(U, "S", return_value=True), \
             mock.patch.object(U, "dbg_now", return_value=True), \
             mock.patch.object(U.QMessageBox, "warning") as warning:
            s.assertFalse(U.App.sec_ok(app))
        warning.assert_called_once_with(
            app, "Security", "A debugger or tracer was detected, so this action is blocked.")

    def test_capability_gate_blocks_writes_without_auth_or_during_read_only_and_recovery(s):
        s.assertEqual(
            U.capability_block_reason(
                "vault_read", authenticated=False, read_only=False, recovery_pending=False),
            "Authenticate to the vault before using this capability.")
        s.assertEqual(
            U.capability_block_reason(
                "vault_write", authenticated=True, read_only=True, recovery_pending=False),
            "This is a read-only session; vault changes are disabled.")
        s.assertEqual(
            U.capability_block_reason(
                "destructive", authenticated=True, read_only=False, recovery_pending=True),
            "Resolve the pending vault recovery before starting another operation.")
        s.assertIsNone(U.capability_block_reason(
            "vault_read", authenticated=True, read_only=True, recovery_pending=False))

    def test_capability_security_gate_is_used_by_app_security_check(s):
        class AppState:
            root = None
            ro = False
            def integ_ok(self): return True

        with mock.patch.object(U, "COMPILED", False), \
             mock.patch.object(U, "S", return_value=False), \
             mock.patch.object(U.QMessageBox, "warning") as warning:
            s.assertFalse(U.App.sec_ok(AppState(), "vault_read"))
        warning.assert_called_once_with(
            mock.ANY, "Capability unavailable",
            "Authenticate to the vault before using this capability.")

    def test_integrity_failure_screen_waits_for_explicit_quit_acknowledgment(s):
        app = mock.MagicMock()
        app.root = b"root-key"
        app.ro = True
        app.cards = {}
        app.cds = {}
        app.dlg = None
        app.logo = mock.Mock(return_value=mock.MagicMock())
        app.panel = mock.Mock(return_value=mock.MagicMock())
        app.show_w = mock.Mock()
        quit_button = mock.MagicMock()
        callbacks = []
        quit_button.clicked.connect.side_effect = callbacks.append
        prior_integrity = U.INTEG[0]
        prior_error = U.integ_error
        try:
            with mock.patch.object(U, "btn", return_value=quit_button), \
                 mock.patch.object(U, "lbl", return_value=mock.MagicMock()), \
                 mock.patch.object(U, "SecurityFailurePulse", return_value=mock.MagicMock()) as failure_pulse, \
                 mock.patch.object(U, "support_message", return_value="Integrity failure") as support, \
                 mock.patch.object(U, "S", return_value=False), \
                 mock.patch.object(U, "HOME", s.d), \
                 mock.patch.object(U, "integ_error", "runtime_debugger_detected"), \
                 mock.patch.object(U, "_close_widget") as close_widget:
                U.App.integ_fail(app)
                app.show_w.assert_called_once()
                s.assertEqual(app.show_w.call_args.args[1], "blocked")
                failure_pulse.assert_called_once_with(app)
                s.assertEqual(len(callbacks), 1)
                s.assertIn(
                    "Diagnostic category: runtime_debugger_detected",
                    support.call_args.args[0],
                )
                close_widget.assert_not_called()
                callbacks[0]()
                app.acknowledge_integrity_failure.assert_called_once_with()
        finally:
            U.INTEG[0] = prior_integrity
            U.integ_error = prior_error

    def test_integrity_failure_cleans_owned_media_only_when_release_code_is_trusted(s):
        app = mock.MagicMock()
        app.root = b"root-key"
        app.ro = False
        app.cards = {}
        app.cds = {}
        app.dlg = None
        app.logo.return_value = mock.MagicMock()
        app.panel.return_value = mock.MagicMock()
        with mock.patch.object(U, "btn", return_value=mock.MagicMock()), \
             mock.patch.object(U, "lbl", return_value=mock.MagicMock()), \
             mock.patch.object(U, "SecurityFailurePulse", return_value=mock.MagicMock()), \
             mock.patch.object(U, "support_message", return_value="blocked"), \
             mock.patch.object(U, "S", return_value=False), \
             mock.patch.object(U, "release_integrity_state", "ok"), \
             mock.patch.object(U, "cleanup_temp_files") as cleanup, \
             mock.patch.object(U, "HOME", s.d):
            U.App.integ_fail(app)
        cleanup.assert_called_once_with()

        with mock.patch.object(U, "btn", return_value=mock.MagicMock()), \
             mock.patch.object(U, "lbl", return_value=mock.MagicMock()), \
             mock.patch.object(U, "SecurityFailurePulse", return_value=mock.MagicMock()), \
             mock.patch.object(U, "support_message", return_value="blocked"), \
             mock.patch.object(U, "S", return_value=False), \
             mock.patch.object(U, "release_integrity_state", "fail"), \
             mock.patch.object(U, "cleanup_temp_files") as cleanup_untrusted, \
             mock.patch.object(U, "HOME", s.d):
            U.App.integ_fail(app)
        cleanup_untrusted.assert_not_called()

    def test_integrity_failure_acknowledgment_is_idempotent(s):
        app = mock.MagicMock()
        app.mode = "blocked"
        app._integrity_exit_started = False
        app.working.return_value = False
        with mock.patch.object(U, "_close_widget") as close_widget:
            U.App.acknowledge_integrity_failure(app)
            U.App.acknowledge_integrity_failure(app)
        close_widget.assert_called_once_with(app)

    def test_integrity_failure_exit_waits_for_active_operation_to_drain(s):
        app = mock.MagicMock()
        app.mode = "blocked"
        app._integrity_exit_started = False
        app.integrity_message = mock.MagicMock()
        app.working.return_value = True
        with mock.patch.object(U.QTimer, "singleShot") as schedule, \
             mock.patch.object(U, "_close_widget") as close_widget:
            U.App.acknowledge_integrity_failure(app)
            schedule.assert_called_once()
            close_widget.assert_not_called()
            app.integrity_message.setText.assert_called_once()
        app.working.return_value = False
        with mock.patch.object(U, "_close_widget") as close_widget:
            U.App._complete_integrity_exit(app)
        close_widget.assert_called_once_with(app)

    def test_failed_gate_cannot_resume_normal_flow_or_trigger_destructive_hotkeys(s):
        app = mock.MagicMock()
        app.mode = "blocked"
        app.busy = False
        prior_integrity = U.INTEG[0]
        try:
            U.INTEG[0] = "fail"
            U.App.show_w(app, mock.MagicMock(), "vault")
            U.App.hotkey(app)
            with mock.patch.object(U, "pending_self_destruct_deadline") as deadline:
                U.App.tick(app)
            s.assertEqual(app.mode, "blocked")
            app.panic.assert_not_called()
            app.destruct.assert_not_called()
            deadline.assert_not_called()
        finally:
            U.INTEG[0] = prior_integrity

    def test_blocked_screen_global_key_acknowledges_once_and_ignores_key_repeat(s):
        app = mock.MagicMock()
        app.mode = "blocked"
        event = mock.MagicMock()
        event.type.return_value = U.QEvent.Type.KeyPress
        event.isAutoRepeat.return_value = False
        with mock.patch.object(U, "S", return_value=False):
            s.assertTrue(U.App.eventFilter(app, None, event))
        app.acknowledge_integrity_failure.assert_called_once_with()

        app.reset_mock()
        event.isAutoRepeat.return_value = True
        with mock.patch.object(U, "S", return_value=False):
            s.assertFalse(U.App.eventFilter(app, None, event))
        app.acknowledge_integrity_failure.assert_not_called()

class TestPasswords(Base):
    def test_weak_rejected_strong_accepted(s):
        for w in ["Password1234!", "Summer2024!!", "Welcome12345!", "Qwerty123456!", "Iloveyou2024!", "Admin@123456", "Football2024!", "Monkey123456!", "Letmein12345!", "Ahmed2000!!!!"]: s.assertFalse(U.check_pw(w)[0], w)
        for g in [PW, "tN7#vQ9!pLz2$kR", "my-Cat-eats-9-Blue-Pears!"]: s.assertTrue(U.check_pw(g)[0], g)

class TestAppearance(Base):
    def test_reopening_current_profile_skips_activation_and_returns_to_sign_in(s):
        app = mock.MagicMock()
        profile = {"id": "current-profile", "name": "Current", "path": str(s.d)}
        old_profile_id = U.active_profile_id
        old_recovery_error = U.STARTUP_RECOVERY_ERROR
        U.active_profile_id = profile["id"]
        U.STARTUP_RECOVERY_ERROR = None
        try:
            with mock.patch.object(U, "activate_profile") as activate:
                U.App.open_profile(app, profile)
            activate.assert_not_called()
            app.route_startup_config.assert_called_once_with()
        finally:
            U.active_profile_id = old_profile_id
            U.STARTUP_RECOVERY_ERROR = old_recovery_error
    def test_new_quiet_field_theme_uses_static_background_and_muted_palette(s):
        s.assertEqual(U.PRE["tired"], ("#100b0b", "#c9c0ae", "#87424a"))
        s.assertIn(("I'm Tired", "tired"), U.THEMES)
        s.assertIn(("Quiet field (still)", "tiredfield"), U.BGS)
        s.assertIn("tiredfield", U.STILL)
        s.assertNotIn("tiredfield", U.ANIM)
        image = ROOT / "assets" / "im_tired.jpg"
        s.assertTrue(image.is_file())
        s.assertEqual(image.read_bytes()[:2], b"\xff\xd8")
    def test_native_context_menus_and_duplicate_lists_use_theme_aware_dark_styles(s):
        stylesheet = U.qss()
        s.assertIn("QMenu::item:selected", stylesheet)
        s.assertIn("QListWidget::item:selected", stylesheet)
        s.assertIn("QAbstractItemView,QListWidget{background:", stylesheet)
        s.assertIn(U.TH["fg"], stylesheet)
    def test_drag_feedback_acceptance_requires_safe_local_file_or_folder(s):
        class Url:
            def __init__(self, path, local=True):
                self.path, self.local = path, local
            def isLocalFile(self): return self.local
            def toLocalFile(self): return str(self.path)
        class Mime:
            def __init__(self, urls): self._urls = urls
            def hasUrls(self): return bool(self._urls)
            def urls(self): return self._urls
        path = s.d / "drop-valid.txt"
        path.write_text("safe", encoding="utf-8")
        app = mock.MagicMock()
        s.assertTrue(U.App._valid_drop_mime(app, Mime([Url(path)])))
        s.assertFalse(U.App._valid_drop_mime(app, Mime([Url(path, local=False)])))
        s.assertFalse(U.App._valid_drop_mime(app, Mime([Url(s.d / "missing.txt")])))
    def test_drag_drop_routes_files_and_folders_to_existing_pipelines(s):
        class Url:
            def __init__(self, path=None, local=True):
                self.path = path
                self.local = local
            def isLocalFile(self): return self.local
            def toLocalFile(self): return str(self.path)
        class Mime:
            def __init__(self, urls): self._urls = urls
            def hasUrls(self): return bool(self._urls)
            def urls(self): return self._urls
        class Event:
            def __init__(self, mime): self._mime = mime; self.accepted = False; self.ignored = False
            def mimeData(self): return self._mime
            def pos(self): return U.QPointF(100, 120)
            def acceptProposedAction(self): self.accepted = True
            def accept(self): self.accepted = True
            def ignore(self): self.ignored = True
        source_file = s.d / "drop.txt"; source_file.write_text("source", encoding="utf-8")
        source_folder = s.d / "drop-folder"; source_folder.mkdir()
        app = mock.MagicMock()
        app.mode = "vault"; app.ro = False; app.busy = False; app.root = b"vault-key"
        app.working.return_value = False; app.windowTitle.return_value = "UNKNWN"
        app._drop_enabled = lambda: U.App._drop_enabled(app)
        app._restore_drop_title = lambda: U.App._restore_drop_title(app)
        app._drop_previous_title = None
        app.add_files = mock.Mock(); app.add_folder = mock.Mock(); app.setWindowTitle = mock.Mock()
        mime = Mime([Url(source_file), Url(source_folder), Url(local=False)])
        enter = Event(mime)
        U.App.dragEnterEvent(app, enter)
        s.assertTrue(enter.accepted)
        app.setWindowTitle.assert_called_with("Drop items to validate and seal")
        app._drop_previous_title = "UNKNWN"
        drop = Event(mime)
        with mock.patch.object(U.QMessageBox, "warning") as warning:
            U.App.dropEvent(app, drop)
        s.assertTrue(drop.accepted)
        app.add_files.assert_called_once_with([source_file])
        app.add_folder.assert_called_once_with(source_folder)
        warning.assert_called_once()
        s.assertEqual(source_file.read_text(encoding="utf-8"), "source")
    def test_new_vault_creation_requires_terms_acceptance(s):
        app = mock.MagicMock()
        app.tos_agree.isChecked.return_value = False
        U.App._create(app)
        app.msg.setText.assert_called_once_with("Read the Terms of Service and Responsible Use Policy and agree before creating a vault.")
        app.sec_ok.assert_not_called()
    def test_profile_switch_locks_and_starts_the_profile_handoff(s):
        app = mock.MagicMock()
        app.mode = "vault"; app.busy = False; app.hold = 0; app.working.return_value = False
        app.profile_chooser = mock.Mock(); app.record_session_event = mock.Mock()
        handoff = mock.Mock()
        with mock.patch.object(U, "pending_self_destruct_deadline", return_value=None), \
             mock.patch.object(U, "_read_profiles", return_value=[{"id": "profile"}]) as read_profiles, \
             mock.patch.object(U, "ProfileSwitchSequence", return_value=handoff) as animation:
            app.lock = mock.Mock()
            U.App.switch_profile(app)
        app.sec_ok.assert_called_once()
        read_profiles.assert_called_once_with()
        app.record_session_event.assert_called_once_with("profile_switch")
        app.lock.assert_called_once_with(False)
        animation.assert_called_once_with(app, app.profile_chooser, 1)
        s.assertFalse(app.relocked)
        s.assertIsNone(app.session_id)
        s.assertIsNone(app.session_started)
        s.assertEqual(app.session_activity, [])
    def test_profile_switch_cannot_bypass_a_self_destruct_countdown(s):
        app = mock.MagicMock()
        app.mode = "vault"
        with mock.patch.object(U, "pending_self_destruct_deadline", return_value=time.time() + 300), \
             mock.patch.object(U.QMessageBox, "warning") as warning, \
             mock.patch.object(U.App, "lock") as lock:
            U.App.switch_profile(app)
        warning.assert_called_once()
        lock.assert_not_called()
    def test_terms_dialog_displays_the_complete_policy_in_a_theme_styled_browser(s):
        s.assertIn("# UNKNWN — Legal Notice, Responsible Use & Acceptable Use Policy", U.TERMS_OF_SERVICE)
        s.assertIn("## 13. Final Statement", U.TERMS_OF_SERVICE)
        s.assertIn("**Protect your privacy. Respect other people's rights. Use the software responsibly.**", U.TERMS_OF_SERVICE)
        app = mock.MagicMock(); app.screen.return_value = None
        dialog = mock.MagicMock(); frame = mock.MagicMock(); policy = mock.MagicMock()
        layout = mock.MagicMock(); close = mock.MagicMock()
        with mock.patch.object(U, "QDialog", return_value=dialog), \
             mock.patch.object(U, "QVBoxLayout", return_value=layout), \
             mock.patch.object(U, "QFrame", return_value=frame), \
             mock.patch.object(U, "QTextBrowser", return_value=policy), \
             mock.patch.object(U, "tlbl", side_effect=lambda *args: mock.MagicMock()), \
             mock.patch.object(U, "btn", return_value=close):
            U.App.show_terms(app)
        policy.setMarkdown.assert_called_once_with(U.TERMS_OF_SERVICE)
        policy.setOpenLinks.assert_called_once_with(False)
        policy.setOpenExternalLinks.assert_called_once_with(False)
        policy.setStyleSheet.assert_called_once()
    def test_terminal_label_accepts_bold_profile_heading(s):
        label = mock.MagicMock()
        with mock.patch.object(U, "QLabel", return_value=label):
            result = U.tlbl("CHOOSE A VAULT", 23, U.TH["acc"], True)
        s.assertIs(result, label)
        label.setStyleSheet.assert_called_once()
        s.assertIn("font-weight:bold", label.setStyleSheet.call_args.args[0])
    def test_security_status_icons_use_full_unicode_codepoints(s):
        s.assertEqual(U.LOCK_ICON, chr(0x1F512))
        s.assertEqual(U.FIRE_ICON, chr(0x1F525))
        s.assertEqual(len(U.LOCK_ICON), 1)
        s.assertEqual(len(U.FIRE_ICON), 1)

    def test_failed_settings_save_keeps_live_value_and_skips_side_effects(s):
        U.cfg["set"] = dict(U.DEF, hideuser=False)
        before = U.copy.deepcopy(U.cfg)
        app = U.App.__new__(U.App)
        app.mode = "vault"
        app.owner = False
        app.root = None
        app.record_session_event = mock.Mock()
        app.push_settings_history = mock.Mock()
        with mock.patch.object(U, "jsave", side_effect=OSError("disk full")), \
             mock.patch.object(U.QMessageBox, "warning") as warning:
            U.App.put(app, "hideuser", True)

        s.assertEqual(U.cfg, before)
        warning.assert_called_once()
        app.record_session_event.assert_not_called()
        app.push_settings_history.assert_not_called()

    def test_protected_setting_and_integrity_snapshot_commit_together(s):
        dek, _, _ = s.vault(sizes=())
        app = U.App.__new__(U.App)
        app.mode = "vault"
        app.owner = True
        app.root = dek
        app.record_session_event = mock.Mock()
        U.App.put(app, "export", False)

        status, _good, changed = U.IG.snap_check(dek, U.cfg.get("sc"), U.secset())

        s.assertEqual(status, "ok")
        s.assertEqual(changed, [])
        s.assertFalse(U.cfg["set"]["export"])
        s.assertEqual(U.jload(U.CFG, {})["set"]["export"], False)

    def test_session_events_record_only_changed_settings_and_stored_names(s):
        U.cfg["set"] = dict(U.DEF)
        app = U.App.__new__(U.App); app.mode = "vault"; app.owner = False; app.root = None; app.session_activity = []
        app.session_stored_names = []; app.session_stored_count = 0; app.session_setting_changes = 0
        U.App.put(app, "hideuser", True); U.App.put(app, "hideuser", True)
        s.assertEqual(len(app.session_activity), 1)
        s.assertEqual(app.session_activity[0]["kind"], "setting_changed")
        s.assertEqual((app.session_activity[0]["key"], app.session_activity[0]["before"], app.session_activity[0]["after"]),
                      ("hideuser", False, True))
        U.App.record_session_event(app, "files_stored", count=2, names=["north.png", "notes.txt"])
        s.assertEqual(app.session_stored_count, 2)
        s.assertEqual(app.session_stored_names, ["north.png", "notes.txt"])
    def test_session_history_persists_encrypted_allowlisted_events(s):
        dek, _, _ = s.vault(sizes=())
        app = U.App.__new__(U.App); app.root = dek; app.session_id = __import__("uuid").uuid4().hex
        app.session_started = time.time(); app.session_activity = [
            {"t": time.time(), "kind": "vault_unlocked", "method": "password", "password": "never store"},
            {"t": time.time(), "kind": "file_opened", "name": "private.txt", "content": "never store"},
        ]
        U.App.persist_session_event(app)
        encrypted = U.LOG.read_bytes()
        entries = json.loads(U.unseal(U.file_key(dek, b"unknwn-log"), encrypted))
        session = next(entry for entry in entries if entry.get("type") == "session")
        s.assertEqual([event["kind"] for event in session["events"]], ["vault_unlocked", "file_opened"])
        s.assertNotIn("password", session["events"][0]); s.assertNotIn("content", session["events"][1])
        s.assertEqual(session["events"][1]["name"], "private.txt")
        s.assertNotIn(b"private.txt", encrypted)
        s.assertTrue(any(entry.get("ok") is True for entry in entries), "existing sign-in records must remain")
    def test_corrupted_session_history_is_not_overwritten(s):
        dek, _, _ = s.vault(sizes=())
        damaged = b"not valid authenticated history"; U.LOG.write_bytes(damaged)
        app = U.App.__new__(U.App); app.root = dek; app.session_id = __import__("uuid").uuid4().hex
        app.session_started = time.time(); app.session_activity = [{"t": time.time(), "kind": "vault_unlocked"}]
        U.App.persist_session_event(app)
        s.assertEqual(U.LOG.read_bytes(), damaged)
        s.assertEqual(app.session_history_error, "InvalidTag")
    def test_session_history_retention_and_event_limits(s):
        dek, _, _ = s.vault(sizes=())
        signin_records = [{"t": i, "ok": True, "how": "password", "ro": False} for i in range(305)]
        old_sessions = [{"type": "session", "sid": f"{i:032x}", "t": i, "events": []} for i in range(51)]
        U.LOG.write_bytes(U.seal(U.file_key(dek, b"unknwn-log"), json.dumps(signin_records + old_sessions).encode()))
        app = U.App.__new__(U.App); app.root = dek; app.session_id = __import__("uuid").uuid4().hex
        app.session_started = time.time()
        app.session_activity = [{"t": i, "kind": "vault_locked"} for i in range(U.MAX_SESSION_EVENTS + 5)]
        U.App.persist_session_event(app)
        entries = json.loads(U.unseal(U.file_key(dek, b"unknwn-log"), U.LOG.read_bytes()))
        s.assertEqual(sum(entry.get("ok") is True for entry in entries), U.MAX_SIGNIN_HISTORY)
        sessions = [entry for entry in entries if entry.get("type") == "session"]
        s.assertEqual(len(sessions), U.MAX_SESSION_HISTORY)
        current = next(entry for entry in sessions if entry["sid"] == app.session_id)
        s.assertEqual(len(current["events"]), U.MAX_SESSION_EVENTS)
    def test_vault_intro_scripts_are_distinct_and_bounded(s):
        with mock.patch.object(U, "release_integrity_state", "dev"), \
             mock.patch.object(U, "runtime_trust_state", "not_enforced"), \
             mock.patch.object(U, "INTEG", ["dev"]):
            full = U.startup_script(3); brief = U.startup_script(1)
            text = "\n".join(line for line, _, _, _ in full)
            s.assertIn("VAULT SEALED", text); s.assertIn("AUTHENTICATION REQUIRED", text)
            s.assertIn("signed package signature/inventory", text)
            s.assertIn("visual only; no security decision", text)
            s.assertIn("runtime debugger/tracing", text)
            s.assertIn("not read before authentication", text)
            s.assertIn("protected manifest", text)
            s.assertIn("not applicable (development/source run)", text)
            s.assertNotIn("entropy source", text); s.assertNotIn("plaintext buffers", text)
            s.assertTrue(all("decrypt " not in line for line, _, _, _ in full))
            s.assertLess(
                sum(len(line) / max(1, cps) + pause / 1000 for line, _, cps, pause in full),
                8.0,
            )
            stateful = "\n".join(
                line for line, _, _, _ in U.startup_script(3, {
                    "location": "validated",
                    "config": "loaded",
                    "cleanup": "pending",
                })
            )
            s.assertIn("persisted location ............. validated", stateful)
            s.assertIn("parsed; vault authentication still required", stateful)
            s.assertIn("validated; recovery is required", stateful)
            s.assertIn("deferred until profile/authentication", stateful)
            s.assertIn("not read before authentication", stateful)
            s.assertIn("password/unlock readiness ....... authentication required", stateful)
            recovered_config = "\n".join(
                line for line, _, _, _ in U.startup_script(
                    3, {"config": "recovered_backup"}))
            s.assertIn("primary unavailable; valid backup selected", recovered_config)
            unavailable = "\n".join(
                line for line, _, _, _ in U.startup_script(3, {
                    "location": "unavailable",
                    "config": "unavailable",
                    "cleanup": "unavailable",
                })
            )
            s.assertIn("persisted location ............. unavailable; startup blocked", unavailable)
            s.assertIn("persisted config ............... unavailable; startup blocked", unavailable)
            s.assertIn("cleanup recovery journal ....... unavailable; recovery screen required", unavailable)
        s.assertLess(len(brief), len(full))
        prior_integrity = U.INTEG[0]
        prior_release = U.release_integrity_state
        prior_error = U.integ_error
        prior_runtime = U.runtime_trust_state
        try:
            U.INTEG[0] = "fail"
            U.release_integrity_state = "fail"
            U.integ_error = "release_integrity"
            U.runtime_trust_state = "debugger"
            text = "\n".join(line for line, _, _, _ in U.startup_script(1))
            s.assertIn("FAILED - package untrusted", text)
            s.assertIn("FAILED - startup blocked (release_integrity)", text)
        finally:
            U.INTEG[0] = prior_integrity
            U.release_integrity_state = prior_release
            U.runtime_trust_state = prior_runtime
            U.integ_error = prior_error
        warden = "\n".join(line for line, _, _, _ in U.warden_script())
        s.assertIn("WARDEN ONLINE", warden); s.assertIn("ACCESS RESTORED", warden)
        s.assertGreaterEqual(U.warden_script()[-1][3], 2500)
    def test_password_unlock_transitions_into_warden_then_vault(s):
        app = mock.MagicMock(); unlock = mock.MagicMock(); warden = object()
        with mock.patch.object(U, "Unlock", return_value=unlock) as make_unlock, \
             mock.patch.object(U, "Warden", return_value=warden) as make_warden:
            U.App.unlock_fx(app)
            done = make_unlock.call_args.args[0]
            done()
        make_unlock.assert_called_once_with(done, app)
        make_warden.assert_called_once_with(app.vault_screen, app)
        app.show_w.assert_any_call(unlock, "unlock")
        app.show_w.assert_any_call(warden, "unlock")
        s.assertEqual(app.show_w.call_count, 2)
    def test_warden_randomly_selects_from_embedded_art(s):
        art = U.WARDEN_ART
        s.assertEqual(len(art), 200)
        s.assertEqual(len(set(art)), 200)
        U._LAST_WARDEN_ART = None
        with mock.patch.object(U.random, "choice", side_effect=(art[0], art[-1])) as choose:
            first = U.warden_script()
            second = U.warden_script()
        s.assertEqual(choose.call_args_list[0], mock.call(art))
        s.assertNotIn(art[0], choose.call_args_list[1].args[0])
        s.assertEqual(choose.call_args_list[1].args[0], tuple(item for item in art if item != art[0]))
        first_lines = [line for line, _, _, _ in first]
        second_lines = [line for line, _, _, _ in second]
        s.assertIn(art[0].splitlines()[0], first_lines)
        s.assertIn(art[-1].splitlines()[0], second_lines)
        s.assertNotEqual(first_lines, second_lines)
        U._LAST_WARDEN_ART = None
        s.assertFalse((U.Path(__file__).resolve().parents[1] / "warden_art").exists())
    def test_warden_selection_never_repeats_consecutively(s):
        previous = U._LAST_WARDEN_ART
        U._LAST_WARDEN_ART = None
        selected = [U.random_warden_art() for _ in range(2000)]
        s.assertTrue(all(left != right for left, right in zip(selected, selected[1:])))
        U._LAST_WARDEN_ART = previous
    def test_warden_is_shown_after_in_app_relock_and_unlock(s):
        dummy = mock.MagicMock(); dummy.relocked = True; dummy.t0 = 0; dummy.vault_screen = mock.Mock()
        marker = object()
        with mock.patch.object(U, "Warden", return_value=marker) as warden:
            U.App.enter_vault(dummy)
        warden.assert_called_once_with(dummy.vault_screen, dummy)
        dummy.show_w.assert_called_once_with(marker, "unlock")
        s.assertFalse(dummy.relocked)
        dummy.reset_mock(); dummy.relocked = False
        U.App.enter_vault(dummy)
        dummy.unlock_fx.assert_called_once_with()
        dummy.show_w.assert_not_called()
    def test_lock_marks_same_app_reauthentication_for_short_intro(s):
        dummy = mock.MagicMock()
        dummy.mode = "vault"; dummy.relocked = False; dummy.busy = False; dummy.dying = set()
        dummy.dlg = None; dummy.studio = None; dummy.hold = 0
        dummy.defer_seal_action.return_value = False
        with mock.patch.object(U, "S", return_value=False):
            U.App.lock(dummy)
        s.assertTrue(dummy.relocked)
        dummy.login_screen.assert_called_once_with()
    def test_reset_settings_requires_confirmation_before_changing_preferences(s):
        app = mock.MagicMock(); app.ro = False; app.mode = "vault"; app.owner = True
        U.cfg["set"] = {"mask": True, "custom": "preserve"}
        previous = dict(U.cfg["set"])
        with mock.patch.object(U, "terminal_confirm", return_value=False) as confirm:
            U.App.reset_settings(app)
        confirm.assert_called_once()
        s.assertEqual(U.cfg["set"], previous)
    def test_reset_settings_restores_known_defaults_and_preserves_unknown_keys(s):
        app = mock.MagicMock(); app.ro = False; app.mode = "vault"; app.owner = True
        app.root = None
        app.put = lambda key, value: U.App.put(app, key, value)
        app.set_th = lambda theme: U.App.set_th(app, theme)
        U.cfg["set"] = {"mask": True, "hk_act": "wipe", "custom": "preserve"}
        with mock.patch.object(U, "terminal_confirm", return_value=True), \
             mock.patch.object(U, "nocap"), mock.patch.object(U, "_refresh_theme"), \
             mock.patch.object(U.QApplication, "instance", return_value=mock.MagicMock()), \
             mock.patch.object(U.QMessageBox, "information"):
            U.App.reset_settings(app)
        for key, value in U.DEF.items():
            s.assertEqual(U.cfg["set"][key], value)
        s.assertEqual(U.cfg["set"]["custom"], "preserve")
        app.apply_hk.assert_called()
    def test_setting_history_undoes_and_redoes_reversible_preferences(s):
        app = mock.MagicMock()
        app.ro = False; app.mode = "vault"; app.owner = True; app.root = None
        app.settings_undo_stack = []; app.settings_redo_stack = []
        app._settings_history_group = None; app._settings_history_replay = False
        app.record_session_event = mock.Mock()
        app.refresh_settings_history_controls = lambda: U.App.refresh_settings_history_controls(app)
        app.push_settings_history = lambda changes: U.App.push_settings_history(app, changes)
        app.put = lambda key, value: U.App.put(app, key, value)
        app.replay_settings_history = lambda undo: U.App.replay_settings_history(app, undo)
        U.cfg["set"] = dict(U.DEF)
        U.App.put(app, "title", "Personal title")
        s.assertEqual(U.cfg["set"]["title"], "Personal title")
        s.assertEqual(len(app.settings_undo_stack), 1)
        U.App.undo_setting(app)
        s.assertEqual(U.cfg["set"]["title"], U.DEF["title"])
        s.assertEqual(len(app.settings_redo_stack), 1)
        U.App.redo_setting(app)
        s.assertEqual(U.cfg["set"]["title"], "Personal title")
        s.assertEqual(len(app.settings_undo_stack), 1)
    def test_setting_history_excludes_security_sensitive_settings(s):
        app = mock.MagicMock()
        app.ro = False; app.mode = "vault"; app.owner = True; app.root = None
        app.settings_undo_stack = []; app.settings_redo_stack = []
        app._settings_history_group = None; app._settings_history_replay = False
        app.record_session_event = mock.Mock()
        app.refresh_settings_history_controls = mock.Mock()
        app.push_settings_history = lambda changes: U.App.push_settings_history(app, changes)
        U.cfg["set"] = dict(U.DEF)
        U.App.put(app, "clip", False)
        s.assertEqual(U.cfg["set"]["clip"], False)
        s.assertEqual(app.settings_undo_stack, [])
    def test_shortcut_manager_rejects_reserved_and_multistep_sequences(s):
        app = mock.MagicMock()
        app.scs = []; app.findChildren.return_value = []
        s.assertIsNone(U.App.shortcut_problem(app, U.QKeySequence("Ctrl+Shift+P")))
        s.assertIn("reserved", U.App.shortcut_problem(app, U.QKeySequence("Ctrl+C")))
        s.assertIn("reserved", U.App.shortcut_problem(app, U.QKeySequence("Ctrl+K")))
        s.assertIn("reserved", U.App.shortcut_problem(app, U.QKeySequence("Ctrl+Left")))
        s.assertIn("one key combination", U.App.shortcut_problem(app, U.QKeySequence("Ctrl+K, Ctrl+C")))
        s.assertIn("Ctrl, Alt, or Windows", U.App.shortcut_problem(app, U.QKeySequence("A")))
        s.assertIn("non-empty", U.App.shortcut_problem(app, U.QKeySequence()))
        existing = mock.MagicMock(); existing.key.return_value = U.QKeySequence("Ctrl+Shift+P")
        app.findChildren.return_value = [existing]
        s.assertIn("already used", U.App.shortcut_problem(app, U.QKeySequence("Ctrl+Shift+P")))
    def test_terminal_art_backgrounds_are_static_and_registered(s):
        choices = {key for _, key in U.BGS}
        for key in ("termart", "sigil", "casefile"):
            s.assertIn(key, choices)
            s.assertNotIn(key, U.ANIM)
        s.assertIn(("Noir sentinel (still)", "sigil"), U.BGS)
        s.assertIn(("Operator console (still)", "termart"), U.BGS)
        s.assertFalse({"fire", "embers"} & U.ANIM)
        s.assertFalse({"fire", "embers"} & choices)
        for key in ("archive", "nightglass", "map", "rooftop", "alley", "blueprint"):
            s.assertNotIn(key, choices)
        s.assertIn("paper", choices)
        U.cfg.setdefault("set", {}).update(bg="termart", perf="full")
        timer = mock.MagicMock()
        canvas = mock.MagicMock(); canvas.tm = timer; canvas.bgname.return_value = "termart"
        U.Stage.setfps(canvas)
        timer.stop.assert_called_once()
        timer.start.assert_not_called()
    def test_removed_animated_backgrounds_are_retired(s):
        choices = {key for _, key in U.BGS}
        s.assertNotIn("cipher", choices); s.assertNotIn("cipher", U.ANIM)
        s.assertNotIn("sweep", choices); s.assertNotIn("pulse", choices)
        s.assertNotIn("sweep", U.ANIM); s.assertNotIn("pulse", U.ANIM)
        s.assertIn("reels", choices); s.assertIn("reels", U.ANIM)
    def test_animated_backgrounds_are_unique_and_registered(s):
        choices = {key for _, key in U.BGS}
        s.assertEqual(U.ANIM, {"rain", "stars", "aurora", "waves", "bubbles", "grid", "glyphs", "radar", "termlog",
                               "orbit", "scan", "vectors", "datastream", "cipherbars",
                               "glassrain", "reels", "beacon"})
        s.assertTrue(U.ANIM <= choices)
        s.assertEqual(len(U.BGS), len(choices))
    def test_shortcut_warning_and_manual_confirmation_are_distinct(s):
        app = mock.MagicMock()
        app.busy = False
        app.mode = "vault"
        combo = mock.MagicMock()
        combo.currentData.return_value = "wipe"
        U.App.set_act(app, combo)
        app.put.assert_called_once_with("hk_act", "wipe")
        with mock.patch.object(U, "S", side_effect=lambda key: {
                "hk_act": "wipe", "hk_notice": True}.get(key, False)), \
             mock.patch.object(U.QMessageBox, "information") as notice:
            U.App.hotkey(app)
        notice.assert_called_once()
        app.panic.assert_called_once_with(False)
        app.confirm_panic.assert_not_called()
        app.panic.reset_mock()
        app.confirm_panic.reset_mock()
        with mock.patch.object(U, "S", side_effect=lambda key: {
                "hk_act": "wipe", "hk_notice": False}.get(key, False)), \
             mock.patch.object(U.QMessageBox, "information") as notice:
            U.App.hotkey(app)
        notice.assert_not_called()
        app.panic.assert_called_once_with(False)
        app.confirm_panic.assert_not_called()
    def test_retired_backgrounds_and_particle_settings_migrate(s):
        for retired in ("fire", "embers", *U.RETIRED_BGS):
            U.cfg["set"] = {"bg": retired, "spark": "fire", "trail": True, "csparks": True, "btnfx": True}
            U.normalize_look_settings()
            s.assertEqual(U.S("bg"), "termlog")
        s.assertFalse({"spark", "trail", "csparks", "btnfx"} & set(U.cfg["set"]))
    def test_available_unique_backgrounds_remain_selected(s):
        choices = {key for _, key in U.BGS}
        for background in choices:
            U.cfg["set"] = {"bg": background}
            U.normalize_look_settings()
            s.assertEqual(U.S("bg"), background)
            s.assertIn(background, choices)
    def test_lock_and_panic_visuals_use_terminal_sequences(s):
        app = mock.MagicMock()
        app.mode = "vault"
        app.busy = False
        app.defer_seal_action.return_value = False
        app.dying = []
        app.dlg = None
        app.studio = None
        app.cards = {}
        app.cds = {}
        with mock.patch.object(U, "S", side_effect=lambda key: {
                "wipefx": "full", "clip": False, "ghost": False}.get(key, False)), \
             mock.patch.object(U, "perf", return_value="normal"), \
             mock.patch.object(U, "LockSequence") as lock_sequence:
            U.App.lock(app, True)
        lock_sequence.assert_called_once_with(app)
        app.login_screen.assert_called_once_with()

        app = mock.MagicMock()
        app.busy = False
        app.defer_seal_action.return_value = False
        with mock.patch.object(U, "S", return_value="full"), \
             mock.patch.object(U, "begin_destructive_cleanup") as begin, \
             mock.patch.object(U, "PanicSequence") as panic_sequence:
            U.App.panic(app, ask=False)
        begin.assert_called_once_with("panic-wipe")
        panic_sequence.assert_called_once_with(app, app.wipe_all, "full")

@unittest.skipUnless(REAL_QT, "requires PyQt5 for real viewer widget coverage")
class TestViewerWidgets(Base):
    def setUp(s):
        super().setUp()
        s.app = qt_test_application()
    def test_warden_sequence_is_parented_to_main_window(s):
        parent = U.QWidget()
        warden = U.Warden(lambda: None, parent)
        try:
            s.assertIs(warden.parentWidget(), parent)
            s.assertFalse(warden.isWindow())
        finally:
            warden.tm.stop()
            parent.close()
            parent.deleteLater()
    def test_fast_deletion_does_not_flash_progress_window(s):
        parent = U.QWidget()
        progress = U.Upload(parent)
        try:
            s.assertIs(progress.parentWidget(), parent)
            s.assertFalse(progress.isWindow())
            progress.show_after(1000)
            timer = progress._show_timer
            assert timer is not None
            progress.finish("Removed from vault.")
            s.assertFalse(progress.isVisible())
            s.assertFalse(timer.isActive())
        finally:
            progress.close()
            parent.close()
            parent.deleteLater()
    def test_tired_theme_renders_the_supplied_photo_asset(s):
        old_set = U.cfg.get("set")
        U.cfg["set"] = dict(U.DEF, bg="tiredfield", th="tired", perf="min")
        stage = U.Stage()
        try:
            stage.resize(320, 180)
            stage.show()
            s.app.processEvents()
            s.assertIsNotNone(stage.tired_image)
            assert stage.tired_image is not None
            s.assertFalse(stage.tired_image.isNull())
            s.assertIsNotNone(stage.tired_scaled)
        finally:
            stage.tm.stop()
            stage.deleteLater()
            if old_set is None:
                U.cfg.pop("set", None)
            else:
                U.cfg["set"] = old_set
    def test_vault_multi_selection_toolbar_tracks_selection_and_clear(s):
        window = U.App.__new__(U.App)
        U.QWidget.__init__(window)
        s.addCleanup(window.deleteLater)
        item = U.QFrame(window)
        checkbox = U.QCheckBox(item)
        window.cards = {"0123456789ab": item}
        window.selected_items = set()
        window.ro = False
        window._syncing_selection = False
        window.move_dialog = None
        window.seal_dialog = None
        window.vault_analysis_dialog = None
        window.package_dialog = None
        window.selection_toolbar = U.QWidget(window)
        window.selection_label = U.QLabel()
        window.select_visible = U.QCheckBox()
        keys = ("view", "group", "rename", "config", "clear", "delete")
        window.bulk_buttons = {key: U.QPushButton() for key in keys}

        U.App.set_item_selected(window, "0123456789ab", True)
        s.assertEqual(window.selection_label.text(), "1 selected")
        s.assertTrue(window.bulk_buttons["delete"].isEnabled())
        s.assertTrue(window.bulk_buttons["rename"].isEnabled())
        U.App.clear_item_selection(window)
        s.assertEqual(window.selected_items, set())
        s.assertFalse(checkbox.isChecked())
        s.assertFalse(window.bulk_buttons["delete"].isEnabled())
    def test_operation_center_displays_the_shared_what_changed_report(s):
        operation = U.OPERATION_MANAGER.create("Report integration")
        operation.start()
        operation.complete()
        operation.report_result(
            "seal_file", affected_items=("private-item",),
            succeeded_items=("private-item",), verified_items=("private-item",),
            committed_items=("private-item",), recovered_items=("private-item",))
        parent = U.QWidget()
        dialog = U.OperationCenterDialog(parent)
        try:
            item = dialog.operations.currentItem()
            assert item is not None
            item.setData(U.Qt.ItemDataRole.UserRole, operation.operation_id)
            dialog._selection_changed(item, None)
            text = dialog.details.toPlainText()
            s.assertIn("WHAT CHANGED", text)
            s.assertIn("Requested: seal_file", text)
            s.assertIn("Affected: 1", text)
            s.assertIn("Verified: 1", text)
            s.assertIn("Committed: 1", text)
            s.assertIn("Recovered: 1", text)
            s.assertIn("Reporting incomplete: no", text)
            s.assertNotIn("private-item", text)
        finally:
            dialog.close()
            dialog.deleteLater()
            parent.deleteLater()
    def test_file_inspector_rejects_stale_authoritative_state(s):
        rid = "stale-inspector-" + os.urandom(6).hex()
        key = "inspector-test:" + rid
        state = U.FILE_STATE_MANAGER.register(key)
        U.FILE_STATE_MANAGER.lock_available(key, state.revision)

        class Card:
            _file_state_revision = state.revision

        class Dummy:
            mode = "vault"
            root = b"authenticated-root"
            cards = {rid: Card()}
            def sec_ok(self): return True
            def _vault_file_state_key(self, _rid): return key

        U.idx[rid] = {
            "s": U.b64e(os.urandom(16)), "nm": U.b64e(os.urandom(32)),
            "size": 1, "exp": None, "views": None,
        }
        with mock.patch.object(U.QMessageBox, "warning") as warning, \
             mock.patch.object(U.QMessageBox, "information") as information:
            U.App.inspect_vault_item(Dummy(), rid)
        warning.assert_called_once()
        information.assert_not_called()
    def test_vault_folder_header_minimizes_and_selects_all_members(s):
        window = U.App.__new__(U.App); U.QWidget.__init__(window)
        s.addCleanup(window.deleteLater)
        container = U.QWidget(window)
        window.rows = U.QVBoxLayout(container)
        window.cards = {}
        window.selected_items = set()
        window._syncing_selection = False
        window.search_edit = U.QLineEdit()
        window.empty = U.QLabel()
        window.no_results = U.QLabel()
        for rid in ("aaaaaaaaaaaa", "bbbbbbbbbbbb"):
            card = U.Card()
            card.rid = rid
            card.name = f"{rid[0]}.txt"
            card.meta = {"s": "", "nm": "", "size": 1, "exp": None,
                         "views": None, "group": "Notes"}
            card.filter_text = card.name
            card.setObjectName("card")
            U.QCheckBox(card)
            window.cards[rid] = card

        U.App.apply_vault_sort(window)
        s.assertIn("notes", window._group_header_checks)
        U.App.set_group_items_selected(window, "notes", True)
        s.assertEqual(window.selected_items, set(window.cards))
        window._group_collapse_buttons["notes"].click()
        s.assertTrue(all(card.isHidden() for card in window.cards.values()))
        s.assertEqual(window._group_collapse_buttons["notes"].text(), "Expand")
        window._group_collapse_buttons["notes"].click()
        s.assertTrue(all(not card.isHidden() for card in window.cards.values()))
        s.assertEqual(window._group_collapse_buttons["notes"].text(), "Minimize")
        window._group_collapse_buttons["notes"].click()
        s.assertTrue(all(card.isHidden() for card in window.cards.values()))
        U.App.apply_vault_sort(window)
        s.assertFalse(window._group_headers_by_key["notes"].isHidden())
        s.assertEqual(window._group_collapse_buttons["notes"].text(), "Expand")
        window._group_collapse_buttons["notes"].click()
        s.assertTrue(all(not card.isHidden() for card in window.cards.values()))
        U.App.set_group_items_selected(window, "notes", False)
        s.assertEqual(window.selected_items, set())
    def test_rebuilding_vault_clears_deleted_folder_header_references(s):
        window = U.App.__new__(U.App); U.QWidget.__init__(window)
        s.addCleanup(window.deleteLater)
        stale_header = U.QFrame(window)
        stale_header.deleteLater()
        window.cards = {}
        window.empty = U.QLabel()
        window.no_results = U.QLabel()
        window.search_edit = U.QLineEdit()
        window._group_headers = [stale_header]
        window._group_headers_by_key = {"old": stale_header}
        window._group_header_members = {"old": ()}
        window._group_header_checks = {}
        window._group_collapse_buttons = {}
        window._collapsed_groups = {"old"}
        flush_deferred_deletes()
        with s.assertRaisesRegex(RuntimeError, "deleted"):
            U.App.apply_vault_filter(window)
        U.App.reset_vault_group_widgets(window)
        U.App.apply_vault_filter(window)
        s.assertEqual(window._group_headers, [])
        s.assertEqual(window._group_headers_by_key, {})
        s.assertEqual(window._group_header_members, {})
        s.assertEqual(window._collapsed_groups, {"old"})
    def test_seal_jobs_are_started_in_fifo_order_one_at_a_time(s):
        window = U.App.__new__(U.App); U.QWidget.__init__(window)
        s.addCleanup(window.deleteLater)
        window.mode = "vault"; window.root = os.urandom(32); window.ro = False
        window._seal_queue = []; window._seal_queue_active = False
        window._seal_active_cleanup = None; window.seal_dialog = None
        window._pending_seal_action = None; window.cards = {}
        window.refresh_vault_item_actions = mock.Mock()
        started = []; dialogs = []; completed = []

        class QueueDialog:
            def __init__(self, _app, worker, on_finished, title, **_kwargs):
                self.worker = worker
                self.on_finished = on_finished
                self.title = title
                self.is_running = True
                dialogs.append(self)
            def set_queued_count(self, count):
                self.queued_count = count
            def show(self):
                pass

        def finished(index):
            def callback(result):
                completed.append(index)
                U.App._seal_queue_job_finished(window)
            return callback

        def factory():
            return U._SealWorker((), window.root, {}, 0, 0, False, 0, True)

        with mock.patch.object(U, "_SealProgressDialog", QueueDialog), \
             mock.patch.object(U, "_start_qrunnable", side_effect=started.append), \
             mock.patch.object(U.QTimer, "singleShot", side_effect=lambda _delay, callback: callback()):
            U.App._queue_seal_job(window, "first job", window.root, factory, finished(1))
            U.App._queue_seal_job(window, "second job", window.root, factory, finished(2))
            s.assertEqual(len(started), 1)
            s.assertEqual(dialogs[0].title, "first job")
            s.assertEqual(dialogs[0].queued_count, 1)
            dialogs[0].on_finished({"status": "completed"})
            s.assertEqual(completed, [1])
            s.assertEqual(len(started), 2)
            s.assertEqual(dialogs[1].title, "second job")
            dialogs[1].on_finished({"status": "completed"})
        s.assertEqual(completed, [1, 2])
        s.assertEqual(window._seal_queue, [])
        s.assertFalse(window._seal_queue_active)
    def test_limited_item_decrypt_action_does_not_export_and_closes_preview_only(s):
        viewer = U.Viewer("limited.txt", b"limited note contents", False, None,
                          limited_access=True)
        s.addCleanup(viewer.close)
        viewer.show()
        s.assertIsNotNone(viewer.sv)
        assert viewer.sv is not None
        s.assertEqual(viewer.sv.text(), "Decrypt")
        viewer.sv.click()
        s.app.processEvents()
        notices = viewer.findChildren(U.QDialog)
        s.assertEqual(len(notices), 1)
        notice = notices[0]
        s.assertIn("HAHAHAAH GET FOOLED", "\n".join(
            label.text() for label in notice.findChildren(U.QLabel)))
        timer = notice.findChild(U.QTimer)
        s.assertIsNotNone(timer)
        assert timer is not None
        timer.timeout.emit()
        s.app.processEvents()
        s.assertFalse(viewer.isVisible())
        s.assertFalse(notice.isVisible())
    def test_vault_search_easter_egg_commands_require_explicit_prefix(s):
        window = U.App.__new__(U.App); U.QWidget.__init__(window)
        s.addCleanup(window.deleteLater)
        window.mode = "vault"
        window.act = time.time()
        window.search_edit = U.QLineEdit()
        window.search_edit.textEdited.connect(window.handle_vault_search_command)
        with mock.patch.object(window, "show_meow_easter_egg") as show_photo, \
             mock.patch.object(U.QMessageBox, "information") as information:
            window.search_edit.setText("!MEOW")
            window.search_edit.textEdited.emit("!MEOW")
            show_photo.assert_called_once()
            s.assertEqual(window.search_edit.text(), "")
            window.search_edit.setText(" !SeCrEt ")
            window.search_edit.textEdited.emit(" !SeCrEt ")
            information.assert_called_once_with(
                window, "UNKNWN // SECRET",
                "so uhm , contact this user on telegram : unknown1soldier")
            s.assertEqual(window.search_edit.text(), "")
            window.search_edit.setText("secret")
            window.search_edit.textEdited.emit("secret")
            show_photo.assert_called_once()
            information.assert_called_once()
            s.assertEqual(window.search_edit.text(), "secret")
            for character in "MEOW":
                event = mock.Mock(
                    type=lambda: U.QEvent.Type.KeyPress,
                    key=lambda: U.Qt.Key.Key_unknown,
                )
                U.App.eventFilter(window, None, event)
            show_photo.assert_called_once()
    def test_file_inspector_uses_authenticated_metadata_without_opening_plaintext(s):
        window = U.App.__new__(U.App); U.QWidget.__init__(window)
        s.addCleanup(window.deleteLater)
        root = os.urandom(32)
        salt = os.urandom(16)
        rid = os.urandom(6).hex()
        metadata = {
            "s": U.b64e(salt),
            "nm": U.b64e(U.seal(U.file_key(root, salt), b"report.pdf")),
            "size": 123,
            "exp": None,
            "views": 2,
            "group": "Documents",
        }
        old_index = dict(U.idx)
        U.idx.clear()
        U.idx[rid] = metadata
        s.addCleanup(lambda: (U.idx.clear(), U.idx.update(old_index)))
        old_set = U.cfg.get("set")
        U.cfg["set"] = dict(U.DEF, mask=False)
        def restore_settings():
            if old_set is None:
                U.cfg.pop("set", None)
            else:
                U.cfg["set"] = old_set
        s.addCleanup(restore_settings)
        card = U.QFrame()
        card.name = "report.pdf"
        state_key = "inspector-test:" + rid
        state = U.FILE_STATE_MANAGER.register(state_key)
        card._file_state_revision = state.revision
        window.mode = "vault"
        window.root = root
        window.cards = {rid: card}
        window._vault_file_state_key = lambda _rid: state_key
        window.sec_ok = mock.Mock(return_value=True)
        with tempfile.TemporaryDirectory() as directory:
            ciphertext = Path(directory) / "item.cdr"
            ciphertext.write_bytes(b"TOP SECRET CONTENTS")
            with mock.patch.object(U, "_storage_file_path", return_value=ciphertext), \
                 mock.patch.object(U.QMessageBox, "information") as information:
                U.App.inspect_vault_item(window, rid)
        output = information.call_args.args[2]
        s.assertIn("Name: report.pdf", output)
        s.assertIn("Type: pdf", output)
        s.assertIn("Documents", output)
        s.assertIn("2 view(s)", output)
        s.assertIn("not rechecked by this view", output)
        s.assertNotIn("TOP SECRET CONTENTS", output)
    def test_command_palette_filters_and_executes_local_action(s):
        parent = U.QWidget()
        s.addCleanup(parent.deleteLater)
        action = mock.Mock()
        dialog = U.CommandPaletteDialog(
            parent, [("Open Settings", "settings appearance", action),
                     ("Open Vault", "vault", mock.Mock())])
        s.addCleanup(dialog.close)
        s.assertEqual(dialog.results.count(), 2)
        dialog.show()
        s.app.processEvents()
        dialog.search.setText("appearance")
        s.assertEqual(dialog.results.count(), 1)
        first_result = dialog.results.item(0)
        s.assertIsNotNone(first_result)
        assert first_result is not None
        s.assertEqual(first_result.text(), "Open Settings")
        down = mock.Mock(type=lambda: U.QEvent.Type.KeyPress,
                         key=lambda: U.Qt.Key.Key_Down)
        s.assertTrue(dialog.eventFilter(dialog.search, down))
        s.assertIs(U.QApplication.focusWidget(), dialog.results)
        dialog.activate_current()
        s.app.processEvents()
        action.assert_called_once_with()
        dialog.search.clear()
        s.assertEqual(dialog.results.count(), 2)
        dialog.search.setText("no matching action")
        s.assertEqual(dialog.results.count(), 0)
    def test_command_palette_respects_masked_vault_names(s):
        window = U.App.__new__(U.App); U.QWidget.__init__(window)
        s.addCleanup(window.deleteLater)
        old_set = U.cfg.get("set")
        U.cfg["set"] = dict(U.DEF, mask=True)
        s.addCleanup(lambda: U.cfg.pop("set", None) if old_set is None
                     else U.cfg.__setitem__("set", old_set))
        item = U.QFrame(window)
        item.rid = "0123456789ab"
        item.name = "private-report.txt"
        item.meta = {"size": 5, "exp": None, "views": None, "group": "Private group"}
        item.filter_text = U.vault_search_text(
            item.rid, item.name, "TXT / 5 B / Unlimited views / GROUPED", True)
        window.mode = "vault"
        window.cards = {item.rid: item}
        with mock.patch.object(U, "_read_profiles", return_value=[]), \
             mock.patch.object(U.OPERATION_MANAGER, "snapshots", return_value=[]):
            U.App.open_command_palette(window)
        s.addCleanup(window.command_palette.close)
        visible_labels = []
        for index in range(window.command_palette.results.count()):
            result = window.command_palette.results.item(index)
            s.assertIsNotNone(result)
            assert result is not None
            visible_labels.append(result.text())
        s.assertTrue(any("Hidden item" in label for label in visible_labels))
        s.assertFalse(any("private-report.txt" in label for label in visible_labels))
        s.assertFalse(any("Private group" in label for label in visible_labels))
    def test_vault_avatar_is_encrypted_and_rendered_as_a_circular_crop(s):
        window = U.App.__new__(U.App); U.QWidget.__init__(window)
        s.addCleanup(window.deleteLater)
        window.root = os.urandom(32)
        U.cfg["set"] = dict(U.DEF, avatar_crop="left")
        source = U.QPixmap(40, 20)
        source.fill(U._QC("red"))
        painter = U.QPainter(source)
        painter.fillRect(20, 0, 20, 20, U._QC("blue"))
        painter.end()
        buffer = U.QBuffer()
        s.assertTrue(buffer.open(U.QIODevice.OpenModeFlag.WriteOnly))
        s.assertTrue(source.save(buffer, "PNG"))
        image_data = bytes(buffer.data())
        buffer.close()

        U.App._write_vault_avatar(window, image_data)
        stored = U.App.vault_avatar_path(window).read_bytes()
        s.assertTrue(stored.startswith(U._AVATAR_MAGIC))
        s.assertNotIn(image_data, stored)
        s.assertEqual(U.App._vault_avatar_data(window), image_data)
        avatar = U.App.avatar_label(window, 40)
        s.addCleanup(avatar.deleteLater)
        pixmap = avatar.pixmap()
        assert pixmap is not None
        rendered = pixmap.toImage()
        s.assertEqual(rendered.pixelColor(0, 0).alpha(), 0)
        s.assertGreater(rendered.pixelColor(20, 20).red(), rendered.pixelColor(20, 20).blue())

        U.cfg["set"]["avatar_crop"] = "right"
        right_avatar = U.App.avatar_label(window, 40)
        s.addCleanup(right_avatar.deleteLater)
        right_pixmap = right_avatar.pixmap()
        assert right_pixmap is not None
        right_center = right_pixmap.toImage().pixelColor(20, 20)
        s.assertGreater(right_center.blue(), right_center.red())
    def test_profile_photo_refresh_handles_profiles_without_an_avatar(s):
        qt_test_application()
        window = U.App.__new__(U.App); U.QWidget.__init__(window)
        s.addCleanup(window.deleteLater)
        window.root = None
        U.cfg["set"] = dict(U.DEF, avatar_crop="center")
        avatar = U.App.avatar_label(window, 40)
        avatar.setParent(window)

        U.App._refresh_profile_photo(window)

        s.assertIsNone(avatar.pixmap())
    def test_duplicate_decisions_show_keep_remove_and_require_a_retained_item(s):
        dialog = U.VaultAnalysisDialog.__new__(U.VaultAnalysisDialog)
        U.QDialog.__init__(dialog)
        s.addCleanup(dialog.deleteLater)
        first, second = os.urandom(6).hex(), os.urandom(6).hex()
        U.idx.clear()
        U.idx.update({first: {"s": "", "nm": "", "size": 1, "exp": None, "views": None},
                      second: {"s": "", "nm": "", "size": 1, "exp": None, "views": None}})
        dialog.duplicate_list = U.QListWidget(dialog)
        dialog.duplicate_list.itemChanged.connect(dialog._duplicate_item_changed)
        dialog.remove_selected_button = U.QPushButton()
        dialog.status = U.QLabel()
        dialog._duplicate_groups = {}
        dialog._duplicate_item_names = {}
        dialog._updating_duplicate_items = False
        dialog._running = False
        U.VaultAnalysisDialog._populate_duplicate_choices(
            dialog, [[{"rid": first, "name": "one.txt"}, {"rid": second, "name": "two.txt"}]])
        s.assertEqual(dialog.duplicate_list.count(), 3)
        first_item, second_item = dialog.duplicate_list.item(1), dialog.duplicate_list.item(2)
        assert first_item is not None
        assert second_item is not None
        s.assertIn("KEEP", first_item.text())
        first_item.setCheckState(U.Qt.CheckState.Checked)
        s.assertIn("REMOVE", first_item.text())
        s.assertTrue(dialog.remove_selected_button.isEnabled())
        second_item.setCheckState(U.Qt.CheckState.Checked)
        s.assertFalse(dialog.remove_selected_button.isEnabled())
        U.idx.clear()
    def test_duplicate_removal_requires_confirmation_and_only_burns_checked_items(s):
        app = U.App.__new__(U.App); U.QWidget.__init__(app)
        s.addCleanup(app.deleteLater)
        app.root = os.urandom(32)
        app.dying = set()
        app.working = mock.Mock(return_value=False)
        app.burn = mock.Mock()
        dialog = U.VaultAnalysisDialog.__new__(U.VaultAnalysisDialog)
        U.QDialog.__init__(dialog, app)
        s.addCleanup(dialog.deleteLater)
        first, second = os.urandom(6).hex(), os.urandom(6).hex()
        old_index = dict(U.idx)
        U.idx.clear()
        U.idx.update({first: {"s": "", "nm": "", "size": 1, "exp": None, "views": None},
                      second: {"s": "", "nm": "", "size": 1, "exp": None, "views": None}})
        s.addCleanup(lambda: (U.idx.clear(), U.idx.update(old_index)))
        dialog.duplicate_list = U.QListWidget(dialog)
        dialog.duplicate_list.itemChanged.connect(dialog._duplicate_item_changed)
        dialog.remove_selected_button = U.QPushButton()
        dialog.status = U.QLabel()
        dialog._duplicate_groups = {}
        dialog._duplicate_item_names = {}
        dialog._updating_duplicate_items = False
        dialog._running = False
        U.VaultAnalysisDialog._populate_duplicate_choices(
            dialog, [[{"rid": first, "name": "remove.txt"},
                      {"rid": second, "name": "keep.txt"}]])
        remove_item = dialog.duplicate_list.item(1)
        assert remove_item is not None
        remove_item.setCheckState(U.Qt.CheckState.Checked)
        no = U.QMessageBox.StandardButton.No
        with mock.patch.object(U.QMessageBox, "question", return_value=no):
            U.VaultAnalysisDialog.remove_selected_duplicates(dialog)
        app.burn.assert_not_called()
        with mock.patch.object(
                U.QMessageBox, "question",
                return_value=U.QMessageBox.StandardButton.Yes):
            U.VaultAnalysisDialog.remove_selected_duplicates(dialog)
        app.burn.assert_called_once_with(first, ask=False)
    def test_main_window_retains_native_move_maximize_controls(s):
        window = U.QWidget()
        s.addCleanup(window.deleteLater)
        U.configure_main_window_frame(window)
        flags = window.windowFlags()
        s.assertTrue(flags & U.Qt.WindowType.WindowTitleHint)
        s.assertTrue(flags & U.Qt.WindowType.WindowSystemMenuHint)
        s.assertTrue(flags & U.Qt.WindowType.WindowMinimizeButtonHint)
        s.assertTrue(flags & U.Qt.WindowType.WindowMaximizeButtonHint)
        s.assertTrue(flags & U.Qt.WindowType.WindowCloseButtonHint)

    def test_ghost_mode_refreshes_window_style_without_hiding_window(s):
        user32 = mock.MagicMock()
        user32.GetWindowLongW.return_value = 0x40000
        window = mock.MagicMock()
        window.winId.return_value = 123
        settings = {"ghost": True, "nocap": False}
        with mock.patch.object(U, "S", side_effect=lambda key: settings[key]), \
                mock.patch.object(U, "nocap"), \
                mock.patch.object(U.sys, "platform", "win32"), \
                mock.patch.object(U.ctypes, "windll", mock.MagicMock(user32=user32), create=True):
            U.App.ghost_apply(window)
        user32.SetWindowLongW.assert_called_once_with(123, -20, 0x80)
        user32.SetWindowPos.assert_called_once_with(
            123, 0, 0, 0, 0, 0, U.WINDOW_FRAME_REFRESH_FLAGS)
        window.hide.assert_not_called()
        window.show.assert_not_called()

    def test_operation_center_uses_active_dark_palette(s):
        parent = U.QWidget()
        s.addCleanup(parent.deleteLater)
        dialog = U.OperationCenterDialog(parent)
        s.addCleanup(dialog.close)
        stylesheet = dialog.styleSheet()
        s.assertIn(U.TH["bg0"], stylesheet)
        s.assertIn(U.TH["fg"], stylesheet)
        s.assertIn(U.TH["field"], stylesheet)
    def test_seal_progress_popup_is_movable_nonmodal_with_pause_cancel_and_auto_close(s):
        worker = U._SealWorker((), os.urandom(32), {}, 0, 0, False, 0, True)
        parent = U.QWidget()
        s.addCleanup(parent.deleteLater)
        completed = mock.Mock()
        dialog = U._SealProgressDialog(parent, worker, completed)
        s.addCleanup(dialog.close)
        dialog.show()
        s.app.processEvents()

        s.assertFalse(dialog.isModal())
        s.assertEqual(dialog.windowModality(), U.Qt.WindowModality.NonModal)
        s.assertTrue(dialog.windowFlags() & U.Qt.WindowType.WindowSystemMenuHint)
        s.assertTrue(dialog.windowFlags() & U.Qt.WindowType.WindowCloseButtonHint)
        s.assertTrue(dialog.isVisible())
        s.assertTrue(dialog.pause_button.isEnabled())
        with mock.patch.object(U.QMessageBox, "warning"):
            dialog.toggle_pause()
        s.assertFalse(worker.resume_event.is_set())
        s.assertEqual(dialog.pause_button.text(), "Resume")
        dialog.toggle_pause()
        s.assertTrue(worker.resume_event.is_set())
        s.assertEqual(dialog.pause_button.text(), "Pause")

        dialog.finish({"status": "completed", "records": [], "failures": [], "completed": 0, "total": 0})
        s.assertFalse(dialog.is_running)
        s.assertTrue(dialog.isVisible())
        s.assertEqual(dialog.cancel_button.text(), "Close")
        s.assertIn("Encryption complete", dialog.status.text())
        s.assertIn("automatically", dialog.status.text())
        completed.assert_called_once()
    def test_file_sealing_runs_while_unrelated_main_window_controls_remain_usable(s):
        source = s.d / "background-source.bin"
        source.write_bytes(os.urandom(4096))
        window = U.App.__new__(U.App); U.Stage.__init__(window)
        window.ro = False
        window.root = os.urandom(32)
        window.mode = "vault"
        window.hold = 0
        window.dying = set()
        window._seal_queue = []
        window._seal_queue_active = False
        window._seal_active_cleanup = None
        window.seal_dialog = None
        window._pending_seal_action = None
        window.sec_ok = mock.Mock(return_value=True)
        window.ex = mock.Mock()
        window.ex.currentData.return_value = 0
        window.vw = mock.Mock()
        window.vw.currentData.return_value = 0
        window.rm = mock.Mock()
        window.rm.isChecked.return_value = False
        card = U.QWidget(window)
        view_action = U.QPushButton("View", card)
        burn_action = U.QPushButton("Burn", card)
        window.cards = {"record": card}
        window.refresh_vault_item_actions = lambda: U.App.refresh_vault_item_actions(window)
        results = []
        def finished(result):
            results.append(result)
            U.App._seal_queue_job_finished(window)
        window.finish_seal_operation = finished
        unrelated_action = U.QPushButton("Unrelated")
        unrelated_action.setParent(window)
        clicked = []
        unrelated_action.clicked.connect(lambda: clicked.append(True))

        def dispose_window():
            window.hide()
            window.deleteLater()

        started = threading.Event()
        resume_encryption = threading.Event()
        original_enc_file = U.enc_file

        def pause_worker(src, dst, key, progress, cancel, on_stage_created=None, resume=None):
            started.set()
            if not resume_encryption.wait(5):
                raise TimeoutError("test worker was not released")
            return original_enc_file(src, dst, key, progress, cancel, on_stage_created, resume)

        window.show()
        s.addCleanup(dispose_window)
        try:
            with mock.patch.object(U, "terminal_confirm", return_value=True), \
                 mock.patch.object(U, "enc_file", side_effect=pause_worker):
                U.App.add_files(window, [source])
                dialog = window.seal_dialog
                s.assertTrue(started.wait(3), "encryption worker did not start")
                s.assertIsNotNone(dialog)
                s.assertFalse(dialog.isModal())
                s.assertTrue(dialog.isVisible())
                s.assertFalse(view_action.isEnabled())
                s.assertFalse(burn_action.isEnabled())
                s.assertIn("Unavailable while encryption", view_action.toolTip())
                unrelated_action.click()
                s.assertEqual(clicked, [True])

                resume_encryption.set()
                deadline = time.monotonic() + 5
                while not results and time.monotonic() < deadline:
                    s.app.processEvents()
                    time.sleep(.01)
                s.assertEqual(len(results), 1, "background completion was not delivered")
                s.assertEqual(results[0]["status"], "completed")
                s.assertTrue(dialog.isVisible())
                s.assertIn("Encryption complete", dialog.status.text())
                U.App.refresh_vault_item_actions(window)
                s.assertTrue(view_action.isEnabled())
                s.assertTrue(burn_action.isEnabled())
                dialog.close()
        finally:
            resume_encryption.set()
            s.app.processEvents()
    def settings_widget(s):
        widget = U.App.__new__(U.App); U.QWidget.__init__(widget)
        widget.ro = False; widget.owner = True; widget.mode = "vault"; widget.root = None
        widget.lock_ui = lambda _layout: None; widget.pop = lambda *_args, **_kwargs: None
        widget.refresh_shortcut_status = lambda: None
        widget.record_session_event = lambda *_args, **_kwargs: None
        widget.settings_undo_stack = []; widget.settings_redo_stack = []
        widget.push_settings_history = lambda _changes: None
        widget.refresh_settings_history_controls = lambda: None
        widget.put = lambda key, value: U.cfg.setdefault("set", {}).__setitem__(key, value)
        return widget
    def test_settings_search_aliases_and_per_setting_reset(s):
        U.cfg["set"] = dict(U.DEF, mask=True, hk_notice=False)
        widget = s.settings_widget(); s.addCleanup(s.app.processEvents); s.addCleanup(widget.deleteLater)
        with mock.patch.object(U, "active_profile_id", None):
            page = U.App.build_settings(widget)
        page.show(); s.app.processEvents(); s.addCleanup(page.deleteLater)
        search = page.findChild(U.QLineEdit, "settingsSearch")
        s.assertIsNotNone(search)
        search.setText("session timeout"); s.app.processEvents()
        cards: dict[str, U.QFrame] = {}
        for card in page.findChildren(U.QFrame):
            if card.objectName() != "card":
                continue
            title = card.findChild(U.QLabel)
            cards[title.text()] = card
        s.assertFalse(cards["Security & self-destruct"].isHidden())
        s.assertNotIn("Advanced privacy", cards)
        s.assertFalse(cards["Privacy"].isHidden())
        s.assertTrue(any(label.text() == "ADVANCED PRIVACY"
                         for label in cards["Privacy"].findChildren(U.QLabel)))
        search.setText("mask file names"); s.app.processEvents()
        privacy = cards["Privacy"]
        mask = next(control for control in privacy.findChildren(U.QCheckBox)
                    if control.text() == "Mask file names in the list")
        def find_reset_button(section: U.QFrame, control: U.QWidget) -> U.QPushButton:
            section_layout = section.layout()
            if section_layout is None:
                raise AssertionError("Settings section has no layout.")
            for index in range(section_layout.count()):
                section_item = section_layout.itemAt(index)
                if section_item is None:
                    continue
                row = section_item.layout()
                if row is None:
                    continue
                control_item = row.itemAt(0)
                reset_item = row.itemAt(2)
                if control_item is None or reset_item is None:
                    continue
                if control_item.widget() is control:
                    reset = reset_item.widget()
                    if isinstance(reset, U.QPushButton):
                        return reset
            raise AssertionError("Could not find the setting's Reset button.")

        reset = find_reset_button(privacy, mask)
        s.assertFalse(reset.isHidden())
        reset.click()
        s.assertFalse(U.cfg["set"]["mask"])
        s.assertIn("hk_notice", U.PROTKEYS)
        s.assertIn("hk_notice", U.SECKEYS)
        shortcut_section = cards["Shortcut manager"]
        notice_setting = next(control for control in shortcut_section.findChildren(U.QCheckBox)
                              if control.text() == "Show a notice when the panic shortcut is used")
        s.assertFalse(notice_setting.isChecked())
        notice_reset = find_reset_button(shortcut_section, notice_setting)
        with mock.patch.object(U, "terminal_confirm", return_value=False) as confirm:
            notice_reset.click()
        confirm.assert_called_once()
        s.assertFalse(U.cfg["set"]["hk_notice"])
        s.assertTrue(U.DEF["hk_notice"])
    def test_security_failure_animation_is_persistent_and_looping(s):
        parent = U.QWidget()
        indicator = U.SecurityFailurePulse(parent)
        s.addCleanup(parent.deleteLater)
        s.addCleanup(indicator.deleteLater)
        s.addCleanup(indicator.animation.stop)
        s.assertEqual(indicator.text(), "STARTUP BLOCKED")
        s.assertEqual(indicator.animation.loopCount(), -1)
        s.assertIsInstance(indicator.graphicsEffect(), U.QGraphicsOpacityEffect)
        s.assertEqual(
            indicator.animation.state(),
            U._QtCore.QAbstractAnimation.State.Running,
        )
    def test_overview_dashboard_widgets_follow_profile_preferences(s):
        app = mock.MagicMock()
        app.working.return_value = False; app.session_activity = []; app.ro = False
        values = {"dash_session": False, "dash_look": True, "dash_privacy": False}
        get_setting = U.S
        def setting(key):
            return values[key] if key in values else get_setting(key)
        with mock.patch.object(U, "S", side_effect=setting):
            page = U.App.build_changes(app)
        labels = [label.text() for label in page.findChildren(U.QLabel)]
        s.assertNotIn("ACTIVE VAULT SESSION", labels)
        s.assertIn("CURRENT LOOK", labels)
        s.assertNotIn("PRIVACY & HISTORY", labels)

    def test_long_buttons_wrap_to_fit_narrow_windows(s):
        control = U.btn("FULL SELF-DESTRUCT: erase everything, delete UNKNWN, restart PC")
        control.resize(125, 38); s.app.processEvents()
        s.assertIn("\n", control.text())
        s.assertGreaterEqual(control.minimumHeight(), 38)
        control.close()
    def test_wordmark_alignment_generic_greeting_and_clock(s):
        U.cfg.setdefault("set", {}).update(hideuser=True)
        app = U.App.__new__(U.App); U.QWidget.__init__(app); app.root = None; s.addCleanup(app.deleteLater)
        row = U.App.logo(app); s.addCleanup(row.deleteLater)
        layout = row.layout()
        assert layout is not None
        mark_item = layout.itemAt(1); greeting_item = layout.itemAt(2)
        assert mark_item is not None
        assert greeting_item is not None
        mark = mark_item.widget(); greeting = greeting_item.widget()
        assert isinstance(mark, U.QLabel)
        assert isinstance(greeting, U.QLabel)
        s.assertEqual(mark.alignment(), U.Qt.AlignLeft | U.Qt.AlignVCenter)
        s.assertEqual(greeting.text(), "Hi, operator")
        assert layout.itemAt(4) is None
        clock = U.App.clock_label(app); s.addCleanup(clock.deleteLater)
        s.assertRegex(clock.text(), r"^\d{2}:\d{2}:\d{2}$")
        s.assertEqual(clock.objectName(), "clockBadge")
        sample = "00:00:00" if U.S("clock24") else "00:00:00 PM"
        s.assertEqual(clock.minimumWidth(), U.QFontMetrics(clock.font()).horizontalAdvance(sample) + 30)
        s.assertIn(U.TH["acc"], clock.styleSheet())
        s.assertIn(U.TH["line"], clock.styleSheet())
    def test_clock_click_toggles_persistent_12_and_24_hour_formats(s):
        from PyQt5.QtTest import QTest
        U.cfg["set"] = dict(U.DEF, clock24=True)
        app = U.App.__new__(U.App); U.QWidget.__init__(app); s.addCleanup(app.deleteLater)
        clock = U.App.clock_label(app); s.addCleanup(clock.deleteLater)
        s.assertRegex(clock.text(), r"^\d{2}:\d{2}:\d{2}$")
        QTest.mouseClick(clock, U.Qt.LeftButton)
        s.assertFalse(U.S("clock24"))
        s.assertRegex(clock.text(), r"^\d{2}:\d{2}:\d{2} [AP]M$")
        QTest.mouseClick(clock, U.Qt.LeftButton)
        s.assertTrue(U.S("clock24"))
        s.assertRegex(clock.text(), r"^\d{2}:\d{2}:\d{2}$")
    def test_clock_long_press_hint_explains_the_format_toggle(s):
        clock = U.ClockBadge(lambda: None); s.addCleanup(clock.deleteLater)
        with mock.patch.object(U.QToolTip, "showText") as show:
            clock.show_clock_hint()
        s.assertIn("Change clock format", show.call_args.args[1])
        s.assertIn("12-hour and 24-hour", show.call_args.args[1])
    def test_popup_question_help_describes_buttons_and_password_fields(s):
        dialog = U.QDialog(); dialog.setWindowTitle("Confirm vault action")
        abort = U.QPushButton("ABORT", dialog); execute = U.QPushButton("EXECUTE", dialog)
        password = U.QLineEdit(dialog); password.setEchoMode(U.QLineEdit.Password)
        app = U.App.__new__(U.App)
        U.App.prepare_popup_help(app, dialog)
        s.assertIn("Read its message", dialog.whatsThis())
        s.assertTrue(dialog.windowFlags() & U.Qt.WindowContextHelpButtonHint)
        s.assertIn("without confirming", abort.whatsThis())
        s.assertIn("confirms the action", execute.whatsThis())
        s.assertIn("masked", password.whatsThis())
        dialog.deleteLater()
    def test_profile_switch_sequence_is_a_distinct_skippable_terminal_intro(s):
        parent = U.QWidget(); done = []
        sequence = U.ProfileSwitchSequence(parent, lambda: done.append(True))
        s.addCleanup(parent.deleteLater)
        text = "\n".join(line for line, _, _, _ in sequence.sc)
        s.assertIn("PROFILE SWITCH REQUESTED", text)
        s.assertIn("current profile key", text)
        lock = U.LockSequence(parent); lock.tm.stop(); s.addCleanup(lock.deleteLater)
        s.assertNotEqual(sequence.sc, lock.sc)
        sequence.tm.stop()
        for _ in range(4000):
            if done: break
            sequence.step()
        s.assertEqual(done, [True])
    def test_login_greeting_welcomes_existing_profile_and_respects_name_privacy(s):
        app = U.App.__new__(U.App); app.show_profile_art = mock.Mock()
        with mock.patch.dict(os.environ, {"USERPROFILE": r"C:\Users\operator-name"}):
            U.cfg.setdefault("set", {}).update(hideuser=False)
            greeting = U.App.login_greeting(app); s.addCleanup(greeting.deleteLater)
            s.assertEqual(greeting.text(), "Welcome back, operator-name")
            U.cfg["set"]["hideuser"] = True
            private_greeting = U.App.login_greeting(app); s.addCleanup(private_greeting.deleteLater)
            s.assertEqual(private_greeting.text(), "Welcome back, operator")
    def test_profile_greeting_easter_egg_needs_ten_consecutive_clicks(s):
        reveal = mock.Mock(); greeting = U.ProfileGreeting("Hi, operator", reveal); s.addCleanup(greeting.deleteLater)
        for _ in range(9): greeting.register_click()
        reveal.assert_not_called()
        greeting.register_click()
        reveal.assert_called_once_with()
        s.assertEqual(greeting.click_count, 0)
    def test_activity_filter_and_changes_tab_show_real_state(s):
        U.cfg["set"] = dict(U.DEF)
        app = U.App.__new__(U.App); app.ro = False; app.ap = U.QScrollArea(); app.pop = lambda *_: None; app.log_filter = "all"
        app.session_activity = []; app.session_started = None; app.session_stored_names = []
        app.session_stored_count = 0; app.session_setting_changes = 0; app.session_activity_omitted = 0
        app.open_health_center = mock.Mock(); app.open_diagnostics_center = mock.Mock(); app.look_studio = mock.Mock()
        app.switch_profile = mock.Mock()
        app.tab = mock.Mock(); app.working = lambda: False
        app.logs = lambda: [{"t": 100, "ok": True, "how": "password", "ro": False},
                            {"t": 200, "ok": False, "attempt": 2}]
        app.set_log_filter = lambda value: U.App.set_log_filter(app, value)
        app.ap.setWidget(U.App.build_log(app))
        log_view = app.ap.widget()
        assert log_view is not None
        selector = log_view.findChild(U.QComboBox); assert isinstance(selector, U.QComboBox)
        selector.setCurrentIndex(selector.findData("failed")); s.app.processEvents()
        current_log_view = app.ap.widget()
        assert current_log_view is not None
        labels = [item.text() for item in current_log_view.findChildren(U.QLabel)]
        s.assertTrue(any("Authentication failed" in text for text in labels))
        s.assertFalse(any("Authentication succeeded" in text for text in labels))
        changes = U.App.build_changes(app)
        notes = [item.text() for item in changes.findChildren(U.QLabel)]
        s.assertTrue(any("SYSTEM OVERVIEW" in text for text in notes))
        s.assertTrue(any("ACTIVE VAULT SESSION" in text for text in notes))
        s.assertTrue(any("Background:" in text for text in notes))
        s.assertTrue(any("Standard access" in text for text in notes))
        s.assertTrue(any("Current session events: 0" in text for text in notes))
        s.assertTrue(any("Switch profile locks this vault" in text for text in notes))
        s.assertTrue(any("Click the clock to switch" in text for text in notes))
        buttons = {item.text(): item for item in changes.findChildren(U.QPushButton)}
        buttons["Vault Health Center"].click()
        app.open_health_center.assert_called_once_with()
        buttons["Diagnostics Center"].click()
        app.open_diagnostics_center.assert_called_once_with()
        buttons["Look Studio"].click()
        app.look_studio.assert_called_once_with()
        buttons["Switch profile"].click()
        app.switch_profile.assert_called_once_with()
        buttons["Settings"].click()
        app.tab.assert_called_once_with(1)
    def test_activity_center_summarizes_session_files_and_setting_changes(s):
        U.cfg["set"] = dict(U.DEF)
        app = U.App.__new__(U.App); app.ro = False; app.ap = U.QScrollArea(); app.pop = lambda *_: None; app.log_filter = "all"
        app.logs = lambda: []; app.combo = lambda items: U.App.combo(app, items); app.set_log_filter = lambda *_: None
        app.session_started = time.time() - 42; app.session_activity_omitted = 0
        app.session_stored_names = ["north.png", "notes.txt"]; app.session_stored_count = 2; app.session_setting_changes = 1
        app.session_activity = [
            {"t": time.time() - 40, "kind": "vault_unlocked", "method": "password"},
            {"t": time.time() - 20, "kind": "files_stored", "count": 2, "names": ["north.png", "notes.txt"]},
            {"t": time.time() - 10, "kind": "setting_changed", "key": "bg", "before": "rain", "after": "sweep"},
        ]
        view = U.App.build_log(app); s.addCleanup(view.deleteLater)
        labels = [item.text() for item in view.findChildren(U.QLabel)]
        text = "\n".join(labels)
        s.assertIn("ACTIVITY CENTER", text)
        s.assertIn("Vault items stored this session: 2", text)
        s.assertIn("north.png", text); s.assertIn("notes.txt", text)
        s.assertIn("Settings changed this session: 1", text)
        backgrounds = {key: title for title, key in U.BGS}
        s.assertIn(f"Background: {backgrounds['rain']} -> Sweep lamp (retired)", text)
        s.assertNotIn("SENSITIVE_FILE_CONTENT", text)
    def test_activity_center_respects_hidden_names_and_counts(s):
        U.cfg["set"] = dict(U.DEF, mask=True, hidecnt=True)
        app = U.App.__new__(U.App); app.ro = False; app.ap = U.QScrollArea(); app.pop = lambda *_: None; app.log_filter = "all"
        app.logs = lambda: []; app.combo = lambda items: U.App.combo(app, items); app.set_log_filter = lambda *_: None
        app.session_started = time.time(); app.session_activity_omitted = 0
        app.session_stored_names = ["private-name.txt"]; app.session_stored_count = 1; app.session_setting_changes = 0
        app.session_activity = [{"t": time.time(), "kind": "files_stored", "count": 1, "names": ["private-name.txt"]}]
        view = U.App.build_log(app); s.addCleanup(view.deleteLater)
        text = "\n".join(item.text() for item in view.findChildren(U.QLabel))
        s.assertNotIn("private-name.txt", text)
        s.assertIn("File names are masked", text)
        s.assertIn("Stored item count is hidden", text)
    def test_activity_center_has_a_button_for_each_persistent_session(s):
        session = {"type": "session", "sid": "a" * 32, "t": time.time(),
                   "events": [{"t": time.time(), "kind": "vault_unlocked", "method": "password"}]}
        app = U.App.__new__(U.App); app.ro = False; app.ap = U.QScrollArea(); app.pop = lambda *_: None
        app.log_filter = "all"; app.logs = lambda: [session]; app.combo = lambda items: U.App.combo(app, items)
        app.open_health_center = mock.Mock(); app.open_diagnostics_center = mock.Mock(); app.show_session_log = mock.Mock()
        app.session_started = None; app.session_activity = []; app.session_stored_names = []; app.session_stored_count = 0
        app.session_setting_changes = 0; app.session_activity_omitted = 0
        view = U.App.build_log(app); s.addCleanup(view.deleteLater)
        buttons = [button for button in view.findChildren(U.QPushButton) if button.text() == "View session log"]
        s.assertEqual(len(buttons), 1)
        buttons[0].click()
        app.show_session_log.assert_called_once_with(session)
    def test_main_tab_switch_uses_interruptible_fade(s):
        app = U.App.__new__(U.App); app.stack = U.QStackedWidget(); app.tabs = [U.QPushButton() for _ in range(4)]
        app._tab_animation = None; app._tab_effect = None
        app.sp = U.QScrollArea(); app.ap = U.QScrollArea(); app.changes = U.QScrollArea()
        app.build_settings = lambda: U.QWidget(); app.build_log = lambda: U.QWidget(); app.build_changes = lambda: U.QWidget()
        app.pop = lambda *_: None
        for _ in range(4): app.stack.addWidget(U.QWidget())
        s.addCleanup(app.stack.deleteLater)
        U.App.tab(app, 2)
        s.assertEqual(app.stack.currentIndex(), 2)
        s.assertIsInstance(app.stack.graphicsEffect(), U.QGraphicsOpacityEffect)
        s.assertEqual(app._tab_animation.duration(), 280)
        prior = app._tab_animation
        U.App.tab(app, 3)
        s.assertEqual(app.stack.currentIndex(), 3)
        s.assertNotEqual(app._tab_animation, prior)
        s.assertEqual(app._tab_animation.duration(), 280)
        app._tab_animation.stop()
    def test_every_background_renders_without_replacing_existing_choices(s):
        preview = U.Preview(); preview.resize(320, 180); s.addCleanup(preview.close)
        preview.tm.stop()
        original = {key for _, key in U.BGS}
        s.assertTrue({"glyphs", "radar", "termlog", "sigil", "reels"} <= original)
        s.assertFalse({"sweep", "pulse"} & original)
        s.assertTrue({"glassrain", "reels", "beacon", "platform", "desk", "signalroom"} <= original)
        U.cfg.setdefault("set", {}).update(bg="rain", perf="full", bgden=100, bgspd=100)
        preview.d = preview.mk("rain", preview.width(), preview.height(), 70)
        preview.bgm = ("rain", 1.0)
        U.cfg["set"]["bg"] = "termlog"
        image = U.QImage(preview.size(), U.QImage.Format_ARGB32); image.fill(U.QColor("#000000"))
        painter = U.QPainter(image); preview.render(painter); painter.end()
        s.assertEqual(preview.bgm, ("termlog", 1.0))
        s.assertTrue(all(len(item) == 4 for item in preview.d))
        for _, key in U.BGS:
            U.cfg.setdefault("set", {}).update(bg=key, perf="full", bgden=100, bgspd=100)
            image = U.QImage(preview.size(), U.QImage.Format_ARGB32); image.fill(U.QColor("#000000"))
            painter = U.QPainter(image); preview.render(painter); painter.end()
            s.assertFalse(image.isNull(), key)
            if key in U.ANIM:
                s.assertEqual(preview.bgm, (key, 1.0), f"stale animation data when switching to {key}")
    def test_look_preview_switches_animation_and_stops_on_static_or_close(s):
        U.cfg["set"] = dict(U.DEF, bg="solid", perf="full", reduce_motion=False, bgfocus=False)
        main_stage = U.Stage()
        main_stage.resize(320, 180)
        main_stage.show()
        s.addCleanup(main_stage.close)
        preview = U.Preview()
        preview.resize(320, 180)
        preview.show()
        s.addCleanup(preview.close)
        s.app.processEvents()
        s.assertFalse(preview.tm.isActive())
        s.assertFalse(main_stage.tm.isActive())

        main_stage.owner = True
        main_stage.mode = "vault"
        main_stage.root = None
        main_stage._settings_history_replay = True
        main_stage.record_session_event = mock.Mock()
        timer = preview.tm
        main_timer = main_stage.tm
        U.App.put(main_stage, "bg", "rain")
        s.app.processEvents()
        s.assertTrue(preview.tm.isActive())
        s.assertTrue(main_stage.tm.isActive())
        s.assertIs(preview.tm, timer)
        s.assertIs(main_stage.tm, main_timer)
        main_stage.step()
        preview.step()
        s.assertEqual(preview.bgm, ("rain", 1.0))
        s.assertEqual(main_stage.bgm, ("rain", 1.0))
        s.assertEqual(len(preview.findChildren(U.QTimer)), 1)
        preview.step()
        s.assertGreater(preview.ph, 0)

        U.App.put(main_stage, "bg", "stars")
        s.app.processEvents()
        s.assertTrue(preview.tm.isActive())
        s.assertTrue(main_stage.tm.isActive())
        s.assertEqual(preview.bgm, ("stars", 1.0))
        s.assertEqual(main_stage.bgm, ("stars", 1.0))
        s.assertTrue(all(len(item) == 3 for item in preview.d))
        s.assertTrue(all(len(item) == 3 for item in main_stage.d))
        main_stage.step()
        preview.step()
        s.assertIs(preview.tm, timer)

        U.App.put(main_stage, "bg", "solid")
        s.app.processEvents()
        s.assertFalse(preview.tm.isActive())
        s.assertFalse(main_stage.tm.isActive())
        s.assertIsNone(preview.bgm)
        s.assertEqual(preview.d, [])
        preview.close()
        s.assertFalse(preview.tm.isActive())
    def test_closing_look_studio_stops_its_preview_timer(s):
        U.cfg["set"] = dict(U.DEF, bg="rain", perf="full", reduce_motion=False, bgfocus=False)
        app = U.App.__new__(U.App)
        U.QWidget.__init__(app)
        app.studio = None
        app.pop = lambda *_args, **_kwargs: None
        s.addCleanup(app.deleteLater)

        U.App.look_studio(app)
        studio = app.studio
        preview = studio.findChild(U.Preview)
        assert preview is not None
        studio.show()
        s.app.processEvents()
        s.assertTrue(preview.tm.isActive())

        studio.close()
        s.app.processEvents()
        s.assertFalse(preview.tm.isActive())
    def test_noir_sentinel_renders_with_each_theme(s):
        preview = U.Preview(); preview.resize(640, 360)
        s.addCleanup(preview.close)
        for theme in U.PRE:
            U.cfg["set"] = dict(U.DEF, bg="sigil", th=theme, perf="min")
            U.set_theme(); preview.update(); s.app.processEvents()
            image = U.QImage(preview.size(), U.QImage.Format_ARGB32); image.fill(U.QColor("#000000"))
            painter = U.QPainter(image); preview.render(painter); painter.end()
            s.assertFalse(image.isNull(), theme)
            s.assertNotEqual(image.pixelColor(320, 180).name(), "#000000", theme)
    def test_selecting_theme_refreshes_application_and_live_preview(s):
        U.cfg["set"] = dict(U.DEF, bg="solid", th="matrix", perf="min")
        U._refresh_theme()
        preview = U.Preview(); preview.resize(320, 180); s.addCleanup(preview.close)
        window = U.App.__new__(U.App)
        window.mode = "vault"; window.owner = True; window.root = None
        window.record_session_event = mock.Mock()
        window.vault_screen = mock.Mock(); window.tab = mock.Mock()

        U.App.set_th(window, "blood")
        s.app.processEvents()
        s.assertEqual(U.S("th"), "blood")
        s.assertEqual(U.TH["acc"], U.PRE["blood"][2])
        s.assertIn(U.PRE["blood"][2], s.app.styleSheet())

        image = U.QImage(preview.size(), U.QImage.Format_ARGB32)
        image.fill(U.QColor("#000000"))
        painter = U.QPainter(image); preview.render(painter); painter.end()
        s.assertEqual(image.pixelColor(160, 90).name(), U.PRE["blood"][0])
    def png_bytes(s, width=80, height=60):
        image = U.QImage(width, height, U.QImage.Format_RGB32); image.fill(U.QColor("#31404a"))
        data = U.QByteArray(); buffer = U.QBuffer(data); buffer.open(U.QIODevice.WriteOnly); image.save(buffer, "PNG"); buffer.close()
        return bytes(data)
    def test_photo_canvas_draws_marks_zooms_and_erases_in_memory(s):
        viewer = U.Viewer("photo.png", s.png_bytes(), False, None); s.addCleanup(viewer.close)
        canvas = viewer.lb
        assert isinstance(canvas, U.PhotoCanvas)
        s.assertTrue(viewer.photo_tool_buttons["pan"].isChecked())
        viewer.select_photo_tool("highlight"); s.assertEqual(canvas.tool, "highlight")
        canvas.marks = [{"kind": "pin", "point": (.5, .5)}, {"kind": "highlight", "points": [(.1, .1), (.8, .8)]}]
        marked = canvas.marked_image()
        s.assertEqual((marked.width(), marked.height()), (80, 60))
        canvas.erase_at((.5, .5)); s.assertEqual(len(canvas.marks), 1)
        viewer.show(); s.app.processEvents()
        anchor = U.QPoint(canvas.width() // 2, canvas.height() // 2)
        photo_scroll = viewer.photo_scroll
        assert photo_scroll is not None
        horizontal = photo_scroll.horizontalScrollBar(); vertical = photo_scroll.verticalScrollBar()
        assert horizontal is not None
        assert vertical is not None
        keep = (anchor.x() / canvas.width(), anchor.y() / canvas.height(), anchor.x() - horizontal.value(), anchor.y() - vertical.value())
        viewer.change_zoom(1.25, anchor); s.app.processEvents(); s.assertEqual(viewer.image_zoom, 1.25)
        expected_x = min(horizontal.maximum(), max(horizontal.minimum(), round(keep[0] * canvas.width() - keep[2])))
        expected_y = min(vertical.maximum(), max(vertical.minimum(), round(keep[1] * canvas.height() - keep[3])))
        s.assertEqual(horizontal.value(), expected_x); s.assertEqual(vertical.value(), expected_y)
        pan_view = U.Viewer("large.png", s.png_bytes(400, 300), False, None); s.addCleanup(pan_view.close)
        pan_view.show(); s.app.processEvents(); pan_view.change_zoom(8); s.app.processEvents()
        pan_canvas = pan_view.lb; assert isinstance(pan_canvas, U.PhotoCanvas)
        pan_scroll = pan_view.photo_scroll
        assert pan_scroll is not None
        horizontal = pan_scroll.horizontalScrollBar(); vertical = pan_scroll.verticalScrollBar()
        assert horizontal is not None
        assert vertical is not None
        s.assertGreater(horizontal.maximum(), 0); s.assertGreater(vertical.maximum(), 0)
        horizontal.setValue(300); vertical.setValue(200); anchor = U.QPoint(450, 300)
        keep_x, keep_y = anchor.x() / pan_canvas.width(), anchor.y() / pan_canvas.height()
        viewport_x, viewport_y = anchor.x() - horizontal.value(), anchor.y() - vertical.value()
        pan_view.change_zoom(.8, anchor); s.app.processEvents()
        expected_x = min(horizontal.maximum(), max(horizontal.minimum(), round(keep_x * pan_canvas.width() - viewport_x)))
        expected_y = min(vertical.maximum(), max(vertical.minimum(), round(keep_y * pan_canvas.height() - viewport_y)))
        s.assertEqual(horizontal.value(), expected_x); s.assertEqual(vertical.value(), expected_y)
        pan_canvas.set_tool("pan")
        start_x, start_y = horizontal.value(), vertical.value()
        press = mock.Mock(); press.button.return_value = U.Qt.LeftButton; press.pos.return_value = U.QPoint(200, 180); press.globalPos.return_value = U.QPoint(200, 180)
        move = mock.Mock(); move.globalPos.return_value = U.QPoint(160, 150)
        release = mock.Mock()
        pan_canvas.mousePressEvent(press); pan_canvas.mouseMoveEvent(move); pan_canvas.mouseReleaseEvent(release); s.app.processEvents()
        s.assertGreater(horizontal.value(), start_x); s.assertGreater(vertical.value(), start_y)
        canvas.clear_marks(); s.assertEqual(canvas.marks, [])
    def test_pdf_reader_renders_pages_from_memory_and_closes(s):
        import pymupdf
        source = pymupdf.open(); source.new_page().insert_text((72, 72), "First page"); source.new_page().insert_text((72, 72), "Second page")
        data = source.tobytes(); source.close()
        viewer = U.Viewer("sample.pdf", data, False, None); s.addCleanup(viewer.close)
        assert isinstance(viewer.pdf_page_label, U.QLabel)
        assert isinstance(viewer.pdf_zoom_label, U.QLabel)
        assert isinstance(viewer.pdf_image, U.QLabel)
        s.assertEqual(viewer.pdf_page_label.text(), "PAGE 1 / 2")
        s.assertIsNotNone(viewer.pdf_image.pixmap())
        viewer.change_pdf_page(1); viewer.change_pdf_zoom(1.25)
        s.assertEqual(viewer.pdf_page_label.text(), "PAGE 2 / 2")
        s.assertEqual(viewer.pdf_zoom_label.text(), "125%")
        viewer.fit_pdf_page()
        s.assertGreaterEqual(viewer.pdf_zoom, .1)
        s.assertLessEqual(viewer.pdf_zoom, 3.0)
        s.assertIsNotNone(viewer.pdf_image.pixmap())
        viewer.done(0); s.assertIsNone(viewer.pdf_doc)
    def test_office_document_reader_uses_safe_text_preview(s):
        import io, zipfile
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as archive:
            archive.writestr("word/document.xml", '<w:document xmlns:w="urn:w"><w:body><w:p><w:r><w:t>Private report text</w:t></w:r></w:p></w:body></w:document>')
        viewer = U.Viewer("report.docx", stream.getvalue(), False, None); s.addCleanup(viewer.close)
        text_preview = viewer.findChild(U.QPlainTextEdit)
        assert text_preview is not None
        s.assertIn("Private report text", text_preview.toPlainText())
    def test_zip_viewer_lists_members_without_extracting(s):
        import io, zipfile
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as archive: archive.writestr("folder/readme.txt", "contents stay inside")
        viewer = U.Viewer("bundle.zip", stream.getvalue(), False, None); s.addCleanup(viewer.close)
        listing = viewer.findChild(U.QListWidget)
        s.assertIsNotNone(listing)
        assert listing is not None
        s.assertEqual(listing.count(), 1)
        item = listing.item(0)
        assert item is not None
        s.assertIn("folder", item.text())
        s.assertNotIn("contents stay inside", item.text())
        stylesheet = listing.styleSheet()
        s.assertIn(f"background-color:{U.TH['panel']}", stylesheet)
        s.assertIn(f"color:{U.TH['fg']}", stylesheet)
        s.assertIn(f"border-left:2px solid {U.TH['acc']}", stylesheet)
    def test_wordmark_triple_click_fires_one_callback(s):
        from PyQt5.QtTest import QTest
        called = []; mark = U.Glitch("UNKNWN", 16, lambda: called.append(True)); mark.show()
        for _ in range(3): QTest.mouseClick(mark, U.Qt.LeftButton)
        s.assertEqual(called, [True]); mark.close()

@unittest.skipIf(REAL_QT, "UI smoke tests use the Qt stand-in")
class TestUiCodePaths(Base):
    """Runs the new UI code against a permissive Qt stand-in: catches typos, bad names and logic errors. It does NOT prove it looks right on screen."""
    def test_terminal_unlock_and_intro_state_machines(s):
        done = []; t = U.Unlock(lambda: done.append(1), U.QWidget()); n = 0
        while not done and n < 6000: t.step(); n += 1
        s.assertEqual(done, [1]); s.assertGreater(len(t.out), 10); t.step(); s.assertEqual(done, [1])
        d2 = []; i = U.Intro(U.QWidget(), 1, lambda: d2.append(1)); n = 0
        while not d2 and n < 6000: i.step(); n += 1
        quote = [x for x in i.out if x[1] == U.Term.WHT]; s.assertTrue(quote); s.assertEqual(d2, [1]); s.assertLess(n * 30 / 1000, 15)
    def test_every_background_runs_step_and_paint(s):
        class T(U.Stage):
            def isVisible(s): return True
            def isMinimized(s): return False
        with mock.patch.object(U.QApplication, "applicationState", staticmethod(lambda: U.Qt.ApplicationActive), create=True):
            for _, key in U.BGS:
                for perf in ("full", "lite", "min"):
                    U.cfg.setdefault("set", {}).update(bg=key, perf=perf, bgden=150, bgspd=200); t = T(); t.resize(800, 500)
                    for _ in range(8): t.step()
                    t.paintEvent(None)
        s.assertTrue({"glyphs", "radar", "termlog"} <= {k for _, k in U.BGS})
    def test_retired_animated_backgrounds_are_not_selectable_and_migrate(s):
        selected = {key for _, key in U.BGS}
        s.assertNotIn("sweep", selected); s.assertNotIn("pulse", selected)
        for key in ("sweep", "pulse"):
            U.cfg["set"] = dict(U.DEF, bg=key)
            U.normalize_look_settings()
            s.assertEqual(U.S("bg"), "termlog")
    def test_look_studio_rotate_damaged_and_progress_window_build(s):
        a = U.App.__new__(U.App); U.look_ok = True
        U.App.look_studio(a); U.App.damaged_screen(a)
        u = U.Upload.__new__(U.Upload); u.shown = .34; u.txt = "Decrypting x"; u.hx = "ab"; u.paintEvent(None)
    def test_new_settings_have_defaults_and_qss_toggles(s):
        for k in ("bgspd", "bgden", "tstyle", "crt"): s.assertIn(k, U.DEF)
        U.cfg["set"] = {"tstyle": False}; plain = U.qss(); U.cfg["set"] = {"tstyle": True}; term = U.qss()
        s.assertIn("monospace", term); s.assertNotIn("monospace", plain)

    def test_invalid_custom_theme_colors_fallback_to_safe_default_palette(s):
        old = U.cfg.get("set")
        try:
            U.cfg["set"] = dict(U.DEF, th="custom", tbg="bad", tfg="nope", tac="#12ff34")
            U.set_theme()
            s.assertEqual(U.TH["bg0"], U.PRE["matrix"][0])
            s.assertEqual(U.TH["fg"], U.PRE["matrix"][1])
            s.assertEqual(U.TH["acc"], U.PRE["matrix"][2])
        finally:
            if old is None:
                U.cfg.pop("set", None)
            else:
                U.cfg["set"] = old
            U.set_theme()

if __name__ == "__main__": unittest.main()

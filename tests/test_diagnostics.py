"""Focused tests for the bounded local diagnostics and Activity Center entry points."""
import os
import sys
import shutil
import time
import unittest
from pathlib import Path
from typing import Any, cast
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).parent))
from qt_test_support import flush_deferred_deletes
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

try:
    from PyQt5.QtWidgets import QApplication as _QApplication
    real_qt = True
except Exception:
    import importlib
    importlib.import_module("qtstub")
    _QApplication = None
    real_qt = False

import unknwn as U

if _QApplication is not None:
    _qt_app = _QApplication.instance() or _QApplication([])
else:
    _qt_app = None
DG = U


def _noop_widget(_widget: Any, _duration: int = 0) -> None:
    return None

def _noop_value(_value: Any) -> None:
    return None

def _noop_cb(*_args: Any) -> None:
    return None


class TestSanitization(unittest.TestCase):
    def test_redacts_sensitive_fields_assignments_and_identifying_paths(self):
        source: dict[str, Any] = {
            "password": "clear-text-password",
            "details": "passphrase = 'clear words' opened C:\\Users\\Alice Smith\\vault\\error.txt and /home/alice/My Vault/file.txt",
            "nested": {"email": "person@example.invalid"},
        }
        result = DG.sanitize_value(source)
        rendered = str(result)
        for secret in ("clear-text-password", "clear words", "Alice Smith", "alice", "person@example.invalid"):
            self.assertNotIn(secret, rendered)
        self.assertIn("[REDACTED]", rendered)
        self.assertIn("[PATH REDACTED]", rendered)
        authorization = DG.sanitize_text("Authorization: Bearer " + "diagnostic-auth-marker-42")
        self.assertNotIn("diagnostic-auth-marker-42", authorization)

    def test_sanitizer_caps_untrusted_text(self):
        self.assertTrue(DG.sanitize_text("x" * 100, limit=20).endswith("…[truncated]"))

    def test_redacts_free_text_key_material_and_email_addresses(self):
        text = DG.sanitize_text("vault key = root-secret-marker")
        email = DG.sanitize_text("contact person@example.invalid for support")
        self.assertNotIn("root-secret-marker", text)
        self.assertIn("[REDACTED]", text)
        self.assertNotIn("person@example.invalid", email)
        self.assertIn("[EMAIL REDACTED]", email)

    def test_dependency_advisor_is_offline_and_reports_optional_capabilities(self):
        with mock.patch.object(U, "fitz", None), \
             mock.patch.object(U.MD, "py7zr", None), \
             mock.patch.object(U.MD, "rarfile", None):
            dependencies = U.dependency_advisor()

        indexed = {dependency["name"]: dependency for dependency in dependencies}
        self.assertEqual(indexed["PyQt5"]["status"], "available")
        self.assertEqual(indexed["cryptography"]["status"], "available")
        self.assertEqual(indexed["PyMuPDF"]["status"], "optional-missing")
        self.assertEqual(indexed["py7zr"]["status"], "optional-missing")
        self.assertEqual(indexed["rarfile"]["status"], "optional-missing")
        self.assertIn("No network request", indexed["py7zr"]["advice"])
        report = U.format_diagnostics([], False, False, dependencies)
        self.assertIn("OFFLINE DEPENDENCY ADVISOR", report)
        self.assertIn("PDF preview", report)
        self.assertIn("No network or export is used", report)


class TestDiagnosticSources(unittest.TestCase):
    def setUp(self):
        self.home = Path(__file__).parent / f"_diagnostics_testdata_{os.getpid()}"
        shutil.rmtree(self.home, ignore_errors=True)
        self.home.mkdir()

    def tearDown(self):
        shutil.rmtree(self.home, ignore_errors=True)

    def test_missing_sources_are_reported_without_inventing_events(self):
        sources = cast(list[dict[str, Any]], DG.read_local_logs(self.home))
        self.assertEqual([source["state"] for source in sources], ["missing", "missing", "missing"])
        self.assertEqual(sources[0]["entries"], [])
        report = DG.format_diagnostics(sources, False, False)
        self.assertIn("No security event log is present", report)
        self.assertIn("Encrypted sign-in logging setting: disabled", report)
        absent = DG.read_local_logs(self.home / "not-created")
        self.assertEqual([source["state"] for source in absent], ["missing", "missing", "missing"])

    def test_malformed_security_records_and_log_redaction_are_reported(self):
        (self.home / "security-2026-10-10.log").write_text(
            '{"ts":1,"event":"login_failed","password":"dont-display","detail":"C:\\\\Users\\\\Alice\\\\vault"}\nnot json\n',
            encoding="utf-8",
        )
        (self.home / "error.log").write_text(
            "ValueError: password=" + "diagnostic-test-marker-42" + " at C:\\Users\\Alice\\private\\file.py\n",
            encoding="utf-8",
        )
        sources = cast(list[dict[str, Any]], DG.read_local_logs(self.home))
        self.assertEqual(sources[0]["state"], "malformed")
        self.assertEqual(len(sources[0]["entries"]), 1)
        self.assertNotIn("dont-display", str(sources[0]["entries"]))
        self.assertNotIn("Alice", str(sources[0]["entries"]))
        self.assertNotIn("diagnostic-test-marker-42", sources[1]["text"])
        self.assertNotIn("C:\\Users\\Alice", sources[1]["text"])
        report = DG.format_diagnostics(sources, True, False)
        self.assertIn("Some records were malformed", report)
        self.assertIn("[REDACTED]", report)

    def test_log_reading_is_bounded_and_marks_truncation(self):
        payload = '{"event":"ordinary"}\n' * (DG.MAX_ERROR_BYTES // 10)
        (self.home / "error.log").write_text(payload, encoding="utf-8")
        source = cast(list[dict[str, Any]], DG.read_local_logs(self.home))[1]
        self.assertLessEqual(len(source["text"]), DG.MAX_ERROR_BYTES + 100)
        self.assertIn("Older log content omitted", source["text"])

    def test_non_regular_log_source_is_unavailable(self):
        source = self.home / "error.log"
        source.mkdir()
        result = cast(list[dict[str, Any]], DG.read_local_logs(self.home))[1]
        self.assertEqual(result["state"], "unavailable")

    def test_persisted_error_log_omits_exception_text_and_filesystem_paths(self):
        secret = "password=diagnostic-secret-marker"
        filename = r"C:\Users\Private User\Vault\private-name.dat"
        try:
            raise ValueError(f"{secret} opened {filename}")
        except ValueError as exc:
            DG.write_error_log(self.home, type(exc), exc.__traceback__)

        report = (self.home / "error.log").read_text(encoding="utf-8")
        self.assertIn("ValueError", report)
        self.assertIn("line ", report)
        self.assertNotIn(secret, report)
        self.assertNotIn("diagnostic-secret-marker", report)
        self.assertNotIn("Private User", report)
        self.assertNotIn("private-name.dat", report)


class TestHealthStates(unittest.TestCase):
    def test_integrity_results_distinguish_all_expected_states(self):
        self.assertEqual(DG.integrity_health_result("ok")["status"], "pass")
        self.assertEqual(DG.integrity_health_result("fail")["status"], "fail")
        self.assertEqual(DG.integrity_health_result("dev")["status"], "warning")
        self.assertEqual(DG.integrity_health_result("unknown")["status"], "unavailable")
        for status in ("pass", "fail", "warning", "unavailable"):
            self.assertEqual(DG.vault_health_result(status, "Explicit result.")["status"], status)
        self.assertEqual(DG.vault_health_result("unavailable", "Not checked.")["status"], "unavailable")
        with self.assertRaises(ValueError):
            DG.health_result("test", "skipped", "must not be treated as a pass")


class TestActivityCenterIntegration(unittest.TestCase):
    def test_centers_are_added_without_replacing_existing_history(self):
        if not real_qt:
            self.skipTest("Real Qt widgets are required for the Activity Center integration check.")
        self.addCleanup(flush_deferred_deletes)
        assert _qt_app is not None
        app_instance = _qt_app
        old_settings = U.cfg.get("set")
        U.cfg["set"] = dict(U.DEF)
        self.addCleanup(lambda: U.cfg.__setitem__("set", old_settings) if old_settings is not None else U.cfg.pop("set", None))
        activity = U.App.__new__(U.App)
        activity.ro = False
        activity.ap = U.QScrollArea()
        mock.patch.object(activity, "pop", new=_noop_widget).start()
        activity.log_filter = "all"
        activity.logs = lambda: []
        activity.combo = lambda items: U.App.combo(activity, items)
        mock.patch.object(activity, "set_log_filter", new=_noop_value).start()
        activity.session_started = None
        activity.session_activity = []
        activity.session_stored_names = []
        activity.session_stored_count = 0
        activity.session_setting_changes = 0
        activity.session_activity_omitted = 0
        view = U.App.build_log(activity)
        self.addCleanup(view.deleteLater)
        buttons = [button.text() for button in view.findChildren(U.QPushButton)]
        labels = [label.text() for label in view.findChildren(U.QLabel)]
        self.assertIn("Vault Health Center", buttons)
        self.assertIn("Diagnostics Center", buttons)
        self.assertIn("ACTIVITY CENTER", labels)
        self.assertIn("SESSION TIMELINE", labels)
        self.assertIn("ENCRYPTED SIGN-IN HISTORY", labels)
        self.assertTrue(callable(U.App.open_health_center))
        self.assertTrue(callable(U.App.open_diagnostics_center))
        app_instance.processEvents()


class TestHealthWorker(unittest.TestCase):
    def setUp(self):
        self.addCleanup(flush_deferred_deletes)
        self.home = Path(__file__).parent / f"_health_testdata_{os.getpid()}"
        shutil.rmtree(self.home, ignore_errors=True)
        self.home.mkdir()
        self.old_home = U.HOME
        self.old_index = dict(U.idx)
        U.set_home(self.home)
        U.VAULT.mkdir()
        U.idx.clear()

    def tearDown(self):
        U.idx.clear()
        U.idx.update(self.old_index)
        U.set_home(self.old_home)
        shutil.rmtree(self.home, ignore_errors=True)

    def test_checks_run_in_background_and_classify_authenticated_vault_storage(self):
        if not real_qt:
            self.skipTest("Real Qt threads are required for the health worker check.")
        assert _qt_app is not None
        root = os.urandom(32)
        rid = "0123456789ab"
        salt = os.urandom(16)
        key = U.file_key(root, salt)
        source = self.home / "health-check-source.bin"
        source.write_bytes(b"health check fixture")
        encrypted = U.VAULT / f"{rid}.cdr"
        U.enc_file(source, encrypted, key, _noop_cb)
        U.idx[rid] = {"s": U.b64e(salt), "nm": U.b64e(U.seal(key, b"fixture.bin")),
                      "size": source.stat().st_size, "exp": None, "views": None}
        U.save_idx(root, U.idx)
        activity = U.App.__new__(U.App)
        activity.root = root
        activity.working = lambda: False
        dialog = U.HealthCenterDialog(cast(U.App, None))
        dialog.app = activity
        self.addCleanup(dialog.deleteLater)
        with mock.patch.object(U.IG, "state", return_value="dev"):
            dialog.run_checks()
            active_worker = getattr(dialog, "_worker")
            dialog.run_checks()
            self.assertIs(getattr(dialog, "_worker"), active_worker, "a second run must not overlap the active worker")
            deadline = time.monotonic() + 5
            while getattr(dialog, "_running") and time.monotonic() < deadline:
                _qt_app.processEvents()
                time.sleep(0.01)
            _qt_app.processEvents()
        self.assertFalse(getattr(dialog, "_running"), "the health worker did not report completion")
        output = dialog.output.toPlainText()
        self.assertIn("[WARNING] Release integrity", output)
        self.assertIn("[PASS] Vault storage", output)
        self.assertIn("every indexed item passed", output.lower())
        self.assertNotIn("/100", output)
        damaged = bytearray(encrypted.read_bytes())
        damaged[-1] ^= 1
        encrypted.write_bytes(damaged)
        with mock.patch.object(U.IG, "state", return_value="dev"):
            dialog.run_checks()
            deadline = time.monotonic() + 5
            while getattr(dialog, "_running") and time.monotonic() < deadline:
                _qt_app.processEvents()
                time.sleep(0.01)
            _qt_app.processEvents()
        self.assertFalse(getattr(dialog, "_running"), "the tamper check did not report completion")
        self.assertIn("[FAIL] Vault storage", dialog.output.toPlainText())


if __name__ == "__main__":
    unittest.main()

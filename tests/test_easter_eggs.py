import os
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from typing import Any, cast
from unittest import mock
from PyQt5.QtTest import QTest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
_TEST_HOME = tempfile.mkdtemp(prefix="unknwn_easter_egg_home_")
os.environ["HOME"] = _TEST_HOME
os.environ["USERPROFILE"] = _TEST_HOME

import easter_eggs as EE
import unknwn as U


def qt_application() -> U.QApplication:
    existing = U.QApplication.instance()
    if isinstance(existing, U.QApplication):
        return existing
    return U.QApplication([])


class ThemeWindow(U.QWidget):
    _easter_theme_snapshot: EE.ThemeSnapshot | None
    _easter_theme_timer: U.QTimer | None
    _easter_theme_image: U.QPixmap | None

    def __init__(self):
        super().__init__()
        self._easter_theme_snapshot = None
        self._easter_theme_timer = None
        self._easter_theme_image = None
        self.search_edit = mock.Mock()

    @property
    def theme_snapshot(self) -> EE.ThemeSnapshot | None:
        return cast(EE.ThemeSnapshot | None, getattr(self, "_easter_theme_snapshot", None))

    @property
    def theme_image(self) -> U.QPixmap | None:
        return cast(U.QPixmap | None, getattr(self, "_easter_theme_image", None))

    def apply_secret_theme(self, snapshot: EE.ThemeSnapshot) -> None:
        U.App.apply_secret_theme(self, snapshot)

    def restore_secret_theme(self) -> None:
        U.App.restore_secret_theme(self)


class TestEasterEggResources(unittest.TestCase):
    def test_embedded_message_collections_have_expected_counts_and_uniqueness(self):
        expected = {
            "loading": (EE.loading_messages, 1200),
            "cancellation": (EE.cancellation_messages, 1200),
            "empty_search": (EE.empty_search_messages, 1200),
            "warden": (EE.warden_intro_messages, 1200),
            "hidden_nothing": (EE.hidden_nothing_button_messages, 20),
        }
        for category, (messages, count) in expected.items():
            with self.subTest(category=category):
                self.assertEqual(len(messages), count)
                self.assertEqual(len(set(messages)), count)
                self.assertTrue(all(message.strip() for message in messages))

    def test_message_loading_does_not_read_external_text_files(self):
        with mock.patch.object(Path, "read_text",
                               side_effect=AssertionError("Unexpected text-file read")):
            eggs = EE.EasterEggs()
            for category in EE.MESSAGE_COLLECTIONS:
                self.assertTrue(eggs.message(category))

    def test_message_pool_is_shuffled_without_repeats_within_a_cycle(self):
        pool = EE.MessagePool(tuple(f"message {number}" for number in range(60)))
        selections = [pool.next() for _ in range(240)]
        for start in range(0, len(selections), 60):
            self.assertEqual(set(selections[start:start + 60]), set(pool.messages))
        self.assertTrue(all(
            selection not in selections[index - 32:index]
            for index, selection in enumerate(selections)
            if index >= 32))

    def test_development_resource_resolution_uses_module_directory(self):
        path = EE.resource_path(
            "assets/uwu_kawaii.jpg", module_file=ROOT / "easter_eggs.py",
            executable_path=ROOT / "UNKNWN.exe")
        self.assertEqual(path, ROOT / "assets" / "uwu_kawaii.jpg")

    def test_packaged_resource_resolution_uses_executable_resource_root(self):
        with tempfile.TemporaryDirectory() as temporary:
            package_root = Path(temporary)
            asset_root = package_root / "assets"
            asset_root.mkdir()
            packaged_asset = asset_root / "uwu_kawaii.jpg"
            packaged_asset.write_bytes((ROOT / "assets" / "uwu_kawaii.jpg").read_bytes())
            resolved = EE.resource_path(
                "assets/uwu_kawaii.jpg",
                module_file=package_root / "easter_eggs.py",
                executable_path=package_root / "UNKNWN.exe")
            self.assertEqual(resolved, packaged_asset)

    def test_resource_path_rejects_parent_traversal(self):
        with self.assertRaises(ValueError):
            EE.resource_path("../outside.jpg", resource_roots=(ROOT,))

    def test_upload_uses_an_embedded_loading_message(self):
        app = qt_application()
        parent = U.QWidget()
        long_message = "A full decrypting status message that must remain readable. " * 8
        with mock.patch.object(U.EASTER_EGGS, "message", return_value=long_message) as message:
            upload = U.Upload(parent)
        self.assertEqual(upload.loading_message, long_message)
        self.assertEqual(upload.loading_message_label.text(), long_message)
        self.assertTrue(upload.loading_message_label.wordWrap())
        self.assertGreater(upload.loading_message_label.height(), 22)
        self.assertLess(
            upload.loading_message_label.geometry().bottom(),
            62 + upload._loading_message_extra_height)
        self.assertGreater(upload.height(), 250)
        message.assert_called_once_with("loading")
        upload.close()
        parent.close()
        self.assertIsNotNone(app)

    def test_other_operation_progress_dialogs_show_loading_messages(self):
        app = qt_application()
        parent = U.QWidget()

        def worker_fixture() -> mock.MagicMock:
            worker = mock.MagicMock()
            worker.cancel = threading.Event()
            worker.pause = threading.Event()
            worker.resume_event = threading.Event()
            worker.resume_event.set()
            return worker

        move_worker = worker_fixture()
        package_worker = worker_fixture()
        seal_worker = worker_fixture()
        analysis_worker = worker_fixture()
        parent.root = os.urandom(32)
        dialogs: list[U.QDialog] = []
        try:
            with mock.patch.object(U.EASTER_EGGS, "message",
                                   wraps=U.EASTER_EGGS.message) as message, \
                 mock.patch.object(U, "_VaultAnalysisWorker",
                                   return_value=analysis_worker), \
                 mock.patch.object(U, "_start_qrunnable"):
                dialogs.extend((
                    U.MoveProgressDialog(parent, move_worker, mock.Mock()),
                    U.PackageProgressDialog(
                        parent, package_worker, "Package operation", mock.Mock()),
                    U._SealProgressDialog(parent, seal_worker, mock.Mock()),
                    U.VaultAnalysisDialog(parent),
                ))
                for dialog in dialogs:
                    label = dialog.findChild(U.QLabel, "easterEggLoadingMessage")
                    self.assertIsNotNone(label)
                    assert label is not None
                    self.assertIn(label.text(), EE.loading_messages)
                    self.assertTrue(label.wordWrap())
                self.assertEqual(message.call_count, len(dialogs))
                self.assertTrue(all(call.args == ("loading",) for call in message.call_args_list))
        finally:
            for dialog in dialogs:
                dialog._running = False
                dialog.close()
            parent.close()
        self.assertIsNotNone(app)

    def test_health_check_selects_loading_message_only_when_started(self):
            app = qt_application()
            parent = U.QWidget()
            parent.root = os.urandom(32)
            parent.working = lambda: False
            dialog = U.HealthCenterDialog(cast(U.App, parent))
            worker = mock.MagicMock()
            dialog._running = False
            with mock.patch.object(U, "_HealthWorker", return_value=worker), \
                 mock.patch.object(U, "_start_qrunnable"), \
                 mock.patch.object(U.EASTER_EGGS, "message",
                                   wraps=U.EASTER_EGGS.message) as message:
                self.assertTrue(dialog.loading_message_label.isHidden())
                message.assert_not_called()
                dialog.run_checks()
                message.assert_called_once_with("loading")
                self.assertFalse(dialog.loading_message_label.isHidden())
                self.assertIn(dialog.loading_message_label.text(), EE.loading_messages)
                dialog.checks_finished([])
                self.assertTrue(dialog.loading_message_label.isHidden())
            dialog.close()
            parent.close()
            self.assertIsNotNone(app)

    def test_large_file_view_renders_full_loading_message_inside_decrypt_popup(self):
        qt_app = qt_application()
        with tempfile.TemporaryDirectory() as temporary:
            old_home = U.HOME
            old_cfg = U.copy.deepcopy(U.cfg)
            old_idx = U.copy.deepcopy(U.idx)
            try:
                U.set_home(Path(temporary) / "app-data")
                U.cfg.clear()
                U.idx.clear()
                U.VAULT.mkdir(parents=True)
                root = os.urandom(32)
                salt = os.urandom(16)
                key = U.file_key(root, salt)
                rid = "easter-decrypt-" + os.urandom(8).hex()
                name = "large-loading-test.bin"
                plaintext = os.urandom(U.BIG)
                source = Path(temporary) / name
                source.write_bytes(plaintext)
                encrypted = U.VAULT / f"{rid}.cdr"
                U.enc_file(source, encrypted, key, lambda *_: None)
                source.unlink()
                metadata = {
                    "s": U.b64e(salt),
                    "nm": U.b64e(U.seal(key, name.encode())),
                    "size": len(plaintext),
                    "exp": None,
                    "views": None,
                }
                U.idx[rid] = metadata

                class Card:
                    def __init__(self) -> None:
                        self.name = name
                        self.meta = metadata
                        self.vl = U.QLabel()

                class ViewParent(U.QWidget):
                    _vault_file_state_key = U.App._vault_file_state_key
                    _simulate_vault_action = U.App._simulate_vault_action
                    _begin_vault_file_operation = U.App._begin_vault_file_operation
                    _finish_vault_file_operation = U.App._finish_vault_file_operation

                app = ViewParent()
                app.root = root
                app.ro = True
                app.hold = 0
                card = Card()
                app.cards = {rid: card}
                app.dlg = None
                app.sec_ok = mock.Mock(return_value=True)
                app.record_session_event = mock.Mock()
                app.tick = mock.Mock()
                card._file_state_revision = U.FILE_STATE_MANAGER.register(
                    U.App._vault_file_state_key(app, rid)).revision
                long_message = (
                    "The decrypting operation is safely checking authenticated data "
                    "while this complete loading message wraps inside the progress popup. "
                ) * 5
                created_uploads: list[U.Upload] = []
                real_upload = U.Upload

                def capture_upload(parent: U.QWidget) -> U.Upload:
                    upload = real_upload(parent)
                    created_uploads.append(upload)
                    return upload

                class Viewer:
                    def __init__(self, *_args: object, **_kwargs: object) -> None:
                        self.tmp = None
                    def exec_(self) -> None:
                        return

                setting_values = {
                    "reauth": False, "vmode": "mem", "ghost": False, "mask": False,
                }
                with mock.patch.object(U, "S", side_effect=lambda key: setting_values.get(
                        key, U.DEF.get(key))), \
                     mock.patch.object(U, "Upload", side_effect=capture_upload), \
                     mock.patch.object(U, "Viewer", Viewer), \
                     mock.patch.object(U.EASTER_EGGS, "message",
                                       return_value=long_message) as message:
                    U.App.view(app, rid)

                self.assertEqual(len(created_uploads), 1)
                upload = created_uploads[0]
                self.assertEqual(upload.loading_message_label.text(), long_message)
                self.assertTrue(upload.loading_message_label.wordWrap())
                self.assertGreater(upload.loading_message_label.height(), 22)
                self.assertGreater(upload.height(), 250)
                message.assert_called_once_with("loading")
                upload.close()
                app.close()
                self.assertIsNotNone(qt_app)
            finally:
                U.set_home(old_home)
                U.cfg.clear()
                U.cfg.update(old_cfg)
                U.idx.clear()
                U.idx.update(old_idx)

    def test_warden_joke_is_separate_from_authoritative_status_lines(self):
        with mock.patch.object(U.EASTER_EGGS, "message",
                               return_value="harmless WARDEN quip"):
            script = U.warden_script()
        lines = [line for line, _color, _start, _duration in script]
        self.assertIn("> harmless WARDEN quip", lines)
        self.assertIn("> local identity ............ verified", lines)
        self.assertIn("> sealed catalog ........... ready", lines)
        self.assertIn("  [  WARDEN  /  ACCESS RESTORED  ]", lines)

    def test_warden_intro_renders_the_complete_selected_quip(self):
        app = qt_application()
        parent = U.QWidget()
        parent.resize(700, 520)
        long_message = "A complete decorative WARDEN message that wraps safely. " * 5
        with mock.patch.object(U.EASTER_EGGS, "message", return_value=long_message) as message:
            warden = U.Warden(mock.Mock(), parent)
        warden.resize(700, 520)
        parent.show()
        warden.show()
        warden.tm.stop()
        quip_index = warden.quip_script_index
        warden.out = [["", color] for _, color, _, _ in warden.sc[:quip_index]]
        warden.i = quip_index
        warden.c = 0
        warden.wait = 0
        warden.acc = 0.0
        for _ in range(len(warden.sc[quip_index][0]) * 2 + 4):
            warden.step()
            if warden.i > quip_index:
                break
        self.assertEqual(warden.quip_label.text(), "> " + long_message)
        self.assertTrue(warden.quip_label.isVisible())
        self.assertTrue(warden.quip_label.wordWrap())
        self.assertGreater(warden.quip_label.width(), 0)
        message.assert_called_once_with("warden")
        warden.close()
        parent.close()
        self.assertIsNotNone(app)

    def test_warden_widget_selects_a_real_embedded_intro_message(self):
        app = qt_application()
        parent = U.QWidget()
        with mock.patch.object(U.EASTER_EGGS, "message",
                               wraps=U.EASTER_EGGS.message) as message:
            warden = U.Warden(mock.Mock(), parent)
        warden.tm.stop()
        quip = warden.sc[warden.quip_script_index][0][2:]
        message.assert_called_once_with("warden")
        self.assertIn(quip, EE.warden_intro_messages)
        warden.close()
        parent.close()
        self.assertIsNotNone(app)


class TestEasterEggTheme(unittest.TestCase):
    def test_secret_theme_trigger_requires_exact_phrase_and_is_one_time(self):
        eggs = EE.EasterEggs()
        previous_palette = {"bg0": "#010203", "acc": "#abcdef"}
        for query in ("!FUCK", "!FUCK THIS SHIT!", "!fuck this shit", " !FUCK THIS SHIT"):
            self.assertIsNone(eggs.activate_secret_theme(
                "profile-exact-trigger", query, "matrix", previous_palette))
        snapshot = eggs.activate_secret_theme(
            "profile-exact-trigger", EE.SECRET_THEME_PHRASE, "matrix", previous_palette)
        if snapshot is None:
            self.fail("The exact trigger should activate the theme once.")
        self.assertEqual(snapshot.theme_name, "matrix")
        self.assertEqual(snapshot.palette, previous_palette)
        self.assertIsNone(eggs.activate_secret_theme(
            "profile-exact-trigger", EE.SECRET_THEME_PHRASE, "ice", {"acc": "pink"}))
        self.assertEqual(eggs.restore_secret_theme("profile-exact-trigger"), snapshot)
        self.assertIsNone(eggs.restore_secret_theme("profile-exact-trigger"))

    def test_temporary_theme_restores_exact_palette_without_config_changes(self):
        app = qt_application()
        widget = ThemeWindow()
        prior_theme = dict(U.TH)
        prior_cfg = U.copy.deepcopy(U.cfg)
        prior_idx = U.copy.deepcopy(U.idx)
        profile = "easter-restore-" + os.urandom(8).hex()
        snapshot = EE.EASTER_EGGS.activate_secret_theme(
            profile, EE.SECRET_THEME_PHRASE, "violet", prior_theme)
        if snapshot is None:
            self.fail("The exact trigger should activate the theme once.")
        try:
            widget.apply_secret_theme(snapshot)
            for key, color in EE.SECRET_THEME_PALETTE.items():
                self.assertEqual(U.TH[key], color)
            image = widget.theme_image
            if not isinstance(image, U.QPixmap):
                self.fail("The supplied kawaii theme image should load.")
            self.assertFalse(image.isNull())
            widget.restore_secret_theme()
            self.assertEqual(U.TH, prior_theme)
            self.assertIsNone(widget.theme_image)
            self.assertEqual(U.cfg, prior_cfg)
            self.assertEqual(U.idx, prior_idx)
        finally:
            U.TH.clear()
            U.TH.update(prior_theme)
            app.setStyleSheet(U.qss())
            widget.close()

    def test_search_command_activates_only_exact_phrase_once(self):
        app = qt_application()
        widget = ThemeWindow()
        profile = "easter-search-" + os.urandom(8).hex()
        with mock.patch.object(U, "active_profile_id", profile):
            U.App.handle_vault_search_command(widget, "!FUCK THIS")
            self.assertIsNone(widget.theme_snapshot)
            U.App.handle_vault_search_command(widget, EE.SECRET_THEME_PHRASE)
            snapshot = widget.theme_snapshot
            image = widget.theme_image
            if not isinstance(snapshot, EE.ThemeSnapshot):
                self.fail("The exact trigger should activate the theme.")
            self.assertEqual(snapshot.profile_key, profile)
            if not isinstance(image, U.QPixmap):
                self.fail("The supplied kawaii theme image should load.")
            self.assertFalse(image.isNull())
            widget.search_edit.clear.assert_called_once()
            widget.restore_secret_theme()
            U.App.handle_vault_search_command(widget, EE.SECRET_THEME_PHRASE)
            self.assertIsNone(widget.theme_snapshot)
        widget.close()
        self.assertIsNotNone(app)

    def test_secret_theme_uses_the_user_search_signal_and_restores_on_timer(self):
        app = qt_application()
        widget = ThemeWindow()
        widget.resize(700, 500)
        widget.search_edit = U.QLineEdit(widget)
        profile = "easter-user-input-" + os.urandom(8).hex()
        previous_theme = dict(U.TH)
        previous_config = U.copy.deepcopy(U.cfg)
        with mock.patch.object(U, "active_profile_id", profile), \
             mock.patch.object(U, "SECRET_THEME_DURATION_MS", 10):
            widget.search_edit.textEdited.connect(
                lambda query: U.App.handle_vault_search_command(widget, query))
            widget.show()
            widget.search_edit.show()
            widget.search_edit.setFocus()
            QTest.keyClicks(widget.search_edit, "!FUCK THIS")
            self.assertIsNone(widget.theme_snapshot)
            widget.search_edit.clear()
            QTest.keyClicks(widget.search_edit, EE.SECRET_THEME_PHRASE)
            snapshot = widget.theme_snapshot
            self.assertIsInstance(snapshot, EE.ThemeSnapshot)
            self.assertEqual(widget.search_edit.text(), "")
            self.assertNotEqual(U.TH, previous_theme)
            assert widget._easter_theme_timer is not None
            widget._easter_theme_timer.start(1)
            wait_loop = U._QtCore.QEventLoop()
            wait_timer = U.QTimer()
            wait_timer.setSingleShot(True)
            wait_timer.timeout.connect(wait_loop.quit)
            wait_timer.start(30)
            wait_loop.exec_()
            self.assertIsNone(widget.theme_snapshot)
            self.assertEqual(U.TH, previous_theme)
            self.assertEqual(U.cfg, previous_config)
        widget.close()

    def test_vault_lock_restores_temporary_theme_without_persisting_it(self):
        app = qt_application()
        widget = mock.MagicMock()
        widget.mode = "vault"
        widget.defer_seal_action.return_value = False
        widget.root = os.urandom(32)
        widget.ro = False
        widget.dlg = None
        widget.studio = None
        widget.cards = {}
        widget.cds = {}
        widget.restore_secret_theme.side_effect = (
            lambda: U.App.restore_secret_theme(widget))
        profile = "easter-lock-" + os.urandom(8).hex()
        prior_theme = dict(U.TH)
        prior_config = U.copy.deepcopy(U.cfg)
        snapshot = EE.EASTER_EGGS.activate_secret_theme(
            profile, EE.SECRET_THEME_PHRASE, "default", prior_theme)
        self.assertIsNotNone(snapshot)
        widget._easter_theme_snapshot = snapshot
        U.TH.update(EE.SECRET_THEME_PALETTE)
        with mock.patch.object(U, "active_profile_id", profile):
            U.App.lock(widget, False)
        self.assertEqual(U.TH, prior_theme)
        self.assertEqual(U.cfg, prior_config)
        self.assertIsNone(widget._easter_theme_snapshot)
        self.assertIsNotNone(app)


class TestHarmlessNothingButton(unittest.TestCase):
    def test_button_only_shows_an_editable_response(self):
        app = qt_application()
        widget = U.QWidget()
        callback = mock.Mock()
        button = U.nothing_egg_button(callback)
        self.assertEqual(button.objectName(), "nothingEggButton")
        self.assertEqual(button.accessibleName(), "Harmless Nothing Easter Egg")
        button.click()
        callback.assert_called_once_with()
        widget.close()
        self.assertIsNotNone(app)

    def test_nothing_response_does_not_change_security_or_vault_state(self):
        app = mock.Mock()
        before_cfg = U.copy.deepcopy(U.cfg)
        before_idx = U.copy.deepcopy(U.idx)
        with mock.patch.object(U.EASTER_EGGS, "message",
                               return_value="Nothing happened.") as message, \
             mock.patch.object(U.QMessageBox, "information") as information:
            U.App.show_nothing_easter_egg(app)
        message.assert_called_once_with("hidden_nothing")
        information.assert_called_once_with(app, "Nothing", "Nothing happened.")
        self.assertEqual(U.cfg, before_cfg)
        self.assertEqual(U.idx, before_idx)

    def test_overview_nothing_button_click_selects_and_displays_embedded_response(self):
        app = qt_application()
        window = mock.MagicMock()
        window.working.return_value = False
        window.session_activity = []
        window.ro = False
        window.show_nothing_easter_egg.side_effect = (
            lambda: U.App.show_nothing_easter_egg(window))
        page = U.App.build_changes(window)
        button = page.findChild(U.QPushButton, "nothingEggButton")
        self.assertIsNotNone(button)
        before_cfg = U.copy.deepcopy(U.cfg)
        before_idx = U.copy.deepcopy(U.idx)
        with mock.patch.object(U.QMessageBox, "information") as information, \
             mock.patch.object(U.EASTER_EGGS, "message",
                               wraps=U.EASTER_EGGS.message) as message:
            button.click()
        message.assert_called_once_with("hidden_nothing")
        displayed = information.call_args.args[2]
        self.assertIn(displayed, EE.hidden_nothing_button_messages)
        self.assertEqual(U.cfg, before_cfg)
        self.assertEqual(U.idx, before_idx)
        page.deleteLater()
        self.assertIsNotNone(app)

    def test_empty_search_message_tracks_only_real_zero_result_searches(self):
        class Card:
            rid = "fixture-id"
            name = "existing.txt"
            meta = {}
            filter_text = ""
            visible = True
            def setVisible(self, visible: bool) -> None: self.visible = visible
            def isHidden(self) -> bool: return not self.visible

        class Search:
            query = "not-present"
            def text(self): return self.query

        class Window:
            cards = {"fixture-id": Card()}
            search_edit = Search()
            empty = mock.Mock()
            no_results = mock.Mock()
            def card_details(self, _metadata: object, _name: str) -> str: return ""

        window = Window()
        with mock.patch.object(U, "vault_search_text", return_value="existing.txt"), \
             mock.patch.object(U.EASTER_EGGS, "message",
                               return_value="No results. A harmless joke.") as message:
            U.App.apply_vault_filter(cast(Any, window))
            self.assertEqual(
                window.no_results.setText.call_args.args[0],
                "No results. A harmless joke.")
            self.assertEqual(window.search_edit.text(), "not-present")
            U.App.apply_vault_filter(cast(Any, window))
            message.assert_called_once_with("empty_search")
            window.search_edit.query = "existing"
            U.App.apply_vault_filter(cast(Any, window))
            self.assertFalse(window.no_results.setVisible.call_args.args[0])
            window.search_edit.query = "not-present-again"
            U.App.apply_vault_filter(cast(Any, window))
            self.assertEqual(message.call_count, 2)

    def test_real_search_input_signal_displays_embedded_empty_search_response(self):
        app = qt_application()
        class Card:
            rid = "search-integration"
            name = "present.txt"
            meta: dict[str, object] = {}
            filter_text = ""
            visible = True
            def setVisible(self, visible: bool) -> None:
                self.visible = visible
            def isHidden(self) -> bool:
                return not self.visible

        class Window:
            def __init__(self) -> None:
                self.cards = {"search-integration": Card()}
                self.search_edit = U.QLineEdit()
                self.empty = U.QLabel()
                self.no_results = U.QLabel()
            def card_details(self, _metadata: object, _name: str) -> str:
                return ""

        window = Window()
        window.search_edit.textChanged.connect(
            lambda query: U.App.apply_vault_filter(cast(Any, window), query))
        with mock.patch.object(U, "vault_search_text", return_value="present.txt"), \
             mock.patch.object(U.EASTER_EGGS, "message",
                               wraps=U.EASTER_EGGS.message) as message:
            window.search_edit.setText("absent")
        message.assert_called_once_with("empty_search")
        self.assertIn(window.no_results.text(), EE.empty_search_messages)
        self.assertTrue(window.no_results.isVisible())
        window.search_edit.close()
        window.empty.close()
        window.no_results.close()
        self.assertIsNotNone(app)

    def test_cancellation_is_requested_before_selecting_a_joke(self):
        app = qt_application()
        parent = U.QWidget()
        worker = mock.MagicMock()
        worker.resume_event = threading.Event()
        worker.resume_event.set()
        dialog = U._SealProgressDialog(parent, worker, mock.Mock())
        try:
            with mock.patch.object(U.EASTER_EGGS, "message",
                                   wraps=U.EASTER_EGGS.message) as message:
                dialog.cancel_button.click()
                self.assertFalse(dialog.cancellation_message_label.isHidden())
                self.assertIn(
                    dialog.cancellation_message_label.text(),
                    EE.cancellation_messages)
                self.assertTrue(worker.operation.request_cancel.called)
                dialog.update_progress("Still finishing the current safe step", 1, 2, 0, 1)
                self.assertFalse(dialog.cancellation_message_label.isHidden())
                message.assert_called_once_with("cancellation")
            dialog.cancel_button.click()
            self.assertEqual(message.call_count, 1)
        finally:
            dialog._running = False
            dialog.close()
            parent.close()
        self.assertIsNotNone(app)

    def test_each_cancellable_progress_ui_retains_message_after_progress_updates(self):
        app = qt_application()
        parent = U.QWidget()
        def worker_fixture() -> mock.MagicMock:
            worker = mock.MagicMock()
            worker.cancel = threading.Event()
            worker.pause = threading.Event()
            worker.resume_event = threading.Event()
            worker.resume_event.set()
            return worker

        move_worker = worker_fixture()
        package_worker = worker_fixture()
        seal_worker = worker_fixture()
        analysis_worker = worker_fixture()
        parent.root = os.urandom(32)
        dialogs: list[tuple[U.QDialog, tuple[object, ...]]] = []
        try:
            with mock.patch.object(U, "_VaultAnalysisWorker",
                                   return_value=analysis_worker), \
                 mock.patch.object(U, "_start_qrunnable"):
                move = U.MoveProgressDialog(parent, move_worker, mock.Mock())
                package = U.PackageProgressDialog(
                    parent, package_worker, "Package operation", mock.Mock())
                seal = U._SealProgressDialog(parent, seal_worker, mock.Mock())
                analysis = U.VaultAnalysisDialog(parent)
            dialogs.extend((
                (move, ("move", move_worker, "source", 1, 2)),
                (package, ("package", package_worker, "source", 1, 2)),
                (seal, ("seal", seal_worker, "source", 1, 2)),
                (analysis, ("analysis", analysis_worker, "source", 1, 2)),
            ))
            with mock.patch.object(U.EASTER_EGGS, "message",
                                   wraps=U.EASTER_EGGS.message) as message:
                for dialog, (kind, worker, _source, _done, _total) in dialogs:
                    cancel_label = dialog.findChild(
                        U.QLabel, "easterEggCancellationMessage")
                    self.assertIsNotNone(cancel_label)
                    assert cancel_label is not None
                    self.assertTrue(cancel_label.isHidden())
                    dialog.cancel_button.click()
                    self.assertFalse(cancel_label.isHidden())
                    self.assertIn(cancel_label.text(), EE.cancellation_messages)
                    if kind == "package":
                        self.assertEqual(worker.lifecycle.request_cancel.call_count, 1)
                    else:
                        self.assertEqual(worker.operation.request_cancel.call_count, 1)
                    if kind == "move":
                        dialog.update_progress("Copying", 1, 2)
                    elif kind == "package":
                        dialog.update_progress("Packaging", 1, 2)
                    elif kind == "seal":
                        dialog.update_progress("Sealing", 1, 2, 0, 1)
                    else:
                        dialog.update_progress("Analyzing", 1, 2, 0, 1)
                    self.assertFalse(cancel_label.isHidden())
                message.assert_has_calls([mock.call("cancellation")] * len(dialogs))
                self.assertEqual(message.call_count, len(dialogs))
        finally:
            for dialog, _args in dialogs:
                dialog._running = False
                dialog.close()
            parent.close()
        self.assertIsNotNone(app)


if __name__ == "__main__":
    unittest.main()

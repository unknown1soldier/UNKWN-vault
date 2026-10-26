"""Vault list, storage preflight, and reduced-motion regression tests."""
# pyright: reportConstantRedefinition=false, reportPossiblyUnboundVariable=false
# pyright: reportArgumentType=false, reportOptionalMemberAccess=false
# pyright: reportUnknownMemberType=false, reportUnknownLambdaType=false
# pyright: reportUnknownArgumentType=false, reportUnknownParameterType=false
# pyright: reportMissingParameterType=false
import importlib
import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).parent))
from qt_test_support import flush_deferred_deletes
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

try:
    from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QLabel, QFrame, QLineEdit, QComboBox
    REAL_QT = True
except Exception:
    importlib.import_module("qtstub")
    REAL_QT = False

import unknwn as U

_QT_APP = QApplication.instance() or (QApplication([]) if REAL_QT else None)


class TestStorageForecast(unittest.TestCase):
    def test_ciphertext_estimate_includes_chunk_framing_and_final_chunk(self):
        self.assertEqual(U.estimate_ciphertext_size(0), 32)
        self.assertEqual(U.estimate_ciphertext_size(1), 33)
        self.assertEqual(U.estimate_ciphertext_size(U.CH), U.CH + 64)
        self.assertEqual(U.estimate_ciphertext_size(U.CH + 1), U.CH + 1 + 64)

    def test_storage_preflight_applies_margin_and_reports_unknown_space(self):
        target = Path(tempfile.gettempdir())
        estimated = 2 << 20
        required = estimated + max(1 << 20, estimated // 20)
        with mock.patch.object(U.shutil, "disk_usage", return_value=SimpleNamespace(free=required)):
            result = U.storage_preflight(target, estimated)
        self.assertEqual(result["status"], "pass")
        self.assertEqual(result["required"], required)
        with mock.patch.object(U.shutil, "disk_usage", return_value=SimpleNamespace(free=required - 1)):
            result = U.storage_preflight(target, estimated)
        self.assertEqual(result["status"], "insufficient")
        with mock.patch.object(U.shutil, "disk_usage", side_effect=OSError("unavailable")):
            result = U.storage_preflight(target, estimated)
        self.assertEqual(result["status"], "unavailable")
        self.assertIsNone(result["free"])

    def test_estimates_reject_invalid_sizes(self):
        for size in (-1, True, 1.5):
            with self.subTest(size=size), self.assertRaises(ValueError):
                U.estimate_ciphertext_size(size)
        with self.assertRaises(ValueError):
            U.storage_preflight(Path(tempfile.gettempdir()), -1)


class TestSearchPrivacy(unittest.TestCase):
    def test_masked_search_index_excludes_file_name(self):
        visible = U.vault_search_text("0123456789ab", "private-report.pdf", "PDF / 12 KB", True)
        unmasked = U.vault_search_text("0123456789ab", "private-report.pdf", "PDF / 12 KB", False)
        self.assertNotIn("private-report", visible)
        self.assertIn("0123", visible)
        self.assertIn("private-report.pdf", unmasked)


@unittest.skipUnless(REAL_QT, "Real Qt widgets are required for vault UI checks.")
class TestVaultListWidgets(unittest.TestCase):
    def setUp(self):
        self.addCleanup(flush_deferred_deletes)
        self.old_set = U.cfg.get("set")
        U.cfg["set"] = dict(U.DEF, mask=False)
        self.parent = QWidget()
        self.layout = QVBoxLayout(self.parent)
        self.empty = QLabel("empty")
        self.no_results = QLabel("no matches")
        self.layout.addWidget(self.empty)
        self.layout.addWidget(self.no_results)
        self.parent.show()
        _QT_APP.processEvents()
        self.cards = {}
        self.search = QLineEdit()
        self.sort = QComboBox()
        for label, value in (("Stored", "stored"), ("Type", "type"),
                             ("Largest", "largest"), ("Smallest", "smallest")):
            self.sort.addItem(label, value)
        self.state = SimpleNamespace(
            cards=self.cards,
            empty=self.empty,
            no_results=self.no_results,
            search_edit=self.search,
            sort_order=self.sort,
            rows=self.layout,
            card_details=lambda meta, name: U.App.card_details(self.state, meta, name),
            apply_vault_filter=lambda query=None: U.App.apply_vault_filter(self.state, query),
            set_group_collapsed=lambda key, collapsed: U.App.set_group_collapsed(
                self.state, key, collapsed),
            toggle_group_collapsed=lambda key: U.App.toggle_group_collapsed(
                self.state, key),
            set_group_items_selected=lambda key, selected: U.App.set_group_items_selected(
                self.state, key, selected),
        )

    def tearDown(self):
        self.parent.deleteLater()
        if self.old_set is None:
            U.cfg.pop("set", None)
        else:
            U.cfg["set"] = self.old_set

    def add_card(self, rid, name, size, group=None):
        card = QFrame(self.parent)
        card.rid = rid
        card.name = name
        card.meta = {"size": size, "exp": None, "views": None}
        if group is not None:
            card.meta["group"] = group
        card.filter_text = U.vault_search_text(rid, name, U.App.card_details(self.state, card.meta, name), False)
        self.cards[rid] = card
        self.layout.addWidget(card)

    def test_search_and_sort_use_only_allowed_fields_when_masked(self):
        self.add_card("111111111111", "private-report.pdf", 100)
        self.add_card("222222222222", "notes.txt", 200)
        U.App.apply_vault_filter(self.state, "pdf")
        self.assertFalse(self.cards["111111111111"].isHidden())
        self.assertTrue(self.cards["222222222222"].isHidden())

        U.cfg["set"]["mask"] = True
        U.App.apply_vault_filter(self.state, "private-report")
        self.assertTrue(self.cards["111111111111"].isHidden())
        self.assertTrue(self.no_results.isVisible())
        U.App.apply_vault_filter(self.state, "2222")
        self.assertFalse(self.cards["222222222222"].isHidden())
        self.assertNotIn("private-report", self.cards["111111111111"].filter_text)

        self.sort.setCurrentIndex(self.sort.findData("largest"))
        U.App.apply_vault_sort(self.state)
        ordered = [self.layout.itemAt(i).widget() for i in range(2, self.layout.count())]
        self.assertEqual(ordered, [self.cards["222222222222"], self.cards["111111111111"]])

    def test_empty_and_no_match_states_are_distinct(self):
        U.App.apply_vault_filter(self.state, "missing")
        self.assertTrue(self.empty.isVisible())
        self.assertFalse(self.no_results.isVisible())
        self.add_card("111111111111", "notes.txt", 10)
        U.App.apply_vault_filter(self.state, "missing")
        self.assertFalse(self.empty.isVisible())
        self.assertTrue(self.no_results.isVisible())

    def test_grouped_items_render_together_under_virtual_folder_headers(self):
        self.add_card("111111111111", "trip-a.txt", 10, "Travel")
        self.add_card("222222222222", "loose.txt", 20)
        self.add_card("333333333333", "trip-b.txt", 30, "Travel")
        self.add_card("444444444444", "work.txt", 40, "Work")

        U.App.apply_vault_sort(self.state)
        widgets = [self.layout.itemAt(index).widget() for index in range(self.layout.count())]
        travel_header = next(widget for widget in widgets
                             if widget is not None and widget.objectName() == "folderHeader"
                             and "Travel" in widget.findChild(QLabel).text())
        travel_index = widgets.index(travel_header)
        self.assertEqual(widgets[travel_index + 1:travel_index + 3],
                         [self.cards["111111111111"], self.cards["333333333333"]])

        U.App.apply_vault_filter(self.state, "trip-a")
        self.assertTrue(travel_header.isVisible())
        work_header = next(widget for widget in widgets
                           if widget is not None and widget.objectName() == "folderHeader"
                           and "Work" in widget.findChild(QLabel).text())
        self.assertFalse(work_header.isVisible())

    def test_drag_feedback_overlay_tracks_recent_cursor_path_and_clears_it(self):
        overlay = U.DropFeedbackOverlay(self.parent)
        overlay.resize(300, 200)
        overlay.track_position(U.QPointF(20, 30))
        overlay.track_position(U.QPointF(45, 55))
        self.assertEqual(len(overlay.trace_points), 2)
        self.assertEqual(overlay.cursor_position, U.QPointF(45, 55))
        overlay.clear_trace()
        self.assertEqual(overlay.trace_points, ())


@unittest.skipUnless(REAL_QT, "Real Qt timers are required for reduced-motion checks.")
class TestReducedMotion(unittest.TestCase):
    def test_reduced_motion_pauses_animated_background_without_changing_security_settings(self):
        self.addCleanup(flush_deferred_deletes)
        old_set = U.cfg.get("set")
        U.cfg["set"] = dict(U.DEF, bg="rain", perf="full", reduce_motion=False, bgfocus=False)
        stage = U.Stage()
        try:
            stage.show()
            U.QApplication.processEvents()
            self.assertTrue(stage.tm.isActive())
            U.cfg["set"]["reduce_motion"] = True
            U.Stage.setfps(stage)
            self.assertFalse(stage.tm.isActive())
            self.assertFalse(U.DEF["reduce_motion"])
            self.assertNotIn("reduce_motion", U.SECKEYS)
            self.assertNotIn("reduce_motion", U.PROTKEYS)
        finally:
            stage.tm.stop()
            stage.deleteLater()
            if old_set is None:
                U.cfg.pop("set", None)
            else:
                U.cfg["set"] = old_set


if __name__ == "__main__":
    unittest.main()

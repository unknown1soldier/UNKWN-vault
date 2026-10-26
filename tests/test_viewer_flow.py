"""Control-flow test of the Viewer with Qt replaced by stubs (no Qt/Windows needed). Proves routing and fallbacks, NOT real Qt rendering."""
# pyright: reportConstantRedefinition=false, reportUnknownParameterType=false, reportMissingParameterType=false
# pyright: reportUnknownArgumentType=false, reportUnknownMemberType=false, reportUnknownVariableType=false
# pyright: reportSelfClsParameterName=false, reportPrivateUsage=false, reportUnknownLambdaType=false
# pyright: reportCallIssue=false, reportArgumentType=false, reportIndexIssue=false, reportAssignmentType=false
# pyright: reportUnusedVariable=false, reportOptionalSubscript=false, reportAttributeAccessIssue=false, reportOptionalCall=false
# pyright: reportOptionalMemberAccess=false
import os, sys, unittest, tempfile
from types import SimpleNamespace
from pathlib import Path
from typing import Any, Callable, Optional, Union, cast
from unittest.mock import MagicMock
ROOT = Path(__file__).resolve().parent.parent; sys.path.insert(0, str(ROOT))
import unknwn_media as MD
import unknwn as U
SRC = (ROOT / "unknwn.py").read_text(encoding="utf-8"); CLS = SRC[SRC.index("class Viewer(QDialog):"):SRC.index("class App(Stage):")]

class Sz:
    def width(s): return 100
    def height(s): return 100
    def scaled(s, *a): return s
class Movie:
    ok, frames = True, 3
    def __init__(s, *a): pass
    def isValid(s): return s.ok
    def frameCount(s): return s.frames
    def jumpToFrame(s, n): pass
    def currentImage(s): return MagicMock(size=lambda: Sz())
    def setScaledSize(s, z): pass
    def start(s): pass
    def stop(s): Movie.stopped = True
class Dialog:
    def __init__(s, *a): pass
    def done(s, r): pass
    def closeEvent(s, e): pass
    def resizeEvent(s, e): pass
    def paintEvent(s, e): pass
    def __getattr__(s, n): return MagicMock()

class PhotoCanvasMeta(type):
    @property
    def return_value(cls):
        return cls._return_value

    @return_value.setter
    def return_value(cls, value):
        cls._return_value = value

    def __instancecheck__(cls, instance):
        return instance is cls._return_value

class PhotoCanvasStub(metaclass=PhotoCanvasMeta):
    """Type-shaped mock factory for Viewer checks and test assertions."""
    _return_value = MagicMock()

    def __new__(cls, *args, **kwargs):
        return cls._return_value

def make(loadok=True, media=True, svg=True, export=True, movie_ok=True, vmode="mem", ghost=0, fitz_module=None, theme=None):
    pm = MagicMock(); pm.loadFromData.return_value = loadok
    qpix = MagicMock(return_value=pm); qpix.fromImage = MagicMock()
    qscroll = MagicMock()
    qscroll.return_value.viewport.return_value.width.return_value = 800
    qscroll.return_value.viewport.return_value.height.return_value = 600
    qlineedit = MagicMock(); qlineedit.return_value.text.return_value = ""
    qcombobox = MagicMock(); qcombobox.return_value.currentText.return_value = "Name"
    PhotoCanvasStub.return_value = MagicMock()
    theme = theme or {"panel": "#140e24", "field": "#0b0816", "fg": "#ece8ff", "line": "#2a2145", "acc": "#8b5cff"}
    g = dict(QDialog=Dialog, S=lambda k: {"export": export, "vmode": vmode, "ghost": ghost}.get(k, 0), MD=MD, ACC="#22d3ee", TH=theme,
             mix=lambda a, b, amount: f"mix({a},{b},{amount})", lbl=MagicMock(), btn=MagicMock(), nocap=lambda *a: None, fmt=lambda n: f"{n} B", MUT="#888",
             QPointF=MagicMock(), QPoint=MagicMock(), QRect=MagicMock(), QRectF=MagicMock(), QEvent=MagicMock(), QAbstractNativeEventFilter=MagicMock(), QObject=MagicMock(), QRunnable=MagicMock(), QThreadPool=MagicMock(),
             QPixmap=qpix, QMovie=Movie, QByteArray=MagicMock(), QBuffer=MagicMock(), QIODevice=MagicMock(), QGraphicsOpacityEffect=MagicMock(), QVBoxLayout=MagicMock(), QHBoxLayout=MagicMock(),
             QLabel=MagicMock(side_effect=lambda *args, **kwargs: MagicMock()), QPushButton=MagicMock(), QFrame=MagicMock(), QCloseEvent=MagicMock(), QResizeEvent=MagicMock(), QPaintEvent=MagicMock(), PhotoCanvas=PhotoCanvasStub, QScrollArea=qscroll, QWidget=MagicMock(), QImage=MagicMock(), QPlainTextEdit=MagicMock(), QSlider=MagicMock(), QSizePolicy=MagicMock(), QFont=MagicMock(), Qt=MagicMock(), QTimer=MagicMock(), QPainter=MagicMock(),
             QColor=MagicMock(), QTransform=MagicMock(), QUrl=MagicMock(), tmp_media=MagicMock(return_value=Path("/t/x.mp4")), tmp_wipe=MagicMock(), log_security_event=MagicMock(), QFileDialog=MagicMock(), Path=Path, QMediaContent=MagicMock(),
             QMediaPlayer=MagicMock() if media else None, QVideoWidget=MagicMock(), QSvgWidget=MagicMock() if svg else None, QShortcut=MagicMock(), QKeySequence=lambda key: key, fitz=fitz_module,
             QListWidget=MagicMock(), QListWidgetItem=MagicMock(), QMessageBox=MagicMock(), QSpinBox=MagicMock(),
             QLineEdit=qlineedit, QComboBox=qcombobox, sanitize_text=lambda value, limit=2000: str(value)[:limit],
             HOME=Path(tempfile.gettempdir()) / "unknwn-viewer-flow-home", Callable=Callable, Optional=Optional, Union=Union, os=os,
             Any=Any, cast=cast, _clicked_slot=U._clicked_slot, _noarg_slot=U._noarg_slot,
             _PdfRendererLike=U._PdfRendererLike, _PdfDocumentLike=U._PdfDocumentLike,
             atomic_write_bytes=lambda path, data: Path(path).write_bytes(data),
             save_verified_temp_copy=MagicMock())
    Movie.ok = movie_ok; exec(CLS, g); return g, g["Viewer"]

class Flow(unittest.TestCase):
    def view(s, name, data, **kw):
        g, V = make(**kw); v = V(name, data, False, None); return g, v
    def test_text_goes_to_text_editor(s):
        g, v = s.view("a.txt", "h\u00E9llo".encode()); g["QPlainTextEdit"].assert_called_once(); s.assertEqual(g["QPlainTextEdit"].call_args[0][0], "h\u00E9llo")
    def test_utf16_text(s):
        g, v = s.view("a.txt", "h\u00E9llo".encode("utf-16")); s.assertEqual(g["QPlainTextEdit"].call_args[0][0], "h\u00E9llo")
    def test_image_shown(s):
        g, v = s.view("a.png", b"\x89PNG\r\n\x1a\n" + b"x" * 40); s.assertIsNotNone(v.pm); s.assertIsNone(v.mp)
    def test_undecodable_image_falls_back_to_info_hexdump(s):
        g, v = s.view("a.png", b"\x89PNG\r\n\x1a\n\0\0\0", loadok=False); s.assertIsNone(v.pm); s.assertIn("00000000", g["QPlainTextEdit"].call_args[0][0])
    def test_animated_gif_uses_movie(s):
        g, v = s.view("a.gif", b"GIF89a" + b"x" * 40); s.assertIsInstance(v.mv, Movie)
    def test_single_frame_gif_is_a_picture(s):
        Movie.frames = 1
        try: g, v = s.view("a.gif", b"GIF89a" + b"x" * 40); s.assertIsNone(v.mv); s.assertIsNotNone(v.pm)
        finally: Movie.frames = 3
    def test_video_uses_player_from_memory_buffer(s):
        g, v = s.view("a.mp4", b"\0\0\0\x18ftypisom" + b"x" * 40); s.assertIsNotNone(v.mp); g["QBuffer"].return_value.setData.assert_called_once()
    def test_default_video_playback_does_not_create_plaintext_temp_file(s):
        g, v = s.view("a.mp4", b"\0\0\0\x18ftypisom" + b"x" * 40)
        g["tmp_media"].assert_not_called(); g["QBuffer"].return_value.setData.assert_called_once()
    def test_sideways_phone_photo_is_rotated(s):
        e = lambda n: n.to_bytes(2, "little"); q = lambda n: n.to_bytes(4, "little")
        seg = b"Exif\0\0" + b"II" + e(42) + q(8) + e(1) + e(0x0112) + e(3) + q(1) + e(6) + b"\0\0" + q(0); jpg = b"\xff\xd8\xff\xe1" + (len(seg) + 2).to_bytes(2, "big") + seg + b"\xff\xd9"
        g, v = s.view("a.jpg", jpg); s.assertTrue(g["QPixmap"]().transformed.called); s.assertIsNotNone(v.pm)
    def test_plain_png_is_not_transformed(s):
        g, v = s.view("a.png", b"\x89PNG\r\n\x1a\n" + b"x" * 40); s.assertFalse(g["QPixmap"]().transformed.called)
    def test_image_zoom_in_out_and_reset(s):
        g, v = s.view("a.png", b"\x89PNG\r\n\x1a\n" + b"x" * 40)
        label = g["PhotoCanvas"].return_value; label.width.return_value = 300; label.height.return_value = 200
        g["QPixmap"]().size.return_value = Sz()
        v.change_zoom(1.25)
        s.assertEqual(v.image_zoom, 1.25); g["lbl"].return_value.setText.assert_called_with("125%")
        g["QPixmap"]().scaled.assert_called_with(
            125,
            125,
            g["Qt"].AspectRatioMode.KeepAspectRatio,
            g["Qt"].TransformationMode.SmoothTransformation,
        )
        v.change_zoom(1 / 1.25); s.assertEqual(v.image_zoom, 1.0)
        v.change_zoom(1 / 1.25); s.assertEqual(v.image_zoom, 0.8)
        v.reset_zoom(); s.assertEqual(v.image_zoom, 1.0); g["lbl"].return_value.setText.assert_called_with("100%")
    def test_photo_zoom_shortcuts_are_registered(s):
        g, v = s.view("a.png", b"\x89PNG\r\n\x1a\n" + b"x" * 40)
        keys = [call.args[0] for call in g["QShortcut"].call_args_list]
        s.assertEqual(keys, ["+", "-", "0", "Escape"])
    def test_photo_canvas_supports_marking_and_wheel_zoom(s):
        g, v = s.view("a.png", b"\x89PNG\r\n\x1a\n" + b"x" * 40)
        s.assertEqual(v.lb.zoom_callback, v.change_zoom)
        s.assertTrue(v.photo_scroll.setWidget.called)
        keys = [call.args[0] for call in g["QShortcut"].call_args_list]
        s.assertIn("Escape", keys)
    def test_media_starts_after_the_window_is_shown_not_in_the_constructor(s):
        g, v = s.view("a.mp4", b"\0\0\0\x18ftypisom" + b"x" * 40); v.mp.setMedia.assert_not_called(); v.mp.play.assert_not_called(); g["QTimer"].singleShot.assert_called()
        v.start_media(); v.mp.setMedia.assert_called_once(); v.mp.play.assert_called_once()
    def test_playback_speed_controls_are_bounded_and_shortcut_enabled(s):
        g, v = s.view("a.mp4", b"\0\0\0\x18ftypisom" + b"x" * 40)
        keys = [call.args[0] for call in g["QShortcut"].call_args_list]
        s.assertEqual(keys, ["F", "M", "Space", "Ctrl+Left", "Ctrl+Right", "Left", "Right", "Up", "Down"])
        v.change_speed(0.25); s.assertEqual(v.speed, 1.25); v.mp.setPlaybackRate.assert_called_with(1.25)
        for _ in range(10): v.change_speed(0.25)
        s.assertEqual(v.speed, 2.0)
        for _ in range(10): v.change_speed(-0.25)
        s.assertEqual(v.speed, 0.5)
        v.release_media(); g["btn"].return_value.setEnabled.assert_called_with(False)
    def test_video_time_seek_mute_and_fullscreen_controls(s):
        g, v = s.view("a.mp4", b"\0\0\0\x18ftypisom" + b"x" * 40)
        s.assertEqual(v.format_time(3_723_000), "01:02:03")
        v.mp.position.return_value = 4000; v.mp.duration.return_value = 10_000
        v.seek_by(8_000); v.mp.setPosition.assert_called_with(10_000)
        v.seek_by(-20_000); v.mp.setPosition.assert_called_with(0)
        v.volume_slider.value.return_value = 70; v.toggle_mute(g["btn"].return_value)
        v.volume_slider.setValue.assert_called_with(0)
        v.isFullScreen = MagicMock(return_value=False); v.showFullScreen = MagicMock(); v.showNormal = MagicMock()
        v.toggle_fullscreen(); v.showFullScreen.assert_called_once()
        v.isFullScreen.return_value = True; v.toggle_fullscreen(); v.showNormal.assert_called_once()
    def test_file_mode_writes_one_temp_file_and_wipes_it_on_close(s):
        g, v = s.view("a.mp4", b"\0\0\0\x18ftypisom" + b"x" * 40, vmode="file"); g["tmp_media"].assert_called_once(); g["QBuffer"].assert_not_called(); g["tmp_wipe"].assert_not_called()
        v.done(0); g["tmp_wipe"].assert_called_once_with(Path("/t/x.mp4"))
    def test_streamed_disk_media_path_is_used_without_copying_to_another_temp_file(s):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "a.mp4"; path.write_bytes(b"\0\0\0\x18ftypisom" + b"x" * 40)
            g, V = make(vmode="file")
            v = V("a.mp4", None, False, None, media_path=path)
            s.assertEqual(v.tmp, path)
            g["tmp_media"].assert_not_called()
            g["QBuffer"].assert_not_called()
            v.closeEvent(MagicMock())
            g["tmp_wipe"].assert_called_once_with(path)
    def test_disk_backed_media_exposes_verified_save_action_when_exports_are_enabled(s):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "a.mp4"; path.write_bytes(b"\0\0\0\x18ftypisom" + b"x" * 40)
            output = Path(directory) / "saved.mp4"
            g, V = make(vmode="file")
            v = V("a.mp4", None, False, None, media_path=path, media_digest="verified-digest")
            s.assertIsNotNone(v.sv)
            g["QFileDialog"].getSaveFileName.return_value = (str(output), "")
            v.save_temp_copy()
            g["save_verified_temp_copy"].assert_called_once_with(path, output, "verified-digest")
    def test_window_close_releases_player_and_wipes_file_backed_media(s):
        g, v = s.view("a.mp4", b"\0\0\0\x18ftypisom" + b"x" * 40, vmode="file")
        player = v.mp
        v.closeEvent(MagicMock())
        g["tmp_wipe"].assert_called_once_with(Path("/t/x.mp4"))
        player.deleteLater.assert_called_once()
        s.assertIsNone(v.tmp)
        s.assertTrue(v.closed)
    def test_playback_error_releases_and_wipes_file_backed_media(s):
        g, v = s.view("a.mp4", b"\0\0\0\x18ftypisom" + b"x" * 40, vmode="file")
        player = v.mp
        v.media_error(MagicMock(), player)
        g["tmp_wipe"].assert_called_once_with(Path("/t/x.mp4"))
        player.deleteLater.assert_called_once()
    def test_pause_button_after_playback_error_does_not_use_released_player(s):
        g, v = s.view("a.mp4", b"\0\0\0\x18ftypisom" + b"x" * 40, vmode="file")
        player = v.mp
        pause_handler = g["btn"].return_value.clicked.connect.call_args_list[0].args[0]
        v.media_error(MagicMock(), player)
        g["btn"].return_value.setEnabled.assert_called_with(False)
        pause_handler()
    def test_player_setup_exception_wipes_file_backed_media(s):
        g, V = make(vmode="file")
        g["QMediaPlayer"].side_effect = RuntimeError("player init failed")
        v = V("a.mp4", b"\0\0\0\x18ftypisom" + b"x" * 40, False, None)
        g["tmp_media"].assert_called_once()
        g["tmp_wipe"].assert_called_once_with(Path("/t/x.mp4"))
    def test_ghost_mode_never_writes_a_temp_file(s):
        g, v = s.view("a.mp4", b"\0\0\0\x18ftypisom" + b"x" * 40, vmode="file", ghost=1); g["tmp_media"].assert_not_called(); g["QBuffer"].assert_called()
    def test_video_off_shows_info_only(s):
        g, v = s.view("a.mp4", b"\0\0\0\x18ftypisom" + b"x" * 40, vmode="off"); s.assertIsNone(v.mp); s.assertIn("00000000", g["QPlainTextEdit"].call_args[0][0])
    def test_start_after_close_does_nothing(s):
        g, v = s.view("a.mp4", b"\0\0\0\x18ftypisom" + b"x" * 40); player = v.mp; v.done(0); player.setMedia.reset_mock(); v.start_media(); player.play.assert_not_called()
    def test_audio_uses_player(s): g, v = s.view("a.mp3", b"ID3\x03" + b"x" * 40); s.assertIsNotNone(v.mp)
    def test_video_without_multimedia_falls_back_to_info(s):
        g, v = s.view("a.mp4", b"\0\0\0\x18ftypisom" + b"x" * 40, media=False); s.assertIsNone(v.mp); s.assertIn("00000000", g["QPlainTextEdit"].call_args[0][0])
    def test_unknown_binary_gets_info_and_save_button_when_export_allowed(s):
        g, v = s.view("a.bin", bytes(range(256)) * 4, loadok=False); s.assertIn("00000000", g["QPlainTextEdit"].call_args[0][0]); s.assertIsNotNone(v.sv)
    def test_no_save_button_when_export_off(s):
        g, v = s.view("a.bin", bytes(range(256)) * 4, loadok=False, export=False); s.assertIsNone(v.sv)
    def test_zip_uses_in_app_archive_listing(s):
        import io, zipfile
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as archive: archive.writestr("readme.txt", "hello")
        g, v = s.view("bundle.zip", stream.getvalue())
        g["QListWidget"].assert_called_once(); g["QPlainTextEdit"].assert_not_called()
        g["QListWidgetItem"].assert_called_once()
        s.assertIn("readme.txt", g["QListWidgetItem"].call_args.args[0]); s.assertIsNotNone(v.sv)
        v.show_archive_statistics()
        s.assertIn("Files: 1", g["QMessageBox"].information.call_args.args[2])
    def test_zip_browser_search_filters_current_directory(s):
        import io, zipfile
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as archive:
            archive.writestr("readme.txt", "hello"); archive.writestr("other.bin", b"\0")
        g, v = s.view("bundle.zip", stream.getvalue())
        g["QListWidgetItem"].reset_mock()
        v.archive_search.text.return_value = "readme"
        v.populate_archive()
        g["QListWidgetItem"].assert_called_once()
        s.assertIn("readme.txt", g["QListWidgetItem"].call_args.args[0])
    def test_zip_browser_uses_active_theme_for_list_background_and_selection(s):
        theme = {"panel": "#030a10", "field": "#091522", "fg": "#e6f6ff", "line": "#294455", "acc": "#38c8ff"}
        g, v = s.view("bundle.zip", b"PK\x05\x06" + b"\0" * 18, theme=theme)
        listing = g["QListWidget"].return_value
        listing.setStyleSheet.assert_called_once()
        stylesheet = listing.setStyleSheet.call_args.args[0]
        s.assertIn(f"background-color:{theme['panel']}", stylesheet)
        s.assertIn(f"color:{theme['fg']}", stylesheet)
        s.assertIn(f"background-color:{theme['field']}", stylesheet)
        s.assertIn(f"border-left:2px solid {theme['acc']}", stylesheet)
        s.assertIn("::item:selected", stylesheet)
    def test_zip_browser_navigates_into_folders_and_back(s):
        import io, zipfile
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as archive:
            archive.writestr("docs/readme.txt", "hello"); archive.writestr("root.txt", "root")
        g, v = s.view("bundle.zip", stream.getvalue())
        folder = MD.zip_directory_entries(stream.getvalue())[0]
        v.open_archive_item(SimpleNamespace(data=lambda role: folder))
        s.assertEqual(v.archive_path, "docs")
        v.back_archive()
        s.assertEqual(v.archive_path, "")
        v.up_archive()
        s.assertEqual(v.archive_path, "")
    def test_zip_browser_opens_member_in_existing_viewer_flow(s):
        import io, zipfile
        from unittest.mock import patch
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as archive: archive.writestr("docs/readme.txt", "hello")
        data = stream.getvalue(); g, v = s.view("bundle.zip", data)
        entry = MD.zip_directory_entries(data)[0]
        v.navigate_archive(entry["path"])
        member = MD.zip_directory_entries(data, entry["path"])[0]
        child = MagicMock()
        viewer_factory = MagicMock(return_value=child)
        with patch.dict(g, {"Viewer": viewer_factory}):
            v.open_archive_item(SimpleNamespace(data=lambda role: member))
        viewer_factory.assert_called_once_with("docs/readme.txt", b"hello", False, v)
        child.exec_.assert_called_once()
    def test_svg_without_renderer_shows_source(s):
        g, v = s.view("a.svg", b'<svg xmlns="http://www.w3.org/2000/svg"></svg>', svg=False); s.assertIn("<svg", g["QPlainTextEdit"].call_args[0][0])
    def test_pdf_without_renderer_shows_clear_fallback(s):
        g, v = s.view("a.pdf", b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n" + b"\0" * 20, loadok=False)
        message = g["lbl"].call_args_list[0].args[0]
        s.assertIn("PyMuPDF is missing from this app build", message)
        s.assertIn("install the requirements.txt dependencies", message)
        s.assertIn("original remains encrypted", message)
    def test_standalone_build_ships_pymupdf_wrapper_outside_c_backend(s):
        build_script = (ROOT / "build.ps1").read_text(encoding="utf-8")
        s.assertNotIn('"--include-package=pymupdf"', build_script)
        s.assertIn('"--nofollow-import-to=pymupdf.mupdf"', build_script)
        s.assertIn('"--include-data-files=$pymupdfWrapper=mupdf.py"', build_script)
        s.assertIn('"--include-data-files=$pymupdfExtension=_mupdf.pyd"', build_script)
        s.assertIn('"--include-data-files=$pymupdfNativeDll=pymupdf/mupdfcpp64.dll"', build_script)
        s.assertIn('"--msvc=latest"', build_script)
        s.assertIn('"--lto=no"', build_script)
        s.assertNotIn('"--show-scons"', build_script)
        source = (ROOT / "unknwn.py").read_text(encoding="utf-8")
        s.assertIn("try: import pymupdf as fitz", source)
        s.assertIn('if "__compiled__" in globals() or getattr(sys, "frozen", False):\n    sys.dont_write_bytecode = True', source)
        s.assertLess(source.index("sys.dont_write_bytecode = True"), source.index("try: import pymupdf as fitz"))
        s.assertIn("os.add_dll_directory(_pymupdf_dll_directory)", source)
        s.assertNotIn('SetEnvironmentVariable("_CL_"', build_script)
        s.assertNotIn('"/Od"', build_script)
        s.assertRegex(source, r"(?m)^DEV_BUILD = False\s+#")
        s.assertIn("(?m)^DEV_BUILD = False(?=[ \\t]*(?:#|$))", build_script)
    def test_pdf_renders_from_memory_and_supports_page_zoom_and_close(s):
        page = SimpleNamespace(rect=SimpleNamespace(width=612, height=792), get_pixmap=MagicMock(return_value=SimpleNamespace(samples=b"\0\0\0", width=1, height=1, stride=3)))
        doc = SimpleNamespace(needs_pass=False, page_count=2, load_page=MagicMock(return_value=page), close=MagicMock())
        renderer = SimpleNamespace(open=MagicMock(return_value=doc), Matrix=MagicMock(), csRGB=object())
        g, v = s.view("a.pdf", b"%PDF-1.7\n" + b"x" * 20, fitz_module=renderer)
        renderer.open.assert_called_once_with(stream=b"%PDF-1.7\n" + b"x" * 20, filetype="pdf")
        v.change_pdf_page(1); v.change_pdf_zoom(1.25)
        s.assertEqual(v.pdf_page, 1); s.assertEqual(v.pdf_zoom, 1.25); s.assertGreaterEqual(page.get_pixmap.call_count, 3)
        v.done(0); doc.close.assert_called_once()
    def test_pdf_toolbar_exposes_page_jump_fit_width_and_text_search(s):
        page = SimpleNamespace(rect=SimpleNamespace(width=612, height=792, x0=0, y0=0),
                               get_pixmap=MagicMock(return_value=SimpleNamespace(samples=b"\0\0\0", width=1, height=1, stride=3)),
                               search_for=MagicMock(return_value=[]))
        doc = SimpleNamespace(needs_pass=False, page_count=2, load_page=MagicMock(return_value=page), close=MagicMock())
        renderer = SimpleNamespace(open=MagicMock(return_value=doc), Matrix=MagicMock(), csRGB=object())
        g, v = s.view("a.pdf", b"%PDF-1.7\n" + b"x" * 20, fitz_module=renderer)
        v.pdf_search_status = MagicMock()
        s.assertTrue(g["QSpinBox"].return_value.setRange.called)
        v.go_pdf_page(1)
        s.assertEqual(v.pdf_page, 1)
        v.fit_pdf_width()
        s.assertAlmostEqual(v.pdf_zoom, 776 / 612)
        v.pdf_search_input.text.return_value = "needle"
        v.find_pdf_text()
        s.assertEqual(v.pdf_search_status.setText.call_args.args[0], "No matches.")
        page.search_for.return_value = [SimpleNamespace(x0=1, y0=2, width=3, height=4)]
        v.find_pdf_text()
        s.assertEqual(v.pdf_search_status.setText.call_args.args[0], "Found on page 1")
        s.assertTrue(v.pdf_search_rects)
    def test_save_decrypted_copy_button_writes_selected_destination(s):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); output = root / "saved.pdf"
            g, v = s.view("source.pdf", b"%PDF-1.7\ncontents")
            g["HOME"] = root / "appdata"; (g["HOME"] / "vault").mkdir(parents=True)
            g["QFileDialog"].getSaveFileName.return_value = (str(output), "")
            v.save("source.pdf", b"decrypted PDF bytes")
            s.assertEqual(output.read_bytes(), b"decrypted PDF bytes")
    def test_save_decrypted_copy_refuses_vault_destination(s):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); vault = root / "appdata" / "vault"; vault.mkdir(parents=True)
            output = vault / "replacement.cdr"
            g, v = s.view("source.pdf", b"%PDF-1.7\ncontents")
            g["HOME"] = root / "appdata"
            g["QFileDialog"].getSaveFileName.return_value = (str(output), "")
            v.save("source.pdf", b"decrypted content")
            g["QMessageBox"].warning.assert_called_once()
            s.assertFalse(output.exists())
    def test_save_decrypted_copy_cancellation_does_not_write(s):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "saved.bin"
            g, v = s.view("source.bin", b"decrypted content")
            g["QFileDialog"].getSaveFileName.return_value = ("", "")
            v.save("source.bin", b"decrypted content")
            s.assertFalse(output.exists())
            g["QMessageBox"].warning.assert_not_called()
    def test_password_protected_pdf_is_not_rendered(s):
        doc = SimpleNamespace(needs_pass=True, close=MagicMock())
        renderer = SimpleNamespace(open=MagicMock(return_value=doc))
        g, v = s.view("a.pdf", b"%PDF-1.7\n" + b"x" * 20, fitz_module=renderer)
        doc.close.assert_called_once()
        s.assertIn("password-protected", g["lbl"].call_args_list[0].args[0])
    def test_malformed_pdf_reports_preview_failure(s):
        renderer = SimpleNamespace(open=MagicMock(side_effect=RuntimeError("bad PDF")))
        g, v = s.view("a.pdf", b"%PDF-1.7\n" + b"x" * 20, fitz_module=renderer)
        s.assertIn("damaged or uses an unsupported format", g["lbl"].call_args_list[0].args[0])
    def test_exception_in_a_renderer_does_not_crash(s):
        g, V = make(); g["QBuffer"].side_effect = RuntimeError("boom"); v = V("a.mp4", b"\0\0\0\x18ftypisom" + b"x" * 40, False, None); g["QPlainTextEdit"].assert_called()
    def test_empty_file_opens_as_empty_text(s): g, v = s.view("a.txt", b""); s.assertEqual(g["QPlainTextEdit"].call_args[0][0], "")
    def test_done_stops_playback(s):
        g, v = s.view("a.mp4", b"\0\0\0\x18ftypisom" + b"x" * 40); player = v.mp; v.done(0); player.stop.assert_called()

if __name__ == "__main__": unittest.main()

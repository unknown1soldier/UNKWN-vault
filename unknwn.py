"""UNKNWN: offline privacy vault (PyQt5 + AES-256-GCM + scrypt).
Run:   pip install -r requirements.txt  &&  python unknwn.py      (add --portable to keep data next to the app)
Build: .\\build.ps1
Test the self-destruct SAFELY: set UNKNWN_DRYRUN=1 first (nothing is deleted, nothing restarts).
Keys: one random vault key, wrapped twice: by your password and by 8 recovery words (scrypt, 128 MB). No network code."""
import os, sys, json, time, math, random, base64, struct, secrets, re, shutil, subprocess, tempfile, ctypes, hashlib, hmac, platform, uuid, zipfile, zlib, stat, threading, copy, weakref
import importlib.metadata as importlib_metadata
from pathlib import Path
from types import TracebackType
from typing import Any, Callable, Iterable, Iterator, Literal, Mapping, NoReturn, Optional, Protocol, TypedDict, Union, cast, overload
from PyQt5.QtCore import Qt, QTimer, QPropertyAnimation, QEasingCurve, QPointF, QPoint, QRect, QRectF, QEvent, QAbstractNativeEventFilter, QByteArray, QBuffer, QIODevice, QUrl, QObject, QRunnable, QThreadPool, pyqtSignal
import PyQt5.QtCore as _QtCore
from PyQt5.QtGui import QPainter, QLinearGradient, QRadialGradient, QPixmap, QKeySequence, QPen, QFont, QFontMetrics, QPainterPath, QCursor, QMovie, QTransform, QImage, QCloseEvent, QMouseEvent
from PyQt5.QtGui import QColor as _QC
from PyQt5.QtWidgets import (QApplication, QWidget, QFrame, QVBoxLayout, QHBoxLayout, QGridLayout, QLabel, QLineEdit, QPushButton,
    QComboBox, QCheckBox, QFileDialog, QDialog, QPlainTextEdit, QTextBrowser, QScrollArea, QMessageBox,
    QGraphicsOpacityEffect, QShortcut, QStackedWidget, QKeySequenceEdit, QColorDialog, QInputDialog, QSlider, QSizePolicy, QProgressBar,
    QListWidget, QListWidgetItem, QSpinBox, QToolTip)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag
from easter_eggs import (
    EASTER_EGGS,
    SECRET_THEME_DURATION_MS,
    SECRET_THEME_PALETTE,
    SECRET_THEME_PHRASE,
    ThemeSnapshot,
    resource_path,
)
import unknwn_integrity as IG
import unknwn_media as MD
from warden_art import WARDEN_ART
from operation_engine import (
    FileState,
    FileStateError,
    FileStateManager,
    InvalidOperationTransition,
    Operation,
    OperationBlocked,
    OperationManager,
    OperationState,
    SimulationPlan,
    StaleFileState,
    StaleSimulationPlan,
    advise_settings,
)


pyqtProperty: Callable[[type, Callable[..., object], Callable[..., object]], object] = cast(
    Callable[[type, Callable[..., object], Callable[..., object]], object],
    getattr(_QtCore, "pyqtProperty"),
)


class _VaultMetadata(TypedDict):
    s: str
    nm: str
    size: int
    exp: Union[int, float, None]
    views: Optional[int]


class _StorageRecoveryPreview(TypedDict):
    indexed_items: int
    missing_objects: int
    orphan_objects: int
    staged_objects: int
    unsafe_objects: int
    pending_transaction: Optional[str]
    pending_seal_stage: bool


class _OperationFailure(TypedDict):
    name: str
    detail: str


class _SealedRecord(TypedDict):
    rid: str
    metadata: _VaultMetadata
    name: str


class _VaultExportItem(TypedDict):
    rid: str
    file: str
    size: int
    sha256: str


class _PinMark(TypedDict):
    kind: Literal["pin"]
    point: tuple[float, float]


class _HighlightMark(TypedDict):
    kind: Literal["highlight"]
    points: list[tuple[float, float]]


_PhotoMark = Union[_PinMark, _HighlightMark]


class _MediaPlayerLike(Protocol):
    def errorString(self) -> str: ...


class _PdfRectLike(Protocol):
    x0: float
    y0: float
    width: float
    height: float


class _PdfPixmapLike(Protocol):
    samples: bytes
    width: int
    height: int
    stride: int


class _PdfPageLike(Protocol):
    rect: _PdfRectLike
    def get_pixmap(self, *, matrix: Any, colorspace: Any, alpha: bool) -> _PdfPixmapLike: ...
    def search_for(self, text: str) -> list[_PdfRectLike]: ...


class _PdfDocumentLike(Protocol):
    needs_pass: bool
    page_count: int
    def close(self) -> None: ...
    def load_page(self, page: int) -> _PdfPageLike: ...


class _PdfRendererLike(Protocol):
    csRGB: Any
    def open(self, *, stream: bytes, filetype: str) -> _PdfDocumentLike: ...
    def Matrix(self, x: float, y: float) -> Any: ...


class _MoveFileEntry(TypedDict):
    kind: Literal["file"]
    path: str
    size: int
    sha256: str
    mtime_ns: int
    dev: int
    ino: int


class _MoveDirectoryEntry(TypedDict):
    kind: Literal["dir"]
    path: str
    size: int
    sha256: str


_MoveEntry = Union[_MoveFileEntry, _MoveDirectoryEntry]


class _MoveJournal(TypedDict):
    version: int
    operation: str
    phase: Literal["copying", "verified", "committed"]
    entries: list[_MoveEntry]
    source: str
    target: str
    stage: str


class _MoveRecoveryState(TypedDict):
    phase: Literal["copying", "verified", "committed", "unreadable"]
    stage: Optional[str]


class _MoveCopyCompletedResult(TypedDict):
    status: Literal["completed"]
    target: str
    source: str
    retained_backup: bool


class _MoveCopyRecoveryResult(TypedDict):
    status: Literal["recovery_required"]
    target: str
    source: str
    journal: str
    retained_backup: bool


_MoveCopyResult = Union[_MoveCopyCompletedResult, _MoveCopyRecoveryResult]


class _MoveInterruptedResult(TypedDict):
    status: Literal["interrupted"]
    source: str
    target: str
    stage: str


_MoveRecoveryResult = Union[_MoveCopyCompletedResult, _MoveCopyRecoveryResult, _MoveInterruptedResult]


class _MoveCancelledResult(TypedDict):
    status: Literal["cancelled"]
    detail: str


class _MoveFailedResult(TypedDict):
    status: Literal["failed"]
    error: str
    detail: str
    source: str
    target: str
    journal: str
    recovery_state: Optional[_MoveRecoveryState]


_MoveWorkerResult = Union[_MoveCopyCompletedResult, _MoveCopyRecoveryResult, _MoveCancelledResult, _MoveFailedResult]


class _DestructJournalFields(TypedDict):
    version: int
    operation: Literal["panic-wipe", "self-destruct"]
    phase: Literal["pending", "data-cleared"]
    install_target: Optional[str]
    failures: list[str]


class _DestructJournal(_DestructJournalFields, total=False):
    updated: int


class _VaultAnalysisStats(TypedDict):
    file_count: int
    total_bytes: int
    type_bytes: dict[str, int]
    largest: list[tuple[int, str]]
    candidate_count: int


class _SealStageJournal(TypedDict):
    version: Literal[1]
    rid: str
    operation_id: str
    stage_identity: Optional[list[int]]


try: from PyQt5.QtMultimedia import QMediaPlayer, QMediaContent; from PyQt5.QtMultimediaWidgets import QVideoWidget
except Exception: QMediaPlayer = QMediaContent = QVideoWidget = None   # video/audio fall back to the info page
try: from PyQt5.QtSvg import QSvgWidget
except Exception: QSvgWidget = None                                   # SVG falls back to its source text
if "__compiled__" in globals() or getattr(sys, "frozen", False):
    sys.dont_write_bytecode = True
_pymupdf_dll_directory_handle = None
_pymupdf_dll_directory = os.path.join(os.path.dirname(sys.executable), "pymupdf")
if os.name == "nt" and os.path.isdir(_pymupdf_dll_directory) and hasattr(os, "add_dll_directory"):
    _pymupdf_dll_directory_handle = os.add_dll_directory(_pymupdf_dll_directory)
try: import pymupdf as fitz
except ImportError: fitz = None                                       # PDFs show a clear unavailable-renderer message

OPERATION_MANAGER = OperationManager()
FILE_STATE_MANAGER = FileStateManager(OPERATION_MANAGER)


def _start_qrunnable(worker: QRunnable) -> None:
    pool = QThreadPool.globalInstance()
    if pool is None:
        raise RuntimeError("The Qt worker thread pool is unavailable.")
    pool.start(worker)


def _close_widget(widget: QWidget) -> None:
    widget.close()


MAX_SECURITY_FILES = 14
MAX_SECURITY_CANDIDATES = 4096
MAX_SECURITY_BYTES = 64 * 1024
MAX_ERROR_BYTES = 48 * 1024
MAX_INTEGRITY_BYTES = 16 * 1024
MAX_EVENTS = 100
TERMS_OF_SERVICE = """# UNKNWN — Legal Notice, Responsible Use & Acceptable Use Policy
## 1. Purpose of UNKNWN
UNKNWN is a privacy and security application designed to help users protect, organize, encrypt, and manage their own data.
The project is intended for legitimate purposes such as:
- Protecting personal and private files.
- Protecting confidential work or project data.
- Preventing unauthorized access to information.
- Securely storing sensitive information.
- Testing and learning about defensive security and privacy.
- Maintaining personal data confidentiality.
- Safely transferring or backing up data belonging to the user or data the user is legally authorized to manage.
UNKNWN is **not designed, advertised, or intended to facilitate criminal activity, conceal evidence of crimes, evade law enforcement, distribute illegal material, or provide a safe haven for unlawful content.**
---
## 2. User Responsibility
The user is solely responsible for everything they store, import, export, encrypt, decrypt, transfer, or otherwise manage using UNKNWN.
Using encryption or privacy technology does not make otherwise illegal activity legal.
Users must ensure that:
- They have the legal right to possess the data they store.
- They have the necessary authorization to access or manage the data.
- They comply with all applicable laws and regulations.
- They do not use UNKNWN to conceal, distribute, or facilitate illegal material or activity.
- They do not use UNKNWN to interfere with legitimate investigations or legal processes.
- They do not use UNKNWN to intentionally facilitate harm to other people.
UNKNWN does not determine whether a user's data is legal or illegal and does not provide legal authorization for any particular use.
---
## 3. Prohibited Uses
UNKNWN must not be used to intentionally facilitate, conceal, or support:
- Child sexual abuse material or any other sexual exploitation of minors.
- Terrorist or extremist material or activity.
- Planning or facilitating violent criminal activity.
- Fraud, extortion, blackmail, or theft.
- Distribution of malware or other malicious software.
- Unauthorized access to computer systems, accounts, networks, or devices.
- Concealment or destruction of evidence for the purpose of obstructing a lawful investigation.
- Money laundering or other financial crimes.
- Distribution or storage of material that the user is legally prohibited from possessing.
- Any other activity prohibited by applicable law.
This list is not exhaustive. The absence of a particular activity from this list does not make that activity permitted.
---
## 4. Privacy Does Not Mean Immunity
UNKNWN is designed to provide privacy and security. Privacy, however, should not be interpreted as immunity from legal responsibility.
A privacy tool can be used by ordinary people to protect legitimate information, just as many other general-purpose technologies can be misused.
The existence of a security or privacy feature does not constitute an endorsement of unlawful use of that feature.
Users remain responsible for complying with the laws applicable to them.
---
## 5. No Guarantee of Anonymity
UNKNWN is a security and privacy application, not a guarantee of anonymity or immunity from investigation.
No software can honestly guarantee that information will never be recovered, compromised, exposed, or obtained through every possible technical, physical, legal, or investigative method.
Security depends on many factors, including:
- The user's password and recovery information.
- The security of the operating system and device.
- Physical access to the device.
- Malware or other compromise of the device.
- User configuration.
- Backup and recovery procedures.
- Hardware failures.
- Operating-system behavior.
- Human error.
- Vulnerabilities that may be discovered in the future.
Users should therefore not assume that UNKNWN makes any particular information completely unrecoverable or completely inaccessible under every circumstance.
---
## 6. No Endorsement of Illegal Content
UNKNWN does not endorse, approve, encourage, or support illegal content merely because the software is capable of encrypting or storing arbitrary user data.
A general-purpose encryption mechanism cannot reliably determine the legality of every file without inspecting its contents, and UNKNWN is not intended to act as a universal content-classification or law-enforcement system.
The responsibility for the content remains with the person who possesses or manages it.
---
## 7. Lawful Use and Law Enforcement
Nothing in UNKNWN's design, documentation, or licensing should be interpreted as encouraging users to obstruct lawful investigations or evade lawful legal processes.
Users must comply with legally applicable orders, obligations, and requirements.
At the same time, the project recognizes that legitimate privacy and security are important rights and legitimate technical objectives.
The purpose of providing encryption is to protect lawful users and their information from unauthorized access—not to provide a mechanism for criminal activity.
---
## 8. Developer Position
The developer does not authorize or encourage the use of UNKNWN for illegal purposes.
The developer's intention is to provide a legitimate privacy and security tool that can be used by ordinary users, developers, researchers, professionals, and organizations to protect information they are authorized to possess.
The developer does not knowingly endorse the use of UNKNWN for criminal activity or for the storage or distribution of illegal material.
Users should not represent their unlawful use of UNKNWN as being supported, authorized, or endorsed by the developer.
---
## 9. Religious and Ethical Principle
The project is also guided by a simple personal ethical principle:
**Technology is a tool, and the responsibility for how that tool is used belongs to the person using it.**
The developer does not intend to create a tool for harming people, facilitating exploitation, or enabling wrongdoing.
From an Islamic ethical perspective, protecting legitimate privacy and property is fundamentally different from deliberately helping someone commit wrongdoing or conceal harm.
The developer therefore intends UNKNWN to be used for lawful, legitimate, and beneficial purposes and disclaims any intention to participate in or facilitate wrongdoing through the software.
Users remain responsible for their own actions and for the consequences of how they choose to use the software.
---
## 10. No Legal Advice
This document is not legal advice.
Laws differ between countries and jurisdictions and may change over time.
If a user's intended use of UNKNWN involves legally sensitive information, regulated material, investigations, employment confidentiality, or other high-risk circumstances, the user should obtain appropriate professional legal advice.
---
## 11. No Warranty Against Misuse
Because UNKNWN is a general-purpose security application, the developer cannot control every way in which users may choose to use it.
The developer cannot guarantee that every user will follow this policy.
The existence of prohibited-use rules does not mean the developer can technically prevent every prohibited use.
These rules instead clearly state the intended scope of the project and the developer's position regarding misuse.
---
## 12. Important Notice
**If you are using UNKNWN, you are responsible for what you put inside it.**
Do not store, distribute, or manage information using UNKNWN unless you are legally permitted to possess and manage that information.
Do not use UNKNWN as a tool for criminal activity, exploitation, violence, fraud, unauthorized access, or obstruction of lawful investigations.
Use privacy technology responsibly.
---
## 13. Final Statement
UNKNWN exists because people deserve the ability to protect legitimate private information.
The goal is to provide privacy—not to provide a hiding place for crime.
The developer does not intend to create, encourage, or facilitate illegal activity through UNKNWN, and any unlawful use of the software is outside the project's intended purpose and responsibility.
**Protect your privacy. Respect other people's rights. Use the software responsibly.**"""
_DIAGNOSTIC_SENSITIVE_KEYS = (
    "password", "passphrase", "secret", "token", "api_key", "apikey", "credential",
    "authorization", "cookie", "recovery", "phrase", "key", "clipboard", "keystroke",
    "username", "email", "user_path",
)
_DIAGNOSTIC_SECRET_ASSIGNMENT = re.compile(
    r"""(?i)\b(password|passphrase|secret|token|api[_-]?key|credential|authorization|cookie|recovery(?:\s+words?)?|(?:vault|root|master|data[-_ ]?encryption|wrapping)\s+key|dek|key)\b"""
    r"""(\s*[:=]\s*)(?:"[^"]*"|'[^']*'|\[[^\]]*\]|[^,\r\n;]+)"""
)
_DIAGNOSTIC_EMAIL = re.compile(r"""(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b""")
_DIAGNOSTIC_WINDOWS_PATH = re.compile(r"""(?i)\b[A-Z]:\\(?:[^\\\r\n:*?"<>|]+\\)*[^\\\r\n:*?"<>|]+""")
_DIAGNOSTIC_UNC_PATH = re.compile(r"""\\\\[^\\/\r\n]+\\[^\\/\r\n]+(?:\\[^\\/\r\n]+)*""")
_DIAGNOSTIC_POSIX_PATH = re.compile(r"""(?<![\w:])/(?:[^/\r\n"'<>|]+/)*[^/\r\n"'<>|]+""")


def sanitize_text(value: object, limit: int = 2000) -> str:
    text = str(value).replace("\x00", "")
    text = _DIAGNOSTIC_SECRET_ASSIGNMENT.sub(lambda m: m.group(1) + m.group(2) + "[REDACTED]", text)
    text = _DIAGNOSTIC_EMAIL.sub("[EMAIL REDACTED]", text)
    text = _DIAGNOSTIC_WINDOWS_PATH.sub("[PATH REDACTED]", text)
    text = _DIAGNOSTIC_UNC_PATH.sub("[PATH REDACTED]", text)
    text = _DIAGNOSTIC_POSIX_PATH.sub("[PATH REDACTED]", text)
    return text if len(text) <= limit else text[:limit] + "…[truncated]"


def sanitize_value(
    value: object,
    key: Optional[object] = None,
    depth: int = 0,
) -> object:
    if key is not None and any(token in str(key).lower() for token in _DIAGNOSTIC_SENSITIVE_KEYS):
        return "[REDACTED]"
    if depth > 8:
        return "[TRUNCATED]"
    if isinstance(value, dict):
        items = cast(dict[object, object], value).items()
        return {sanitize_text(k, 120): sanitize_value(v, k, depth + 1) for k, v in list(items)[:40]}
    if isinstance(value, (list, tuple)):
        sequence = cast(Union[list[object], tuple[object, ...]], value)
        return [sanitize_value(item, depth=depth + 1) for item in list(sequence)[:40]]
    if isinstance(value, str):
        return sanitize_text(value)
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return sanitize_text(value)


def format_error_log(
    error_type: type[BaseException],
    tb: Optional[TracebackType],
) -> str:
    import traceback

    name = error_type.__name__
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,79}", name):
        name = "Exception"
    frames: traceback.StackSummary = (
        traceback.extract_tb(tb, limit=64) if tb is not None else traceback.StackSummary()
    )
    locations: list[str] = []
    for frame in frames:
        function = frame.name
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,99}", function):
            function = "<frame>"
        locations.append(f"  at {function} (line {frame.lineno})")
    details = "\n".join(locations) if locations else "  No traceback frames were available."
    return f"{tfmt(time.time())}  ERROR {secrets.token_hex(8)}  {name}\n{details}\n"


def write_error_log(
    home: Union[os.PathLike[str], str],
    error_type: type[BaseException],
    tb: Optional[TracebackType],
) -> None:
    directory = Path(home)
    directory.mkdir(parents=True, exist_ok=True)
    with open(directory / "error.log", "a", encoding="utf-8") as output:
        output.write(format_error_log(error_type, tb))


def health_result(name: str, status: str, detail: str) -> dict[str, str]:
    if status not in {"pass", "fail", "warning", "unavailable"}:
        raise ValueError("Unsupported health status")
    return {"name": sanitize_text(name, 120), "status": status, "detail": sanitize_text(detail, 500)}


def integrity_health_result(state: str) -> dict[str, str]:
    if state == "ok":
        return health_result("Release integrity", "pass", "The existing release-integrity checker verified this installation.")
    if state == "dev":
        return health_result("Release integrity", "warning", "This development build does not enforce signed-release integrity.")
    if state == "fail":
        return health_result("Release integrity", "fail", "The existing release-integrity checker blocked this installation.")
    return health_result("Release integrity", "unavailable", "The existing release-integrity checker did not return a recognized state.")


def vault_health_result(status: str, detail: str) -> dict[str, str]:
    labels = {
        "pass": "Authenticated vault index and all indexed encrypted items were verified.",
        "fail": "The vault index or at least one encrypted item could not be authenticated or matched.",
        "warning": "The vault check completed with a warning.",
        "unavailable": "The vault check could not be completed; no skipped check is treated as passing.",
    }
    return health_result("Vault storage", status, detail or labels.get(status, labels["unavailable"]))


def _read_diagnostic_file(
    path: Union[os.PathLike[str], str], limit: int
) -> tuple[str, bytes, bool]:
    try:
        info = Path(path).lstat()
    except FileNotFoundError:
        return "missing", b"", False
    except OSError:
        return "unavailable", b"", False
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        return "unavailable", b"", False
    try:
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as stream:
            opened = os.fstat(stream.fileno())
            if not stat.S_ISREG(opened.st_mode) or opened.st_nlink > 1:
                return "unavailable", b"", False
            if info.st_ino and opened.st_ino and (info.st_ino != opened.st_ino or info.st_dev != opened.st_dev):
                return "unavailable", b"", False
            truncated = opened.st_size > limit
            if truncated:
                stream.seek(-limit, os.SEEK_END)
            raw = stream.read(limit + 1)
        if len(raw) > limit:
            raw = raw[-limit:]
            truncated = True
        return "available", raw, truncated
    except OSError:
        return "unavailable", b"", False


def _read_security_logs(
    home: Union[os.PathLike[str], str],
) -> dict[str, object]:
    candidates: list[Path] = []
    candidate_limit_reached = False
    try:
        with os.scandir(home) as directory:
            for entry in directory:
                if entry.name.startswith("security-") and entry.name.endswith(".log"):
                    candidates.append(Path(home) / entry.name)
                    if len(candidates) >= MAX_SECURITY_CANDIDATES:
                        candidate_limit_reached = True
                        break
    except FileNotFoundError:
        return {"name": "Security event logs", "state": "missing", "detail": "No local log directory or security event log is present; no events are inferred.", "entries": []}
    except OSError:
        return {"name": "Security event logs", "state": "unavailable", "detail": "The local log directory could not be inspected.", "entries": []}
    candidates.sort(key=lambda path: path.name, reverse=True)
    if not candidates:
        return {"name": "Security event logs", "state": "missing", "detail": "No security event log is present; no events are inferred.", "entries": []}
    entries: list[object] = []
    malformed = unavailable = readable_files = 0
    truncated = False
    remaining = MAX_SECURITY_BYTES
    for path in candidates[:MAX_SECURITY_FILES]:
        if remaining <= 0:
            truncated = True
            break
        state, raw, was_truncated = _read_diagnostic_file(path, min(remaining, 16 * 1024))
        if state == "unavailable":
            unavailable += 1
            continue
        if state == "missing":
            continue
        readable_files += 1
        remaining -= len(raw)
        truncated = truncated or was_truncated
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            text = raw.decode("utf-8", errors="replace")
            malformed += 1
        lines = text.splitlines()
        if was_truncated and lines:
            lines = lines[1:]
        for line in lines:
            if not line.strip():
                continue
            try:
                event = json.loads(line)
                if not isinstance(event, dict):
                    raise ValueError("record is not an object")
                entries.append(sanitize_value(cast(dict[object, object], event)))
            except (ValueError, TypeError, json.JSONDecodeError):
                malformed += 1
    entries = entries[-MAX_EVENTS:]
    if malformed:
        state = "malformed"
        detail = f"Some records were malformed or undecodable ({malformed} record(s)); valid records are shown."
    elif unavailable:
        state = "unavailable"
        detail = "One or more local log files could not be read safely."
    elif not readable_files:
        state = "missing"
        detail = "No readable local security-event log is present; no events are inferred."
    elif not entries:
        state = "available"
        detail = "Local security-event logs are present but contain no readable event records."
    else:
        state = "available"
        detail = "Local security-event records are shown; this is a bounded recent excerpt."
    if truncated or len(candidates) > MAX_SECURITY_FILES or remaining <= 0 or candidate_limit_reached:
        detail += " Additional local log data may be omitted by display limits."
    return {"name": "Security event logs", "state": state, "detail": detail, "entries": entries}


def _read_text_diagnostic(
    home: Union[os.PathLike[str], str], filename: str, display_name: str, limit: int
) -> dict[str, str]:
    state, raw, truncated = _read_diagnostic_file(Path(home) / filename, limit)
    if state == "missing":
        return {"name": display_name, "state": "missing", "detail": "This local log is not present; no information is inferred.", "text": ""}
    if state == "unavailable":
        return {"name": display_name, "state": "unavailable", "detail": "The local log could not be read safely.", "text": ""}
    malformed = False
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        text = raw.decode("utf-8", errors="replace")
        malformed = True
    text = sanitize_text(text, limit=limit)
    if truncated:
        text = "[Older log content omitted by the display limit.]\n" + text
    if malformed:
        return {"name": display_name, "state": "malformed", "detail": "The log contains invalid text encoding; replacement characters are shown.", "text": text}
    if not text.strip():
        return {"name": display_name, "state": "available", "detail": "The local log is present but empty.", "text": ""}
    return {"name": display_name, "state": "available", "detail": "Sanitized local excerpt.", "text": text}


def read_local_logs(
    home: Union[os.PathLike[str], str],
) -> list[Mapping[str, object]]:
    return [
        _read_security_logs(home),
        _read_text_diagnostic(home, "error.log", "Crash/error log", MAX_ERROR_BYTES),
        _read_text_diagnostic(home, "integrity.log", "Integrity failure log", MAX_INTEGRITY_BYTES),
    ]


def dependency_advisor() -> list[dict[str, str]]:
    dependencies = (
        ("PyQt5", "PyQt5", True, True, "Application interface"),
        ("cryptography", "cryptography", True, True, "Vault encryption and authentication"),
        ("PyMuPDF", "PyMuPDF", fitz is not None, False, "PDF preview"),
        ("py7zr", "py7zr", MD.py7zr is not None, False, "7-Zip archive browsing"),
        ("rarfile", "rarfile", MD.rarfile is not None, False, "RAR archive browsing"),
    )
    advice: list[dict[str, str]] = []
    for name, distribution, available, required, purpose in dependencies:
        try:
            version = importlib_metadata.version(distribution)
        except (importlib_metadata.PackageNotFoundError, ValueError):
            version = "version metadata unavailable" if available else "not installed"
        if available:
            status = "available"
            recommendation = f"{purpose} is available."
        elif required:
            status = "required-missing"
            recommendation = f"{purpose} is unavailable; reinstall from a trusted UNKNWN release."
        else:
            status = "optional-missing"
            recommendation = (
                f"{purpose} is disabled; install {distribution} from a trusted package source "
                "if this feature is needed. No network request was made.")
        advice.append({
            "name": name,
            "status": status,
            "version": version,
            "purpose": purpose,
            "advice": recommendation,
        })
    return advice


def format_diagnostics(
    sources: Iterable[Mapping[str, object]],
    sign_in_logging_enabled: bool,
    ghost_mode: bool,
    dependencies: Optional[Iterable[Mapping[str, str]]] = None,
) -> str:
    lines = [
        "LOCAL DIAGNOSTICS",
        "Only bounded local logs, config recovery status, and installed dependency metadata are read. No network or export is used.",
        "Automatic security-event logging is attempted locally when called; write failures are suppressed. It is separate from the encrypted sign-in-history setting.",
        "Crash details are normally saved locally; Ghost Mode suppresses crash-log writes. Sign-in history remains in Activity Center and follows its own setting.",
        "",
        f"Encrypted sign-in logging setting: {'enabled' if sign_in_logging_enabled else 'disabled'}.",
        f"Ghost Mode: {'enabled' if ghost_mode else 'disabled'}.",
        "",
    ]
    if dependencies is not None:
        lines.extend(("OFFLINE DEPENDENCY ADVISOR",))
        for dependency in dependencies:
            name = dependency.get("name", "Unknown dependency")
            state = dependency.get("status", "unavailable")
            version = dependency.get("version", "unknown version")
            purpose = dependency.get("purpose", "")
            advice = dependency.get("advice", "")
            lines.append(f"{name} — {state} ({version})")
            if purpose:
                lines.append(str(purpose))
            if advice:
                lines.append(str(advice))
        lines.append("")
    for source in sources:
        name = source.get("name", "")
        state = source.get("state", "")
        detail = source.get("detail", "")
        lines.append(f"{name} — {str(state).upper()}")
        lines.append(str(detail))
        entries = source.get("entries")
        if isinstance(entries, list) and entries:
            for entry in cast(list[object], entries):
                lines.append(sanitize_text(json.dumps(entry, ensure_ascii=False, sort_keys=True), 3000))
        else:
            text = source.get("text")
            if isinstance(text, str) and text:
                lines.append(text)
        lines.append("")
    return "\n".join(lines).rstrip()


_HEALTH_RUN_LOCK = threading.Lock()


class _HealthSignals(QObject):
    finished = pyqtSignal(object)


def _perform_health_checks(
    app_dir: Path,
    compiled: bool,
    vault_dir: Path,
    home: Path,
    root: Optional[bytes],
    index_snapshot: object,
) -> list[dict[str, str]]:
    results: list[dict[str, str]] = []
    try:
        results.append(integrity_health_result(IG.state(app_dir, compiled)))
    except Exception:
        results.append(health_result("Release integrity", "unavailable",
                                     "The existing release-integrity checker could not complete."))
    if root is None:
        results.append(vault_health_result("unavailable", "The vault is not unlocked, so encrypted storage was not checked."))
        return results
    home = Path(home)
    if (home / "storage-txn.json").exists() or (home / "rotate.json").exists():
        results.append(vault_health_result("unavailable", "A storage recovery journal is present; the health check made no changes."))
        return results
    storage_dir = Path(vault_dir)
    if storage_dir.is_symlink() or not storage_dir.is_dir():
        results.append(vault_health_result("unavailable", "The encrypted vault storage directory is unavailable; no check is marked as passed."))
        return results
    if IDX.is_symlink() or IDX.with_name(IDX.name + ".bak").is_symlink():
        results.append(vault_health_result("unavailable", "A vault index path is a symbolic link and was not followed."))
        return results
    try:
        loaded, legacy_index = load_idx(root, with_legacy=True)
        if loaded != index_snapshot:
            raise InvalidTag("The on-disk index does not match the active session index")
        index_warning = bool(legacy_index)
        if IDX.exists():
            try:
                primary_blob: object = json.loads(IDX.read_text(encoding="utf-8"))
                if isinstance(primary_blob, dict):
                    primary_data: dict[object, object] = cast(dict[object, object], primary_blob)
                    if primary_data.get("format") == "UNKNWN-INDEX-2":
                        primary_index = decode_idx_blob(root, primary_data)
                    elif "payload" in primary_data and "sig" in primary_data:
                        primary_index = _validated_idx(verify_payload(primary_data, idx_key(root)))
                    else:
                        primary_index = _validated_idx(primary_data)
                        index_warning = True
                else:
                    primary_index = _validated_idx(primary_blob)
                    index_warning = True
                if primary_index != loaded:
                    index_warning = True
            except (InvalidTag, ValueError, TypeError, KeyError, json.JSONDecodeError):
                index_warning = True
        elif IDX.with_name(IDX.name + ".bak").exists():
            index_warning = True
        expected = set(loaded)
        actual = {path.stem for path in Path(vault_dir).glob("*.cdr") if path.is_file()}
        if actual != expected:
            raise InvalidTag("The encrypted storage inventory does not match the authenticated index")
        for rid, metadata in loaded.items():
            validate_rid(rid)
            unresolved_path = storage_dir / f"{rid}.cdr"
            if unresolved_path.is_symlink():
                raise InvalidTag("An encrypted vault item is a symbolic link")
            path = vault_file_path(rid)
            key = file_key(root, b64d(metadata["s"]))
            authenticated_chunk = False
            plaintext_size = 0
            for plaintext, _is_last, _read, _total in iter_dec(path, key):
                authenticated_chunk = True
                plaintext_size += len(plaintext)
            if not authenticated_chunk:
                raise InvalidTag("An encrypted item is empty")
            if plaintext_size != metadata["size"]:
                raise InvalidTag("An encrypted item does not match its authenticated size metadata")
        if index_warning:
            results.append(vault_health_result("warning", "Vault items passed streaming AES-GCM authentication, but the active index is legacy or the primary index required a compatible fallback. Review a trusted backup before relying on index metadata."))
        elif not loaded:
            results.append(vault_health_result("pass", "No index or encrypted items were present; there was no item payload to authenticate."))
        else:
            results.append(vault_health_result("pass", "The encrypted index authenticated and every indexed item passed streaming AES-GCM authentication."))
    except (InvalidTag, ValueError, TypeError, KeyError, json.JSONDecodeError):
        results.append(vault_health_result("fail", "The encrypted index or an encrypted item failed authentication or inventory checks. No data was changed."))
    except OSError:
        results.append(vault_health_result("unavailable", "The local vault files could not all be read; no skipped check is treated as passing."))
    except Exception:
        results.append(vault_health_result("unavailable", "The vault check could not complete; no skipped check is treated as passing."))
    return results


class _HealthWorker(QRunnable):
    def __init__(
        self,
        app_dir: Path,
        compiled: bool,
        vault_dir: Path,
        home: Path,
        root: Optional[bytes],
        index_snapshot: object,
    ) -> None:
        super().__init__()
        self.app_dir = app_dir
        self.compiled = compiled
        self.vault_dir = vault_dir
        self.home = home
        self.root = root
        self.index_snapshot = index_snapshot
        self.signals = _HealthSignals()

    def run(self) -> None:
        if not _HEALTH_RUN_LOCK.acquire(blocking=False):
            self.signals.finished.emit([health_result("Health check", "unavailable",
                                                      "Another vault health check is already running.")])
            return
        try:
            results = _perform_health_checks(self.app_dir, self.compiled, self.vault_dir, self.home,
                                             self.root, self.index_snapshot)
        except Exception:
            results = [health_result("Health check", "unavailable",
                                     "The health check could not complete; no skipped check is treated as passing.")]
        finally:
            self.root = None
            self.index_snapshot = None
            _HEALTH_RUN_LOCK.release()
        self.signals.finished.emit(results)


class HealthCenterDialog(QDialog):
    def __init__(self, app: "App") -> None:
        super().__init__(app)
        self.app = app
        self._running = False
        self._worker = None
        self.setWindowTitle("UNKNWN // Vault Health Center")
        self.setModal(True)
        self.resize(650, 500)
        layout = QVBoxLayout(self)
        layout.addWidget(lbl("VAULT HEALTH CENTER", 17, ACC, True))
        note = lbl("Read-only checks. Release integrity and encrypted vault items are checked separately. No score is calculated, and skipped checks are never marked as passed.", 12, MUT)
        note.setWordWrap(True); layout.addWidget(note)
        self.loading_message_label = lbl("", 11, MUT)
        self.loading_message_label.setObjectName("easterEggLoadingMessage")
        self.loading_message_label.hide()
        layout.addWidget(self.loading_message_label)
        self.output = QPlainTextEdit(); self.output.setReadOnly(True)
        self.output.setPlainText("No health check has run in this session.")
        layout.addWidget(self.output, 1)
        row = QHBoxLayout(); self.run_button = btn("Run health checks", "go"); close = btn("Close")
        self.run_button.clicked.connect(self.run_checks); close.clicked.connect(lambda: _close_widget(self))
        row.addWidget(self.run_button); row.addStretch(); row.addWidget(close); layout.addLayout(row)

    def run_checks(self) -> None:
        if self._running:
            return
        if getattr(self.app, "working", lambda: False)():
            self.output.setPlainText("Health check unavailable: another vault operation is in progress.")
            return
        root = getattr(self.app, "root", None)
        snapshot = {rid: dict(metadata) for rid, metadata in idx.items()}
        worker = _HealthWorker(APP.parent, COMPILED, VAULT, HOME, root, snapshot)
        worker.signals.finished.connect(self.checks_finished)
        self._worker: Optional[_HealthWorker] = worker
        self._running = True
        self.run_button.setEnabled(False)
        self.loading_message_label.setText(EASTER_EGGS.message("loading"))
        self.loading_message_label.show()
        self.output.setPlainText("Checking release integrity and authenticating indexed encrypted items in the background…")
        try:
            _start_qrunnable(worker)
        except Exception:
            self._running = False
            self._worker = None
            self.run_button.setEnabled(True)
            self.loading_message_label.hide()
            self.output.setPlainText("Health check unavailable: the background worker could not be started; no check is marked as passed.")

    def checks_finished(self, results: list[dict[str, str]]) -> None:
        self._running = False
        self._worker = None
        self.run_button.setEnabled(True)
        self.loading_message_label.hide()
        lines = ["VAULT HEALTH RESULTS", ""]
        for check in results:
            lines.append(f"[{check['status'].upper()}] {check['name']}")
            lines.append(check["detail"])
            lines.append("")
        self.output.setPlainText("\n".join(lines).rstrip())


class DiagnosticsCenterDialog(QDialog):
    def __init__(self, app: "App") -> None:
        super().__init__(app)
        self.app = app
        self.setWindowTitle("UNKNWN // Diagnostics Center")
        self.resize(720, 560)
        layout = QVBoxLayout(self)
        layout.addWidget(lbl("LOCAL DIAGNOSTICS CENTER", 17, ACC, True))
        self.output = QPlainTextEdit(); self.output.setReadOnly(True)
        layout.addWidget(self.output, 1)
        row = QHBoxLayout(); refresh = btn("Refresh"); close = btn("Close")
        refresh.clicked.connect(self.refresh_sources); close.clicked.connect(lambda: _close_widget(self))
        row.addWidget(refresh); row.addStretch(); row.addWidget(close); layout.addLayout(row)
        self.refresh_sources()

    def refresh_sources(self) -> None:
        sources = read_local_logs(HOME)
        sources.append(config_recovery_diagnostic(CFG, REQUIRED_CFG_KEYS))
        self.output.setPlainText(format_diagnostics(
            sources, bool(S("log")), bool(S("ghost")), dependency_advisor()))


class _MoveSignals(QObject):
    progress = pyqtSignal(str, int, int)
    finished = pyqtSignal(object)


def _remove_owned_seal_stage(
    path: Union[os.PathLike[str], str],
    identity: Optional[tuple[int, int]],
) -> bool:
    if identity is None:
        raise OSError("The staged file identity is unavailable; it was preserved for recovery.")
    path = Path(path)
    try:
        info = path.lstat()
    except FileNotFoundError:
        return False
    if (stat.S_ISLNK(info.st_mode)
            or getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
            or not stat.S_ISREG(info.st_mode)
            or (info.st_dev, info.st_ino) != identity):
        raise OSError("The staged path changed unexpectedly; it was preserved for recovery.")
    path.unlink()
    fsync_directory(path.parent)
    return True


def _cleanup_seal_stage(
    root: bytes,
    operation_id: str,
    path: Optional[Path],
    identity: Optional[tuple[int, int]],
) -> None:
    if path is not None:
        try:
            path.lstat()
        except FileNotFoundError:
            pass
        else:
            _remove_owned_seal_stage(path, identity)
    _clear_seal_stage_journal(root, operation_id)


class _SealSignals(QObject):
    progress = pyqtSignal(str, int, int, int, int)
    finished = pyqtSignal(object)


class _SealWorker(QRunnable):
    def __init__(
        self,
        sources: Iterable[tuple[Path, int, int, int, int]],
        root: bytes,
        index_snapshot: Mapping[str, _VaultMetadata],
        ttl: int,
        views: int,
        remove_sources: bool,
        shred_passes: int,
        mask_names: bool,
        source_names: Optional[Mapping[str, str]] = None,
    ) -> None:
        super().__init__()
        self.sources = tuple(sources)
        self.root = bytes(root)
        self.index = dict(index_snapshot)
        self.ttl = ttl
        self.views = views
        self.remove_sources = remove_sources
        self.shred_passes = shred_passes
        self.mask_names = mask_names
        self.source_names = dict(source_names or {})
        total_bytes = sum(entry[1] for entry in self.sources)
        self.operation = OPERATION_MANAGER.create(
            "Seal files", total_items=len(self.sources), total_bytes=total_bytes,
            require_report=True)
        self.cancel = self.operation.cancel_event
        self.resume_event = threading.Event()
        self.resume_event.set()
        self.signals = _SealSignals()

    def _verify_source(self, path: Path, expected: tuple[int, int, int, int]) -> None:
        info = path.lstat()
        if (stat.S_ISLNK(info.st_mode)
                or getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
                or not stat.S_ISREG(info.st_mode)
                or (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns) != expected):
            raise OSError("The selected source changed after review; it was not sealed.")

    def run(self) -> None:
        if not _start_operation(self.operation):
            canceled_items = tuple(str(path) for path in self.sources)
            self.operation.report_result(
                "seal_files", affected_items=canceled_items,
                cancelled_items=canceled_items)
            self.signals.finished.emit({
                "status": "cancelled", "records": [], "failures": [],
                "completed": 0, "total": len(self.sources),
            })
            return
        records: list[_SealedRecord] = []
        failures: list[_OperationFailure] = []
        byte_base = 0
        completed = 0
        canceled = False
        recovery_required = False
        for index, source_record in enumerate(self.sources):
            path, size, modified, device, inode = source_record
            stored_name = self.source_names.get(str(path), path.name)
            expected = (device, inode, size, modified)
            display_name = f"Hidden file ({index + 1}/{len(self.sources)})" if self.mask_names \
                else f"{sanitize_text(path.name, 120)} ({index + 1}/{len(self.sources)})"
            staged = None
            stage_identity = None
            journal_created = False
            if self.cancel.is_set():
                canceled = True
                break
            try:
                self._verify_source(path, expected)
                VAULT.mkdir(parents=True, exist_ok=True)
                vault_info = VAULT.lstat()
                if (stat.S_ISLNK(vault_info.st_mode)
                        or getattr(vault_info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
                        or not stat.S_ISDIR(vault_info.st_mode)):
                    raise OSError("The active vault storage directory is unsafe.")
                rid = os.urandom(6).hex()
                staged = _storage_file_path(rid, ".cdr.txn")
                _create_seal_stage_journal(self.root, rid, self.operation.operation_id)
                journal_created = True
                self.operation.update(current_item=display_name)

                def report_progress(done: int, _total: int) -> None:
                    self.operation.update(
                        current_item=display_name,
                        completed_items=completed,
                        bytes_processed=byte_base + done,
                    )
                    self.signals.progress.emit(
                        display_name, byte_base + done,
                        self.operation.snapshot.total_bytes or 0,
                        completed, len(self.sources))

                def register_stage(identity: tuple[int, int]) -> None:
                    nonlocal stage_identity
                    stage_identity = identity
                    _write_seal_stage_identity(
                        self.root, rid, self.operation.operation_id, identity)

                salt = os.urandom(16)
                key = file_key(self.root, salt)
                enc_file(
                    path, staged, key, report_progress, self.cancel, register_stage,
                    self.resume_event)
                self._verify_source(path, expected)
                if self.cancel.is_set():
                    raise MoveDataCancelled("Encryption was cancelled before commit.")
                stage_info = staged.lstat()
                if (stat.S_ISLNK(stage_info.st_mode)
                        or getattr(stage_info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
                        or not stat.S_ISREG(stage_info.st_mode)):
                    raise OSError("The encrypted staging output is not a safe regular file.")
                stage_identity = (stage_info.st_dev, stage_info.st_ino)
                candidate = dict(self.index)
                candidate[rid] = {
                    "s": b64e(salt),
                    "nm": b64e(seal(key, stored_name.encode())),
                    "size": size,
                    "exp": time.time() + self.ttl if self.ttl else None,
                    "views": self.views or None,
                }
                commit_storage_transaction(
                    self.root, "seal", rid, candidate, staged, expected_index=self.index)
                self.index = candidate
                records.append({"rid": rid, "metadata": candidate[rid], "name": stored_name})
                completed += 1
                self.operation.update(
                    current_item=display_name,
                    completed_items=completed,
                    bytes_processed=byte_base + size,
                )
                _clear_seal_stage_journal(self.root, self.operation.operation_id)
                journal_created = False
                if self.remove_sources:
                    if self.cancel.is_set():
                        canceled = True
                        break
                    shred(path, self.shred_passes)
            except MoveDataCancelled:
                if journal_created:
                    try:
                        _cleanup_seal_stage(
                            self.root, self.operation.operation_id, staged, stage_identity)
                        journal_created = False
                    except Exception as cleanup_exc:
                        recovery_required = True
                        failures.append({
                            "name": path.name,
                            "detail": f"Encrypted staging cleanup is pending recovery ({type(cleanup_exc).__name__}).",
                        })
                canceled = not recovery_required
                break
            except Exception as exc:
                failures.append({
                    "name": path.name,
                    "detail": f"{type(exc).__name__}: {sanitize_text(exc, 400)}",
                })
                if storage_txn_path().exists():
                    recovery_required = True
                    break
                try:
                    if journal_created:
                        _cleanup_seal_stage(
                            self.root, self.operation.operation_id, staged, stage_identity)
                        journal_created = False
                except Exception as cleanup_exc:
                    recovery_required = True
                    failures.append({
                        "name": path.name,
                        "detail": f"Staging cleanup needs recovery: {type(cleanup_exc).__name__}.",
                    })
                if recovery_required:
                    break
            finally:
                if not canceled and not recovery_required:
                    byte_base += size
        if recovery_required:
            self.operation.fail(
                "A staged seal or storage transaction requires recovery.",
                recovery_state="seal_stage_or_storage_transaction_pending",
            )
            status = "recovery_required"
        elif failures:
            self.operation.fail(f"{len(failures)} of {len(self.sources)} file(s) could not be sealed.")
            status = "failed"
        elif canceled or (self.cancel.is_set() and completed < len(self.sources)):
            _mark_operation_cancelled(self.operation)
            status = "cancelled"
        else:
            self.operation.complete()
            status = "completed"
        self.signals.finished.emit({
            "status": status,
            "records": records,
            "failures": failures,
            "completed": completed,
            "total": len(self.sources),
        })
        successful_ids = tuple(record["rid"] for record in records)
        failed_ids = tuple(failure["name"] for failure in failures)
        handled_names = {record["name"] for record in records} | set(failed_ids)
        cancelled_ids = tuple(
            source[0].name for source in self.sources
            if status == "cancelled" and source[0].name not in handled_names)
        affected_ids = tuple(dict.fromkeys((*successful_ids, *failed_ids, *cancelled_ids)))
        self.operation.report_result(
            "seal_files", affected_items=affected_ids,
            succeeded_items=successful_ids, failed_items=failed_ids,
            cancelled_items=cancelled_ids, verified_items=successful_ids,
            committed_items=successful_ids,
            recovery_items=failed_ids if status == "recovery_required" else (),
            failure_codes=("seal_operation_failed",) if failures else ())


class _FolderSealWorker(QRunnable):
    def __init__(
        self,
        folder: Path,
        entries: Iterable[tuple[Path, str, bool, tuple[int, int, int, int]]],
        root_key: bytes,
        index_snapshot: Mapping[str, _VaultMetadata],
        ttl: int,
        views: int,
        remove_sources: bool,
        shred_passes: int,
        mask_names: bool,
    ) -> None:
        super().__init__()
        self.folder = Path(folder)
        self.entries = tuple(entries)
        self.root_key = bytes(root_key)
        self.index = dict(index_snapshot)
        self.ttl = ttl
        self.views = views
        self.remove_sources = remove_sources
        self.shred_passes = shred_passes
        self.mask_names = mask_names
        self.total_bytes = sum(snapshot[2] for _, _, is_dir, snapshot in self.entries if not is_dir)
        self.operation = OPERATION_MANAGER.create(
            "Seal folder", total_items=1, total_bytes=self.total_bytes,
            require_report=True)
        self.cancel = self.operation.cancel_event
        self.resume_event = threading.Event()
        self.resume_event.set()
        self.signals = _SealSignals()

    def run(self) -> None:
        if not _start_operation(self.operation):
            self.operation.report_result(
                "seal_folder", affected_items=(str(self.folder),),
                cancelled_items=(str(self.folder),))
            self.signals.finished.emit({
                "status": "cancelled", "records": [], "failures": [],
                "completed": 0, "total": 1,
            })
            return
        staged = None
        stage_identity = None
        journal_created = False
        records: list[_SealedRecord] = []
        failures: list[_OperationFailure] = []
        canceled = False
        recovery_required = False
        cleanup_warning = False
        archive_name = self.folder.name + ".zip"
        display_name = "Hidden folder archive" if self.mask_names else sanitize_text(archive_name, 120)
        try:
            current_root, current_entries = folder_entries(self.folder)
            if current_root != self.folder.resolve(strict=True) or current_entries != list(self.entries):
                raise OSError("The selected folder changed after review; it was not sealed.")
            VAULT.mkdir(parents=True, exist_ok=True)
            vault_info = VAULT.lstat()
            if (stat.S_ISLNK(vault_info.st_mode)
                    or getattr(vault_info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
                    or not stat.S_ISDIR(vault_info.st_mode)):
                raise OSError("The active vault storage directory is unsafe.")
            rid = os.urandom(6).hex()
            staged = _storage_file_path(rid, ".cdr.txn")
            _create_seal_stage_journal(self.root_key, rid, self.operation.operation_id)
            journal_created = True
            self.operation.update(current_item=display_name)

            def report_progress(done: int, total: int) -> None:
                processed = min(done, self.total_bytes) if self.total_bytes else 0
                self.operation.update(current_item=display_name, bytes_processed=processed)
                self.signals.progress.emit(display_name, processed, self.total_bytes, 0, 1)

            def register_stage(identity: tuple[int, int]) -> None:
                nonlocal stage_identity
                stage_identity = identity
                _write_seal_stage_identity(
                    self.root_key, rid, self.operation.operation_id, identity)

            salt = os.urandom(16)
            key = file_key(self.root_key, salt)
            packed_root, packed_entries, archive_size = enc_folder(
                self.folder, staged, key, report_progress, self.cancel, register_stage,
                self.resume_event)
            if packed_root != self.folder.resolve(strict=True) or packed_entries != list(self.entries):
                raise OSError("The folder inventory changed while it was being sealed.")
            if self.cancel.is_set():
                raise MoveDataCancelled("Folder sealing was cancelled before commit.")
            stage_info = staged.lstat()
            if (stat.S_ISLNK(stage_info.st_mode)
                    or getattr(stage_info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
                    or not stat.S_ISREG(stage_info.st_mode)):
                raise OSError("The encrypted folder stage is not a safe regular file.")
            stage_identity = (stage_info.st_dev, stage_info.st_ino)
            candidate = dict(self.index)
            candidate[rid] = {
                "s": b64e(salt),
                "nm": b64e(seal(key, archive_name.encode())),
                "size": archive_size,
                "exp": time.time() + self.ttl if self.ttl else None,
                "views": self.views or None,
            }
            commit_storage_transaction(
                self.root_key, "seal", rid, candidate, staged, expected_index=self.index)
            self.index = candidate
            records.append({"rid": rid, "metadata": candidate[rid], "name": archive_name})
            self.operation.update(current_item=display_name, completed_items=1, bytes_processed=self.total_bytes)
            self.signals.progress.emit(display_name, self.total_bytes, self.total_bytes, 1, 1)
            _clear_seal_stage_journal(self.root_key, self.operation.operation_id)
            journal_created = False
            if self.remove_sources:
                if self.cancel.is_set():
                    canceled = True
                else:
                    try:
                        remove_folder_sources(self.folder, packed_entries, self.shred_passes)
                    except Exception as exc:
                        cleanup_warning = True
                        log_security_event("folder_source_cleanup_failed", error=type(exc).__name__)
        except MoveDataCancelled:
            if journal_created:
                try:
                    _cleanup_seal_stage(
                        self.root_key, self.operation.operation_id, staged, stage_identity)
                    journal_created = False
                except Exception as cleanup_exc:
                    recovery_required = True
                    failures.append({
                        "name": archive_name,
                        "detail": f"Encrypted staging cleanup is pending recovery ({type(cleanup_exc).__name__}).",
                    })
            canceled = not recovery_required
        except Exception as exc:
            failures.append({"name": archive_name, "detail": f"{type(exc).__name__}: {sanitize_text(exc, 400)}"})
            if storage_txn_path().exists():
                recovery_required = True
            else:
                try:
                    if journal_created:
                        _cleanup_seal_stage(
                            self.root_key, self.operation.operation_id, staged, stage_identity)
                        journal_created = False
                except Exception as cleanup_exc:
                    recovery_required = True
                    failures.append({"name": archive_name,
                                     "detail": f"Staging cleanup needs recovery: {type(cleanup_exc).__name__}."})
        if recovery_required:
            self.operation.fail(
                "A staged folder seal or storage transaction requires recovery.",
                recovery_state="seal_stage_or_storage_transaction_pending",
            )
            status = "recovery_required"
        elif failures:
            self.operation.fail(f"Folder sealing failed: {len(failures)} issue(s).")
            status = "failed"
        elif canceled:
            _mark_operation_cancelled(self.operation)
            status = "cancelled"
        else:
            self.operation.complete()
            status = "completed"
        self.signals.finished.emit({
            "status": status, "records": records, "failures": failures,
            "completed": len(records), "total": 1, "cleanup_warning": cleanup_warning,
        })
        successful_ids = tuple(record["rid"] for record in records)
        failed_ids = tuple(failure["name"] for failure in failures)
        affected_ids = tuple(dict.fromkeys((*successful_ids, *failed_ids)))
        canceled_ids = (str(self.folder),) if status == "cancelled" and not affected_ids else ()
        affected_ids = tuple(dict.fromkeys((*affected_ids, *canceled_ids)))
        self.operation.report_result(
            "seal_folder", affected_items=affected_ids,
            succeeded_items=successful_ids, failed_items=failed_ids,
            cancelled_items=canceled_ids, verified_items=successful_ids,
            committed_items=successful_ids,
            recovery_items=failed_ids if status == "recovery_required" else (),
            failure_codes=("folder_seal_failed",) if failures else ())


_SealQueueJob = tuple[
    str, bytes, Callable[[], Union[_SealWorker, _FolderSealWorker]],
    Callable[[Mapping[str, Any]], None], Optional[Callable[[], None]],
]
_AVATAR_MAGIC = b"UNKNWN-VAULT-AVATAR-v1\x00"
_AVATAR_MAX_BYTES = 5 * 1024 * 1024


def _analysis_category(name: str) -> Literal["Images", "Videos", "Audio", "Documents", "Archives", "Other"]:
    extension = Path(name).suffix.casefold()
    if extension in MD.IMG_EXT:
        return "Images"
    if extension in MD.VID_EXT:
        return "Videos"
    if extension in MD.AUD_EXT:
        return "Audio"
    if extension in {".pdf", ".doc", ".docx", ".odt", ".rtf", ".txt", ".md", ".csv", ".json"}:
        return "Documents"
    if extension in {".zip", ".rar", ".7z", ".gz", ".tar", ".xz", ".bz2"}:
        return "Archives"
    return "Other"


class _VaultAnalysisSignals(QObject):
    progress = pyqtSignal(str, int, int, int, int)
    finished = pyqtSignal(object)


class _VaultAnalysisWorker(QRunnable):
    def __init__(
        self,
        root: bytes,
        index_snapshot: Mapping[str, _VaultMetadata],
        mask_names: bool,
    ) -> None:
        super().__init__()
        self.root = bytes(root)
        self.index: dict[str, _VaultMetadata] = {
            rid: cast(_VaultMetadata, dict(metadata))
            for rid, metadata in index_snapshot.items()
        }
        self.mask_names = mask_names
        self.cancel = threading.Event()
        self.signals = _VaultAnalysisSignals()
        sizes: dict[int, list[str]] = {}
        for rid, metadata in self.index.items():
            sizes.setdefault(metadata["size"], []).append(rid)
        candidates = [rid for group in sizes.values() if len(group) > 1 for rid in group]
        self.candidate_ids: tuple[str, ...] = tuple(sorted(candidates))
        self.total_bytes = sum(self.index[rid]["size"] for rid in self.candidate_ids)
        self.operation = OPERATION_MANAGER.create(
            "Analyze vault duplicates",
            total_items=len(self.candidate_ids),
            total_bytes=self.total_bytes,
            require_report=True,
        )

    def _display_name(self, rid: str, name: str) -> str:
        return f"Hidden file {rid[:4]}" if self.mask_names else sanitize_text(name, 120)

    def run(self) -> None:
        if not _start_operation(self.operation):
            canceled_items = self.candidate_ids
            self.operation.report_result(
                "analyze_vault", affected_items=canceled_items,
                cancelled_items=canceled_items)
            self.signals.finished.emit({"status": "cancelled", "stats": {}, "duplicates": [], "failures": []})
            return
        names: dict[str, str] = {}
        type_bytes: dict[str, int] = {}
        sizes_by_id: dict[str, int] = {}
        failures: list[_OperationFailure] = []
        largest: list[tuple[int, str]] = []
        for rid, metadata in self.index.items():
            try:
                key = file_key(self.root, b64d(metadata["s"]))
                name = unseal(key, b64d(metadata["nm"])).decode("utf-8")
            except Exception as exc:
                name = "Unknown item"
                failures.append({"name": self._display_name(rid, name), "detail": type(exc).__name__})
            names[rid] = name
            size = metadata["size"]
            sizes_by_id[rid] = size
            category = _analysis_category(name)
            type_bytes[category] = type_bytes.get(category, 0) + size
            largest.append((size, self._display_name(rid, name)))

        size_groups: dict[int, list[str]] = {}
        for rid in self.index:
            size_groups.setdefault(sizes_by_id[rid], []).append(rid)
        candidate_ids: list[str] = [rid for group in size_groups.values() if len(group) > 1 for rid in group]
        candidate_total = sum(sizes_by_id[rid] for rid in candidate_ids)
        digest_groups: dict[bytes, list[str]] = {}
        verified_ids: list[str] = []
        failed_ids: list[str] = []
        processed = 0
        completed = 0
        cancelled = False
        for rid in candidate_ids:
            if self.cancel.is_set():
                cancelled = True
                break
            metadata = self.index[rid]
            name = names[rid]
            display = self._display_name(rid, name)
            digest = hashlib.sha256()
            plaintext_size = 0
            try:
                key = file_key(self.root, b64d(metadata["s"]))
                path = _storage_file_path(rid)
                for block, _last, _read, _total in iter_dec(path, key, self.cancel):
                    digest.update(block)
                    plaintext_size += len(block)
                    processed += len(block)
                    self.operation.update(
                        current_item=display,
                        completed_items=completed,
                        bytes_processed=processed,
                    )
                    self.signals.progress.emit(display, processed, candidate_total, completed, len(candidate_ids))
                if plaintext_size != metadata["size"]:
                    raise InvalidTag("Authenticated plaintext size does not match the vault index.")
                digest_groups.setdefault(digest.digest(), []).append(rid)
                verified_ids.append(rid)
                completed += 1
                self.operation.update(
                    current_item=display,
                    completed_items=completed,
                    bytes_processed=processed,
                )
            except MoveDataCancelled:
                cancelled = True
                break
            except Exception as exc:
                failed_ids.append(rid)
                failures.append({"name": display, "detail": type(exc).__name__})

        duplicate_ids = [group for group in digest_groups.values() if len(group) > 1]
        duplicates = [[self._display_name(rid, names[rid]) for rid in group]
                      for group in duplicate_ids]
        duplicate_records = [
            [{"rid": rid, "name": self._display_name(rid, names[rid])} for rid in group]
            for group in duplicate_ids
        ]
        stats: _VaultAnalysisStats = {
            "file_count": len(self.index),
            "total_bytes": sum(sizes_by_id.values()),
            "type_bytes": type_bytes,
            "largest": sorted(largest, reverse=True)[:10],
            "candidate_count": len(candidate_ids),
        }
        if failures:
            self.operation.fail(f"Vault analysis could not authenticate {len(failures)} item(s).")
            status = "failed"
        elif cancelled or (self.cancel.is_set() and completed < len(candidate_ids)):
            _mark_operation_cancelled(self.operation)
            status = "cancelled"
        else:
            self.operation.complete()
            status = "completed"
        self.signals.finished.emit({
            "status": status, "stats": stats, "duplicates": duplicates,
            "duplicate_records": duplicate_records, "failures": failures,
        })
        cancelled_ids = tuple(
            rid for rid in candidate_ids
            if status == "cancelled" and rid not in verified_ids and rid not in failed_ids)
        affected_ids = tuple(dict.fromkeys((*candidate_ids, *failed_ids)))
        self.operation.report_result(
            "analyze_vault", affected_items=affected_ids,
            succeeded_items=verified_ids, failed_items=failed_ids,
            cancelled_items=cancelled_ids,
            verified_items=verified_ids,
            failure_codes=("vault_analysis_failed",) if failures else ())


class _MoveWorker(QRunnable):
    def __init__(
        self,
        source: Union[os.PathLike[str], str],
        target: Union[os.PathLike[str], str],
        root: bytes,
        allow_unknown_space: bool = False,
    ) -> None:
        super().__init__()
        self.source = Path(source)
        self.target = Path(target)
        self.root = root
        self.operation = OPERATION_MANAGER.create(
            "Move vault data", require_report=True)
        self.cancel = self.operation.cancel_event
        self.allow_unknown_space = allow_unknown_space
        self.signals = _MoveSignals()

    def _progress(self, event: tuple[str, int, int]) -> None:
        label, done, total = event
        if label in {"Copying encrypted data", "Destination verified"}:
            self.operation.update(current_item=label, bytes_processed=done, total_bytes=total)
        else:
            self.operation.update(current_item=label)
        self.signals.progress.emit(label, done, total)

    def run(self) -> None:
        if not _start_operation(self.operation):
            del self.root
            self.operation.report_result(
                "move_data", affected_items=(str(self.source), str(self.target)),
                cancelled_items=(str(self.source), str(self.target)))
            self.signals.finished.emit({
                "status": "cancelled",
                "detail": "The queued move was cancelled.",
                "source": str(self.source),
                "target": str(self.target),
                "journal": str(_move_journal_path(self.source)),
            })
            return
        result: _MoveWorkerResult
        try:
            result = copy_data_tree_transaction(
                self.source, self.target, self.root, self.cancel,
                self._progress, self.allow_unknown_space)
        except MoveDataCancelled as exc:
            result = {"status": "cancelled", "detail": sanitize_text(exc, 600)}
        except Exception as exc:
            journal = _move_journal_path(self.source)
            recovery_state: Optional[_MoveRecoveryState] = None
            if journal.exists():
                try:
                    record = _read_move_journal(self.source, self.root)
                    phase_value = record["phase"]
                    stage_value = record["stage"]
                    recovery_state = {
                        "phase": phase_value,
                        "stage": stage_value,
                    }
                except Exception:
                    recovery_state = {"phase": "unreadable", "stage": None}
            failed_result: _MoveFailedResult = {
                "status": "failed",
                "error": type(exc).__name__,
                "detail": sanitize_text(exc, 600),
                "source": str(self.source),
                "target": str(self.target),
                "journal": str(journal),
                "recovery_state": recovery_state,
            }
            result = failed_result
        if result["status"] == "completed":
            self.operation.complete()
        elif result["status"] == "cancelled":
            _mark_operation_cancelled(self.operation)
        else:
            if result["status"] == "recovery_required":
                recovery_state = None
                detail = "The move did not complete."
            else:
                recovery_state = result["recovery_state"]
                detail = result["detail"]
            self.operation.fail(
                detail,
                recovery_state=str(recovery_state) if recovery_state else None,
            )
        del self.root
        self.signals.finished.emit(result)
        affected = (str(self.source), str(self.target))
        if result["status"] == "completed":
            self.operation.report_result(
                "move_data", affected_items=affected, succeeded_items=affected,
                verified_items=(str(self.target),), committed_items=(str(self.target),))
        elif result["status"] == "cancelled":
            self.operation.report_result(
                "move_data", affected_items=affected, cancelled_items=affected)
        else:
            recovery_items = affected if result["status"] == "recovery_required" else ()
            self.operation.report_result(
                "move_data", affected_items=affected, failed_items=affected,
                recovery_items=recovery_items, failure_codes=("move_data_failed",))


class MoveProgressDialog(QDialog):
    def __init__(
        self,
        app: "App",
        worker: _MoveWorker,
        on_finished: Callable[[Any], None],
    ) -> None:
        super().__init__(app)
        self._running = True
        self.cancel = worker.cancel
        self.on_finished = on_finished
        self.setWindowTitle("UNKNWN // Move data")
        self.setModal(True)
        self.setMinimumWidth(460)
        layout = QVBoxLayout(self)
        layout.addWidget(lbl("MOVING ENCRYPTED VAULT DATA", 16, ACC, True))
        self.status: QLabel = lbl("Checking the source and available destination space…", 12, MUT)
        self.status.setWordWrap(True); layout.addWidget(self.status)
        self.loading_message_label = loading_egg_label()
        layout.addWidget(self.loading_message_label)
        self.cancellation_message_label = cancellation_egg_label()
        layout.addWidget(self.cancellation_message_label)
        self._cancellation_egg_shown = False
        self.progress: QProgressBar = QProgressBar()
        self.progress.setRange(0, 0)
        self.progress.setTextVisible(True)
        self.progress.setFormat("Preparing secure copy…")
        layout.addWidget(self.progress)
        self.cancel_button: QPushButton = btn("Cancel")
        self.cancel_button.clicked.connect(self.request_cancel)
        layout.addWidget(self.cancel_button, 0, Qt.AlignmentFlag.AlignRight)
        self._worker: Optional[_MoveWorker] = worker
        worker.signals.progress.connect(self.update_progress)
        worker.signals.finished.connect(self.finish)

    @property
    def is_running(self) -> bool:
        return self._running

    def request_cancel(self) -> None:
        worker = self._worker
        if self._running and worker is not None and not self._cancellation_egg_shown:
            worker.operation.request_cancel()
            self.cancel_button.setEnabled(False)
            self.status.setText(
                "Cancellation requested. The source remains untouched while the current safe step finishes…")
            show_cancellation_egg(self, self.cancellation_message_label)

    def update_progress(self, label: str, done: int, total: int) -> None:
        self.status.setText(label)
        if total > 0:
            self.progress.setRange(0, 1000)
            self.progress.setValue(min(1000, int(done * 1000 / total)))
            self.progress.setFormat(f"{min(100, int(done * 100 / total))}%")
        else:
            self.progress.setRange(0, 0)

    def finish(self, result: object) -> None:
        if not self._running:
            return
        self._running = False
        self._worker = None
        self.accept()

        def notify_finished() -> None:
            self.on_finished(result)

        QTimer.singleShot(0, notify_finished)

    def closeEvent(self, a0: Optional[QCloseEvent]) -> None:
        if self._running:
            self.request_cancel()
            if a0 is not None:
                a0.ignore()
            return
        super().closeEvent(a0)


class _PackageSignals(QObject):
    progress = pyqtSignal(str, int, int)
    finished = pyqtSignal(object)


class _PackageWorker(QRunnable):
    def __init__(self, operation: str, arguments: dict[str, Any]) -> None:
        super().__init__()
        self.operation = operation
        self.arguments: dict[str, Any] = arguments
        self.lifecycle = OPERATION_MANAGER.create(
            "Export vault package" if operation == "export" else "Import vault package",
            require_report=True)
        self.cancel = self.lifecycle.cancel_event
        self.pause = threading.Event()
        self.signals = _PackageSignals()

    def run(self) -> None:
        if not _start_operation(self.lifecycle):
            self.arguments.clear()
            self.lifecycle.report_result(
                f"{self.operation}_package", affected_items=("vault_package",),
                cancelled_items=("vault_package",))
            self.signals.finished.emit({"status": "cancelled", "detail": "The queued operation was cancelled."})
            return
        try:
            args = dict(self.arguments)
            args.update(progress=self._progress,
                        cancel=self.cancel, pause=self.pause)
            if self.operation == "export":
                result = export_vault_package(**args)
            elif self.operation == "import":
                result = import_vault_package(**args)
            else:
                raise ValueError("Unsupported vault-package operation.")
            result["status"] = "completed"
            self.lifecycle.complete()
        except MoveDataCancelled as exc:
            result = {"status": "cancelled", "detail": str(exc)}
            _mark_operation_cancelled(self.lifecycle)
        except Exception as exc:
            result = {"status": "failed", "error": type(exc).__name__, "detail": sanitize_text(exc, 600)}
            self.lifecycle.fail(result["detail"])
        finally:
            self.arguments.clear()
        self.signals.finished.emit(result)
        item = "vault_package"
        status = result.get("status")
        if status == "completed":
            self.lifecycle.report_result(
                f"{self.operation}_package", affected_items=(item,),
                succeeded_items=(item,), verified_items=(item,), committed_items=(item,))
        elif status == "cancelled":
            self.lifecycle.report_result(
                f"{self.operation}_package", affected_items=(item,), cancelled_items=(item,))
        else:
            self.lifecycle.report_result(
                f"{self.operation}_package", affected_items=(item,), failed_items=(item,),
                failure_codes=("package_operation_failed",))

    def _progress(self, event: tuple[str, int, int]) -> None:
        label, done, total = event
        self.lifecycle.update(current_item=label, bytes_processed=done, total_bytes=total)
        self.signals.progress.emit(label, done, total)


class PackageProgressDialog(QDialog):
    def __init__(
        self,
        app: "App",
        worker: _PackageWorker,
        title: str,
        on_finished: Callable[[Any], None],
    ) -> None:
        super().__init__(app)
        self._running = True
        self.worker = worker
        self.on_finished = on_finished
        self.setWindowTitle(title)
        self.setModal(True)
        self.setMinimumWidth(480)
        layout = QVBoxLayout(self)
        layout.addWidget(lbl(title.upper(), 16, ACC, True))
        self.status: QLabel = lbl("Preparing the verified operation…", 12, MUT)
        self.status.setWordWrap(True); layout.addWidget(self.status)
        self.loading_message_label = loading_egg_label()
        layout.addWidget(self.loading_message_label)
        self.cancellation_message_label = cancellation_egg_label()
        layout.addWidget(self.cancellation_message_label)
        self._cancellation_egg_shown = False
        self.progress: QProgressBar = QProgressBar(); self.progress.setRange(0, 0); layout.addWidget(self.progress)
        row = QHBoxLayout()
        self.pause_button: QPushButton = btn("Pause")
        self.pause_button.clicked.connect(self.toggle_pause)
        self.cancel_button: QPushButton = btn("Cancel")
        self.cancel_button.clicked.connect(self.request_cancel)
        row.addWidget(self.pause_button); row.addStretch(); row.addWidget(self.cancel_button); layout.addLayout(row)
        worker.signals.progress.connect(self.update_progress)
        worker.signals.finished.connect(self.finish)

    @property
    def is_running(self) -> bool:
        return self._running

    def toggle_pause(self) -> None:
        worker = self.worker
        if worker is None:
            return
        if worker.pause.is_set():
            worker.pause.clear()
            self.pause_button.setText("Pause")
            self.status.setText("Resuming at the next safe checkpoint…")
        else:
            worker.pause.set()
            self.pause_button.setText("Resume")
            self.status.setText("Paused. The operation will continue when you choose Resume.")

    def request_cancel(self) -> None:
        worker = self.worker
        if self._running and worker is not None and not self._cancellation_egg_shown:
            worker.lifecycle.request_cancel()
            worker.pause.clear()
            self.pause_button.setEnabled(False)
            self.cancel_button.setEnabled(False)
            self.status.setText(
                "Cancellation requested. The current safe step will finish first…")
            show_cancellation_egg(self, self.cancellation_message_label)

    def update_progress(self, label: str, done: int, total: int) -> None:
        worker = self.worker
        if worker is None or worker.pause.is_set():
            return
        self.status.setText(label)
        if total > 0:
            self.progress.setRange(0, 1000)
            self.progress.setValue(min(1000, int(done * 1000 / total)))
            self.progress.setFormat(f"{min(100, int(done * 100 / total))}%")
        else:
            self.progress.setRange(0, 0)

    def finish(self, result: object) -> None:
        if not self._running: return
        self._running = False
        self.worker = None
        self.accept()

        def notify_finished() -> None:
            self.on_finished(result)

        QTimer.singleShot(0, notify_finished)

    def closeEvent(self, a0: Optional[QCloseEvent]) -> None:
        if self._running:
            self.request_cancel()
            if a0 is not None:
                a0.ignore()
            return
        super().closeEvent(a0)


def _mark_operation_cancelled(operation: Operation) -> None:
    state = operation.snapshot.state
    if state == OperationState.RUNNING:
        operation.request_cancel()
        state = operation.snapshot.state
    if state == OperationState.CANCEL_REQUESTED:
        operation.canceled()


def _start_operation(operation: Operation) -> bool:
    try:
        operation.start()
    except InvalidOperationTransition:
        if operation.snapshot.state == OperationState.CANCELED:
            return False
        raise
    return True


class OperationCenterDialog(QDialog):
    def __init__(self, app: "App") -> None:
        super().__init__(app)
        self.apply_theme()
        self.setWindowTitle("UNKNWN // Operation Center")
        self.setMinimumSize(620, 420)
        layout = QVBoxLayout(self)
        layout.addWidget(lbl("OPERATION CENTER", 17, ACC, True))
        note = lbl("Current and recent vault operations. Cancellation is cooperative and takes effect at a safe checkpoint.", 12, MUT)
        note.setWordWrap(True)
        layout.addWidget(note)
        self.operations = QListWidget()
        self.operations.currentItemChanged.connect(self._selection_changed)
        layout.addWidget(self.operations, 1)
        self.details = QPlainTextEdit()
        self.details.setReadOnly(True)
        self.details.setMaximumHeight(120)
        self.details.setPlaceholderText("Select an operation for details.")
        layout.addWidget(self.details)
        row = QHBoxLayout()
        self.cancel_button = btn("Cancel selected")
        self.cancel_button.clicked.connect(self._cancel_selected)
        close = btn("Close")
        close.clicked.connect(self.accept)
        row.addWidget(self.cancel_button)
        row.addStretch()
        row.addWidget(close)
        layout.addLayout(row)
        self._timer = QTimer(self)
        self._timer.setInterval(750)
        self._timer.timeout.connect(self.refresh)
        self._timer.start()
        self.refresh()

    def apply_theme(self) -> None:
        self.setStyleSheet(
            f"QDialog{{background:{TH['bg0']};color:{TH['fg']};}}"
            f"QListWidget,QPlainTextEdit{{background:{TH['field']};color:{TH['fg']};"
            f"border:1px solid {TH['line']};selection-background-color:{TH['acc']};}}"
        )

    def refresh(self) -> None:
        current = self.operations.currentItem()
        selected_id = current.data(Qt.ItemDataRole.UserRole) if current is not None else None
        snapshots = OPERATION_MANAGER.snapshots()
        self.operations.clear()
        for snapshot in snapshots:
            progress = f"{snapshot.percent}%" if snapshot.percent is not None else "Progress unavailable"
            elapsed = f"{snapshot.elapsed_seconds:.1f}s"
            eta = snapshot.estimated_remaining_seconds
            timing = f"elapsed {elapsed}" + (f" / ETA {eta:.1f}s" if eta is not None else "")
            current_item = ""
            if snapshot.current_item:
                visible_item = "Current item hidden" if S("mask") else sanitize_text(snapshot.current_item, 120)
                current_item = f" — {visible_item}"
            detail = f"{snapshot.name} — {snapshot.state.value.upper()} — {progress} — {timing}{current_item}"
            item = QListWidgetItem(detail)
            item.setData(Qt.ItemDataRole.UserRole, snapshot.operation_id)
            self.operations.addItem(item)
            if snapshot.operation_id == selected_id:
                self.operations.setCurrentItem(item)
        if self.operations.currentItem() is None and self.operations.count():
            self.operations.setCurrentRow(0)
        self._selection_changed(self.operations.currentItem(), None)

    def _selection_changed(
        self,
        current: Optional[QListWidgetItem],
        _previous: Optional[QListWidgetItem],
    ) -> None:
        if current is None:
            self.cancel_button.setEnabled(False)
            self.details.clear()
            return
        operation_id = current.data(Qt.ItemDataRole.UserRole)
        try:
            snapshot = OPERATION_MANAGER.get(operation_id)
        except KeyError:
            self.cancel_button.setEnabled(False)
            self.details.setPlainText("This operation is no longer in history.")
            return
        self.cancel_button.setEnabled(
            snapshot.state in {OperationState.QUEUED, OperationState.WAITING, OperationState.RUNNING})
        lines = [f"Status: {snapshot.state.value}"]
        if snapshot.waiting_reason:
            lines.append(f"Waiting: {sanitize_text(snapshot.waiting_reason, 300)}")
        if snapshot.total_items is not None:
            lines.append(f"Items: {snapshot.completed_items} / {snapshot.total_items}")
        if snapshot.total_bytes is not None:
            lines.append(f"Bytes: {snapshot.bytes_processed:,} / {snapshot.total_bytes:,}")
        lines.append(f"Elapsed: {snapshot.elapsed_seconds:.1f}s")
        if snapshot.estimated_remaining_seconds is not None:
            lines.append(f"Estimated remaining: {snapshot.estimated_remaining_seconds:.1f}s")
        if snapshot.recovery_state:
            lines.append(f"Recovery: {sanitize_text(snapshot.recovery_state, 200)}")
        if snapshot.error:
            detail = "Failure detail hidden by file-name masking." if S("mask") else sanitize_text(snapshot.error, 600)
            lines.append(f"Failure: {detail}")
        report = OPERATION_MANAGER.report_for(snapshot.operation_id)
        if report is not None:
            lines.extend((
                "",
                "WHAT CHANGED",
                f"Requested: {report.requested}",
                f"Outcome: {report.status}",
                f"Affected: {report.affected_count}",
                f"Succeeded: {report.succeeded_count}",
                f"Failed: {report.failed_count}",
                f"Cancelled: {report.cancelled_count}",
                f"Skipped: {report.skipped_count}",
                f"Verified: {report.verified_count}",
                f"Committed: {report.committed_count}",
                f"Recovered: {report.recovered_count}",
                f"Recovery required: {'yes' if report.recovery_required else 'no'}",
                f"Manual review required: {'yes' if report.manual_review_required else 'no'}",
                f"Reporting incomplete: {'yes' if report.reporting_incomplete else 'no'}",
            ))
            if report.failure_codes:
                lines.append("Failure codes: " + ", ".join(report.failure_codes))
        self.details.setPlainText("\n".join(lines))

    def _cancel_selected(self) -> None:
        item = self.operations.currentItem()
        if item is None:
            return
        operation_id = item.data(Qt.ItemDataRole.UserRole)
        try:
            OPERATION_MANAGER.request_cancel(operation_id)
        except KeyError:
            return
        self.refresh()

    def closeEvent(self, a0: Optional[QCloseEvent]) -> None:
        self._timer.stop()
        super().closeEvent(a0)


class _SealProgressDialog(QDialog):
    def __init__(
        self,
        app: "App",
        worker: Union[_SealWorker, _FolderSealWorker],
        on_finished: Callable[[Any], None],
        title: str = "Seal files",
        cancel_queued: Optional[Callable[[], None]] = None,
    ) -> None:
        super().__init__(
            app,
            Qt.WindowFlags(Qt.WindowType.Dialog)
            | Qt.WindowType.CustomizeWindowHint
            | Qt.WindowType.WindowTitleHint,
        )
        self._running = True
        self.worker = worker
        self.on_finished = on_finished
        self.setWindowTitle(f"UNKNWN // {title}")
        self.setWindowModality(Qt.WindowModality.NonModal)
        self.setWindowFlag(Qt.WindowType.WindowSystemMenuHint, True)
        self.setWindowFlag(Qt.WindowType.WindowCloseButtonHint, True)
        self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose, True)
        self.setMinimumWidth(480)
        layout = QVBoxLayout(self)
        layout.addWidget(lbl(title.upper(), 16, ACC, True))
        self.status: QLabel = lbl("Preparing verified encrypted output…", 12, MUT)
        self.status.setWordWrap(True)
        layout.addWidget(self.status)
        self.loading_message_label = loading_egg_label()
        layout.addWidget(self.loading_message_label)
        self.cancellation_message_label = cancellation_egg_label()
        layout.addWidget(self.cancellation_message_label)
        self._cancellation_egg_shown = False
        self.progress: QProgressBar = QProgressBar()
        self.progress.setRange(0, 0)
        layout.addWidget(self.progress)
        controls = QHBoxLayout()
        self.pause_button: QPushButton = btn("Pause")
        self.pause_button.clicked.connect(self.toggle_pause)
        self.cancel_button: QPushButton = btn("Cancel")
        self.cancel_button.clicked.connect(self.reject)
        self._auto_close_timer: Optional[QTimer] = None
        self._close_ref: Optional[weakref.ReferenceType["_SealProgressDialog"]] = weakref.ref(self)
        controls.addWidget(self.pause_button)
        controls.addStretch()
        controls.addWidget(self.cancel_button)
        layout.addLayout(controls)
        queue_controls = QHBoxLayout()
        self.queue_status: QLabel = lbl("No queued jobs", 11, MUT)
        self.cancel_queued_button: QPushButton = btn("Cancel queued jobs", "flat")
        self.cancel_queued_button.setVisible(False)
        if cancel_queued is not None:
            self.cancel_queued_button.clicked.connect(_noarg_slot(cancel_queued))
        queue_controls.addWidget(self.queue_status, 1)
        queue_controls.addWidget(self.cancel_queued_button)
        layout.addLayout(queue_controls)
        worker.signals.progress.connect(self.update_progress)
        worker.signals.finished.connect(self.finish)

    def set_queued_count(self, count: int) -> None:
        pending = max(0, count)
        self.queue_status.setText(
            f"{pending} job(s) waiting in FIFO order" if pending else "No queued jobs")
        self.cancel_queued_button.setVisible(pending > 0)

    @property
    def is_running(self) -> bool:
        return self._running

    def request_cancel(self) -> None:
        worker = self.worker
        if self._running and worker is not None and not self._cancellation_egg_shown:
            worker.operation.request_cancel()
            worker.resume_event.set()
            self.pause_button.setEnabled(False)
            self.cancel_button.setEnabled(False)
            self.status.setText(
                "Cancellation requested. The current staged output will be removed; committed files remain.")
            show_cancellation_egg(self, self.cancellation_message_label)

    def toggle_pause(self) -> None:
        worker = self.worker
        if not self._running or worker is None:
            return
        if worker.resume_event.is_set():
            worker.resume_event.clear()
            self.pause_button.setText("Resume")
            self.status.setText(
                "Paused at a safe checkpoint. The source file is unchanged; resume or cancel when ready.")
            QMessageBox.warning(
                self, "Encryption paused",
                "Pausing does not corrupt the source. If UNKNWN closes or the computer shuts down "
                "while paused, the incomplete encrypted stage will be removed during authenticated "
                "recovery and the original source will remain unchanged. Keep UNKNWN open to resume "
                "or cancel normally.")
        else:
            worker.resume_event.set()
            self.pause_button.setText("Pause")
            self.status.setText("Resuming at the next safe encryption checkpoint…")

    def update_progress(
        self, label: str, done: int, total: int, completed: int, total_items: int,
    ) -> None:
        worker = self.worker
        if worker is None or not worker.resume_event.is_set():
            return
        self.status.setText(f"{label} — {completed} / {total_items} item(s) committed")
        if total > 0:
            self.progress.setRange(0, 1000)
            self.progress.setValue(min(1000, int(done * 1000 / total)))
            self.progress.setFormat(f"{min(100, int(done * 100 / total))}%")
        elif total_items > 0:
            self.progress.setRange(0, total_items)
            self.progress.setValue(completed)
            self.progress.setFormat(f"{completed} / {total_items} files")
        else:
            self.progress.setRange(0, 0)

    def finish(self, result: object) -> None:
        if not self._running:
            return
        self._running = False
        self.worker = None
        self.pause_button.setEnabled(False)
        self.cancel_button.setEnabled(True)
        self.cancel_button.setText("Close")
        status = ""
        if isinstance(result, Mapping):
            result_mapping = cast(Mapping[str, object], result)
            status_value = result_mapping.get("status")
            if isinstance(status_value, str):
                status = status_value
        messages: dict[str, str] = {
            "completed": "Encryption complete. The encrypted items are available in your vault.",
            "cancelled": "Encryption cancelled safely. Committed items remain; uncommitted sources were preserved.",
            "failed": "Encryption finished with errors. Review the result summary.",
            "recovery_required": "Storage recovery is required. The vault was locked; sign in again to recover.",
        }
        message = messages.get(status, "The encryption operation has finished.")
        if status == "completed":
            message += " This window will close automatically in a few seconds."
        self.status.setText(message)
        if status == "completed":
            self.progress.setRange(0, 1)
            self.progress.setValue(1)
            self.progress.setFormat("Complete")
        self.on_finished(result)
        if status == "completed":
            if self._auto_close_timer is not None:
                self._auto_close_timer.stop()
            self._auto_close_timer = QTimer(self)
            self._auto_close_timer.setSingleShot(True)
            self._auto_close_timer.setInterval(3500)
            self._auto_close_timer.timeout.connect(self._close_after_completion)
            self._auto_close_timer.start()

    def _close_after_completion(self) -> None:
        if self._auto_close_timer is not None:
            self._auto_close_timer.stop()
        target = self._close_ref() if self._close_ref is not None else None
        if target is not None and (target.isVisible() or target.isHidden()):
            target.close()

    def reject(self) -> None:
        if self._running:
            self.request_cancel()
            return
        super().reject()

    def closeEvent(self, a0: Optional[QCloseEvent]) -> None:
        if self._auto_close_timer is not None:
            self._auto_close_timer.stop()
            self._auto_close_timer.deleteLater()
            self._auto_close_timer = None
        self._close_ref = None
        if self._running:
            self.request_cancel()
            if a0 is not None:
                a0.ignore()
            return
        super().closeEvent(a0)


class VaultAnalysisDialog(QDialog):
    def __init__(self, app: "App") -> None:
        super().__init__(app)
        self._running = True
        self.setWindowTitle("UNKNWN // Vault Statistics & Duplicates")
        self.setMinimumSize(620, 470)
        layout = QVBoxLayout(self)
        layout.addWidget(lbl("VAULT STATISTICS & DUPLICATES", 17, ACC, True))
        note = lbl("Statistics use authenticated vault metadata. Duplicate review compares authenticated plaintext content hashes; nothing is removed.", 12, MUT)
        note.setWordWrap(True)
        layout.addWidget(note)
        self.status: QLabel = lbl("Scanning vault metadata and exact-size duplicate candidates…", 12, MUT)
        self.status.setWordWrap(True)
        layout.addWidget(self.status)
        self.loading_message_label = loading_egg_label()
        layout.addWidget(self.loading_message_label)
        self.cancellation_message_label = cancellation_egg_label()
        layout.addWidget(self.cancellation_message_label)
        self._cancellation_egg_shown = False
        self.progress: QProgressBar = QProgressBar()
        self.progress.setRange(0, 0)
        layout.addWidget(self.progress)
        self.output: QPlainTextEdit = QPlainTextEdit()
        self.output.setReadOnly(True)
        self.output.setPlainText("Analysis is running in the background. Cancel is safe at authenticated chunk boundaries.")
        layout.addWidget(self.output, 1)
        self.duplicate_list = QListWidget()
        self.duplicate_list.setAccessibleName("Duplicate keep and remove decisions")
        self.duplicate_list.setToolTip("Checked items are marked for removal. Leave at least one item unchecked in each group.")
        self.duplicate_list.itemChanged.connect(self._duplicate_item_changed)
        self.duplicate_list.hide()
        layout.addWidget(self.duplicate_list, 1)
        self.remove_selected_button = btn("Remove Selected", "danger")
        self.remove_selected_button.setEnabled(False)
        self.remove_selected_button.clicked.connect(self.remove_selected_duplicates)
        layout.addWidget(self.remove_selected_button, 0, Qt.AlignmentFlag.AlignRight)
        self._duplicate_groups: dict[int, set[str]] = {}
        self._duplicate_item_names: dict[str, str] = {}
        self._updating_duplicate_items = False
        row = QHBoxLayout()
        self.cancel_button: QPushButton = btn("Cancel analysis")
        self.cancel_button.clicked.connect(self.request_cancel)
        close = btn("Close")
        close.clicked.connect(lambda: _close_widget(self))
        row.addWidget(self.cancel_button)
        row.addStretch()
        row.addWidget(close)
        layout.addLayout(row)
        root = app.root
        if root is None:
            raise RuntimeError("The vault must be unlocked before analyzing its contents.")
        self.worker = _VaultAnalysisWorker(root, dict(idx), bool(S("mask")))
        self.worker.signals.progress.connect(self.update_progress)
        self.worker.signals.finished.connect(self.finish)
        try:
            _start_qrunnable(self.worker)
        except Exception as exc:
            self.worker.operation.fail(type(exc).__name__)
            self.finish({"status": "failed", "stats": {}, "duplicates": [],
                         "failures": [{"name": "Analysis", "detail": type(exc).__name__}]})

    @property
    def is_running(self) -> bool:
        return self._running

    def request_cancel(self) -> None:
        if self._running and self.worker is not None and not self._cancellation_egg_shown:
            self.worker.operation.request_cancel()
            self.cancel_button.setEnabled(False)
            self.status.setText(
                "Cancellation requested. The current authenticated chunk will finish safely.")
            show_cancellation_egg(self, self.cancellation_message_label)

    def update_progress(
        self, label: str, done: int, total: int, completed: int, total_items: int,
    ) -> None:
        self.status.setText(f"{label} — {completed} / {total_items} candidate file(s) checked")
        if total > 0:
            self.progress.setRange(0, 1000)
            self.progress.setValue(min(1000, int(done * 1000 / total)))
            self.progress.setFormat(f"{min(100, int(done * 100 / total))}%")
        elif total_items > 0:
            self.progress.setRange(0, total_items)
            self.progress.setValue(completed)
            self.progress.setFormat(f"{completed} / {total_items} files")

    def finish(self, result: Mapping[str, object]) -> None:
        if not self._running:
            return
        self._running = False
        self.worker = None
        self.cancel_button.setEnabled(False)
        stats_value = result.get("stats", {})
        stats = cast(dict[str, object], stats_value) if isinstance(stats_value, dict) else {}
        status = result.get("status", "failed")
        file_count = stats.get("file_count", 0)
        total_bytes = stats.get("total_bytes", 0)
        candidate_count = stats.get("candidate_count", 0)
        lines = [
            f"Status: {status.upper() if isinstance(status, str) else 'FAILED'}",
            f"Vault items: {file_count if isinstance(file_count, int) else 0}",
            f"Total logical size: {fmt(total_bytes if isinstance(total_bytes, (int, float)) else 0)}",
            f"Exact-size candidates authenticated: {candidate_count if isinstance(candidate_count, int) else 0}",
            "",
            "TYPE BREAKDOWN",
        ]
        type_bytes_value = stats.get("type_bytes", {})
        if isinstance(type_bytes_value, dict):
            for category, size in cast(dict[object, object], type_bytes_value).items():
                if isinstance(category, str):
                    lines.append(f"{category}: {fmt(size if isinstance(size, (int, float)) else 0)}")
        lines.extend(["", "LARGEST ITEMS"])
        largest_value = stats.get("largest", [])
        if isinstance(largest_value, list):
            for entry in cast(list[object], largest_value):
                if isinstance(entry, tuple):
                    item_values = cast(tuple[object, ...], entry)
                    if (len(item_values) == 2 and isinstance(item_values[1], str)
                            and isinstance(item_values[0], (int, float))):
                        lines.append(f"{item_values[1]}: {fmt(item_values[0])}")
        lines.extend(["", "EXACT CONTENT DUPLICATES"])
        duplicates_value = result.get("duplicates", [])
        duplicates = cast(list[object], duplicates_value) if isinstance(duplicates_value, list) else []
        if duplicates:
            for group in duplicates:
                if not isinstance(group, list):
                    continue
                lines.append("Identical authenticated content:")
                lines.extend(f"  {name}" for name in cast(list[object], group) if isinstance(name, str))
        else:
            lines.append("No exact content duplicates found.")
        records_value = result.get("duplicate_records", [])
        records = cast(list[object], records_value) if isinstance(records_value, list) else []
        if records and status == "completed":
            self._populate_duplicate_choices(records)
        failures_value = result.get("failures", [])
        failures = cast(list[object], failures_value) if isinstance(failures_value, list) else []
        if failures:
            lines.extend(["", "ITEMS THAT COULD NOT BE ANALYZED"])
            for item_value in failures[:20]:
                if isinstance(item_value, dict):
                    item = cast(dict[str, object], item_value)
                    lines.append(f"{item.get('name', 'Unknown item')}: {item.get('detail', 'Unknown error')}")
            if len(failures) > 20:
                lines.append(f"…and {len(failures) - 20} more.")
        self.output.setPlainText("\n".join(lines))
        self.status.setText("Analysis complete. Review duplicate groups before taking any action.")

    def _populate_duplicate_choices(self, records: list[object]) -> None:
        self._updating_duplicate_items = True
        self.duplicate_list.clear()
        self._duplicate_groups.clear()
        self._duplicate_item_names.clear()
        for group_index, record in enumerate(records):
            if not isinstance(record, list):
                continue
            items = cast(list[object], record)
            if len(items) < 2:
                continue
            header = QListWidgetItem(f"GROUP {group_index + 1}  /  choose what to keep")
            header.setFlags(Qt.ItemFlag.ItemIsEnabled)
            self.duplicate_list.addItem(header)
            self._duplicate_groups[group_index] = set()
            for item_value in items:
                if not isinstance(item_value, dict):
                    continue
                item = cast(dict[str, object], item_value)
                rid, name = item.get("rid"), item.get("name")
                if not isinstance(rid, str) or rid not in idx or not isinstance(name, str):
                    continue
                entry = QListWidgetItem(f"KEEP  →  {name}")
                entry.setFlags(cast(Qt.ItemFlags,
                    Qt.ItemFlag.ItemIsEnabled
                    | Qt.ItemFlag.ItemIsSelectable
                    | Qt.ItemFlag.ItemIsUserCheckable
                ))
                entry.setCheckState(Qt.CheckState.Unchecked)
                entry.setData(Qt.ItemDataRole.UserRole, group_index)
                entry.setData(Qt.ItemDataRole.UserRole + 1, rid)
                self.duplicate_list.addItem(entry)
                self._duplicate_groups[group_index].add(rid)
                self._duplicate_item_names[rid] = name
        self._updating_duplicate_items = False
        self.duplicate_list.setVisible(bool(self._duplicate_groups))
        self.remove_selected_button.setVisible(bool(self._duplicate_groups))
        self._duplicate_item_changed()

    def _duplicate_item_changed(self, _item: Optional[QListWidgetItem] = None) -> None:
        if self._updating_duplicate_items:
            return
        selected: list[str] = []
        remaining: dict[int, int] = {group: 0 for group in self._duplicate_groups}
        self._updating_duplicate_items = True
        try:
            for row in range(self.duplicate_list.count()):
                item = self.duplicate_list.item(row)
                if item is None:
                    continue
                rid_value = item.data(Qt.ItemDataRole.UserRole + 1)
                group_value = item.data(Qt.ItemDataRole.UserRole)
                if not isinstance(rid_value, str) or not isinstance(group_value, int):
                    continue
                if rid_value not in idx:
                    item.setText(f"UNAVAILABLE  →  {self._duplicate_item_names[rid_value]}")
                    continue
                if item.checkState() == Qt.CheckState.Checked:
                    selected.append(rid_value)
                    item.setText(f"REMOVE  →  {self._duplicate_item_names[rid_value]}")
                else:
                    remaining[group_value] = remaining.get(group_value, 0) + 1
                    item.setText(f"KEEP  →  {self._duplicate_item_names[rid_value]}")
        finally:
            self._updating_duplicate_items = False
        invalid = any(count == 0 for count in remaining.values())
        self.remove_selected_button.setEnabled(bool(selected) and not invalid and not self._running)
        if invalid:
            self.status.setText("Each duplicate group must retain at least one unchecked item.")
        elif not self._running:
            self.status.setText(f"Analysis complete. {len(selected)} item(s) marked for removal; review before confirming.")

    def remove_selected_duplicates(self) -> None:
        app = self.parent()
        if self._running or not isinstance(app, App) or app.root is None:
            return
        if app.working():
            QMessageBox.information(
                self, "Duplicate removal unavailable",
                "Items cannot be removed while another vault operation is active.")
            return
        selected: list[str] = []
        remaining: dict[int, int] = {group: 0 for group in self._duplicate_groups}
        for row in range(self.duplicate_list.count()):
            item = self.duplicate_list.item(row)
            if item is None:
                continue
            rid_value = item.data(Qt.ItemDataRole.UserRole + 1)
            group_value = item.data(Qt.ItemDataRole.UserRole)
            if not isinstance(rid_value, str) or not isinstance(group_value, int):
                continue
            if rid_value not in idx:
                continue
            if item.checkState() == Qt.CheckState.Checked:
                selected.append(rid_value)
            else:
                remaining[group_value] = remaining.get(group_value, 0) + 1
        selected = [rid for rid in selected if rid in idx and rid not in app.dying]
        if not selected or any(count == 0 for count in remaining.values()):
            QMessageBox.warning(self, "Removal not available", "Keep at least one current item in every duplicate group.")
            return
        listed = "\n".join(
            f"• {self._duplicate_item_names[rid]}" for rid in selected
        )
        if QMessageBox.question(
                self, "Confirm duplicate removal",
                "Only these checked items will be removed through the vault's secure deletion path:\n\n"
                + listed + "\n\nContinue?",
                cast(Any, QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No),
                QMessageBox.StandardButton.No) != QMessageBox.StandardButton.Yes:
            return
        for rid in selected:
            app.burn(rid, ask=False)
        self.remove_selected_button.setEnabled(False)

    def closeEvent(self, a0: Optional[QCloseEvent]) -> None:
        if self._running:
            self.request_cancel()
            if a0 is not None:
                a0.ignore()
            return
        super().closeEvent(a0)


PACKAGED = "__compiled__" in globals() or getattr(sys, "frozen", False)
APP = Path(sys.executable if PACKAGED else __file__).resolve()
DEV_BUILD = False                         # build.ps1 -Dev flips this in the build copy only
COMPILED = "__compiled__" in globals() and not DEV_BUILD
release_integrity_state = IG.state(APP.parent, COMPILED)
runtime_trust_state: Literal["clear", "debugger", "unavailable", "not_enforced", "not_run"] = (
    "not_enforced" if not COMPILED else "not_run"
)
startup_location_state = "not_run"
startup_config_state = "not_run"
if COMPILED and release_integrity_state == "ok":
    runtime_trust_state = IG.runtime_trust()
_GATE_STATUS, integ_error = IG.security_decision(COMPILED, release_integrity_state, runtime_trust_state)
INTEG: list[str] = [_GATE_STATUS]
PORT = APP.parent / "UNKNWN_data"
PROFILE_REGISTRY = Path.home() / ".unknwn-profiles.json"
DESTRUCT_JOURNAL = ".unknwn-destruct.json"
DESTRUCT_RECOVERY_SCRIPT = ".unknwn-destruct-recovery.ps1"
DESTRUCT_RUNONCE_KEY = r"Software\Microsoft\Windows\CurrentVersion\RunOnce"
DESTRUCT_RUNONCE_VALUE = "!UNKNWN-SelfDestruct-Recovery"
DESTRUCT_RUNONCE_RETRY_VALUE = "!UNKNWN-SelfDestruct-Recovery-Retry"
active_profile_id = None
active_profile_name = None


def _read_profiles() -> list[dict[str, str]]:
    profiles: list[object] = []
    try:
        info = PROFILE_REGISTRY.lstat()
    except FileNotFoundError:
        info = None
    except OSError as exc:
        raise ValueError("The vault profile list could not be inspected safely.") from exc
    if info is not None:
        if (stat.S_ISLNK(info.st_mode)
                or getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
                or not stat.S_ISREG(info.st_mode)
                or info.st_size > 64 * 1024):
            raise ValueError("The vault profile list is not a safe regular file.")
        try:
            parsed: object = json.loads(PROFILE_REGISTRY.read_text(encoding="utf-8"))
            if not isinstance(parsed, dict):
                raise ValueError("The vault profile list has an unsupported format.")
            record = cast(dict[object, object], parsed)
            version = record.get("version")
            raw_profiles = record.get("profiles")
            if type(version) is not int or version != 1 or not isinstance(raw_profiles, list):
                raise ValueError("The vault profile list has an unsupported format.")
            profiles = cast(list[object], raw_profiles)
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError("The vault profile list could not be read.") from exc
    clean: list[dict[str, str]] = []
    ids: set[str] = set()
    paths: set[str] = set()
    names: set[str] = set()
    for profile_value in profiles:
        if not isinstance(profile_value, dict):
            raise ValueError("The vault profile list contains an invalid entry.")
        profile = cast(dict[object, object], profile_value)
        profile_id, name, raw_path = profile.get("id"), profile.get("name"), profile.get("path")
        if (not isinstance(profile_id, str) or not re.fullmatch(r"[0-9a-f]{32}", profile_id)
                or not isinstance(name, str) or not name.strip() or len(name) > 64
                or not isinstance(raw_path, str) or len(raw_path) > 32768):
            raise ValueError("The vault profile list contains invalid profile metadata.")
        path = Path(raw_path)
        if not path.is_absolute():
            raise ValueError("A vault profile location is not an absolute path.")
        key_path = os.path.normcase(os.path.abspath(path))
        key_name = name.strip().casefold()
        if profile_id in ids or key_path in paths or key_name in names:
            raise ValueError("The vault profile list contains duplicate identities or locations.")
        ids.add(profile_id); paths.add(key_path); names.add(key_name)
        clean.append({"id": profile_id, "name": name.strip(), "path": str(path)})
    return clean


def _write_profiles(profiles: list[dict[str, str]]) -> None:
    atomic_write_bytes(PROFILE_REGISTRY, canonical_json({"version": 1, "profiles": profiles}))


def _register_profile(
    name: str,
    path: Union[os.PathLike[str], str],
    profile_id: Optional[str] = None,
) -> dict[str, str]:
    name = str(name).strip()
    if not name or len(name) > 64 or any(ord(char) < 32 for char in name):
        raise ValueError("Choose a profile name between 1 and 64 printable characters.")
    path = Path(path).absolute()
    profiles = _read_profiles()
    if any(item["name"].casefold() == name.casefold() for item in profiles):
        raise FileExistsError("A vault profile already uses that name.")
    if any(os.path.normcase(os.path.abspath(item["path"])) == os.path.normcase(str(path)) for item in profiles):
        raise FileExistsError("That folder is already registered as a vault profile.")
    profile_id = uuid.uuid4().hex if profile_id is None else profile_id
    if not re.fullmatch(r"[0-9a-f]{32}", profile_id):
        raise ValueError("The vault profile identity is invalid.")
    profile = {"id": profile_id, "name": name, "path": str(path)}
    _write_profiles(profiles + [profile])
    return profile


def _rename_profile(profile_id: str, name: str) -> dict[str, str]:
    name = str(name).strip()
    if not name or len(name) > 64 or any(ord(char) < 32 for char in name):
        raise ValueError("Choose a profile name between 1 and 64 printable characters.")
    profiles = _read_profiles()
    if any(item["id"] != profile_id and item["name"].casefold() == name.casefold()
           for item in profiles):
        raise FileExistsError("A vault profile already uses that name.")
    for profile in profiles:
        if profile["id"] == profile_id:
            renamed = dict(profile, name=name)
            _write_profiles([
                renamed if item["id"] == profile_id else item
                for item in profiles
            ])
            return renamed
    raise ValueError("The selected vault profile is no longer registered.")


def _set_default_profile(profile_id: str) -> dict[str, str]:
    profiles = _read_profiles()
    index = next((i for i, profile in enumerate(profiles)
                  if profile["id"] == profile_id), None)
    if index is None:
        raise ValueError("The selected vault profile is no longer registered.")
    preferred = profiles.pop(index)
    if index:
        _write_profiles([preferred, *profiles])
    return preferred


def _update_profile_path(
    profile_id: str,
    path: Union[os.PathLike[str], str],
) -> None:
    profiles = _read_profiles()
    normalized = os.path.normcase(os.path.abspath(path))
    if any(item["id"] != profile_id
           and os.path.normcase(os.path.abspath(item["path"])) == normalized for item in profiles):
        raise FileExistsError("Another vault profile already uses that data folder.")
    for profile in profiles:
        if profile["id"] == profile_id:
            profile["path"] = str(Path(path).absolute())
            _write_profiles(profiles)
            return
    raise ValueError("The active vault profile is no longer registered.")


def _import_journal_path(profile_id: str) -> Path:
    return Path.home() / ".unknwn-profiles" / f".import-{profile_id}.json"


def _export_journal_path(operation_id: str) -> Path:
    return Path.home() / ".unknwn-profiles" / f".export-{operation_id}.json"


def _managed_profiles_root() -> Path:
    root = Path.home() / ".unknwn-profiles"
    root.mkdir(parents=True, exist_ok=True)
    info = root.lstat()
    if (stat.S_ISLNK(info.st_mode)
            or getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
            or not stat.S_ISDIR(info.st_mode)):
        raise ValueError("The managed vault-profile folder is not a safe directory.")
    return root.absolute()


def _pending_profile_imports() -> list[dict[str, object]]:
    root = Path.home() / ".unknwn-profiles"
    try:
        info = root.lstat()
    except FileNotFoundError:
        return []
    if (stat.S_ISLNK(info.st_mode)
            or getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
            or not stat.S_ISDIR(info.st_mode)):
        raise ValueError("The managed vault-profile folder is not a safe directory.")
    registered = {item["id"] for item in _read_profiles()}
    pending: list[dict[str, object]] = []
    for path in root.glob(".import-*.json"):
        info = path.lstat()
        if (stat.S_ISLNK(info.st_mode)
                or getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
                or not stat.S_ISREG(info.st_mode) or info.st_size > 8192):
            raise ValueError("An interrupted import record is unsafe.")
        parsed: object = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(parsed, dict):
            raise ValueError("An interrupted import record is invalid.")
        record = cast(dict[str, object], parsed)
        profile_id = record.get("profile_id")
        name = record.get("name")
        if (type(record.get("version")) is not int or record.get("version") != 1
                or not isinstance(profile_id, str) or not re.fullmatch(r"[0-9a-f]{32}", profile_id)
                or not isinstance(name, str) or not name.strip() or len(name) > 64):
            raise ValueError("An interrupted import record is invalid.")
        if path.name != f".import-{profile_id}.json":
            raise ValueError("An interrupted import record has an inconsistent identity.")
        if profile_id not in registered:
            pending.append(record)
    return pending


def _pending_profile_exports(profile_id: str) -> list[dict[str, object]]:
    root = Path.home() / ".unknwn-profiles"
    try:
        info = root.lstat()
    except FileNotFoundError:
        return []
    if (stat.S_ISLNK(info.st_mode)
            or getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
            or not stat.S_ISDIR(info.st_mode)):
        raise ValueError("The managed vault-profile folder is not a safe directory.")
    pending: list[dict[str, object]] = []
    for path in root.glob(".export-*.json"):
        info = path.lstat()
        if (stat.S_ISLNK(info.st_mode)
                or getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
                or not stat.S_ISREG(info.st_mode) or info.st_size > 8192):
            raise ValueError("An interrupted export record is unsafe.")
        parsed: object = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(parsed, dict):
            continue
        record = cast(dict[str, object], parsed)
        operation_id = record.get("operation_id")
        if (type(record.get("version")) is not int or record.get("version") != 1
                or record.get("profile_id") != profile_id
                or not isinstance(operation_id, str)
                or not re.fullmatch(r"[0-9a-f]{32}", operation_id)
                or path.name != f".export-{operation_id}.json"):
            continue
        pending.append(record)
    return pending


def _validate_import_stage(path: Union[os.PathLike[str], str], profile_id: str) -> None:
    path = Path(path)
    root = (Path.home() / ".unknwn-profiles").absolute()
    if path.absolute().parent != root or path.name not in (f".import-{profile_id}.stage", profile_id):
        raise ValueError("The interrupted import stage is outside the managed profile folder.")
    info = path.lstat()
    if (stat.S_ISLNK(info.st_mode)
            or getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
            or not stat.S_ISDIR(info.st_mode)):
        raise ValueError("The interrupted import stage is not a safe directory.")
    marker = path / ".import-owned.json"
    marker_info = marker.lstat()
    if (stat.S_ISLNK(marker_info.st_mode)
            or getattr(marker_info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
            or not stat.S_ISREG(marker_info.st_mode)
            or json.loads(marker.read_text(encoding="utf-8")).get("profile_id") != profile_id):
        raise ValueError("The interrupted import stage ownership marker is invalid.")
    for current, dirs, files in os.walk(path, followlinks=False):
        for entry in dirs + files:
            child = Path(current) / entry
            child_info = child.lstat()
            if (stat.S_ISLNK(child_info.st_mode)
                    or getattr(child_info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)):
                raise ValueError("The interrupted import stage contains a link; it was preserved.")


def _active_location_state_path(
    profile: Optional[Union[os.PathLike[str], str]] = None,
) -> Path:
    return (Path(profile) if profile is not None else Path.home()) / ".unknwn-location"
def select_active_home(
    portable: Union[os.PathLike[str], str],
    profile: Union[os.PathLike[str], str],
    state_path: Optional[Union[os.PathLike[str], str]] = None,
    argv: Optional[Iterable[str]] = None,
) -> Path:
    portable, profile = Path(portable), Path(profile)
    if "--portable" in (sys.argv if argv is None else argv):
        return portable
    state_path = Path(state_path) if state_path is not None else _active_location_state_path()
    try:
        info = state_path.lstat()
    except FileNotFoundError:
        return portable if portable.exists() else profile
    except OSError as exc:
        raise ValueError("The saved UNKNWN data-location setting could not be read.") from exc
    if (stat.S_ISLNK(info.st_mode)
            or getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
            or not stat.S_ISREG(info.st_mode)
            or info.st_size > 16):
        raise ValueError("The saved UNKNWN data-location setting is not a safe regular file.")
    choice = state_path.read_bytes()
    if choice == b"portable":
        return portable
    if choice == b"profile":
        return profile
    raise ValueError("The saved UNKNWN data-location setting is invalid; no data folder was selected.")
def persist_active_location(target: Union[os.PathLike[str], str]) -> None:
    target = Path(target).resolve(strict=True)
    profile = (Path.home() / ".unknwn").resolve()
    portable = Path(PORT).resolve()
    if target == profile:
        choice = b"profile"
    elif target == portable:
        choice = b"portable"
    else:
        raise MoveDataError("The active data folder is not a supported location.")
    atomic_write_bytes(_active_location_state_path(), choice)
def set_home(p: Union[os.PathLike[str], str]) -> None:
    global HOME, VAULT, CFG, IDX, LOG
    HOME = Path(p); VAULT = HOME / "vault"; CFG = HOME / "config.json"; IDX = HOME / "index.json"; LOG = HOME / "log.bin"

def destruct_journal_path() -> Path:
    return Path.home() / DESTRUCT_JOURNAL

def read_destruct_journal() -> Optional[_DestructJournal]:
    path = destruct_journal_path()
    try:
        info = path.lstat()
    except FileNotFoundError:
        return None
    if (stat.S_ISLNK(info.st_mode)
            or getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
            or not stat.S_ISREG(info.st_mode) or info.st_size > 16 * 1024):
        raise ValueError("The UNKNWN cleanup journal is not a safe regular file.")
    try:
        record_value: object = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("The UNKNWN cleanup journal could not be read.") from exc
    if not isinstance(record_value, dict):
        raise ValueError("The UNKNWN cleanup journal has an unsupported format.")
    record = cast(dict[str, object], record_value)
    if (not {"version", "operation", "phase", "install_target", "failures"} <= record.keys()
            or set(record) - {"version", "operation", "phase", "install_target", "failures", "updated"}
            or type(record.get("version")) is not int or record["version"] != 1):
        raise ValueError("The UNKNWN cleanup journal has an unsupported format.")
    operation = record.get("operation")
    if not isinstance(operation, str) or operation not in {"panic-wipe", "self-destruct"}:
        raise ValueError("The UNKNWN cleanup journal has an unsupported operation.")
    phase = record.get("phase")
    if not isinstance(phase, str) or phase not in {"pending", "data-cleared"}:
        raise ValueError("The UNKNWN cleanup journal has an unsupported phase.")
    updated = record.get("updated")
    if "updated" in record and (type(updated) is not int or updated < 0):
        raise ValueError("The UNKNWN cleanup journal has an invalid update timestamp.")
    target = record.get("install_target")
    if operation == "panic-wipe" and target is not None:
        raise ValueError("A panic-wipe journal cannot target an installation.")
    if operation == "self-destruct" and target is None:
        raise ValueError("A full self-destruct journal requires a validated signed installation.")
    if target is not None:
        if not isinstance(target, str) or len(target) > 32768 or not Path(target).is_absolute():
            raise ValueError("The UNKNWN cleanup journal has an invalid installation target.")
        if operation != "self-destruct":
            raise ValueError("A panic-wipe journal cannot target an installation.")
        _validate_packaged_install_target(
            Path(target), require_exists=phase == "pending",
            allow_partial=phase == "data-cleared")
    raw_failures = record.get("failures", [])
    if not isinstance(raw_failures, list) or len(cast(list[object], raw_failures)) > 16:
        raise ValueError("The UNKNWN cleanup journal contains invalid failure metadata.")
    failures = cast(list[object], raw_failures)
    if any(not isinstance(item, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9]{0,39}", item)
           for item in failures):
        raise ValueError("The UNKNWN cleanup journal contains invalid failure metadata.")
    return cast(_DestructJournal, record)

def write_destruct_journal(record: _DestructJournal) -> None:
    path = destruct_journal_path()
    validated = dict(record)
    validated["updated"] = int(time.time())
    atomic_write_bytes(path, canonical_json(validated))

def begin_destructive_cleanup(
    operation: Literal["panic-wipe", "self-destruct"],
    install_target: Optional[Union[os.PathLike[str], str]] = None,
) -> _DestructJournal:
    if operation not in {"panic-wipe", "self-destruct"}:
        raise ValueError("Unsupported destructive cleanup operation.")
    if operation == "self-destruct" and install_target is None:
        raise ValueError("Full Self-Destruct requires a validated signed installation.")
    if operation == "self-destruct" and install_target is not None:
        install_target = _validate_packaged_install_target(Path(install_target))
    if operation == "panic-wipe" and install_target is not None:
        raise ValueError("Panic Wipe cannot target an installation.")
    if read_destruct_journal() is not None:
        raise FileExistsError("An UNKNWN cleanup operation is already pending.")
    record: _DestructJournal = {
        "version": 1,
        "operation": operation,
        "phase": "pending",
        "install_target": str(install_target) if install_target is not None else None,
        "failures": [],
    }
    write_destruct_journal(record)
    return record

def resume_destructive_cleanup(
    current_home: Optional[Union[os.PathLike[str], str]] = None,
    passes: int = 3,
) -> _DestructJournal:
    record = read_destruct_journal()
    if record is None:
        raise FileNotFoundError("There is no authorized UNKNWN cleanup operation to resume.")
    if record["phase"] == "pending":
        try:
            if record["operation"] == "self-destruct":
                wipe_all_vault_data(HOME if current_home is None else current_home, passes,
                                    remove_roots=True)
            else:
                wipe_all_vault_data(HOME if current_home is None else current_home, passes)
        except Exception as exc:
            record["failures"] = (record["failures"] + [type(exc).__name__])[-16:]
            write_destruct_journal(record)
            raise
        record["phase"] = "data-cleared"
        write_destruct_journal(record)
    return record

def clear_destruct_journal() -> None:
    _durable_unlink(destruct_journal_path())


MAX_SIGNIN_HISTORY = 300
MAX_SESSION_HISTORY = 50
MAX_SESSION_EVENTS = 200


def _ensure_initial_profile() -> list[dict[str, str]]:
    global active_profile_id, active_profile_name
    profiles = _read_profiles()
    active_path = os.path.normcase(os.path.abspath(HOME))
    existing = next((item for item in profiles
                     if os.path.normcase(os.path.abspath(item["path"])) == active_path), None)
    registered = False
    if existing is None and (CFG.exists() or any(VAULT.glob("*.cdr"))):
        base_name = "Portable" if active_path == os.path.normcase(os.path.abspath(PORT)) else "Default"
        name = base_name
        suffix = 2
        used = {item["name"].casefold() for item in profiles}
        while name.casefold() in used:
            name = f"{base_name} {suffix}"
            suffix += 1
        existing = _register_profile(name, HOME)
        registered = True
    active_profile_id = existing["id"] if existing is not None else None
    active_profile_name = existing["name"] if existing is not None else None
    return _read_profiles() if registered else profiles


def activate_profile(profile: object) -> None:
    global active_profile_id, active_profile_name, cfg, STARTUP_RECOVERY_ERROR, startup_config_state
    if not isinstance(profile, dict):
        raise ValueError("The selected vault profile is invalid.")
    profile = cast(dict[str, str], profile)
    if not {"id", "name", "path"} <= profile.keys():
        raise ValueError("The selected vault profile is invalid.")
    path = Path(profile["path"])
    try:
        info = path.lstat()
    except FileNotFoundError:
        info = None
    if info is not None and (stat.S_ISLNK(info.st_mode)
            or getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
            or not stat.S_ISDIR(info.st_mode)):
        raise ValueError("The selected vault folder is not a safe directory.")
    set_home(path)
    loaded, config_source = load_config_snapshot(CFG, REQUIRED_CFG_KEYS)
    cfg.clear()
    cfg.update(loaded)
    startup_config_state = {
        "primary": "loaded",
        "backup": "recovered_backup",
        "empty": "empty",
        "damaged": "damaged",
        "unavailable": "unavailable",
    }[config_source]
    cfg.update(f=0, tf=0, lock=0, fails=[])
    idx.clear()
    active_profile_id = profile["id"]
    active_profile_name = profile["name"]
    STARTUP_RECOVERY_ERROR = None  # pyright: ignore[reportConstantRedefinition]
    try:
        rotate_commit()
    except Exception as exc:
        STARTUP_RECOVERY_ERROR = exc  # pyright: ignore[reportConstantRedefinition]


if INTEG[0] == "fail":
    startup_location_state = "not_run"
    set_home(Path.home() / ".unknwn")
else:
    try:
        set_home(select_active_home(PORT, Path.home() / ".unknwn"))
        startup_location_state = "validated"
    except (OSError, ValueError):
        startup_location_state = "failed"
        set_home(Path.home() / ".unknwn")
        INTEG[0] = "fail"
        integ_error = "startup_state_unavailable"
def _validate_packaged_install_target(
    target: Union[os.PathLike[str], str],
    require_exists: bool = True,
    allow_partial: bool = False,
) -> Path:
    target = Path(target)
    if not target.is_absolute():
        raise ValueError("The cleanup target must be an absolute path.")
    resolved = target.resolve(strict=False)
    profile = Path.home().resolve()
    if (not resolved.name.upper().startswith("UNKNWN")
            or resolved == Path(resolved.anchor) or resolved == profile):
        raise ValueError("Refusing to clean outside a dedicated UNKNWN installation directory.")
    if os.path.normcase(os.path.abspath(target)) != os.path.normcase(str(resolved)):
        raise ValueError("Refusing a linked UNKNWN installation path.")
    try:
        info = target.lstat()
    except FileNotFoundError:
        if require_exists:
            raise ValueError("The UNKNWN installation directory is missing.")
        return resolved
    if (stat.S_ISLNK(info.st_mode)
            or getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
            or not stat.S_ISDIR(info.st_mode)):
        raise ValueError("The UNKNWN installation target is not a safe directory.")
    if any((target / marker).exists() for marker in
           (".git", ".venv", "tests", "unknwn.py", "pyproject.toml")):
        raise ValueError("Refusing to clean a source or development directory.")
    if allow_partial:
        valid_package = bool(IG.RELEASE_PUBKEY and IG.verify_partial_dir(target, IG.RELEASE_PUBKEY))
    else:
        executable = target / ("UNKNWN.exe" if sys.platform == "win32" else "UNKNWN")
        try:
            executable_info = executable.lstat()
        except FileNotFoundError:
            raise ValueError("The cleanup target is not a packaged UNKNWN installation.")
        if (stat.S_ISLNK(executable_info.st_mode)
                or getattr(executable_info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
                or not stat.S_ISREG(executable_info.st_mode)):
            raise ValueError("The packaged UNKNWN executable is not a safe regular file.")
        valid_package = bool(IG.RELEASE_PUBKEY and IG.verify_dir(target, IG.RELEASE_PUBKEY))
    if not valid_package:
        raise ValueError("The installation does not match its signed UNKNWN package; manual review is required.")
    return resolved

def _windows_powershell_path() -> Path:
    system_root = Path(os.environ.get("SystemRoot", r"C:\Windows"))
    powershell = system_root / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    if not powershell.is_file():
        found = shutil.which("powershell.exe")
        if not found:
            raise FileNotFoundError("Windows PowerShell was not found; self-cleanup was not started")
        powershell = Path(found)
    return powershell

def _destruct_runonce_command(
    script_path: Union[os.PathLike[str], str],
    value_name: str = DESTRUCT_RUNONCE_VALUE,
) -> str:
    return subprocess.list2cmdline([
        str(_windows_powershell_path()), "-NoProfile", "-NonInteractive",
        "-WindowStyle", "Hidden", "-ExecutionPolicy", "Bypass",
        "-File", str(script_path), "-RunOnceName", value_name,
    ])

def _set_destruct_runonce(command: str, retry_command: str) -> None:
    import winreg
    access = winreg.KEY_QUERY_VALUE | winreg.KEY_SET_VALUE
    with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, DESTRUCT_RUNONCE_KEY, 0, access) as key:
        values = (
            (DESTRUCT_RUNONCE_VALUE, command),
            (DESTRUCT_RUNONCE_RETRY_VALUE, retry_command),
        )
        existing_values = {}
        for name, expected in values:
            try:
                existing, value_type = winreg.QueryValueEx(key, name)
            except FileNotFoundError:
                continue
            if value_type != winreg.REG_SZ or existing != expected:
                raise FileExistsError("An UNKNWN Self-Destruct RunOnce value is already owned by another command.")
            existing_values[name] = existing
        if not existing_values:
            winreg.SetValueEx(key, DESTRUCT_RUNONCE_VALUE, 0, winreg.REG_SZ, command)

def _read_destruct_runonce(
    value_name: str = DESTRUCT_RUNONCE_VALUE,
) -> Optional[tuple[object, int]]:
    import winreg
    access = winreg.KEY_QUERY_VALUE
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, DESTRUCT_RUNONCE_KEY, 0, access) as key:
            return winreg.QueryValueEx(key, value_name)
    except FileNotFoundError:
        return None

def _safe_recovery_script(path: Union[os.PathLike[str], str]) -> bool:
    path = Path(path)
    try:
        info = path.lstat()
    except FileNotFoundError:
        return False
    if (stat.S_ISLNK(info.st_mode)
            or getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
            or not stat.S_ISREG(info.st_mode)
            or getattr(info, "st_nlink", 1) > 1
            or info.st_size > 2 * 1024 * 1024):
        raise ValueError("The Self-Destruct recovery helper is not a safe regular file.")
    return True

def _encode_cleanup_command(script: str) -> str:
    compressed = zlib.compress(script.encode("utf-16le"), level=9, wbits=31)
    payload = base64.b64encode(compressed).decode("ascii")
    loader = (
        f"$__bytes=[Convert]::FromBase64String('{payload}');"
        "$__stream=[IO.MemoryStream]::new($__bytes);"
        "$__gzip=[IO.Compression.GZipStream]::new($__stream,"
        "[IO.Compression.CompressionMode]::Decompress);"
        "& ([ScriptBlock]::Create([IO.StreamReader]::new("
        "$__gzip,[Text.Encoding]::Unicode).ReadToEnd()))"
    )
    return base64.b64encode(loader.encode("utf-16le")).decode("ascii")

def _decode_cleanup_command(encoded: str) -> str:
    loader = base64.b64decode(encoded).decode("utf-16le")
    prefix = "$__bytes=[Convert]::FromBase64String('"
    suffix = "');$__stream=[IO.MemoryStream]::new($__bytes);"
    if not loader.startswith(prefix):
        raise ValueError("The Windows cleanup command has an unexpected wrapper.")
    payload, separator, remainder = loader[len(prefix):].partition(suffix)
    if not separator or not remainder.startswith("$__gzip="):
        raise ValueError("The Windows cleanup command has an invalid compressed payload.")
    return zlib.decompress(base64.b64decode(payload), wbits=31).decode("utf-16le")

def _destruct_recovery_payload(
    target: Union[os.PathLike[str], str],
    journal_path: Optional[Union[os.PathLike[str], str]],
) -> tuple[bytes, str, str]:
    profile = Path.home().resolve()
    script_path = profile / DESTRUCT_RECOVERY_SCRIPT
    command = _destruct_runonce_command(script_path)
    retry_command = _destruct_runonce_command(script_path, DESTRUCT_RUNONCE_RETRY_VALUE)
    runonce = {
        "name": DESTRUCT_RUNONCE_VALUE,
        "retry_name": DESTRUCT_RUNONCE_RETRY_VALUE,
        "key": DESTRUCT_RUNONCE_KEY,
        "script": str(script_path),
        "command": command,
        "retry_command": retry_command,
    }
    encoded_command = windows_cleanup_command(
        target, None, 0, restart=True, journal_path=journal_path,
        allow_pending=True, runonce=runonce,
    )
    script = _decode_cleanup_command(encoded_command[-1])
    script = "param([int]$WaitPid = 0, [string]$RunOnceName = '')\n" + script
    script = script.replace("$pidToWait = 0", "$pidToWait = $WaitPid", 1)
    return script.encode("utf-8"), command, retry_command

def register_destruct_runonce(
    target: Union[os.PathLike[str], str],
    data_home: Optional[Union[os.PathLike[str], str]],
    journal_path: Optional[Union[os.PathLike[str], str]] = None,
) -> Path:
    if sys.platform != "win32":
        raise OSError("The Windows RunOnce recovery helper is available only on Windows.")
    profile = Path.home().resolve()
    script_path = profile / DESTRUCT_RECOVERY_SCRIPT
    if script_path.parent != profile:
        raise ValueError("The Self-Destruct recovery helper is outside the user profile.")
    payload, command, retry_command = _destruct_recovery_payload(target, journal_path)
    created = False
    try:
        if _safe_recovery_script(script_path):
            if script_path.read_bytes() != payload:
                raise FileExistsError("A different file already occupies the Self-Destruct recovery-helper path.")
        else:
            with open(script_path, "xb") as helper:
                helper.write(payload)
                helper.flush()
                os.fsync(helper.fileno())
            created = True
        _set_destruct_runonce(command, retry_command)
    except Exception:
        if created:
            try:
                if _safe_recovery_script(script_path) and script_path.read_bytes() == payload:
                    script_path.unlink()
            except OSError:
                pass
        raise
    return script_path

def destruct_runonce_command(wait_pid: int) -> list[str]:
    script_path = Path.home() / DESTRUCT_RECOVERY_SCRIPT
    if not _safe_recovery_script(script_path):
        raise FileNotFoundError("The persistent Self-Destruct recovery helper is unavailable.")
    import winreg
    record = read_destruct_journal()
    if (record is None or record["operation"] != "self-destruct"
            or record["install_target"] is None):
        raise ValueError("The recovery helper has no authorized signed-installation journal.")
    expected_payload = _destruct_recovery_payload(
        record["install_target"], destruct_journal_path())[0]
    if script_path.read_bytes() != expected_payload:
        raise ValueError("The recovery helper content does not match the signed cleanup operation.")
    names = (DESTRUCT_RUNONCE_VALUE, DESTRUCT_RUNONCE_RETRY_VALUE)
    registered_name = None
    for name in names:
        entry = _read_destruct_runonce(name)
        expected = _destruct_runonce_command(script_path, name)
        if entry is not None and entry[0] == expected and entry[1] == winreg.REG_SZ:
            registered_name = name
            break
    if registered_name is None:
        raise ValueError("The exact Self-Destruct RunOnce recovery entry is not registered.")
    return [
        str(_windows_powershell_path()), "-NoProfile", "-NonInteractive",
        "-WindowStyle", "Hidden", "-ExecutionPolicy", "Bypass",
        "-File", str(script_path), "-WaitPid", str(int(wait_pid)),
        "-RunOnceName", registered_name,
    ]

def clear_destruct_runonce() -> None:
    script_path = Path.home() / DESTRUCT_RECOVERY_SCRIPT
    names = (DESTRUCT_RUNONCE_VALUE, DESTRUCT_RUNONCE_RETRY_VALUE)
    entries = {name: _read_destruct_runonce(name) for name in names}
    script_exists = _safe_recovery_script(script_path)
    if all(entry is None for entry in entries.values()) and not script_exists:
        return
    if all(entry is None for entry in entries.values()):
        raise ValueError("The recovery helper has no matching RunOnce entry and was preserved.")
    import winreg
    expected = {
        name: _destruct_runonce_command(script_path, name)
        for name in names
    }
    if (not script_exists
            or any(entry is not None and
                   (entry[0] != expected[name] or entry[1] != winreg.REG_SZ)
                   for name, entry in entries.items())):
        raise ValueError("The Self-Destruct recovery helper and its RunOnce value do not match.")
    payload = script_path.read_bytes()
    record = read_destruct_journal()
    if (record is None or record["operation"] != "self-destruct"
            or record["install_target"] is None
            or payload != _destruct_recovery_payload(
                record["install_target"], destruct_journal_path())[0]):
        raise ValueError("The recovery helper content does not match the authorized cleanup journal.")
    deleted: list[str] = []
    try:
        access = winreg.KEY_QUERY_VALUE | winreg.KEY_SET_VALUE
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, DESTRUCT_RUNONCE_KEY, 0, access) as key:
            for name in names:
                if entries[name] is None:
                    continue
                current, value_type = winreg.QueryValueEx(key, name)
                if value_type != winreg.REG_SZ or current != expected[name]:
                    raise ValueError("The Self-Destruct RunOnce value changed.")
                winreg.DeleteValue(key, name)
                deleted.append(name)
        script_path.unlink()
    except Exception:
        if not script_path.exists():
            try:
                with open(script_path, "xb") as helper:
                    helper.write(payload)
                    helper.flush()
                    os.fsync(helper.fileno())
            except OSError:
                pass
        try:
            access = winreg.KEY_QUERY_VALUE | winreg.KEY_SET_VALUE
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, DESTRUCT_RUNONCE_KEY, 0, access) as key:
                for name in deleted:
                    try:
                        winreg.QueryValueEx(key, name)
                    except FileNotFoundError:
                        winreg.SetValueEx(key, name, 0, winreg.REG_SZ, expected[name])
        except Exception:
            pass
        raise

def windows_cleanup_command(
    target: Union[os.PathLike[str], str],
    data_home: Optional[Union[os.PathLike[str], str]],
    wait_pid: int,
    restart: bool = True,
    journal_path: Optional[Union[os.PathLike[str], str]] = None,
    allow_pending: bool = False,
    runonce: Optional[dict[str, str]] = None,
) -> list[str]:
    data_home = Path(data_home).resolve() if data_home is not None else None
    profile = Path.home().resolve()
    if data_home is not None:
        home_is_user_data = data_home.name == ".unknwn" and data_home.parent == profile
        home_is_portable = data_home.name == "UNKNWN_data" and data_home.parent == target
        if not (home_is_user_data or home_is_portable):
            raise ValueError("Refusing to clean an unexpected data directory")
    journal_path = Path(journal_path).resolve() if journal_path is not None else None
    if journal_path is not None and (journal_path.name != DESTRUCT_JOURNAL
                                     or journal_path.parent != profile):
        raise ValueError("The cleanup journal is outside UNKNWN's per-user state location.")
    if journal_path is not None:
        record = read_destruct_journal()
        if (record is None or record["operation"] != "self-destruct"
                or record["phase"] not in ({"pending", "data-cleared"} if allow_pending else {"data-cleared"})
                or record["install_target"] is None
                or Path(record["install_target"]).resolve() != Path(target).resolve()):
            raise ValueError("No authorized cleanup journal permits deferred installation removal.")
    target = _validate_packaged_install_target(Path(target), allow_partial=journal_path is not None)
    def ps_quote(value: object) -> str:
        return "'" + str(value).replace("'", "''") + "'"
    data_assignment = "$null"
    if data_home is not None:
        data_assignment = f"[IO.Path]::GetFullPath({ps_quote(data_home)}).TrimEnd('\\')"
    recovery_assignment = "$null"
    runonce_setup = ""
    manifest_data = cast(dict[str, object], IG.load_manifest(target, IG.RELEASE_PUBKEY))
    signed_files = manifest_data.get("files")
    if not isinstance(signed_files, dict) or not signed_files:
        raise ValueError("The signed installation manifest has no file inventory for recovery.")
    executable_name = "UNKNWN.exe" if sys.platform == "win32" else "UNKNWN"
    if executable_name not in signed_files:
        raise ValueError("The signed installation inventory does not contain the running application.")
    raw_file_hashes = cast(dict[object, object], signed_files)
    file_hashes: dict[str, str] = {}
    for relative_name, digest in raw_file_hashes.items():
        if not isinstance(relative_name, str) or not isinstance(digest, str):
            raise ValueError("The signed installation manifest contains an invalid file inventory.")
        file_hashes[relative_name] = digest
    for special_file in (IG.MAN, IG.SIG):
        special_path = target / special_file
        if not special_path.is_file():
            raise ValueError("The signed installation manifest is incomplete.")
        file_hashes[special_file] = hashlib.sha256(special_path.read_bytes()).hexdigest()
    directory_names: set[str] = set()
    folded_names: set[str] = set()
    for relative_name, digest in file_hashes.items():
        if not relative_name or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ValueError("The signed installation manifest contains an invalid file inventory.")
        parts = relative_name.split("/")
        if (any(part in ("", ".", "..") or "\\" in part or ":" in part for part in parts)
                or relative_name.startswith("/")
                or relative_name.casefold() in folded_names):
            raise ValueError("The signed installation manifest contains an unsafe or ambiguous path.")
        folded_names.add(relative_name.casefold())
        directory_names.update("/".join(parts[:index]) for index in range(1, len(parts)))
    file_lines = ["$packageFiles = @{}"]
    file_lines.extend(
        f"$packageFiles[{ps_quote(name)}] = {ps_quote(digest)}"
        for name, digest in sorted(file_hashes.items())
    )
    dir_lines = ["$packageDirectories = @{}"]
    dir_lines.extend(
        f"$packageDirectories[{ps_quote(name)}] = $true"
        for name in sorted(directory_names)
    )
    package_inventory = "\n".join(file_lines)
    package_directories = "\n".join(dir_lines)
    if runonce is not None:
        expected_script = (Path.home().resolve() / DESTRUCT_RECOVERY_SCRIPT)
        if (runonce.get("name") != DESTRUCT_RUNONCE_VALUE
                or runonce.get("retry_name") != DESTRUCT_RUNONCE_RETRY_VALUE
                or runonce.get("key") != DESTRUCT_RUNONCE_KEY
                or Path(runonce.get("script", "")).resolve() != expected_script
                or runonce.get("command") != _destruct_runonce_command(expected_script)
                or len(runonce["command"]) > 32768
                or runonce.get("retry_command") != _destruct_runonce_command(expected_script, DESTRUCT_RUNONCE_RETRY_VALUE)):
            raise ValueError("The Self-Destruct RunOnce recovery configuration is invalid.")
        recovery_assignment = ps_quote(runonce["script"])
        runonce_setup = f"""
$configuredRunOnceName = {ps_quote(runonce["name"])}
$configuredRetryRunOnceName = {ps_quote(runonce["retry_name"])}
$runOnceKeyPath = {ps_quote(runonce["key"])}
$configuredRunOnceCommand = {ps_quote(runonce["command"])}
$configuredRetryRunOnceCommand = {ps_quote(runonce["retry_command"])}
$runOnceName = $RunOnceName
if ([string]::IsNullOrEmpty($runOnceName)) {{ $runOnceName = $configuredRunOnceName }}
if ($runOnceName -ceq $configuredRunOnceName) {{
    $runOnceCommand = $configuredRunOnceCommand
    $retryRunOnceName = $configuredRetryRunOnceName
    $retryRunOnceCommand = $configuredRetryRunOnceCommand
}} elseif ($runOnceName -ceq $configuredRetryRunOnceName) {{
    $runOnceCommand = $configuredRetryRunOnceCommand
    $retryRunOnceName = $configuredRunOnceName
    $retryRunOnceCommand = $configuredRunOnceCommand
}} else {{
    exit 23
}}
"""
    script = f"""
$ErrorActionPreference = 'Stop'
$target = [IO.Path]::GetFullPath({ps_quote(target)}).TrimEnd('\\')
$data = {data_assignment}
$journal = {"$null" if journal_path is None else ps_quote(journal_path)}
$expectedProfile = {ps_quote(profile)}
$pidToWait = {int(wait_pid)}
$recoveryScript = {recovery_assignment}
{runonce_setup}
$packageFiles = $null
$packageDirectories = $null
{package_inventory}
{package_directories}
$recoveryContents = $null
function Stop-Recovery([int]$code) {{
    Record-RecoveryFailure
    if ($null -ne $recoveryScript) {{
        try {{
            if (-not (Test-Path -LiteralPath $recoveryScript) -and $null -ne $recoveryContents) {{
                [IO.File]::WriteAllText($recoveryScript, $recoveryContents, [System.Text.UTF8Encoding]::new($false))
            }}
            $keepKey = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey($runOnceKeyPath)
            if ($null -ne $keepKey) {{
                $existingCommand = $keepKey.GetValue($runOnceName, $null,
                    [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
                $existingKind = $null
                if ($null -ne $existingCommand) {{ $existingKind = $keepKey.GetValueKind($runOnceName) }}
                if ($null -eq $existingCommand -or
                    ($existingCommand -ceq $runOnceCommand -and
                     $existingKind -eq [Microsoft.Win32.RegistryValueKind]::String)) {{
                    $keepKey.SetValue($runOnceName, $runOnceCommand, [Microsoft.Win32.RegistryValueKind]::String)
                }}
                if ($pidToWait -eq 0 -and $null -ne $retryRunOnceName) {{
                    $retryCommand = $keepKey.GetValue($retryRunOnceName, $null,
                        [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
                    $retryKind = $null
                    if ($null -ne $retryCommand) {{ $retryKind = $keepKey.GetValueKind($retryRunOnceName) }}
                    if ($null -eq $retryCommand -or
                        ($retryCommand -ceq $retryRunOnceCommand -and
                         $retryKind -eq [Microsoft.Win32.RegistryValueKind]::String)) {{
                        $keepKey.SetValue($retryRunOnceName, $retryRunOnceCommand,
                            [Microsoft.Win32.RegistryValueKind]::String)
                    }}
                }}
                $keepKey.Close()
            }}
        }} catch {{}}
    }}
    exit $code
}}
$profile = [IO.Path]::GetFullPath($env:USERPROFILE)
$userVault = Join-Path $profile '.unknwn'
$managedProfiles = Join-Path $profile '.unknwn-profiles'
$portableData = Join-Path $target 'UNKNWN_data'
$profileRegistry = Join-Path $profile '.unknwn-profiles.json'
$activeLocation = Join-Path $profile '.unknwn-location'
$journalPath = Join-Path $profile '{DESTRUCT_JOURNAL}'
$root = [IO.Path]::GetPathRoot($target).TrimEnd('\\')
$leaf = [IO.Path]::GetFileName($target)
function Record-RecoveryFailure {{
    if ($null -eq $journal -or $journal -ne $journalPath -or
        -not (Test-Path -LiteralPath $journal -PathType Leaf)) {{ return }}
    $failureTemp = $null
    try {{
        $journalItem = Get-Item -LiteralPath $journal -Force
        if (($journalItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {{ return }}
        $failureRecord = Get-Content -LiteralPath $journal -Raw | ConvertFrom-Json
        if ($failureRecord.version -ne 1 -or $failureRecord.operation -ne 'self-destruct' -or
            $failureRecord.install_target -ne $target -or
            $failureRecord.phase -notin @('pending', 'data-cleared')) {{ return }}
        $failures = @($failureRecord.failures) + @('RecoveryFailure')
        if ($failures.Count -gt 16) {{ $failures = $failures[($failures.Count - 16)..($failures.Count - 1)] }}
        $failureRecord.failures = $failures
        $failureRecord.updated = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
        $failureTemp = $journal + ".recovery-$PID.tmp"
        $bytes = [System.Text.UTF8Encoding]::new($false).GetBytes(
            (ConvertTo-Json -InputObject $failureRecord -Compress -Depth 8))
        $stream = [IO.File]::Open($failureTemp, [IO.FileMode]::CreateNew,
            [IO.FileAccess]::Write, [IO.FileShare]::None)
        try {{ $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true) }}
        finally {{ $stream.Dispose() }}
        [IO.File]::Replace($failureTemp, $journal, $null)
    }} catch {{ }}
    finally {{
        if ($null -ne $failureTemp -and (Test-Path -LiteralPath $failureTemp)) {{
            try {{ [IO.File]::Delete($failureTemp) }} catch {{ }}
        }}
    }}
}}
if ($null -ne $recoveryScript) {{
    try {{ $recoveryContents = [IO.File]::ReadAllText($recoveryScript) }}
    catch {{ Stop-Recovery 26 }}
}}
if ($target -eq $root -or $target -eq $profile -or $leaf -notmatch '^UNKNWN') {{ Stop-Recovery 10 }}
if (-not [string]::Equals($profile, $expectedProfile, [StringComparison]::OrdinalIgnoreCase)) {{ Stop-Recovery 30 }}
if ($null -eq $journal -and
    -not (Test-Path -LiteralPath (Join-Path $target 'UNKNWN.exe') -PathType Leaf)) {{ Stop-Recovery 11 }}
foreach ($marker in @('.git', '.venv', 'tests', 'unknwn.py', 'pyproject.toml')) {{
    if (Test-Path -LiteralPath (Join-Path $target $marker)) {{ Stop-Recovery 12 }}
}}
if ($null -ne $journal) {{
    if ($journal -ne $journalPath -or -not (Test-Path -LiteralPath $journal -PathType Leaf)) {{ Stop-Recovery 16 }}
    try {{
        $journalItem = Get-Item -LiteralPath $journal -Force
        if (($journalItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {{ Stop-Recovery 16 }}
        $intent = Get-Content -LiteralPath $journal -Raw | ConvertFrom-Json
        $allowedPhases = if ($null -ne $recoveryScript) {{ @('pending', 'data-cleared') }} else {{ @('data-cleared') }}
        if ($intent.version -ne 1 -or $intent.operation -ne 'self-destruct' -or
            $intent.phase -notin $allowedPhases -or $intent.install_target -ne $target) {{ Stop-Recovery 17 }}
    }} catch {{ Stop-Recovery 18 }}
}}
if ($null -ne $recoveryScript) {{
    try {{
        $runOnceKey = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($runOnceKeyPath, $false)
        if ($null -eq $runOnceKey) {{ Stop-Recovery 24 }}
        $registeredCommand = $runOnceKey.GetValue($runOnceName, $null,
            [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        $registeredKind = $runOnceKey.GetValueKind($runOnceName)
        $runOnceKey.Close()
        if ($registeredCommand -cne $runOnceCommand -or
            $registeredKind -ne [Microsoft.Win32.RegistryValueKind]::String) {{ Stop-Recovery 25 }}
    }} catch {{ Stop-Recovery 26 }}
}}
if ($null -ne $data) {{
    $dataParent = [IO.Path]::GetDirectoryName($data)
    $dataLeaf = [IO.Path]::GetFileName($data)
    $safeData = ($dataLeaf -eq '.unknwn' -and $dataParent -eq $profile) -or
                ($dataLeaf -eq 'UNKNWN_data' -and $dataParent -eq $target)
    if (-not $safeData -or $data -eq $target) {{ Stop-Recovery 13 }}
}}
function Assert-NoReparsePath([string]$path) {{
    $fullPath = [IO.Path]::GetFullPath($path)
    $volume = [IO.Path]::GetPathRoot($fullPath)
    $cursor = $fullPath
    while (-not [string]::IsNullOrEmpty($cursor)) {{
        if (Test-Path -LiteralPath $cursor) {{
            $item = Get-Item -LiteralPath $cursor -Force
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {{
                throw [IO.InvalidDataException]::new('A cleanup path contains a reparse point.')
            }}
        }}
        if ([string]::Equals($cursor, $volume, [StringComparison]::OrdinalIgnoreCase)) {{ break }}
        $cursor = [IO.Path]::GetDirectoryName($cursor)
    }}
}}
Assert-NoReparsePath $profile
Assert-NoReparsePath $target
Assert-NoReparsePath $userVault
Assert-NoReparsePath $managedProfiles
Assert-NoReparsePath $portableData
if ($null -ne $data) {{ Assert-NoReparsePath $data }}
if ($null -ne $journal) {{ Assert-NoReparsePath $journal }}
for ($i = 0; $pidToWait -gt 0 -and $i -lt 1200 -and
     (Get-Process -Id $pidToWait -ErrorAction SilentlyContinue); $i++) {{ Start-Sleep -Milliseconds 250 }}
if ($pidToWait -gt 0 -and (Get-Process -Id $pidToWait -ErrorAction SilentlyContinue)) {{ Stop-Recovery 14 }}
function Test-OwnedCleanupPath([string]$path) {{
    $fullPath = [IO.Path]::GetFullPath($path).TrimEnd('\\')
    foreach ($ownedRoot in @($userVault, $managedProfiles, $portableData)) {{
        $rootPath = [IO.Path]::GetFullPath($ownedRoot).TrimEnd('\\')
        if ([string]::Equals($fullPath, $rootPath, [StringComparison]::OrdinalIgnoreCase) -or
            $fullPath.StartsWith($rootPath + '\\', [StringComparison]::OrdinalIgnoreCase)) {{ return $true }}
    }}
    foreach ($ownedFile in @($profileRegistry, ($profileRegistry + '.bak'),
                             ($profileRegistry + '.tmp'), $activeLocation)) {{
        if ([string]::Equals($fullPath, [IO.Path]::GetFullPath($ownedFile),
                [StringComparison]::OrdinalIgnoreCase)) {{ return $true }}
    }}
    $profilePrefix = $profile.TrimEnd('\\') + '\\'
    if ($fullPath.StartsWith($profilePrefix, [StringComparison]::OrdinalIgnoreCase)) {{
        $leafName = $fullPath.Substring($profilePrefix.Length)
        if ($leafName -match '^\\.unknwn-profiles\\.json\\.[^\\\\]+\\.tmp$' -or
            $leafName -match '^\\.unknwn-location\\.[^\\\\]+\\.tmp$' -or
            $leafName -match '^[.]unknwn-destruct[.]json\\.[^\\\\]+\\.tmp$') {{ return $true }}
    }}
    return $false
}}
function Remove-SafeTree([string]$path) {{
    if (-not (Test-OwnedCleanupPath $path)) {{
        throw [IO.InvalidDataException]::new('A deletion path is outside the UNKNWN-owned cleanup roots.')
    }}
    if (-not (Test-Path -LiteralPath $path)) {{ return }}
    $parentPath = [IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($path))
    if ($null -ne $parentPath) {{ Assert-NoReparsePath $parentPath }}
    $item = Get-Item -LiteralPath $path -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {{
        if ($item -is [IO.DirectoryInfo]) {{ [IO.Directory]::Delete($path, $false) }}
        else {{ [IO.File]::Delete($path) }}
        return
    }}
    if ($item -is [IO.DirectoryInfo]) {{
        foreach ($child in [IO.Directory]::EnumerateFileSystemEntries($path)) {{ Remove-SafeTree $child }}
        [IO.Directory]::Delete($path, $false)
    }} else {{
        [IO.File]::Delete($path)
    }}
}}
function Remove-InstallTree([string]$path) {{
    if (-not (Test-Path -LiteralPath $path)) {{ return }}
    if ($null -eq $packageFiles -or $null -eq $packageDirectories) {{
        throw [IO.InvalidDataException]::new('The signed package inventory is unavailable.')
    }}
    Assert-NoReparsePath $path
    $rootItem = Get-Item -LiteralPath $path -Force
    if ($rootItem -isnot [IO.DirectoryInfo]) {{
        throw [IO.InvalidDataException]::new('The signed installation root is not a directory.')
    }}
    foreach ($relative in @($packageFiles.Keys | Sort-Object {{ $_.Length }} -Descending)) {{
        $relativePath = $relative.Replace('/', [char]92)
        $filePath = [IO.Path]::GetFullPath([IO.Path]::Combine($path, $relativePath))
        $rootPrefix = [IO.Path]::GetFullPath($path).TrimEnd('\\') + '\\'
        if (-not $filePath.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase)) {{
            throw [IO.InvalidDataException]::new('A signed package file resolves outside the installation root.')
        }}
        if (-not (Test-Path -LiteralPath $filePath)) {{ continue }}
        $parentPath = [IO.Path]::GetDirectoryName($filePath)
        Assert-NoReparsePath $parentPath
        $fileItem = Get-Item -LiteralPath $filePath -Force
        if (($fileItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
            $fileItem -is [IO.DirectoryInfo]) {{
            throw [IO.InvalidDataException]::new('A signed package file was replaced by an unsafe entry.')
        }}
        $actualHash = (Get-FileHash -LiteralPath $filePath -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actualHash -cne $packageFiles[$relative]) {{
            throw [IO.InvalidDataException]::new('A signed package file changed after validation.')
        }}
        [IO.File]::Delete($filePath)
        if (Test-Path -LiteralPath $filePath) {{
            throw [IO.IOException]::new('A verified UNKNWN package file remains locked.')
        }}
    }}
    foreach ($relative in @($packageDirectories.Keys | Sort-Object {{ $_.Length }} -Descending)) {{
        $relativePath = $relative.Replace('/', [char]92)
        $directoryPath = [IO.Path]::GetFullPath([IO.Path]::Combine($path, $relativePath))
        $rootPrefix = [IO.Path]::GetFullPath($path).TrimEnd('\\') + '\\'
        if (-not $directoryPath.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase)) {{
            throw [IO.InvalidDataException]::new('A signed package directory resolves outside the installation root.')
        }}
        if (-not (Test-Path -LiteralPath $directoryPath)) {{ continue }}
        Assert-NoReparsePath $directoryPath
        $directoryItem = Get-Item -LiteralPath $directoryPath -Force
        if ($directoryItem -isnot [IO.DirectoryInfo]) {{
            throw [IO.InvalidDataException]::new('A signed package directory was replaced by an unsafe entry.')
        }}
        [IO.Directory]::Delete($directoryPath, $false)
    }}
    if ([IO.Directory]::EnumerateFileSystemEntries($path).GetEnumerator().MoveNext()) {{
        throw [IO.InvalidDataException]::new('The installation contains an entry outside its signed inventory.')
    }}
    [IO.Directory]::Delete($path, $false)
}}
function Test-SignedPackageRemainder([string]$path, [string]$relative) {{
    if (-not (Test-Path -LiteralPath $path)) {{ return $true }}
    $entry = Get-Item -LiteralPath $path -Force
    if (($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {{ return $false }}
    if ($entry -is [IO.DirectoryInfo]) {{
        if ($relative -eq 'UNKNWN_data') {{ return $true }}
        if ($relative -ne '' -and -not $packageDirectories.ContainsKey($relative)) {{ return $false }}
        foreach ($child in [IO.Directory]::EnumerateFileSystemEntries($path)) {{
        $childRelative = $child.Substring($target.Length).TrimStart([char[]]@(92, 47)).Replace([char]92, [char]47)
            if (-not (Test-SignedPackageRemainder $child $childRelative)) {{ return $false }}
        }}
        return $true
    }}
    if (-not $packageFiles.ContainsKey($relative)) {{ return $false }}
    $actualHash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
    return $actualHash -ceq $packageFiles[$relative]
}}
function Test-KnownDataRemain {{
    if ((Test-Path -LiteralPath $userVault) -or (Test-Path -LiteralPath $managedProfiles) -or
            (Test-Path -LiteralPath $portableData) -or
            (Test-Path -LiteralPath $profileRegistry) -or
        (Test-Path -LiteralPath ($profileRegistry + '.bak')) -or
        (Test-Path -LiteralPath ($profileRegistry + '.tmp')) -or
        (Test-Path -LiteralPath $activeLocation)) {{ return $true }}
    foreach ($pattern in @('.unknwn-profiles.json.*.tmp', '.unknwn-location.*.tmp',
                           '{DESTRUCT_JOURNAL}.*.tmp')) {{
        if ([IO.Directory]::EnumerateFiles($profile, $pattern).GetEnumerator().MoveNext()) {{ return $true }}
    }}
    return $false
}}
$removed = $false
for ($i = 0; $i -lt 80; $i++) {{
    try {{
        if ($null -ne $data -and (Test-Path -LiteralPath $data)) {{ Remove-SafeTree $data }}
        if (Test-Path -LiteralPath $portableData) {{ Remove-SafeTree $portableData }}
        foreach ($emptyDataDir in @($userVault, $managedProfiles)) {{
            if (Test-Path -LiteralPath $emptyDataDir -PathType Container) {{
                Remove-SafeTree $emptyDataDir
            }}
        }}
        foreach ($ownedState in @($profileRegistry, ($profileRegistry + '.bak'),
                                   ($profileRegistry + '.tmp'), $activeLocation)) {{
            Remove-SafeTree $ownedState
        }}
        foreach ($pattern in @('.unknwn-profiles.json.*.tmp', '.unknwn-location.*.tmp',
                               '{DESTRUCT_JOURNAL}.*.tmp')) {{
            foreach ($stateTemp in [IO.Directory]::EnumerateFiles($profile, $pattern)) {{
                Remove-SafeTree $stateTemp
            }}
        }}
        $requestedDataRemain = ($null -ne $data -and (Test-Path -LiteralPath $data)) -or
                               (Test-Path -LiteralPath $portableData)
        $knownDataRemain = Test-KnownDataRemain
        if ($requestedDataRemain -or $knownDataRemain) {{
            throw [IO.IOException]::new('UNKNWN-owned data remains; retaining the application for retry.')
        }}
        if ((Test-Path -LiteralPath $target) -and -not (Test-SignedPackageRemainder $target '')) {{
            throw [IO.InvalidDataException]::new('The installation contains files outside its verified signed inventory.')
        }}
        if (Test-Path -LiteralPath $target) {{ Remove-InstallTree $target }}
    }} catch {{}}
    $knownDataRemain = Test-KnownDataRemain
    if (-not (Test-Path -LiteralPath $target) -and ($null -eq $data -or -not (Test-Path -LiteralPath $data)) -and -not $knownDataRemain) {{ $removed = $true; break }}
    Start-Sleep -Milliseconds 500
}}
if (-not $removed) {{
    Stop-Recovery 15
}}
if ({'$true' if restart else '$false'}) {{
    try {{
        $downloads = Join-Path $profile 'Downloads'
        [IO.Directory]::CreateDirectory($downloads) | Out-Null
        $downloadsItem = Get-Item -LiteralPath $downloads -Force
        if ($downloadsItem -isnot [IO.DirectoryInfo] -or
            ($downloadsItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {{
            throw [IO.InvalidDataException]::new('The Downloads folder is not a safe directory.')
        }}
        $notePath = Join-Path $downloads 'meow.txt'
        $noteBytes = [System.Text.UTF8Encoding]::new($false).GetBytes('meow')
        if (Test-Path -LiteralPath $notePath) {{
            $noteItem = Get-Item -LiteralPath $notePath -Force
            if ($noteItem -is [IO.DirectoryInfo] -or
                ($noteItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
                [Convert]::ToBase64String([IO.File]::ReadAllBytes($notePath)) -cne 'bWVvdw==') {{
                throw [IO.IOException]::new('Downloads\\meow.txt exists with different content and was preserved.')
            }}
        }} else {{
            try {{
                $noteStream = [IO.File]::Open($notePath, [IO.FileMode]::CreateNew,
                    [IO.FileAccess]::Write, [IO.FileShare]::None)
                try {{ $noteStream.Write($noteBytes, 0, $noteBytes.Length); $noteStream.Flush($true) }}
                finally {{ $noteStream.Dispose() }}
            }} catch [IO.IOException] {{
                if (-not (Test-Path -LiteralPath $notePath)) {{ throw }}
            }}
        }}
        $noteItem = Get-Item -LiteralPath $notePath -Force
        if ($noteItem -is [IO.DirectoryInfo] -or
            ($noteItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
            [Convert]::ToBase64String([IO.File]::ReadAllBytes($notePath)) -cne 'bWVvdw==') {{
            throw [IO.IOException]::new('The self-destruct verification marker could not be verified.')
        }}
    }} catch {{ Stop-Recovery 28 }}
}}
if ($null -ne $recoveryScript) {{
    $recoveryContents = $null
    try {{
        $recoveryContents = [IO.File]::ReadAllText($recoveryScript)
        $runOnceKey = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($runOnceKeyPath, $true)
        if ($null -eq $runOnceKey) {{ throw [IO.IOException]::new('The recovery RunOnce key is unavailable.') }}
        $registeredCommand = $runOnceKey.GetValue($runOnceName, $null,
            [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        $registeredKind = $runOnceKey.GetValueKind($runOnceName)
        if ($registeredCommand -cne $runOnceCommand -or
            $registeredKind -ne [Microsoft.Win32.RegistryValueKind]::String) {{
            throw [IO.InvalidDataException]::new('The recovery RunOnce value changed.')
        }}
        $registeredRetryCommand = $runOnceKey.GetValue($retryRunOnceName, $null,
            [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        if ($null -ne $registeredRetryCommand) {{
            $registeredRetryKind = $runOnceKey.GetValueKind($retryRunOnceName)
            if ($registeredRetryCommand -cne $retryRunOnceCommand -or
                $registeredRetryKind -ne [Microsoft.Win32.RegistryValueKind]::String) {{
                throw [IO.InvalidDataException]::new('The retry RunOnce value changed.')
            }}
        }}
        [IO.File]::Delete($recoveryScript)
        if (Test-Path -LiteralPath $recoveryScript) {{ throw [IO.IOException]::new('The recovery helper remains on disk.') }}
        $runOnceKey.DeleteValue($runOnceName, $false)
        if ($null -ne $registeredRetryCommand) {{ $runOnceKey.DeleteValue($retryRunOnceName, $false) }}
        $runOnceKey.Close()
        $checkKey = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($runOnceKeyPath, $false)
        if ($null -ne $checkKey) {{
            $remainingRunOnce = $checkKey.GetValue($runOnceName, $null,
                [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
            $remainingRetryRunOnce = $checkKey.GetValue($retryRunOnceName, $null,
                [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
            $checkKey.Close()
            if ($null -ne $remainingRunOnce -or $null -ne $remainingRetryRunOnce) {{
                throw [IO.IOException]::new('A recovery RunOnce value remains.')
            }}
        }}
    }} catch {{
        try {{
            if ($null -ne $recoveryContents -and -not (Test-Path -LiteralPath $recoveryScript)) {{
                [IO.File]::WriteAllText($recoveryScript, $recoveryContents, [System.Text.UTF8Encoding]::new($false))
            }}
            $restoreKey = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey($runOnceKeyPath)
            if ($null -ne $restoreKey) {{
                $restoreCommand = $restoreKey.GetValue($runOnceName, $null,
                    [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
                $restoreKind = $null
                if ($null -ne $restoreCommand) {{ $restoreKind = $restoreKey.GetValueKind($runOnceName) }}
                if ($null -eq $restoreCommand -or
                    ($restoreCommand -ceq $runOnceCommand -and
                     $restoreKind -eq [Microsoft.Win32.RegistryValueKind]::String)) {{
                    $restoreKey.SetValue($runOnceName, $runOnceCommand,
                        [Microsoft.Win32.RegistryValueKind]::String)
                }}
                $restoreKey.Close()
            }}
        }} catch {{}}
        Stop-Recovery 27
    }}
}}
if ({'$true' if restart else '$false'}) {{
    try {{
        $shutdownPath = Join-Path $env:SystemRoot 'System32\\shutdown.exe'
        if (-not (Test-Path -LiteralPath $shutdownPath -PathType Leaf)) {{
            throw [IO.FileNotFoundException]::new('The Windows restart command is unavailable.')
        }}
        Start-Process -FilePath $shutdownPath -ArgumentList @('/r', '/t', '10') `
            -WindowStyle Hidden -ErrorAction Stop
    }} catch {{ Stop-Recovery 29 }}
}}
if ($null -ne $journal -and (Test-Path -LiteralPath $journal)) {{
    try {{ Remove-Item -LiteralPath $journal -Force -ErrorAction Stop }}
    catch {{
        if ($null -ne $recoveryScript) {{
            try {{
                [IO.File]::WriteAllText($recoveryScript, $recoveryContents, [System.Text.UTF8Encoding]::new($false))
                $restoreKey = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey($runOnceKeyPath)
                if ($null -ne $restoreKey) {{
                    $restoreCommand = $restoreKey.GetValue($runOnceName, $null,
                        [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
                    $restoreKind = $null
                    if ($null -ne $restoreCommand) {{ $restoreKind = $restoreKey.GetValueKind($runOnceName) }}
                    if ($null -eq $restoreCommand -or
                        ($restoreCommand -ceq $runOnceCommand -and
                         $restoreKind -eq [Microsoft.Win32.RegistryValueKind]::String)) {{
                        $restoreKey.SetValue($runOnceName, $runOnceCommand,
                            [Microsoft.Win32.RegistryValueKind]::String)
                    }}
                    $restoreKey.Close()
                }}
            }} catch {{}}
        }}
        Stop-Recovery 19
    }}
}}
"""
    encoded = _encode_cleanup_command(script)
    powershell = _windows_powershell_path()
    command = [
        str(powershell), "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden",
        "-EncodedCommand", encoded,
    ]
    if runonce is None and len(subprocess.list2cmdline(command)) >= 32767:
        raise ValueError("The verified cleanup command is too large to run directly; use the staged recovery helper.")
    return command
def canonical_json(obj: object) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
def signed_payload(payload: object, key: bytes) -> dict[str, object]:
    if not isinstance(payload, dict): raise TypeError("payload must be a dict")
    typed_payload = cast(dict[str, object], payload)
    sig = hmac.new(key, canonical_json(typed_payload), hashlib.sha256).digest()
    return {"payload": typed_payload, "sig": b64e(sig)}
def verify_payload(blob: object, key: bytes) -> object:
    if not isinstance(blob, dict) or "payload" not in blob or "sig" not in blob: raise InvalidTag()
    payload_blob = cast(dict[object, object], blob)
    signature = payload_blob["sig"]
    if not isinstance(signature, str): raise InvalidTag()
    got = b64d(signature)
    exp = hmac.new(key, canonical_json(payload_blob["payload"]), hashlib.sha256).digest()
    if not hmac.compare_digest(got, exp): raise InvalidTag()
    return payload_blob["payload"]
def hkdf_key(secret: Optional[bytes], info: bytes) -> bytes:
    if secret is None: secret = b""
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info).derive(secret)
def idx_key(root: bytes) -> bytes: return hkdf_key(root, b"unknwn-index")
def self_destruct_key(root: bytes) -> bytes: return hkdf_key(root, b"unknwn-selfdestruct")
SELF_DESTRUCT_RUNTIME_KEY = os.urandom(32)
def validate_rid(rid: object) -> str:
    if not isinstance(rid, str) or not re.fullmatch(r"[0-9a-f]{12}", rid):
        raise ValueError(f"Invalid vault id: {rid!r}")
    return rid
def vault_file_path(rid: object, suffix: str = ".cdr") -> Path:
    rid = validate_rid(str(rid))
    p = VAULT / f"{rid}{suffix}"
    try:
        p = p.resolve(strict=False)
        base = VAULT.resolve(strict=False)
        if not safe_under_dir(base, p):
            raise ValueError(f"Path escapes vault directory: {p}")
    except Exception:
        raise ValueError(f"Path escapes vault directory: {rid!r}")
    return p
def safe_under_dir(
    base: Union[os.PathLike[str], str],
    candidate: Union[os.PathLike[str], str],
) -> bool:
    base = Path(base).resolve(strict=False)
    c = Path(candidate).resolve(strict=False)
    return c == base or str(c).startswith(str(base) + os.sep)
def _redact_log(obj: Any) -> Any:
    if isinstance(obj, dict):
        out: dict[str, Any] = {}
        entries = cast(dict[str, Any], obj)
        for k, v in entries.items():
            ks = str(k).lower()
            if any(tok in ks for tok in ("password", "passphrase", "secret", "token", "key", "recovery", "mfa", "vault", "pw", "phrase", "clipboard", "keystroke")):
                out[k] = "[REDACTED]"
            else:
                out[k] = _redact_log(v)
        return out
    if isinstance(obj, list): return [_redact_log(v) for v in cast(list[object], obj)]
    if isinstance(obj, tuple): return tuple(_redact_log(v) for v in cast(tuple[object, ...], obj))
    return obj

def log_security_event(event: object, **fields: object) -> None:
    try:
        HOME.mkdir(parents=True, exist_ok=True)
        day = time.strftime("%Y-%m-%d")
        path = HOME / f"security-{day}.log"
        rec: dict[str, object] = {"ts": time.time(), "event": str(event), **_redact_log(fields)}
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, separators=(",", ":"), ensure_ascii=False) + "\n")
    except Exception:
        pass

def _signed_self_destruct_state(
    root: bytes,
    state: str,
    deadline: float,
) -> dict[str, object]:
    payload: dict[str, object] = {"state": state, "deadline": float(deadline), "ts": int(time.time())}
    sig = hmac.new(self_destruct_key(root), canonical_json(payload), hashlib.sha256).digest()
    return {**payload, "sig": b64e(sig)}

def verify_self_destruct_state(root: bytes, blob: object) -> dict[str, object]:
    if not isinstance(blob, dict): raise ValueError("self-destruct state must be a dict")
    fields = cast(dict[str, object], blob)
    signature = fields.get("sig")
    if not isinstance(signature, str): raise InvalidTag()
    payload: dict[str, object] = {k: v for k, v in fields.items() if k != "sig"}
    exp = hmac.new(self_destruct_key(root), canonical_json(payload), hashlib.sha256).digest()
    if not hmac.compare_digest(b64d(signature), exp): raise InvalidTag()
    if payload.get("state") not in {"pending", "cleared"}: raise ValueError("unsupported self-destruct state")
    deadline = payload.get("deadline", 0.0)
    if type(deadline) not in (int, float): raise ValueError("invalid self-destruct deadline")
    d = float(cast(Union[int, float], deadline))
    if not math.isfinite(d): raise ValueError("invalid self-destruct deadline")
    return payload

def pending_self_destruct_deadline() -> float:
    sd = cfg.get("sd")
    try:
        payload = verify_self_destruct_state(SELF_DESTRUCT_RUNTIME_KEY, sd)
        if payload.get("state") != "pending": return 0.0
        deadline = payload.get("deadline", 0.0)
        return float(deadline) if isinstance(deadline, (int, float)) else 0.0
    except Exception:
        return 0.0

def _validated_idx(payload: object) -> dict[str, _VaultMetadata]:
    if not isinstance(payload, dict): raise ValueError("index payload must be a dict")
    entries = cast(dict[object, object], payload)
    clean: dict[str, _VaultMetadata] = {}
    for k, v in entries.items():
        rr = str(k)
        validate_rid(rr)
        if not isinstance(v, dict): raise ValueError("index metadata must be a dict")
        metadata = cast(dict[object, object], v)
        if "s" not in metadata or "nm" not in metadata or "size" not in metadata or "exp" not in metadata or "views" not in metadata: raise ValueError("missing index metadata fields")
        if type(metadata["size"]) is not int or metadata["size"] < 0: raise ValueError("invalid index size")
        expiry = metadata["exp"]
        if expiry is not None:
            if type(expiry) not in (int, float): raise ValueError("invalid expiry")
            expiry_value = float(cast(Union[int, float], expiry))
            if not math.isfinite(expiry_value) or expiry_value < 0: raise ValueError("invalid expiry")
        if metadata["views"] is not None and (type(metadata["views"]) is not int or metadata["views"] < 0): raise ValueError("invalid view count")
        if not isinstance(metadata["s"], str) or not isinstance(metadata["nm"], str): raise ValueError("invalid index encryption metadata")
        if "group" in metadata:
            group_value = metadata["group"]
            if not isinstance(group_value, str) or len(group_value) > 64 or any(
                    ord(char) < 32 for char in group_value):
                raise ValueError("invalid vault item group")
        clean[rr] = cast(_VaultMetadata, metadata)
    return clean
def encode_idx(root: bytes, payload: object) -> dict[str, str]:
    clean = _validated_idx(payload)
    return {"format": "UNKNWN-INDEX-2", "data": b64e(seal(idx_key(root), canonical_json(clean)))}
def decode_idx_blob(root: bytes, blob: object) -> dict[str, _VaultMetadata]:
    if not isinstance(blob, dict):
        raise InvalidTag("Unsupported encrypted index format")
    blob_data = cast(dict[object, object], blob)
    if blob_data.get("format") != "UNKNWN-INDEX-2":
        raise InvalidTag("Unsupported encrypted index format")
    data = blob_data.get("data")
    if not isinstance(data, str):
        raise InvalidTag("Encrypted index data is malformed")
    payload = json.loads(unseal(idx_key(root), b64d(data)))
    return _validated_idx(payload)
def write_idx_blob(blob: Mapping[str, object]) -> None:
    jsave(IDX, dict(blob))
    try:
        backup_value: object = json.loads(IDX.with_name(IDX.name + ".bak").read_text())
        if not isinstance(backup_value, dict) or cast(dict[str, object], backup_value).get("format") != "UNKNWN-INDEX-2":
            IDX.with_name(IDX.name + ".bak").unlink(missing_ok=True)
    except FileNotFoundError:
        pass
    except (OSError, ValueError, TypeError):
        IDX.with_name(IDX.name + ".bak").unlink(missing_ok=True)
def save_idx(root: bytes, payload: object) -> None:
    write_idx_blob(encode_idx(root, payload))
@overload
def load_idx(root: bytes, with_legacy: Literal[True]) -> tuple[dict[str, _VaultMetadata], bool]: ...
@overload
def load_idx(root: bytes, with_legacy: Literal[False] = False) -> dict[str, _VaultMetadata]: ...
@overload
def load_idx(
    root: bytes, with_legacy: bool,
) -> Union[dict[str, _VaultMetadata], tuple[dict[str, _VaultMetadata], bool]]: ...
def load_idx(
    root: bytes, with_legacy: bool = False,
) -> Union[dict[str, _VaultMetadata], tuple[dict[str, _VaultMetadata], bool]]:
    errors: list[Exception] = []
    found = False
    for path in (IDX, IDX.with_name(IDX.name + ".bak")):
        try:
            raw = path.read_text(encoding="utf-8")
        except FileNotFoundError:
            continue
        except OSError as exc:
            errors.append(exc); continue
        found = True
        try:
            data: object = json.loads(raw)
            if isinstance(data, dict):
                index_blob: dict[object, object] = cast(dict[object, object], data)
                if index_blob.get("format") == "UNKNWN-INDEX-2":
                    result = decode_idx_blob(root, index_blob); legacy = False
                elif "payload" in index_blob and "sig" in index_blob:
                    result = _validated_idx(verify_payload(index_blob, idx_key(root))); legacy = True
                else:
                    result = _validated_idx(index_blob); legacy = True
            else:
                result = _validated_idx(data); legacy = True
            return (result, legacy) if with_legacy else result
        except (InvalidTag, ValueError, TypeError, KeyError, json.JSONDecodeError) as exc:
            errors.append(exc)
    if not found: return ({}, False) if with_legacy else {}
    raise InvalidTag("No valid authenticated vault index was found") from (errors[-1] if errors else None)

def fsync_directory(path: Union[os.PathLike[str], str]) -> None:
    if os.name == "nt": return
    fd = os.open(path, os.O_RDONLY)
    try: os.fsync(fd)
    finally: os.close(fd)

def durable_replace(
    source: Union[os.PathLike[str], str],
    destination: Union[os.PathLike[str], str],
) -> None:
    source = Path(source); destination = Path(destination)
    for attempt in range(6):
        try:
            os.replace(source, destination); break
        except PermissionError:
            if attempt == 5: raise
            time.sleep(.05 * (attempt + 1))
    fsync_directory(destination.parent)

def atomic_write_bytes(path: Union[os.PathLike[str], str], data: bytes) -> None:
    path = Path(path); path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=path.parent)
    temp = Path(temp_name)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data); stream.flush(); os.fsync(stream.fileno())
        durable_replace(temp, path)
    except BaseException:
        try: temp.unlink(missing_ok=True)
        except OSError: pass
        raise

def save_verified_temp_copy(
    source: Union[os.PathLike[str], str],
    destination: Union[os.PathLike[str], str],
    expected_digest: str,
) -> None:
    source = Path(source); destination = Path(destination)
    if not tmp_path_owned(source):
        raise ValueError("The decrypted source is not in UNKNWN's managed temporary folder.")
    source_info = source.lstat()
    if (not stat.S_ISREG(source_info.st_mode)
            or stat.S_ISLNK(source_info.st_mode)
            or getattr(source_info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)):
        raise ValueError("The decrypted temporary source is not a regular file.")
    target_info = None
    try: target_info = destination.lstat()
    except FileNotFoundError: pass
    if target_info is not None and (stat.S_ISLNK(target_info.st_mode)
            or getattr(target_info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)):
        raise ValueError("Choose a regular file path, not a link.")
    vault_root = (HOME / "vault").resolve(strict=False)
    resolved = destination.resolve(strict=False)
    if resolved == vault_root or vault_root in resolved.parents:
        raise ValueError("Decrypted copies cannot be saved inside the encrypted vault folder.")

    destination.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(prefix=destination.name + ".", suffix=".tmp", dir=destination.parent)
    temporary = Path(temporary_name)
    try:
        with open(source, "rb") as incoming:
            opened_info = os.fstat(incoming.fileno())
            if (opened_info.st_dev, opened_info.st_ino) != (source_info.st_dev, source_info.st_ino):
                raise ValueError("The decrypted temporary source changed before it could be copied.")
            digest = hashlib.sha256()
            with os.fdopen(fd, "wb") as outgoing:
                for chunk in iter(lambda: incoming.read(1 << 20), b""):
                    digest.update(chunk); outgoing.write(chunk)
                outgoing.flush(); os.fsync(outgoing.fileno())
            final_info = os.fstat(incoming.fileno())
            if ((final_info.st_dev, final_info.st_ino, final_info.st_size, final_info.st_mtime_ns)
                    != (opened_info.st_dev, opened_info.st_ino, opened_info.st_size, opened_info.st_mtime_ns)
                    or digest.hexdigest() != expected_digest):
                raise ValueError("The decrypted temporary source changed; no copy was saved.")
        durable_replace(temporary, destination)
    except BaseException:
        try: os.close(fd)
        except OSError: pass
        try: temporary.unlink(missing_ok=True)
        except OSError: pass
        raise

def jload(p: Path, d: object) -> object:
    for q in (p, p.with_name(p.name + ".bak")):   # a damaged file falls back to the last good backup
        try: return json.loads(q.read_text())
        except Exception: pass
    return d


def _read_config_object(path: Path) -> tuple[Optional[dict[str, Any]], str]:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return None, "missing"
    except OSError:
        return None, "unavailable"
    if (stat.S_ISLNK(info.st_mode)
            or getattr(info, "st_file_attributes", 0)
            & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
            or not stat.S_ISREG(info.st_mode)
            or getattr(info, "st_nlink", 1) != 1):
        return None, "unsafe"
    if info.st_size > (1 << 20):
        return None, "oversized"
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError:
        return None, "unavailable"
    try:
        value: object = json.loads(raw)
    except (ValueError, TypeError):
        return None, "invalid"
    if not isinstance(value, dict):
        return None, "invalid"
    return cast(dict[str, Any], value), "valid"


def _config_matches_startup_schema(config: Mapping[str, object], required_keys: frozenset[str]) -> bool:
    if not required_keys <= config.keys():
        return False
    if any(not isinstance(config.get(key), str) or not config.get(key)
           for key in ("s1", "s2", "wp", "wr") if key in required_keys):
        return False
    if "f" in required_keys and (type(config.get("f")) is not int or cast(int, config["f"]) < 0):
        return False
    for key in ("lock", "last"):
        value = config.get(key)
        if key in required_keys and (
                type(value) not in (int, float) or not math.isfinite(cast(float, value))):
            return False
    return "set" not in config or isinstance(config.get("set"), dict)


def load_config_snapshot(
    path: Path,
    required_keys: frozenset[str] = frozenset(),
) -> tuple[dict[str, Any], Literal["primary", "backup", "empty", "damaged", "unavailable"]]:
    primary, primary_state = _read_config_object(path)
    if primary is not None and _config_matches_startup_schema(primary, required_keys):
        return primary, "primary"
    backup, backup_state = _read_config_object(path.with_name(path.name + ".bak"))
    if backup is not None and _config_matches_startup_schema(backup, required_keys):
        return backup, "backup"
    if primary_state == "missing" and backup_state == "missing":
        return {}, "empty"
    if primary_state in {"unsafe", "oversized", "unavailable"} \
            or backup_state in {"unsafe", "oversized", "unavailable"}:
        return {}, "unavailable"
    return {}, "damaged"


def config_recovery_diagnostic(path: Path, required_keys: frozenset[str]) -> dict[str, str]:
    _primary, primary_state = _read_config_object(path)
    _backup, backup_state = _read_config_object(path.with_name(path.name + ".bak"))
    primary_valid = _primary is not None and _config_matches_startup_schema(_primary, required_keys)
    backup_valid = _backup is not None and _config_matches_startup_schema(_backup, required_keys)
    if _primary is not None and not primary_valid:
        primary_state = "incomplete"
    if _backup is not None and not backup_valid:
        backup_state = "incomplete"
    if primary_valid:
        state = "pass" if backup_state in {"valid", "missing"} else "warning"
        detail = f"Primary configuration is a safe JSON object; backup status is {backup_state}."
    elif backup_valid:
        state = "warning"
        detail = (
            f"Primary configuration status is {primary_state}; a valid local backup is available. "
            "Startup uses the backup without changing either file.")
    elif primary_state == "missing" and backup_state == "missing":
        state = "missing"
        detail = "No configuration file or backup is present."
    elif "unsafe" in {primary_state, backup_state}:
        state = "unavailable"
        detail = "A configuration path is linked or is not a safe regular file; it was not followed."
    elif "oversized" in {primary_state, backup_state}:
        state = "unavailable"
        detail = "A configuration file exceeds the local size limit; no file was changed."
    elif "unavailable" in {primary_state, backup_state}:
        state = "unavailable"
        detail = "A configuration file could not be read; no file was changed."
    else:
        state = "fail"
        detail = "Neither the primary configuration nor its backup contains a valid vault configuration."
    return {"name": "Configuration recovery", "state": state, "detail": detail}


def jsave(p: Union[os.PathLike[str], str], o: object) -> None:
    """Crash-safe save: write a temp file, fsync, keep the previous good copy as .bak, then atomically replace."""
    p = Path(p); p.parent.mkdir(parents=True, exist_ok=True); tmp = p.with_name(p.name + ".tmp")
    with open(tmp, "w", encoding="utf-8") as f: json.dump(o, f); f.flush(); os.fsync(f.fileno())
    try:
        json.loads(p.read_text(encoding="utf-8"))
        backup_tmp = p.with_name(p.name + ".bak.tmp")
        with open(p, "rb") as source, open(backup_tmp, "wb") as backup:
            shutil.copyfileobj(source, backup); backup.flush(); os.fsync(backup.fileno())
        durable_replace(backup_tmp, p.with_name(p.name + ".bak"))
    except FileNotFoundError:
        pass
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        try: p.with_name(p.name + ".bak.tmp").unlink(missing_ok=True)
        except OSError: pass
    durable_replace(tmp, p)


_CONFIG_TRANSACTION_LOCK = threading.RLock()


def commit_config_transaction(candidate: Mapping[str, object]) -> None:
    """Persist a complete config snapshot before publishing it to the live session."""
    snapshot = copy.deepcopy(dict(candidate))
    settings = snapshot.get("set")
    if settings is not None and not isinstance(settings, dict):
        raise ValueError("The settings section must be a JSON object.")
    if isinstance(settings, dict):
        advice = advise_settings(cast(Mapping[str, object], settings))
        if not advice.valid:
            reasons = "; ".join(issue.message for issue in advice.issues)
            raise ValueError(f"The settings dependency advisor blocked this configuration: {reasons}")
    serialized = json.dumps(snapshot, ensure_ascii=False, allow_nan=False)
    with _CONFIG_TRANSACTION_LOCK:
        jsave(CFG, snapshot)
        cfg.clear()
        cfg.update(cast(dict[str, Any], json.loads(serialized)))


def file_digest(path: Union[os.PathLike[str], str]) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""): digest.update(block)
    return digest.hexdigest()

VAULT_EXPORT_SCHEMA = "UNKNWN-VAULT-EXPORT"
VAULT_EXPORT_VERSION = 2


def _vault_export_auth_key(root: bytes | bytearray) -> bytes:
    return hkdf_key(bytes(root), b"unknwn-vault-export")


def _package_checkpoint(
    cancel: Optional[threading.Event],
    pause: Optional[threading.Event],
) -> None:
    if cancel is not None and cancel.is_set():
        raise MoveDataCancelled("The operation was cancelled.")
    while pause is not None and pause.is_set():
        if cancel is not None and cancel.wait(0.1):
            raise MoveDataCancelled("The operation was cancelled.")
        if cancel is None:
            pause.wait(0.1)
    if cancel is not None and cancel.is_set():
        raise MoveDataCancelled("The operation was cancelled.")


def _derive_profile_password(password: object, salt: bytes) -> bytes:
    password_value: object = password
    if not isinstance(password_value, str) or not password_value:
        raise ValueError("A vault password is required.")
    return Scrypt(salt=salt, length=32, n=2 ** 17, r=8, p=1).derive(password_value.encode("utf-8"))


def export_vault_package(
    root: Union[bytes, bytearray, str, None],
    destination: Union[os.PathLike[str], str],
    progress: Optional[Callable[[tuple[str, int, int]], None]] = None,
    cancel: Optional[threading.Event] = None,
    pause: Optional[threading.Event] = None,
    package_password: Optional[str] = None,
) -> dict[str, object]:
    root = root if isinstance(root, (bytes, bytearray)) else b"" if root is None else root.encode("utf-8")
    destination = Path(destination)
    if destination.exists():
        raise FileExistsError("The export destination already exists; choose a new package path.")
    if not HOME.exists():
        raise FileNotFoundError("No active vault data folder is available for export.")
    if not (HOME / "vault").is_dir():
        raise ValueError("The active vault directory is missing or invalid.")
    _package_checkpoint(cancel, pause)
    idx_path = HOME / "index.json"
    cfg_path = HOME / "config.json"
    export_dir = destination.parent
    export_dir.mkdir(parents=True, exist_ok=True)
    manifest_items: list[_VaultExportItem] = []
    files = sorted((HOME / "vault").glob("*.cdr"), key=_path_name_key)
    total_bytes = sum(path.stat().st_size for path in files if path.is_file() and not path.is_symlink())
    if shutil.disk_usage(export_dir).free < total_bytes + (16 << 20):
        raise OSError("There is not enough free space for a verified vault package.")
    completed_bytes = 0
    snapshots: dict[str, tuple[int, int, int, int]] = {}
    for item_path in files:
        if item_path.is_symlink() or not item_path.is_file():
            raise ValueError(f"The vault export contains an unsafe file: {item_path}")
        before = item_path.stat(follow_symlinks=False)
        snapshots[item_path.name] = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        digest = hashlib.sha256()
        with open(item_path, "rb") as stream:
            for block in iter(lambda: stream.read(1 << 20), b""):
                _package_checkpoint(cancel, pause)
                digest.update(block)
                completed_bytes += len(block)
                if progress is not None:
                    progress(("Verifying encrypted vault files", completed_bytes, max(total_bytes, 1)))
        size = item_path.stat().st_size
        after = item_path.stat(follow_symlinks=False)
        if snapshots[item_path.name] != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
            raise ValueError(f"The vault item {item_path.name} changed during export.")
        validate_rid(item_path.stem)
        manifest_items.append({"rid": item_path.stem, "file": item_path.name, "size": size, "sha256": digest.hexdigest()})
    idx_bytes = idx_path.read_bytes() if idx_path.exists() else b""
    cfg_bytes = cfg_path.read_bytes() if cfg_path.exists() else b""
    if package_password is not None:
        package_config: object = json.loads(cfg_bytes.decode("utf-8"))
        if not isinstance(package_config, dict):
            raise ValueError("The vault configuration is malformed and cannot be exported.")
        package_cfg = cast(dict[str, object], package_config)
        salt = os.urandom(16)
        package_cfg["s1"] = b64e(salt)
        package_cfg["wp"] = b64e(seal(_derive_profile_password(package_password, salt), bytes(root)))
        cfg_bytes = canonical_json(package_cfg)
    manifest: dict[str, object] = {
        "schema": VAULT_EXPORT_SCHEMA,
        "version": VAULT_EXPORT_VERSION,
        "created_at": time.time(),
        "password_mode": "new-master" if package_password is not None else "existing-master",
        "items_count": len(manifest_items),
        "vault_bytes": total_bytes,
        "index_sha256": hashlib.sha256(idx_bytes).hexdigest(),
        "config_sha256": hashlib.sha256(cfg_bytes).hexdigest(),
        "items": manifest_items,
    }
    signed = signed_payload(manifest, _vault_export_auth_key(root))
    temp_path = destination.with_name(f".{destination.name}.{uuid.uuid4().hex}.tmp")
    try:
        with open(temp_path, "xb") as package_stream:
            with zipfile.ZipFile(package_stream, "w", compression=zipfile.ZIP_STORED, allowZip64=True) as archive:
                archive.writestr("manifest.json", json.dumps(signed, separators=(",", ":"), ensure_ascii=False))
                archive.writestr("state/index.json", idx_bytes)
                archive.writestr("state/config.json", cfg_bytes)
                for item in manifest_items:
                    _package_checkpoint(cancel, pause)
                    source = HOME / "vault" / item["file"]
                    before = source.stat(follow_symlinks=False)
                    with open(source, "rb") as input_stream, archive.open(f"vault/{item['file']}", "w") as output_stream:
                        copied = 0
                        copy_digest = hashlib.sha256()
                        while True:
                            block = input_stream.read(1 << 20)
                            if not block:
                                break
                            _package_checkpoint(cancel, pause)
                            output_stream.write(block)
                            copy_digest.update(block)
                            copied += len(block)
                            if progress is not None:
                                progress(("Packaging encrypted vault files", min(total_bytes * 2, total_bytes + copied),
                                          max(total_bytes * 2, 1)))
                    after = source.stat(follow_symlinks=False)
                    snapshot = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
                    if snapshots[source.name] != snapshot or copied != item["size"] or copy_digest.hexdigest() != item["sha256"]:
                        raise ValueError(f"The vault item {item['file']} changed during export.")
            package_stream.flush()
            os.fsync(package_stream.fileno())
        _package_checkpoint(cancel, pause)
        os.replace(temp_path, destination)
        fsync_directory(destination.parent)
        return {"status": "completed", "path": str(destination), "items": len(manifest_items)}
    finally:
        try:
            temp_path.unlink(missing_ok=True)
        except OSError:
            pass


def import_vault_package(
    package_password: str,
    package_path: Union[os.PathLike[str], str],
    destination: Union[os.PathLike[str], str],
    progress: Optional[Callable[[tuple[str, int, int]], None]] = None,
    cancel: Optional[threading.Event] = None,
    pause: Optional[threading.Event] = None,
    profile_name: Optional[str] = None,
    profile_id: Optional[str] = None,
    resume: bool = False,
) -> dict[str, object]:
    source = Path(package_path)
    try:
        source_info = source.lstat()
    except FileNotFoundError:
        raise FileNotFoundError("The vault package does not exist.")
    if (stat.S_ISLNK(source_info.st_mode)
            or getattr(source_info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
            or not stat.S_ISREG(source_info.st_mode)):
        raise ValueError("The selected package is not a safe regular file.")
    target_root = Path(destination)
    managed_root = _managed_profiles_root()
    if target_root.absolute().parent != managed_root or not re.fullmatch(r"[0-9a-f]{32}", target_root.name):
        raise ValueError("Imported vaults must be created in the managed profile folder.")
    profile_id = target_root.name if profile_id is None else profile_id
    if profile_id != target_root.name or not isinstance(profile_name, str) or not profile_name.strip() \
            or len(profile_name.strip()) > 64 or any(ord(char) < 32 for char in profile_name):
        raise ValueError("The imported profile identity or name is invalid.")
    staged_root = managed_root / f".import-{target_root.name}.stage"
    if target_root.exists():
        if not resume:
            raise FileExistsError("The selected profile destination already exists.")
        _validate_import_stage(target_root, target_root.name)
        shutil.rmtree(target_root)
    if staged_root.exists():
        if not resume:
            raise FileExistsError("An interrupted import stage already exists; resume or cancel it first.")
        _validate_import_stage(staged_root, target_root.name)
        shutil.rmtree(staged_root)
    with zipfile.ZipFile(source, "r") as archive:
        infos = archive.infolist()
        names = [info.filename for info in infos]
        if len(names) != len(set(names)):
            raise ValueError("The package contains duplicate paths.")
        required = {"manifest.json", "state/index.json", "state/config.json"}
        missing = required - set(names)
        if missing:
            raise ValueError(f"The package is missing required members: {', '.join(sorted(missing))}")
        info_by_name = {info.filename: info for info in infos}
        for name, info in info_by_name.items():
            mode = (info.external_attr >> 16) & 0xFFFF
            file_type = stat.S_IFMT(mode)
            if stat.S_ISLNK(mode) or (file_type and file_type not in (stat.S_IFREG, stat.S_IFDIR)):
                raise ValueError("The package contains a link or unsupported filesystem entry.")
            if name.startswith("/") or "\\" in name or any(part in ("", ".", "..") for part in name.split("/")):
                raise ValueError("The package contains an unsafe path.")
        if info_by_name["manifest.json"].file_size > 8 * 1024 * 1024:
            raise ValueError("The package manifest is too large.")
        try:
            manifest_value: object = json.loads(archive.read("manifest.json"))
        except (json.JSONDecodeError, TypeError, ValueError) as exc:
            raise ValueError("The package manifest is invalid.") from exc
        if not isinstance(manifest_value, dict):
            raise ValueError("The package manifest is invalid.")
        manifest_raw = cast(dict[str, object], manifest_value)
        payload_value = manifest_raw.get("payload")
        if not isinstance(payload_value, dict):
            raise ValueError("The package manifest is invalid.")
        manifest_body = cast(dict[str, object], payload_value)
        if (manifest_body.get("schema") != VAULT_EXPORT_SCHEMA
                or type(manifest_body.get("version")) is not int
                or manifest_body.get("version") != VAULT_EXPORT_VERSION):
            raise ValueError("Unsupported vault package version.")
        if manifest_body.get("password_mode") not in {"existing-master", "new-master"}:
            raise ValueError("The package password mode is unsupported.")
        raw_items = manifest_body.get("items")
        if not isinstance(raw_items, list):
            raise ValueError("The package contains an invalid item inventory.")
        item_values = cast(list[object], raw_items)
        if (len(item_values) > 100000
                or type(manifest_body.get("items_count")) is not int
                or manifest_body.get("items_count") != len(item_values)):
            raise ValueError("The package contains an invalid item inventory.")
        items: list[_VaultExportItem] = []
        for raw_item in item_values:
            if not isinstance(raw_item, dict):
                raise ValueError("The package contains an invalid item entry.")
            item = cast(dict[str, object], raw_item)
            rid_value, file_value = item.get("rid"), item.get("file")
            size_value, digest_value = item.get("size"), item.get("sha256")
            if (not isinstance(rid_value, str) or not isinstance(file_value, str)
                    or type(size_value) is not int or size_value < 0
                    or not isinstance(digest_value, str)
                    or not re.fullmatch(r"[0-9a-f]{64}", digest_value)):
                raise ValueError("The package contains an invalid item entry.")
            items.append({"rid": validate_rid(rid_value), "file": file_value,
                          "size": size_value, "sha256": digest_value})
        expected_names = required | {f"vault/{item['file']}" for item in items}
        if set(names) != expected_names:
            raise ValueError("The package contains missing or unexpected entries.")
        staged_bytes = sum(info_by_name[name].file_size for name in expected_names if name.startswith("vault/"))
        if shutil.disk_usage(managed_root).free < staged_bytes + (16 << 20):
            raise OSError("There is not enough free space for an imported vault profile.")
        staged_root.mkdir(parents=True, exist_ok=False)
        try:
            with open(staged_root / ".import-owned.json", "xb") as marker:
                marker.write(canonical_json({"profile_id": target_root.name, "name": profile_name}))
                marker.flush(); os.fsync(marker.fileno())
            (staged_root / "vault").mkdir()
            total = sum(info_by_name[name].file_size for name in expected_names if name.startswith("vault/"))
            completed = 0
            for static_name, target in (
                ("state/index.json", staged_root / "index.json"),
                ("state/config.json", staged_root / "config.json"),
            ):
                target_size = info_by_name[static_name].file_size
                if target_size > (64 << 20):
                    raise ValueError("The package state file exceeds the safe size limit.")
                with archive.open(static_name) as input_stream, open(target, "xb") as output_stream:
                    while True:
                        _package_checkpoint(cancel, pause)
                        block = input_stream.read(1 << 20)
                        if not block: break
                        output_stream.write(block)
                    output_stream.flush(); os.fsync(output_stream.fileno())
            for member in items:
                _package_checkpoint(cancel, pause)
                name = member["file"]
                rid = member["rid"]
                if name != f"{rid}.cdr":
                    raise ValueError("The package manifest contains an invalid item entry.")
                info = info_by_name[f"vault/{name}"]
                if type(member.get("size")) is not int or member["size"] != info.file_size:
                    raise ValueError(f"The imported item {name} has an unexpected size.")
                path = staged_root / "vault" / name
                digest = hashlib.sha256()
                with archive.open(info) as input_stream, open(path, "xb") as output_stream:
                    while True:
                        block = input_stream.read(1 << 20)
                        if not block: break
                        _package_checkpoint(cancel, pause)
                        output_stream.write(block); digest.update(block); completed += len(block)
                        if progress is not None:
                            progress(("Verifying imported encrypted files", completed, max(total, 1)))
                    output_stream.flush(); os.fsync(output_stream.fileno())
                if not hmac.compare_digest(member["sha256"], digest.hexdigest()):
                    raise ValueError(f"The imported item {name} failed its checksum.")
            idx_bytes = (staged_root / "index.json").read_bytes()
            cfg_bytes = (staged_root / "config.json").read_bytes()
            if hashlib.sha256(idx_bytes).hexdigest() != manifest_body.get("index_sha256"):
                raise ValueError("The package index failed authentication.")
            if hashlib.sha256(cfg_bytes).hexdigest() != manifest_body.get("config_sha256"):
                raise ValueError("The package configuration failed authentication.")
            package_cfg_value: object = json.loads(cfg_bytes.decode("utf-8"))
            if not isinstance(package_cfg_value, dict):
                raise ValueError("The package vault configuration is incomplete.")
            package_cfg = cast(dict[str, object], package_cfg_value)
            salt_value = package_cfg.get("s1")
            wrapped_key_value = package_cfg.get("wp")
            if (not REQUIRED_CFG_KEYS <= package_cfg.keys()
                    or not isinstance(salt_value, str)
                    or not isinstance(wrapped_key_value, str)):
                raise ValueError("The package vault configuration is incomplete.")
            root = unseal(_derive_profile_password(package_password, b64d(salt_value)),
                          b64d(wrapped_key_value))
            manifest = verify_payload(manifest_raw, _vault_export_auth_key(root))
            if manifest != manifest_body:
                raise InvalidTag("The package manifest authentication failed.")
            index_blob = json.loads(idx_bytes.decode("utf-8"))
            decoded_index = decode_idx_blob(root, index_blob)
            if set(decoded_index) != {item["rid"] for item in items}:
                raise InvalidTag("The package item inventory does not match its authenticated index.")
            for item in items:
                path = staged_root / "vault" / item["file"]
                metadata = decoded_index[item["rid"]]
                key = file_key(root, b64d(metadata["s"]))
                authenticated = False
                plain_size = 0
                for block, _last, _read, _total in iter_dec(path, key):
                    authenticated = True; plain_size += len(block)
                if not authenticated or plain_size != metadata["size"]:
                    raise InvalidTag(f"Imported encrypted item {item['rid']} failed authentication.")
            _package_checkpoint(cancel, pause)
            fsync_directory(staged_root / "vault")
            fsync_directory(staged_root)
            os.replace(staged_root, target_root)
            fsync_directory(target_root.parent)
            return {"status": "completed", "path": str(target_root), "items": len(items),
                    "name": profile_name, "profile_id": profile_id,
                    "password_mode": manifest_body["password_mode"]}
        except Exception:
            if staged_root.exists():
                if (staged_root / ".import-owned.json").exists():
                    _validate_import_stage(staged_root, target_root.name)
                    shutil.rmtree(staged_root)
                elif not any(staged_root.iterdir()):
                    staged_root.rmdir()
            raise
    

def rotate_commit() -> None:
    """Finish (roll forward) an interrupted vault-key rotation, or clean up a failed one. Safe to run at every start.
    The journal (rotate.json) is the commit point: before it exists nothing live has changed; once it exists this always completes."""
    jp = HOME / "rotate.json"; journal_value: object = jload(jp, None) if jp.exists() else None
    if jp.exists():
        if not isinstance(journal_value, dict):
            raise ValueError("The vault-rotation recovery journal is damaged; live data was left untouched")
        journal = cast(dict[str, object], journal_value)
        if not ("idx" in journal or "idx_blob" in journal) or "cfg" not in journal:
            raise ValueError("The vault-rotation recovery journal is damaged; live data was left untouched")
        raw_files = journal.get("files", [])
        if not isinstance(raw_files, list):
            raise ValueError("Invalid vault-rotation file inventory")
        files: list[str] = []
        for rid_value in cast(list[object], raw_files):
            rr = validate_rid(rid_value)
            files.append(rr)
        hashes_value = journal.get("hashes", {})
        if not isinstance(hashes_value, dict): raise ValueError("Invalid vault-rotation file checksums")
        hashes = cast(dict[str, object], hashes_value)
        for hash_value in hashes.values():
            if (not isinstance(hash_value, str)
                    or hash_value and not re.fullmatch(r"[0-9a-f]{64}", hash_value)):
                raise ValueError("Invalid vault-rotation file checksums")
        for rid in files:
            n = vault_file_path(rid, ".cdr.new")
            live = vault_file_path(rid, ".cdr"); expected = hashes.get(rid)
            if n.exists():
                if isinstance(expected, str) and expected and file_digest(n) != expected:
                    raise InvalidTag(f"Staged rotation file {rid} failed its checksum")
                durable_replace(n, live)
            elif isinstance(expected, str) and expected and (not live.exists() or file_digest(live) != expected):
                raise InvalidTag(f"Neither staged nor live rotation file {rid} matches its committed checksum")
        ln = HOME / "log.bin.new"
        log_hash = hashes.get("log.bin")
        if ln.exists():
            if isinstance(log_hash, str) and log_hash and file_digest(ln) != log_hash:
                raise InvalidTag("Staged activity log failed its checksum")
            durable_replace(ln, LOG)
        elif isinstance(log_hash, str) and log_hash and (not LOG.exists() or file_digest(LOG) != log_hash):
            raise InvalidTag("Neither staged nor live activity log matches its committed checksum")
        config_value: object = jload(CFG, {})
        if not isinstance(config_value, dict) or not isinstance(journal["cfg"], dict):
            raise ValueError("The vault-rotation configuration journal is damaged")
        c = cast(dict[str, object], config_value)
        c.update(cast(dict[str, object], journal["cfg"]))
        idx_blob: object = journal.get("idx_blob", journal.get("idx", {}))
        if "idx_blob" in journal:
            if not isinstance(idx_blob, dict):
                raise ValueError("The vault-rotation index journal is damaged")
            IDX.with_name(IDX.name + ".bak").unlink(missing_ok=True)
            write_idx_blob(cast(dict[str, object], idx_blob))
        else:
            if not isinstance(idx_blob, dict):
                raise ValueError("The legacy vault-rotation index journal is damaged")
            legacy = _validated_idx(cast(dict[str, object], idx_blob))
            jsave(IDX, legacy)
        jsave(CFG, c); _durable_unlink(jp)
    else:
        for n in (list(VAULT.glob("*.cdr.new")) if VAULT.is_dir() else []) + [HOME / "log.bin.new", jp]:
            try: n.unlink()
            except OSError: pass
def storage_txn_path() -> Path:
    return HOME / "storage-txn.json"


_STORAGE_TXN_LOCK = threading.RLock()


def _index_blob_digest(blob: object) -> str:
    return hashlib.sha256(canonical_json(blob)).hexdigest()


def _current_index_state(root: bytes) -> tuple[dict[str, _VaultMetadata], str]:
    try:
        info = IDX.lstat()
    except FileNotFoundError:
        return {}, "missing"
    if (stat.S_ISLNK(info.st_mode)
            or getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
            or not stat.S_ISREG(info.st_mode)
            or getattr(info, "st_nlink", 1) != 1):
        raise ValueError("The vault index is not a safe regular file.")
    blob = json.loads(IDX.read_text(encoding="utf-8"))
    decoded = decode_idx_blob(root, blob)
    return decoded, _index_blob_digest(blob)


def _current_index_digest(root: bytes) -> str:
    return _current_index_state(root)[1]


def _read_storage_transaction_record(root: bytes) -> Optional[dict[str, object]]:
    path = storage_txn_path()
    try:
        info = path.lstat()
    except FileNotFoundError:
        return None
    if (stat.S_ISLNK(info.st_mode)
            or getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
            or not stat.S_ISREG(info.st_mode)
            or getattr(info, "st_nlink", 1) != 1):
        raise ValueError("The storage recovery journal is not a safe regular file; vault data was left untouched")
    try:
        record_value: object = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError) as exc:
        raise ValueError("The storage recovery journal is unreadable; vault data was left untouched") from exc
    if not isinstance(record_value, dict):
        raise ValueError("The storage recovery journal is invalid; vault data was left untouched")
    record = cast(dict[str, object], record_value)
    signature = record.get("sig")
    if not isinstance(signature, str):
        raise ValueError("The storage recovery journal is invalid; vault data was left untouched")
    if not hmac.compare_digest(b64d(signature), _storage_txn_signature(record, root)):
        raise InvalidTag("Storage recovery journal authentication failed")
    return record


def storage_recovery_preview(root: bytes) -> _StorageRecoveryPreview:
    with _STORAGE_TXN_LOCK:
        with _MoveDestinationLock(storage_txn_path(), "Vault storage transaction"):
            pending_record = _read_storage_transaction_record(root)
            pending_operation: Optional[str] = None
            if pending_record is not None:
                body = _storage_txn_body(pending_record)
                operation = body.get("operation")
                if (type(body.get("version")) is not int or body.get("version") != 1
                        or operation not in {"seal", "burn", "index"}):
                    raise ValueError("Unsupported storage recovery operation")
                rid = validate_rid(body.get("rid"))
                blob = body.get("index_blob")
                if not isinstance(blob, dict):
                    raise ValueError("Storage recovery index is malformed")
                typed_blob = cast(dict[str, object], blob)
                pending_index = decode_idx_blob(root, typed_blob)
                next_digest = _index_blob_digest(typed_blob)
                if body.get("next_index") != next_digest:
                    raise InvalidTag("Storage recovery index checksum failed")
                current_digest = _current_index_digest(root)
                if current_digest not in (body.get("base_index"), next_digest):
                    raise InvalidTag(
                        "Vault index changed since the interrupted storage operation; refusing to overwrite it")
                if operation == "seal" and rid not in pending_index:
                    raise ValueError("Sealed-item recovery index is missing its item")
                if operation == "burn" and rid in pending_index:
                    raise ValueError("Burn recovery index still contains the burned item")
                if operation == "index" and rid not in pending_index:
                    raise ValueError("Updated-item recovery index is missing its item")
                pending_operation = cast(str, operation)

            index = load_idx(root)
            indexed_ids = set(index)
            present_ids: set[str] = set()
            orphan_objects = 0
            staged_objects = 0
            unsafe_objects = 0
            try:
                vault_info = VAULT.lstat()
            except FileNotFoundError:
                vault_info = None
            if vault_info is not None:
                if (stat.S_ISLNK(vault_info.st_mode)
                        or getattr(vault_info, "st_file_attributes", 0)
                        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
                        or not stat.S_ISDIR(vault_info.st_mode)):
                    raise ValueError("The vault storage directory is not a safe directory.")
                for entry in VAULT.iterdir():
                    name = entry.name
                    is_ciphertext = name.endswith(".cdr")
                    is_stage = name.endswith(".cdr.txn")
                    if not is_ciphertext and not is_stage:
                        continue
                    try:
                        info = entry.lstat()
                    except FileNotFoundError:
                        continue
                    safe_regular = (
                        not stat.S_ISLNK(info.st_mode)
                        and not (getattr(info, "st_file_attributes", 0)
                                 & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
                        and stat.S_ISREG(info.st_mode)
                        and getattr(info, "st_nlink", 1) == 1
                    )
                    if not safe_regular:
                        unsafe_objects += 1
                    if is_stage:
                        staged_objects += 1
                    else:
                        rid_value = name[:-4]
                        try:
                            rid_value = validate_rid(rid_value)
                        except ValueError:
                            orphan_objects += 1
                        else:
                            if rid_value not in indexed_ids:
                                orphan_objects += 1
                            elif safe_regular:
                                present_ids.add(rid_value)

            seal_stage = _read_seal_stage_journal(root) is not None
            return {
                "indexed_items": len(indexed_ids),
                "missing_objects": len(indexed_ids - present_ids),
                "orphan_objects": orphan_objects,
                "staged_objects": staged_objects,
                "unsafe_objects": unsafe_objects,
                "pending_transaction": pending_operation,
                "pending_seal_stage": seal_stage,
            }


def _storage_txn_body(record: Mapping[str, object]) -> dict[str, object]:
    return {key: value for key, value in record.items() if key != "sig"}
def _storage_txn_signature(record: Mapping[str, object], root: bytes) -> bytes:
    return hmac.new(idx_key(root), canonical_json(_storage_txn_body(record)), hashlib.sha256).digest()
def _storage_file_path(rid: object, suffix: str = ".cdr") -> Path:
    path = vault_file_path(rid, suffix)
    try:
        info = path.lstat()
    except FileNotFoundError:
        info = None
    if (info is not None and (stat.S_ISLNK(info.st_mode)
            or getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))):
        raise ValueError("Refusing a linked storage object")
    if path.parent.resolve() != VAULT.resolve():
        raise ValueError("Refusing a storage transaction outside the vault directory")
    return path


def _storage_object_digest(path: Path) -> str:
    info = path.lstat()
    if (stat.S_ISLNK(info.st_mode)
            or getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
            or not stat.S_ISREG(info.st_mode)
            or getattr(info, "st_nlink", 1) != 1):
        raise ValueError("A storage transaction object is not a safe regular file")
    return file_digest(path)


def _validate_storage_candidate(
    current: Mapping[str, _VaultMetadata],
    operation: str,
    rid: str,
    candidate: Mapping[str, _VaultMetadata],
) -> None:
    expected = dict(current)
    if operation == "seal":
        if rid in expected:
            raise FileExistsError("A vault item already exists with this identifier")
        if rid not in candidate:
            raise ValueError("Sealed-item index is missing the new item")
        expected[rid] = candidate[rid]
    elif operation == "burn":
        if rid not in expected:
            raise FileNotFoundError("The selected vault item is no longer in the index")
        if rid in candidate:
            raise ValueError("Burn index still contains the selected item")
        del expected[rid]
    elif operation == "index":
        if rid not in expected or rid not in candidate:
            raise ValueError("Updated vault item is no longer in the index")
        expected[rid] = candidate[rid]
    else:
        raise ValueError("Unsupported storage transaction")
    if expected != dict(candidate):
        raise InvalidTag("Vault metadata changed since this operation was prepared; refresh and review it.")


def _verify_sealed_object(root: bytes, path: Path, metadata: _VaultMetadata) -> None:
    key = file_key(root, b64d(metadata["s"]))
    plaintext_size = 0
    for chunk in iter_dec(path, key):
        plaintext_size += len(chunk[0])
    if plaintext_size != metadata["size"]:
        raise InvalidTag("Authenticated encrypted object has an unexpected plaintext size")


def _durable_unlink(path: Union[os.PathLike[str], str]) -> None:
    try: Path(path).unlink()
    except FileNotFoundError: return
    fsync_directory(Path(path).parent)
def _apply_storage_transaction(
    root: bytes,
    record: Mapping[str, object],
    cb: Optional[Callable[[int, int], None]] = None,
) -> dict[str, object]:
    path = storage_txn_path()
    signature = record.get("sig")
    if not isinstance(signature, str) or not hmac.compare_digest(b64d(signature), _storage_txn_signature(record, root)):
        raise InvalidTag("Storage recovery journal authentication failed")
    body = _storage_txn_body(record)
    if (type(body.get("version")) is not int or body.get("version") != 1
            or body.get("operation") not in {"seal", "burn", "index"}):
        raise ValueError("Unsupported storage recovery operation")
    rid = validate_rid(body.get("rid"))
    blob = body.get("index_blob")
    if not isinstance(blob, dict):
        raise ValueError("Storage recovery index is malformed")
    typed_blob = cast(dict[str, object], blob)
    next_index = decode_idx_blob(root, typed_blob)
    next_digest = _index_blob_digest(typed_blob)
    if body.get("next_index") != next_digest:
        raise InvalidTag("Storage recovery index checksum failed")
    current_digest = _current_index_digest(root)
    if current_digest not in (body.get("base_index"), next_digest):
        raise InvalidTag("Vault index changed since the interrupted storage operation; refusing to overwrite it")
    if body["operation"] == "seal":
        if rid not in next_index: raise ValueError("Sealed-item recovery index is missing its item")
        expected = body.get("ciphertext")
        if not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{64}", expected):
            raise ValueError("Invalid sealed-item recovery checksum")
        staged = _storage_file_path(rid, ".cdr.txn")
        final = _storage_file_path(rid)
        if final.exists():
            if _storage_object_digest(final) != expected: raise InvalidTag("Committed sealed item does not match its recovery checksum")
            if staged.exists(): _durable_unlink(staged)
        elif staged.exists() and _storage_object_digest(staged) == expected:
            durable_replace(staged, final)
        else:
            raise InvalidTag("The complete encrypted item is unavailable; the vault index was not changed")
        if _storage_object_digest(final) != expected:
            raise InvalidTag("Promoted sealed item does not match its recovery checksum")
        _verify_sealed_object(root, final, next_index[rid])
    elif body["operation"] == "burn":
        if rid in next_index: raise ValueError("Burn recovery index still contains the burned item")
        passes = body.get("passes")
        if type(passes) is not int or not 1 <= passes <= 7: raise ValueError("Invalid burn recovery pass count")
        target = _storage_file_path(rid)
        expected = body.get("ciphertext")
        if not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{64}", expected):
            raise ValueError("Invalid removal recovery checksum")
        if target.exists() and _storage_object_digest(target) != expected:
            raise InvalidTag("The selected object changed during removal recovery; it was left untouched")
        if target.exists():
            shred(target, passes, cb)
        if target.exists(): raise OSError("Could not complete the interrupted vault-item removal")
    else:
        if rid not in next_index: raise ValueError("Updated-item recovery index is missing its item")
        target = _storage_file_path(rid)
        expected = body.get("ciphertext")
        if not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{64}", expected):
            raise ValueError("Invalid updated-item recovery checksum")
        if _storage_object_digest(target) != expected:
            raise InvalidTag("Updated vault item changed during configuration recovery")
    if current_digest != next_digest:
        write_idx_blob(cast(dict[str, object], blob))
    committed_index, committed_digest = _current_index_state(root)
    if committed_digest != next_digest or committed_index != next_index:
        raise InvalidTag("Storage transaction post-commit verification failed; recovery journal was retained")
    if body["operation"] == "seal":
        sealed_path = _storage_file_path(rid)
        if _storage_object_digest(sealed_path) != body["ciphertext"]:
            raise InvalidTag("Sealed object verification failed; recovery journal was retained")
    elif body["operation"] == "burn":
        if _storage_file_path(rid).exists() or rid in committed_index:
            raise InvalidTag("Removal postcondition failed; recovery journal was retained")
    elif _storage_object_digest(_storage_file_path(rid)) != body["ciphertext"]:
        raise InvalidTag("Updated object verification failed; recovery journal was retained")
    _durable_unlink(path)
    return {"operation": body["operation"], "rid": rid}
def recover_storage_transaction(root: bytes) -> Optional[dict[str, object]]:
    with _STORAGE_TXN_LOCK:
        with _MoveDestinationLock(storage_txn_path(), "Vault storage transaction"):
            return _recover_storage_transaction_locked(root)


def _recover_storage_transaction_locked(root: bytes) -> Optional[dict[str, object]]:
    record = _read_storage_transaction_record(root)
    if record is None:
        return None
    return _apply_storage_transaction(root, record)
def commit_storage_transaction(
    root: bytes,
    operation: str,
    rid: str,
    next_index: object,
    staged: Optional[Union[os.PathLike[str], str]] = None,
    passes: int = 3,
    cb: Optional[Callable[[int, int], None]] = None,
    expected_index: Optional[Mapping[str, _VaultMetadata]] = None,
) -> dict[str, object]:
    with _STORAGE_TXN_LOCK:
        with _MoveDestinationLock(storage_txn_path(), "Vault storage transaction"):
            return _commit_storage_transaction_locked(
                root, operation, rid, next_index, staged, passes, cb, expected_index)


def _commit_storage_transaction_locked(
    root: bytes,
    operation: str,
    rid: str,
    next_index: object,
    staged: Optional[Union[os.PathLike[str], str]],
    passes: int,
    cb: Optional[Callable[[int, int], None]],
    expected_index: Optional[Mapping[str, _VaultMetadata]],
) -> dict[str, object]:
    journal_path = storage_txn_path()
    try:
        journal_info = journal_path.lstat()
    except FileNotFoundError:
        journal_info = None
    if journal_info is not None:
        if (stat.S_ISLNK(journal_info.st_mode)
                or getattr(journal_info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
                or not stat.S_ISREG(journal_info.st_mode)
                or getattr(journal_info, "st_nlink", 1) != 1):
            raise ValueError("The storage recovery journal path is unsafe; no changes were made")
        raise OSError("A previous storage operation must be recovered before starting another")
    rid = validate_rid(rid)
    candidate = _validated_idx(next_index)
    current_index, base_digest = _current_index_state(root)
    if expected_index is not None and current_index != _validated_idx(expected_index):
        raise InvalidTag("Vault state changed since this operation was prepared; refresh and review it.")
    _validate_storage_candidate(current_index, operation, rid, candidate)
    next_index = candidate
    blob = encode_idx(root, next_index)
    body: dict[str, object] = {"version": 1, "operation": operation, "rid": rid, "index_blob": blob,
            "base_index": base_digest, "next_index": _index_blob_digest(blob)}
    if operation == "seal":
        staged = _storage_file_path(rid, ".cdr.txn") if staged is None else Path(staged)
        if staged != _storage_file_path(rid, ".cdr.txn") or not staged.is_file():
            raise ValueError("Sealed-item staging file is missing or outside the vault directory")
        _validate_storage_candidate(current_index, operation, rid, candidate)
        final = _storage_file_path(rid)
        if final.exists(): raise FileExistsError("A vault item already exists with this identifier")
        body["ciphertext"] = _storage_object_digest(staged)
    elif operation == "burn":
        if type(passes) is not int or not 1 <= passes <= 7: raise ValueError("Invalid burn pass count")
        body["passes"] = passes
        body["ciphertext"] = _storage_object_digest(_storage_file_path(rid))
    elif operation == "index":
        body["ciphertext"] = _storage_object_digest(_storage_file_path(rid))
    else:
        raise ValueError("Unsupported storage transaction")
    record: dict[str, object] = dict(body, sig=b64e(_storage_txn_signature(body, root)))
    journal_bytes = json.dumps(record, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    index_bytes = canonical_json(blob)
    forecast = storage_preflight(HOME, len(journal_bytes) + (2 * len(index_bytes)) + (64 << 10))
    if forecast["status"] != "pass":
        raise OSError(
            f"Storage transaction preflight failed ({forecast['status']}); no persistent change was started.")
    atomic_write_bytes(journal_path, journal_bytes)
    return _apply_storage_transaction(root, record, cb)


def _seal_stage_journal_path() -> Path:
    return HOME / "seal-stage.json"


def _seal_stage_signature(root: bytes, body: object) -> bytes:
    return hmac.new(idx_key(root), b"UNKNWN-SEAL-STAGE\0" + canonical_json(body), hashlib.sha256).digest()


def _read_seal_stage_journal(root: bytes) -> Optional[_SealStageJournal]:
    path = _seal_stage_journal_path()
    try:
        info = path.lstat()
    except FileNotFoundError:
        return None
    if (stat.S_ISLNK(info.st_mode)
            or getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
            or not stat.S_ISREG(info.st_mode)
            or info.st_size > 4096):
        raise ValueError("The interrupted seal journal is not a safe regular file.")
    try:
        record_value: object = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(record_value, dict):
            raise ValueError("The interrupted seal journal is malformed.")
        record = cast(dict[str, object], record_value)
        body_value = record["body"]
        signature_value = record["sig"]
        if not isinstance(signature_value, str):
            raise ValueError("The interrupted seal journal signature is malformed.")
        if not isinstance(body_value, dict):
            raise ValueError("The interrupted seal journal body is malformed.")
        body = cast(dict[str, object], body_value)
        signature = b64d(signature_value)
    except (OSError, ValueError, TypeError, KeyError) as exc:
        raise ValueError("The interrupted seal journal is unreadable.") from exc
    if (set(body) != {"version", "rid", "operation_id", "stage_identity"}
            or type(body.get("version")) is not int
            or body.get("version") != 1):
        raise ValueError("The interrupted seal journal has an unsupported format.")
    validate_rid(body.get("rid"))
    operation_id = body.get("operation_id")
    if not isinstance(operation_id, str) or not re.fullmatch(r"[0-9a-f]{32}", operation_id):
        raise ValueError("The interrupted seal journal has an invalid operation identifier.")
    identity = body.get("stage_identity")
    if identity is not None:
        if not isinstance(identity, list):
            raise ValueError("The interrupted seal journal has an invalid stage identity.")
        identity_values = cast(list[object], identity)
        if len(identity_values) != 2 or any(type(value) is not int or value < 0 for value in identity_values):
            raise ValueError("The interrupted seal journal has an invalid stage identity.")
    if not hmac.compare_digest(signature, _seal_stage_signature(root, body)):
        raise InvalidTag("The interrupted seal journal failed authentication.")
    return cast(_SealStageJournal, body)


def _create_seal_stage_journal(root: bytes, rid: str, operation_id: object) -> None:
    path = _seal_stage_journal_path()
    if path.exists() or path.is_symlink():
        raise FileExistsError("An earlier encrypted-file stage must be recovered first.")
    if not isinstance(operation_id, str) or not re.fullmatch(r"[0-9a-f]{32}", operation_id):
        raise ValueError("The seal operation identifier is invalid.")
    body: dict[str, object] = {"version": 1, "rid": validate_rid(rid), "operation_id": operation_id, "stage_identity": None}
    record: dict[str, object] = {"body": body, "sig": b64e(_seal_stage_signature(root, body))}
    created_identity = None
    try:
        with open(path, "xb") as stream:
            info = os.fstat(stream.fileno())
            created_identity = (info.st_dev, info.st_ino)
            stream.write(canonical_json(record))
            stream.flush()
            os.fsync(stream.fileno())
        fsync_directory(path.parent)
    except Exception:
        if created_identity is not None:
            try:
                info = path.lstat()
                if (stat.S_ISREG(info.st_mode)
                        and (info.st_dev, info.st_ino) == created_identity):
                    path.unlink()
                    fsync_directory(path.parent)
            except FileNotFoundError:
                pass
        raise


def _write_seal_stage_identity(
    root: bytes,
    rid: str,
    operation_id: str,
    identity: tuple[int, int],
) -> None:
    body = _read_seal_stage_journal(root)
    if body is None or body["rid"] != rid or body["operation_id"] != operation_id:
        raise ValueError("The seal stage journal does not match the active operation.")
    if (len(identity) != 2 or any(type(value) is not int or value < 0 for value in identity)):
        raise ValueError("The seal staging identity is invalid.")
    body["stage_identity"] = list(identity)
    record: dict[str, object] = {"body": body, "sig": b64e(_seal_stage_signature(root, body))}
    atomic_write_bytes(_seal_stage_journal_path(), canonical_json(record))


def _clear_seal_stage_journal(root: bytes, operation_id: str) -> None:
    body = _read_seal_stage_journal(root)
    if body is None:
        return
    if body["operation_id"] != operation_id:
        raise ValueError("The interrupted seal journal belongs to a different operation.")
    _durable_unlink(_seal_stage_journal_path())


def recover_orphan_seal_stage(root: bytes) -> Optional[dict[str, Union[str, bool]]]:
    if storage_txn_path().exists():
        raise ValueError("Recover the pending storage transaction before cleaning a staged seal.")
    body = _read_seal_stage_journal(root)
    if body is None:
        return None
    stage = VAULT / f"{body['rid']}.cdr.txn"
    if stage.parent.resolve(strict=True) != VAULT.resolve(strict=True):
        raise ValueError("The interrupted seal stage is outside the active vault.")
    removed = False
    try:
        info = stage.lstat()
    except FileNotFoundError:
        info = None
    if info is not None:
        if (stat.S_ISLNK(info.st_mode)
                or getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
                or not stat.S_ISREG(info.st_mode)
                or body["stage_identity"] is None
                or (info.st_dev, info.st_ino) != tuple(body["stage_identity"])):
            raise ValueError("The interrupted seal stage is not a safe regular file.")
        _durable_unlink(stage)
        removed = True
    _clear_seal_stage_journal(root, body["operation_id"])
    return {"rid": body["rid"], "removed": removed}


def burn_exhausted_view_items(root: bytes) -> list[str]:
    exhausted = [rid for rid, metadata in idx.items() if metadata.get("views") == 0]
    burned: list[str] = []
    for rid in exhausted:
        if rid not in idx:
            continue
        candidate = dict(idx)
        candidate.pop(rid)
        commit_storage_transaction(
            root, "burn", rid, candidate, passes=S("shred"), expected_index=idx)
        idx.clear()
        idx.update(candidate)
        burned.append(rid)
    return burned

STARTUP_RECOVERY_ERROR = None
REQUIRED_CFG_KEYS = frozenset({"s1", "s2", "wp", "wr", "f", "lock", "last"})
# Do not inspect vault configuration until the startup gate and location
# metadata have been validated.
if INTEG[0] == "fail":
    startup_config_state = "not_run"
    cfg: dict[str, Any] = {}
else:
    loaded_cfg, config_source = load_config_snapshot(CFG, REQUIRED_CFG_KEYS)
    startup_config_state = {
        "primary": "loaded",
        "backup": "recovered_backup",
        "empty": "empty",
        "damaged": "damaged",
        "unavailable": "unavailable",
    }[config_source]
    # Persisted settings intentionally allow forward-compatible keys and heterogeneous JSON values.
    cfg = loaded_cfg
if not _config_matches_startup_schema(cfg, REQUIRED_CFG_KEYS): cfg = {}
cfg.update(f=0, tf=0, lock=0, fails=[])
cfg.pop("sd", None)
idx: dict[str, _VaultMetadata] = {}
def has_vault_config() -> bool: return REQUIRED_CFG_KEYS <= cfg.keys()

DEF = dict(lv=0, dead=0, idle=0, blur=False, clip=True, shred=3, mask=False, export=True, log=True, ro_always=False,
           hk="Ctrl+Shift+Tab", hk_act="lock", hk_glob=False, hk_notice=True, nocap=False, intro=3, th="matrix", tbg="#000000", tfg="#f2f2f2", tac="#ffffff",
           minlock=False, vclose=0, nocopy=False, title="UNKNWN", logwipe=False, hidecnt=False, hideuser=False,
           reauth=False, boss=False, sess=0, remote=False, dbg=False, hidename=False, bg="termlog", perf="auto",
           ghost=False, keypad=False, cliptime=0, dimidle=False, winop=100, maxtf=0, bind=False, exitclean=False, wipefx="full", vmode="file", bgspd=100, bgden=100, tstyle=True, crt=True,
           reduce_motion=False, bgfocus=True, clock24=True,
           dash_session=True, dash_look=True, dash_privacy=True,
           lbg="", lfg="", lac="", avatar_crop="center")
LOCK_ICON = "\U0001F512"
FIRE_ICON = "\U0001F525"
RETIRED_BGS = frozenset({"nightglass", "map", "rooftop", "alley", "archive", "blueprint",
                         "harmonics", "cipher", "horizon", "echo", "constellation",
                         "sweep", "pulse"})
def S(k: str) -> Any: return cfg.get("set", {}).get(k, DEF[k])
def normalize_look_settings() -> None:
    settings_value: object = cfg.get("set")
    if not isinstance(settings_value, dict): return
    settings = cast(dict[str, object], settings_value)
    changed = False
    if settings.get("bg") in ("fire", "embers") or settings.get("bg") in RETIRED_BGS:
        settings["bg"] = "termlog"; changed = True
    for key in ("spark", "trail", "csparks", "btnfx"):
        if key in settings: settings.pop(key); changed = True
    if changed: jsave(CFG, cfg)
# Settings password: chosen by the user, never in the code. Stored as a salted scrypt hash, and sealed to the vault key so editing it by hand is detected.
def slk_hash(pw: str, salt: bytes) -> bytes: return hashlib.scrypt(pw.encode(), salt=salt, n=2 ** 15, r=8, p=1, dklen=32, maxmem=64 * 1024 * 1024)
def lock_on() -> bool: return bool(cfg.get("slk") or cfg.get("slc"))   # a lock record without its hash = tampered: stay locked
def lock_ok(pw: str) -> bool:
    try: return hmac.compare_digest(slk_hash(pw, b64d(cfg["slk"]["s"])), b64d(cfg["slk"]["h"]))
    except Exception: return False
def lock_bound(dek: bytes) -> bool:
    try: return unseal(dek, b64d(cfg["slc"])) == b"slk:" + b64d(cfg["slk"]["h"])
    except Exception: return False
def _legacy_fp() -> str:
    return hashlib.sha256((platform.node() + str(uuid.getnode())).encode()).hexdigest()


def fp() -> str:
    """Return a stable per-Windows-installation binding, falling back for older platforms."""
    try:
        import winreg

        access = winreg.KEY_READ | getattr(winreg, "KEY_WOW64_64KEY", 0)
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Cryptography",
            0,
            access,
        ) as key:
            machine_guid, value_type = winreg.QueryValueEx(key, "MachineGuid")
        if value_type == winreg.REG_SZ and isinstance(machine_guid, str):
            normalized_guid = uuid.UUID(machine_guid.strip()).hex
            return hashlib.sha256(
                ("windows-machine-guid:" + normalized_guid).encode("ascii")
            ).hexdigest()
    except (ImportError, OSError, AttributeError, TypeError, ValueError):
        pass
    return _legacy_fp()


def _device_binding_matches(stored_fingerprint: object) -> bool:
    if (not isinstance(stored_fingerprint, str)
            or not re.fullmatch(r"[0-9a-f]{64}", stored_fingerprint)):
        return False
    current = fp()
    if hmac.compare_digest(stored_fingerprint, current):
        return True
    return hmac.compare_digest(stored_fingerprint, _legacy_fp())


PROTSEC = {"Security & self-destruct", "Panic key", "Shortcut manager"}
PROTKEYS = {"lv", "dead", "idle", "shred", "blur", "ro_always", "hk", "hk_act", "hk_glob", "hk_notice", "reauth", "boss", "sess", "remote", "dbg", "maxtf", "bind"}
SECKEYS = PROTKEYS | {"nocap", "export", "clip", "log", "minlock", "ghost", "nocopy", "logwipe", "vmode"}   # settings that protect you: sealed and restored if edited by hand
VaultCapability = Literal["sensitive_action", "vault_read", "vault_write", "destructive"]


def capability_block_reason(
    capability: VaultCapability,
    *,
    authenticated: bool,
    read_only: bool,
    recovery_pending: bool,
) -> Optional[str]:
    if capability == "sensitive_action":
        return None
    if not authenticated:
        return "Authenticate to the vault before using this capability."
    if recovery_pending:
        return "Resolve the pending vault recovery before starting another operation."
    if capability in ("vault_write", "destructive") and read_only:
        return "This is a read-only session; vault changes are disabled."
    return None


UNDOABLE_SETTINGS = frozenset(DEF) - SECKEYS
SETTINGS_HISTORY_LIMIT = 50
RESERVED_SHORTCUTS = {
    "Alt+F4", "Alt+Tab", "Ctrl+Alt+Delete", "Ctrl+Shift+Esc", "Meta+L",
    "Ctrl+A", "Ctrl+C", "Ctrl+F", "Ctrl+K", "Ctrl+P", "Ctrl+Q", "Ctrl+S",
    "Ctrl+V", "Ctrl+W", "Ctrl+X", "Ctrl+Y", "Ctrl+Z", "Ctrl+Left", "Ctrl+Right",
}
def secset() -> dict[str, object]: return {k: S(k) for k in sorted(SECKEYS)}
def dbg_now() -> bool:
    """Python tracer/profiler, or (Windows) a local or remote debugger attached."""
    return IG.runtime_trust() == "debugger"
MUT, DIM, ACC = "#8a82a8", "#6b6390", "#b79cff"
# ---------- themes: old violet colors in the code are remapped to the active theme ----------
PRE = {"mono": ("#000000", "#f2f2f2", "#ffffff"), "violet": ("#07050f", "#ece8ff", "#8b5cff"), "matrix": ("#020a04", "#d6ffe0", "#22ff66"),
       "blood": ("#0a0304", "#ffe3e3", "#ff2d4d"), "ice": ("#030a10", "#e6f6ff", "#38c8ff"), "amber": ("#0a0600", "#ffe9c2", "#ffb000"), "cyber": ("#06010f", "#f3e6ff", "#ff2bd6"), "ocean": ("#02080f", "#dff3ff", "#2dd4bf")}
PRE["tired"] = ("#100b0b", "#c9c0ae", "#87424a")
TH: dict[str, str] = {}
LEG = {"#8b5cff": "acc", "#6d3df0": "acc", "#b79cff": "acc", "#22d3ee": "acc2", "#22a6d8": "acc2", "#ece8ff": "fg", "#8a82a8": "mut", "#6b6390": "dim", "#5b5378": "dim",
       "#0b0816": "field", "#07050f": "bg0", "#1c0d3a": "bg1", "#140e24": "panel", "#120c22": "panel", "#241a3f": "line", "#2a2145": "line", "#3a2e66": "line"}
LEGRGB: dict[tuple[int, int, int], str] = {
    (139, 92, 255): "acc",
    (34, 211, 238): "acc2",
    (236, 232, 255): "fg",
    (235, 225, 255): "fg",
}
def th(t: str) -> str:
    def replace_color(match: re.Match[str]) -> str:
        name = LEG.get(match.group(0).lower())
        if name is None:
            return match.group(0)
        return TH.get(name, match.group(0))
    return re.sub(r"#[0-9a-fA-F]{6}", replace_color, t)
def QColor(*a: Any) -> _QC:
    if len(a) == 1 and isinstance(a[0], str): return _QC(th(a[0]))
    if len(a) in (3, 4) and tuple(a[:3]) in LEGRGB:
        c = _QC(TH[LEGRGB[tuple(a[:3])]])
        if len(a) == 4: c.setAlpha(a[3])
        return c
    return _QC(*a)
_ss = QWidget.setStyleSheet
def _themed_set_stylesheet(self: QWidget, styleSheet: Optional[str]) -> None:
    _ss(self, None if styleSheet is None else th(styleSheet))
QWidget.setStyleSheet = _themed_set_stylesheet
def mix(a: str, b: str, t: float) -> str:
    a, b = _QC(a), _QC(b); return _QC(int(a.red() + (b.red() - a.red()) * t), int(a.green() + (b.green() - a.green()) * t), int(a.blue() + (b.blue() - a.blue()) * t)).name()
def _normalize_theme_color(value: object, fallback: str) -> str:
    if isinstance(value, str) and re.fullmatch(r"#[0-9a-fA-F]{3}|#[0-9a-fA-F]{6}", value):
        return value.lower()
    return fallback


def _custom_theme_palette(
    default: Optional[tuple[str, str, str]] = None,
) -> tuple[str, str, str]:
    default = PRE.get("matrix", ("#020a04", "#d6ffe0", "#22ff66")) if default is None else default
    bg, fg, ac = (S("tbg"), S("tfg"), S("tac"))
    return (
        _normalize_theme_color(bg, default[0]),
        _normalize_theme_color(fg, default[1]),
        _normalize_theme_color(ac, default[2]),
    )


def _resolve_theme_palette(
    theme: Optional[str] = None,
) -> tuple[str, str, str]:
    theme = S("th") if theme is None else theme
    if theme in PRE:
        return PRE[theme]
    return _custom_theme_palette()

def set_theme() -> None:
    bg, fg, ac = _resolve_theme_palette()
    TH.update(bg0=bg, bg1=mix(bg, ac, .14), field=mix(bg, fg, .035), panel=mix(bg, fg, .07), line=mix(bg, fg, .2), fg=fg, mut=mix(bg, fg, .6), dim=mix(bg, fg, .42),
              acc=ac, acc2=mix(ac, bg, .5), on="#000000" if _QC(ac).lightness() > 128 else "#ffffff")
set_theme()

# ---------- crypto ----------
WORDS = sorted(set("""amber anchor angel apple arrow atlas autumn bacon badge baker banjo barrel basket beach beacon berry bicycle bishop
blanket blossom bottle bridge bronze bubble bucket butter cabin cactus camel candle canyon carpet castle cattle cedar celery chair cherry
chess chimney circus clover cobra coffee comet copper coral cotton cradle crystal curtain daisy dancer desert diamond dinner dolphin donkey
dragon drum eagle ember engine falcon feather fiddle forest fossil fountain galaxy garden garlic ginger glacier goblet granite grape guitar
hammer harbor hazel helmet heron honey horizon island ivory jacket jaguar jelly jungle kettle kitten ladder lantern lemon lizard lobster
magnet mango maple marble meadow melon mirror monkey mountain muffin needle nickel noodle oasis ocean olive onion orange orchid otter oyster
paddle panda pepper piano pillow pirate planet pocket pumpkin puzzle rabbit radish raven ribbon river rocket saddle salmon sandal shadow
silver spider spoon squirrel summit sunset table tiger timber tomato tunnel turtle umbrella valley velvet violin walnut whale willow window
winter wizard yogurt zebra zipper acorn alpine anvil apron aspen avocado bagel balloon bamboo banner barley beetle biscuit bobcat boulder
bracelet brook buffalo bundle burrow cabbage canoe captain caramel carrot cauldron chapel cheese chestnut cinnamon clock cloud cookie crown
cricket cucumber dagger dahlia dawn dingo doctor dome dune earth echo eclipse elbow elevator emerald fabric farmer fern ferry flame flute
fox frost gadget gazelle gecko giraffe glove goat gopher gravel hamster harp hawk hedge hippo hollow hornet hurdle iceberg igloo iguana
jackal jasmine jester jewel kayak kernel kiwi knight koala lagoon lamp lava lavender lemur lentil lilac llama locket lotus lunar magpie
mammoth marsh mask mitten moose mosaic moth mustard nectar nest nutmeg oak orbit osprey owl paper parrot peach pearl pebble pelican penguin
pigeon pine plum polar pond poppy prairie quartz quill quilt raccoon raft raisin ranch reef rhino ridge robin rose ruby saffron sage sailor
salad scarab scarf sheep shield shrimp siren skate sloth snail sparrow sphinx sponge stork sugar swan sword tablet teapot thistle thunder
tulip tundra turnip vase vessel volcano wagon waffle walrus wasp weasel wheat whistle wolf yacht yarrow zenith""".split()))
NW = 8   # recovery words (about 67 bits)
def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode()


b64d = base64.b64decode
def kdf(pw: str, salt: bytes) -> bytes:
    work_factor = cfg.get("n", 17)
    if type(work_factor) is not int or work_factor != 17:
        raise ValueError("Unsupported password KDF work factor")
    return Scrypt(salt=salt, length=32, n=2 ** work_factor, r=8, p=1).derive(pw.encode())
def file_key(root: bytes, salt: bytes) -> bytes: return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=b"unknwn-file").derive(root)
def seal(k: bytes, data: bytes) -> bytes: iv = os.urandom(12); return iv + AESGCM(k).encrypt(iv, data, None)
def unseal(k: bytes, blob: bytes) -> bytes: return AESGCM(k).decrypt(blob[:12], blob[12:], None)
CH = 1 << 20


def _encryption_checkpoint(
    cancel: Optional[threading.Event],
    resume: Optional[threading.Event],
) -> None:
    if cancel is not None and cancel.is_set():
        raise MoveDataCancelled("Encryption was cancelled at a safe checkpoint.")
    while resume is not None and not resume.wait(0.1):
        if cancel is not None and cancel.is_set():
            raise MoveDataCancelled("Encryption was cancelled while paused.")
    if cancel is not None and cancel.is_set():
        raise MoveDataCancelled("Encryption was cancelled at a safe checkpoint.")


def enc_file(
    src: Path,
    dst: Path,
    k: bytes,
    cb: Optional[Callable[[int, int], None]],
    cancel: Optional[threading.Event] = None,
    on_stage_created: Optional[Callable[[tuple[int, int]], None]] = None,
    resume: Optional[threading.Event] = None,
) -> None:
    """Chunked AES-GCM; chunk index + 'last' flag are authenticated, so reordering/truncation is detected."""
    a = AESGCM(k); n = src.stat().st_size or 1; done = i = 0
    dst = Path(dst)
    created_identity = None
    try:
        _encryption_checkpoint(cancel, resume)
        with open(src, "rb") as f, open(dst, "xb") as o:
            created = os.fstat(o.fileno())
            created_identity = (created.st_dev, created.st_ino)
            if on_stage_created is not None:
                on_stage_created(created_identity)
            while True:
                _encryption_checkpoint(cancel, resume)
                b = f.read(CH); last = len(b) < CH; iv = os.urandom(12)
                c = a.encrypt(iv, b, struct.pack(">QB", i, last)); o.write(struct.pack(">I", len(c) + 12) + iv + c)
                i += 1; done += len(b)
                if cb is not None: cb(done, n)
                _encryption_checkpoint(cancel, resume)
                if last: break
            o.flush(); os.fsync(o.fileno())
    except BaseException:
        if created_identity is not None:
            try:
                current = dst.lstat()
                if (stat.S_ISREG(current.st_mode)
                        and (current.st_dev, current.st_ino) == created_identity):
                    dst.unlink()
                    fsync_directory(dst.parent)
            except FileNotFoundError:
                pass
            except OSError as cleanup_error:
                raise OSError(
                    f"Encryption failed and its incomplete staging file needs cleanup at {dst}."
                ) from cleanup_error
        raise

def estimate_ciphertext_size(plaintext_size: int) -> int:
    if type(plaintext_size) is not int or plaintext_size < 0:
        raise ValueError("Plaintext size must be a non-negative integer")
    chunks = plaintext_size // CH + 1
    return plaintext_size + chunks * 32

def storage_preflight(
    target_dir: Union[os.PathLike[str], str],
    estimated_bytes: int,
) -> dict[str, Union[str, int, None]]:
    if type(estimated_bytes) is not int or estimated_bytes < 0:
        raise ValueError("Estimated storage must be a non-negative integer")
    target = Path(target_dir)
    if target.is_symlink():
        return {"status": "unsafe", "estimated": estimated_bytes, "required": None, "free": None}
    while not target.exists() and target != target.parent:
        target = target.parent
    if target.is_symlink() or not target.is_dir():
        return {"status": "unsafe", "estimated": estimated_bytes, "required": None, "free": None}
    try:
        free_bytes = shutil.disk_usage(target).free
    except OSError:
        return {"status": "unavailable", "estimated": estimated_bytes, "required": None, "free": None}
    margin = max(1 << 20, estimated_bytes // 20)
    required = estimated_bytes + margin
    return {"status": "pass" if free_bytes >= required else "insufficient",
        "estimated": estimated_bytes, "required": required, "free": free_bytes}

def vault_search_text(rid: str, name: str, details: str, masked: bool) -> str:
    return f"{details} {rid[:4]}" if masked else f"{name} {details} {rid[:4]}"

MOVE_JOURNAL = "data-move.json"
MOVE_MAX_ENTRIES = 100_000
MOVE_MAX_JOURNAL_BYTES = 32 << 20
MOVE_REPARSE_ATTRIBUTE = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)

class MoveDataError(Exception): pass
class MoveDataCancelled(MoveDataError): pass

class _MoveDestinationLock:
    def __init__(
        self,
        target: Union[os.PathLike[str], str],
        purpose: str = "data move",
    ) -> None:
        target = Path(target)
        self.target = target
        self.purpose = purpose
        self.path = target.parent / f".{target.name}.move.lock"
        self.fd = None
        self.windows = os.name == "nt"
        self.handle = None
        self.kernel32 = None

    def __enter__(self) -> "_MoveDestinationLock":
        if self.windows:
            identity = os.path.normcase(str(self.target.absolute())).encode("utf-8")
            name = "Global\\UNKNWN-DataMove-" + hashlib.sha256(identity).hexdigest()
            self.kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            self.kernel32.CreateMutexW.argtypes = (ctypes.c_void_p, ctypes.c_bool, ctypes.c_wchar_p)
            self.kernel32.CreateMutexW.restype = ctypes.c_void_p
            self.kernel32.WaitForSingleObject.argtypes = (ctypes.c_void_p, ctypes.c_uint32)
            self.kernel32.WaitForSingleObject.restype = ctypes.c_uint32
            self.kernel32.ReleaseMutex.argtypes = (ctypes.c_void_p,)
            self.kernel32.CloseHandle.argtypes = (ctypes.c_void_p,)
            self.handle = self.kernel32.CreateMutexW(None, False, name)
            if not self.handle:
                raise ctypes.WinError(ctypes.get_last_error())
            state = self.kernel32.WaitForSingleObject(self.handle, 0)
            if state not in (0, 0x80):
                error = ctypes.get_last_error()
                self.kernel32.CloseHandle(self.handle); self.handle = None
                if state == 258:
                    raise MoveDataError(f"Another {self.purpose} is using this destination.")
                raise ctypes.WinError(error)
            return self
        parent = self.path.parent
        if parent.resolve(strict=True) != parent.absolute():
            raise MoveDataError("The destination lock parent resolves through an unexpected path.")
        flags = os.O_RDWR | getattr(os, "O_BINARY", 0)
        try:
            self.fd = os.open(self.path, flags | os.O_CREAT | os.O_EXCL, 0o600)
            created = True
        except FileExistsError:
            created = False
            info = self.path.lstat()
            if _move_is_reparse(info) or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise MoveDataError("The destination lock path is not a safe regular file.")
            self.fd = os.open(self.path, flags | getattr(os, "O_NOFOLLOW", 0))
            opened = os.fstat(self.fd)
            if not _move_same_object(opened, (info.st_dev, info.st_ino)):
                os.close(self.fd); self.fd = None
                raise MoveDataError("The destination lock path changed while it was opened.")
        try:
            if self.windows:
                if created:
                    os.write(self.fd, b"\0")
                    os.fsync(self.fd)
                import msvcrt
                os.lseek(self.fd, 0, os.SEEK_SET)
                msvcrt.locking(self.fd, msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl_api = cast(Any, fcntl)
                fcntl_api.flock(self.fd, fcntl_api.LOCK_EX | fcntl_api.LOCK_NB)
                if created: fsync_directory(self.path.parent)
        except OSError as exc:
            os.close(self.fd); self.fd = None
            raise MoveDataError(f"Another {self.purpose} is using this destination.") from exc
        return self

    def __exit__(self, *_exc: object) -> None:
        if self.handle is not None:
            kernel32 = self.kernel32
            if kernel32 is None:
                raise RuntimeError("The Windows destination lock lost its kernel handle provider.")
            try:
                if not kernel32.ReleaseMutex(self.handle):
                    raise ctypes.WinError(ctypes.get_last_error())
            finally:
                kernel32.CloseHandle(self.handle)
                self.handle = None
            return
        if self.fd is None:
            return
        try:
            if self.windows:
                import msvcrt
                os.lseek(self.fd, 0, os.SEEK_SET)
                msvcrt.locking(self.fd, msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl_api = cast(Any, fcntl)
                fcntl_api.flock(self.fd, fcntl_api.LOCK_UN)
        finally:
            os.close(self.fd)
            self.fd = None

def _move_is_reparse(info: os.stat_result) -> bool:
    return stat.S_ISLNK(info.st_mode) or bool(getattr(info, "st_file_attributes", 0) & MOVE_REPARSE_ATTRIBUTE)

def _move_file_identity(info: os.stat_result) -> tuple[int, int, int, int]:
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)

def _move_same_object(info: os.stat_result, identity: tuple[int, ...]) -> bool:
    return (info.st_dev, info.st_ino) == tuple(identity[:2])

def _validated_move_source_root(root: Union[os.PathLike[str], str]) -> Path:
    root = Path(root)
    try:
        info = root.lstat()
    except OSError as exc:
        raise MoveDataError("The source data folder is unavailable or unsafe.") from exc
    if _move_is_reparse(info) or not stat.S_ISDIR(info.st_mode):
        raise MoveDataError("The source data folder is a reparse point or is not a directory.")
    resolved = root.resolve(strict=True)
    if os.path.normcase(str(root.absolute())) != os.path.normcase(str(resolved)):
        raise MoveDataError("The source data folder resolves through an unexpected path.")
    return resolved

def _move_hash_file(
    path: Union[os.PathLike[str], str],
    expected_identity: Optional[tuple[int, int, int, int]] = None,
    cancel: Optional[threading.Event] = None,
) -> tuple[int, str]:
    path = Path(path)
    info = path.lstat()
    if _move_is_reparse(info) or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise MoveDataError("A source or staged file is not a safe regular file.")
    if expected_identity is not None and _move_file_identity(info) != tuple(expected_identity):
        raise MoveDataError("A source file changed after the move preview.")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    digest = hashlib.sha256()
    size = 0
    try:
        with os.fdopen(descriptor, "rb") as stream:
            opened = os.fstat(stream.fileno())
            if _move_is_reparse(opened) or not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1:
                raise MoveDataError("A file changed to an unsafe filesystem object.")
            if expected_identity is not None and _move_file_identity(opened) != tuple(expected_identity):
                raise MoveDataError("A source file changed while it was being read.")
            while True:
                if cancel is not None and cancel.is_set():
                    raise MoveDataCancelled("The data move was cancelled.")
                block = stream.read(CH)
                if not block: break
                size += len(block); digest.update(block)
            if _move_file_identity(os.fstat(stream.fileno())) != _move_file_identity(opened):
                raise MoveDataError("A file changed while its checksum was being calculated.")
    except Exception:
        try: os.close(descriptor)
        except OSError: pass
        raise
    return size, digest.hexdigest()

def _move_tree_manifest(
    root: Union[os.PathLike[str], str],
    cancel: Optional[threading.Event] = None,
    progress: Optional[Callable[[tuple[str, int, int]], None]] = None,
) -> tuple[Path, list[_MoveEntry], int]:
    resolved_root = _validated_move_source_root(root)
    entries: list[_MoveEntry] = []
    pending = [(resolved_root, "")]
    while pending:
        if cancel is not None and cancel.is_set():
            raise MoveDataCancelled("The data move was cancelled.")
        directory, prefix = pending.pop()
        try:
            children = sorted(os.scandir(directory), key=lambda child: child.name.casefold(), reverse=True)
        except OSError as exc:
            raise MoveDataError("The source folder could not be inspected.") from exc
        for child in children:
            if not prefix and child.name == MOVE_JOURNAL:
                continue
            relative = f"{prefix}/{child.name}" if prefix else child.name
            info = os.stat(child.path, follow_symlinks=False)
            if _move_is_reparse(info):
                raise MoveDataError("The source contains a symbolic link or reparse point; no move was started.")
            entry: _MoveEntry
            if stat.S_ISDIR(info.st_mode):
                entry = {"path": relative, "kind": "dir", "size": 0, "sha256": ""}
                pending.append((Path(child.path), relative))
            elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
                entry = {"path": relative, "kind": "file", "size": info.st_size, "sha256": "",
                         "mtime_ns": info.st_mtime_ns, "dev": info.st_dev, "ino": info.st_ino}
            else:
                raise MoveDataError("The source contains an unsupported filesystem object or hard link.")
            entries.append(entry)
            if len(entries) > MOVE_MAX_ENTRIES:
                raise MoveDataError("The source contains too many entries to move safely.")
    entries.sort(key=lambda item: item["path"].casefold())
    total = sum(entry["size"] for entry in entries if entry["kind"] == "file")
    done = 0
    for entry in entries:
        if entry["kind"] != "file": continue
        identity = (entry["dev"], entry["ino"], entry["size"], entry["mtime_ns"])
        size, digest = _move_hash_file(resolved_root / Path(entry["path"]), identity, cancel)
        if size != entry["size"]:
            raise MoveDataError("A source file changed while the move inventory was built.")
        entry["sha256"] = digest
        done += size
        if progress is not None: progress(("Scanning source", done, total))
    return resolved_root, entries, total

def _validate_move_entries(entries: object) -> list[_MoveEntry]:
    if not isinstance(entries, list) or len(cast(list[object], entries)) > MOVE_MAX_ENTRIES:
        raise ValueError("Invalid data-move manifest entry count.")
    seen: set[str] = set()
    for entry_value in cast(list[object], entries):
        if not isinstance(entry_value, dict):
            raise ValueError("Invalid data-move manifest entry.")
        entry = cast(dict[str, object], entry_value)
        kind = entry.get("kind")
        if not isinstance(kind, str) or kind not in {"file", "dir"}:
            raise ValueError("Invalid data-move manifest entry.")
        relative = entry.get("path")
        if not isinstance(relative, str) or not relative or "\\" in relative or ":" in relative:
            raise ValueError("Unsafe path in data-move manifest.")
        parts = relative.split("/")
        if any(part in ("", ".", "..") for part in parts) or relative == MOVE_JOURNAL:
            raise ValueError("Unsafe path in data-move manifest.")
        folded = relative.casefold()
        if folded in seen: raise ValueError("Duplicate path in data-move manifest.")
        seen.add(folded)
        size = entry.get("size")
        if type(size) is not int or size < 0:
            raise ValueError("Invalid size in data-move manifest.")
        if kind == "file":
            digest = entry.get("sha256")
            if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
                raise ValueError("Invalid file checksum in data-move manifest.")
            for field in ("mtime_ns", "dev", "ino"):
                if type(entry.get(field)) is not int: raise ValueError("Invalid source identity in data-move manifest.")
        elif size != 0 or entry.get("sha256") != "":
            raise ValueError("Invalid directory entry in data-move manifest.")
    return cast(list[_MoveEntry], entries)

def _move_journal_path(source: Union[os.PathLike[str], str]) -> Path:
    return Path(source) / MOVE_JOURNAL

def _write_move_journal(
    source: Union[os.PathLike[str], str],
    root: bytes,
    record: object,
) -> None:
    raw = canonical_json(record)
    if len(raw) > MOVE_MAX_JOURNAL_BYTES:
        raise MoveDataError("The data-move manifest is too large to journal safely.")
    sealed = seal(idx_key(root), raw)
    atomic_write_bytes(_move_journal_path(source), sealed)

def _create_move_journal(
    source: Union[os.PathLike[str], str],
    root: bytes,
    record: object,
) -> None:
    raw = canonical_json(record)
    if len(raw) > MOVE_MAX_JOURNAL_BYTES:
        raise MoveDataError("The data-move manifest is too large to journal safely.")
    path = _move_journal_path(source)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
    identity = _move_file_identity(os.fstat(fd))[:2]
    try:
        with os.fdopen(fd, "wb") as journal_file:
            journal_file.write(seal(idx_key(root), raw))
            journal_file.flush()
            os.fsync(journal_file.fileno())
        fsync_directory(path.parent)
    except Exception as exc:
        try:
            info = path.lstat()
            if stat.S_ISREG(info.st_mode) and _move_same_object(info, identity):
                path.unlink()
                fsync_directory(path.parent)
        except (OSError, ValueError):
            raise MoveDataError(f"The source is intact, but incomplete move metadata must be preserved at {path}.") from exc
        raise

def _activate_move_stage(
    stage: Union[os.PathLike[str], str],
    target: Union[os.PathLike[str], str],
) -> None:
    stage, target = Path(stage), Path(target)
    if os.name == "nt":
        os.rename(stage, target)
        return
    if sys.platform.startswith("linux"):
        renameat2 = getattr(ctypes.CDLL(None, use_errno=True), "renameat2", None)
        if renameat2 is None:
            raise MoveDataError("This platform cannot safely activate a directory without replacing a concurrent destination.")
        renameat2.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
        renameat2.restype = ctypes.c_int
        result = renameat2(-100, os.fsencode(stage), -100, os.fsencode(target), 1)
    elif sys.platform == "darwin":
        renamex_np = getattr(ctypes.CDLL(None, use_errno=True), "renamex_np", None)
        if renamex_np is None:
            raise MoveDataError("This platform cannot safely activate a directory without replacing a concurrent destination.")
        renamex_np.argtypes = (ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint)
        renamex_np.restype = ctypes.c_int
        result = renamex_np(os.fsencode(stage), os.fsencode(target), 4)
    else:
        raise MoveDataError("This platform cannot safely activate a directory without replacing a concurrent destination.")
    if result:
        code = ctypes.get_errno()
        if code in (17, 39):
            raise FileExistsError(code, os.strerror(code), str(target))
        raise OSError(code, os.strerror(code), str(target))

def _read_move_journal(source: Union[os.PathLike[str], str], root: bytes) -> _MoveJournal:
    path = _move_journal_path(source)
    info = path.lstat()
    if _move_is_reparse(info) or not stat.S_ISREG(info.st_mode) or info.st_size > MOVE_MAX_JOURNAL_BYTES + 64:
        raise ValueError("The data-move journal is not a safe regular file.")
    record_value: object = json.loads(unseal(idx_key(root), path.read_bytes()))
    if not isinstance(record_value, dict):
        raise ValueError("Unsupported data-move journal version.")
    record = cast(dict[str, object], record_value)
    if (type(record.get("version")) is not int
            or record.get("version") != 1):
        raise ValueError("Unsupported data-move journal version.")
    operation = record.get("operation")
    if not isinstance(operation, str) or not re.fullmatch(r"[0-9a-f]{32}", operation):
        raise ValueError("Invalid data-move operation identifier.")
    if record.get("phase") not in {"copying", "verified", "committed"}:
        raise ValueError("Invalid data-move operation phase.")
    _validate_move_entries(record.get("entries"))
    source_value = record.get("source")
    target_value = record.get("target")
    stage_value = record.get("stage")
    if (not isinstance(source_value, str) or not source_value
            or not isinstance(target_value, str) or not target_value
            or not isinstance(stage_value, str) or not stage_value):
        raise ValueError("Invalid data-move directory paths.")
    src = Path(source_value)
    target = Path(target_value)
    stage = Path(stage_value)
    if not src.is_absolute() or not target.is_absolute() or not stage.is_absolute():
        raise ValueError("Invalid data-move directory paths.")
    src = src.resolve(strict=True)
    if src != Path(source).resolve(strict=True):
        raise ValueError("The data-move journal belongs to a different source folder.")
    expected = _move_target_for(src)
    if target != expected or target.parent.resolve(strict=True) != expected.parent.resolve(strict=True):
        raise ValueError("The data-move journal names an unexpected destination.")
    expected_stage = target.parent / f".{target.name}.move-{operation}.staging"
    if stage != expected_stage:
        raise ValueError("The data-move journal names an unexpected staging folder.")
    return cast(_MoveJournal, record)

def _move_target_for(source: Union[os.PathLike[str], str]) -> Path:
    source = Path(source).resolve()
    local = (Path.home() / ".unknwn").resolve()
    portable = PORT.resolve()
    if source == portable: return local
    if source == local: return portable
    raise MoveDataError("The active data folder is not a supported move location.")

def _verify_move_tree(
    root: Union[os.PathLike[str], str],
    entries: object,
    cancel: Optional[threading.Event] = None,
) -> None:
    root = Path(root)
    if root.is_symlink() or not root.is_dir():
        raise MoveDataError("The staged data folder is missing or unsafe.")
    expected = {entry["path"].casefold(): entry for entry in _validate_move_entries(entries)}
    actual_paths: set[str] = set()
    stack = [(root, "")]
    while stack:
        directory, prefix = stack.pop()
        if _move_is_reparse(directory.lstat()): raise MoveDataError("The staged folder contains an unsafe reparse point.")
        for child in os.scandir(directory):
            if cancel is not None and cancel.is_set(): raise MoveDataCancelled("The data move was cancelled.")
            relative = f"{prefix}/{child.name}" if prefix else child.name
            info = os.stat(child.path, follow_symlinks=False)
            if _move_is_reparse(info): raise MoveDataError("The staged folder contains a symbolic link or reparse point.")
            key = relative.casefold()
            entry = expected.get(key)
            if entry is None: raise MoveDataError("The staged destination contains an unexpected file.")
            actual_paths.add(key)
            if entry["kind"] == "dir":
                if not stat.S_ISDIR(info.st_mode): raise MoveDataError("A staged directory does not match the source manifest.")
                stack.append((Path(child.path), relative))
            else:
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size != entry["size"]:
                    raise MoveDataError("A staged file is missing or has an unexpected size.")
                size, digest = _move_hash_file(Path(child.path), cancel=cancel)
                if size != entry["size"] or not hmac.compare_digest(digest, entry["sha256"]):
                    raise MoveDataError("A staged file failed independent checksum verification.")
    if actual_paths != set(expected):
        raise MoveDataError("The staged destination is missing one or more expected files.")

def _copy_move_tree(
    source: Union[os.PathLike[str], str],
    stage: Union[os.PathLike[str], str],
    entries: list[_MoveEntry],
    cancel: threading.Event,
    progress: Optional[Callable[[tuple[str, int, int]], None]],
) -> tuple[list[tuple[Path, tuple[int, int]]], list[tuple[Path, tuple[int, int]]]]:
    source, stage = Path(source), Path(stage)
    stage.mkdir(mode=0o700)
    created_directories: list[tuple[Path, tuple[int, int]]] = [(stage, _move_file_identity(stage.lstat())[:2])]
    created_files: list[tuple[Path, tuple[int, int]]] = []
    total = sum(entry["size"] for entry in entries if entry["kind"] == "file") or 1
    done = 0
    try:
        for entry in sorted((item for item in entries if item["kind"] == "dir"), key=lambda item: item["path"].count("/")):
            if cancel.is_set(): raise MoveDataCancelled("The data move was cancelled.")
            path = stage / Path(entry["path"])
            path.mkdir()
            created_directories.append((path, _move_file_identity(path.lstat())[:2]))
        for entry in (item for item in entries if item["kind"] == "file"):
            if cancel.is_set(): raise MoveDataCancelled("The data move was cancelled.")
            src = source / Path(entry["path"]); dst = stage / Path(entry["path"])
            if _move_file_identity(src.lstat()) != (entry["dev"], entry["ino"], entry["size"], entry["mtime_ns"]):
                raise MoveDataError("A source file changed before it could be copied.")
            parent = dst.parent
            while parent != stage and parent.is_relative_to(stage):
                if _move_is_reparse(parent.lstat()) or not parent.is_dir():
                    raise MoveDataError("A staging parent changed to an unsafe filesystem object.")
                parent = parent.parent
            flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
            source_fd = os.open(src, flags)
            try:
                with os.fdopen(source_fd, "rb") as reader:
                    opened = os.fstat(reader.fileno())
                    if _move_file_identity(opened) != (entry["dev"], entry["ino"], entry["size"], entry["mtime_ns"]):
                        raise MoveDataError("A source file changed while it was opened.")
                    out_fd = os.open(dst, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
                    out_info = os.fstat(out_fd)
                    created_files.append((dst, _move_file_identity(out_info)[:2]))
                    digest = hashlib.sha256(); copied = 0
                    with os.fdopen(out_fd, "wb") as writer:
                        while True:
                            if cancel.is_set(): raise MoveDataCancelled("The data move was cancelled.")
                            block = reader.read(CH)
                            if not block: break
                            writer.write(block); digest.update(block); copied += len(block)
                            if progress is not None: progress(("Copying encrypted data", done + copied, total))
                        writer.flush(); os.fsync(writer.fileno())
                    if copied != entry["size"] or not hmac.compare_digest(digest.hexdigest(), entry["sha256"]):
                        raise MoveDataError("A source file changed or failed verification during the copy.")
                    if _move_file_identity(os.fstat(reader.fileno())) != _move_file_identity(opened):
                        raise MoveDataError("A source file changed while it was copied.")
            except Exception:
                try: os.close(source_fd)
                except OSError: pass
                raise
            os.utime(dst, ns=(entry["mtime_ns"], entry["mtime_ns"]))
            done += entry["size"]
        return created_files, created_directories
    except Exception:
        _cleanup_created_move_tree(stage, created_files, created_directories)
        raise

def _cleanup_created_move_tree(
    stage: Union[os.PathLike[str], str],
    created_files: list[tuple[Path, tuple[int, int]]],
    created_directories: list[tuple[Path, tuple[int, int]]],
) -> list[Path]:
    errors: list[Path] = []
    for path, identity in reversed(created_files):
        try:
            info = path.lstat()
            if _move_is_reparse(info) or not stat.S_ISREG(info.st_mode) or not _move_same_object(info, identity):
                errors.append(path)
                continue
            path.unlink()
        except FileNotFoundError:
            pass
        except OSError:
            errors.append(path)
    for path, identity in reversed(created_directories):
        try:
            info = path.lstat()
            if _move_is_reparse(info) or not stat.S_ISDIR(info.st_mode) or not _move_same_object(info, identity):
                errors.append(path)
                continue
            path.rmdir()
        except FileNotFoundError:
            pass
        except OSError:
            errors.append(path)
    return errors

def copy_data_tree_transaction(
    source: Union[os.PathLike[str], str],
    target: Union[os.PathLike[str], str],
    root: bytes,
    cancel: Optional[threading.Event] = None,
    progress: Optional[Callable[[tuple[str, int, int]], None]] = None,
    allow_unknown_space: bool = False,
) -> _MoveCopyResult:
    target = Path(target).absolute()
    with _MoveDestinationLock(target):
        return _copy_data_tree_transaction_locked(source, target, root, cancel, progress, allow_unknown_space)

def _copy_data_tree_transaction_locked(
    source: Union[os.PathLike[str], str],
    target: Union[os.PathLike[str], str],
    root: bytes,
    cancel: Optional[threading.Event],
    progress: Optional[Callable[[tuple[str, int, int]], None]],
    allow_unknown_space: bool,
) -> _MoveCopyResult:
    cancel = cancel or threading.Event()
    source = _validated_move_source_root(source)
    target = Path(target).absolute()
    if _move_journal_path(source).exists():
        raise MoveDataError("An earlier data move needs recovery; no new copy was started.")
    if target.exists() or target.is_symlink():
        raise FileExistsError("The data-move destination already exists.")
    if target.parent.resolve(strict=True) != target.parent.absolute():
        raise MoveDataError("The destination parent resolves through an unexpected path.")
    if storage_txn_path().exists() or (source / "rotate.json").exists():
        raise MoveDataError("Recover the pending vault operation before moving data.")
    source, entries, total = _move_tree_manifest(source, cancel, progress)
    forecast = storage_preflight(target.parent, total)
    if forecast["status"] == "insufficient":
        raise OSError("The destination does not have enough available space for the estimated copy.")
    if forecast["status"] != "pass" and not allow_unknown_space:
        raise OSError("Available destination space could not be verified.")
    operation = secrets.token_hex(16)
    stage = target.parent / f".{target.name}.move-{operation}.staging"
    record: dict[str, object] = {"version": 1, "operation": operation, "phase": "copying",
              "source": str(source), "target": str(target), "stage": str(stage), "entries": entries}
    _create_move_journal(source, root, record)
    created_files: list[tuple[Path, tuple[int, int]]] = []
    created_directories: list[tuple[Path, tuple[int, int]]] = []
    try:
        created_files, created_directories = _copy_move_tree(source, stage, entries, cancel, progress)
        _verify_move_tree(stage, entries, cancel)
        current_source, current_entries, _ = _move_tree_manifest(source, cancel, progress)
        if current_source != source or current_entries != entries:
            raise MoveDataError("The source data changed during the move; the original was preserved.")
        if cancel.is_set(): raise MoveDataCancelled("The data move was cancelled before activation.")
        forecast = storage_preflight(target.parent, total)
        if forecast["status"] == "insufficient":
            raise OSError("Available space changed before activation; the original was preserved.")
        if forecast["status"] != "pass" and not allow_unknown_space:
            raise OSError("Available space could not be rechecked before activation.")
        if target.exists() or target.is_symlink():
            raise FileExistsError("The destination appeared during the move; it was not overwritten.")
        record["phase"] = "verified"
        _write_move_journal(source, root, record)
        _activate_move_stage(stage, target)
        fsync_directory(target.parent)
        _verify_move_tree(target, entries)
        persist_active_location(target)
        if progress is not None: progress(("Destination verified", max(total, 1), max(total, 1)))
        try:
            record["phase"] = "committed"
            _write_move_journal(source, root, record)
            _durable_unlink(_move_journal_path(source))
        except Exception:
            return {"status": "recovery_required", "target": str(target), "source": str(source),
                    "journal": str(_move_journal_path(source)), "retained_backup": True}
        return {"status": "completed", "target": str(target), "source": str(source), "retained_backup": True}
    except Exception as exc:
        if record["phase"] == "copying":
            cleanup_errors = []
            if stage.exists():
                cleanup_errors = _cleanup_created_move_tree(stage, created_files, created_directories)
                if not cleanup_errors and stage.exists():
                    try: stage.rmdir()
                    except OSError: cleanup_errors.append(stage)
            if not cleanup_errors and not stage.exists():
                try:
                    _durable_unlink(_move_journal_path(source))
                except OSError as cleanup_error:
                    raise MoveDataError(
                        f"The source is intact, but move recovery metadata could not be removed; preserve it at {_move_journal_path(source)}."
                    ) from cleanup_error
            elif cleanup_errors:
                paths = ", ".join(str(path) for path in cleanup_errors)
                raise MoveDataError(
                    f"The source is intact, but partial staging data needs recovery at {stage}; cleanup could not remove: {paths}."
                ) from exc
        raise

def recover_data_move(
    root: bytes,
    source: Optional[Union[os.PathLike[str], str]] = None,
) -> Optional[_MoveRecoveryResult]:
    source = _validated_move_source_root(source or HOME)
    journal = _move_journal_path(source)
    if not journal.exists(): return None
    record = _read_move_journal(source, root)
    target, stage = Path(record["target"]), Path(record["stage"])
    entries = record["entries"]
    if record["phase"] == "copying":
        return {"status": "interrupted", "source": str(source), "target": str(target), "stage": str(stage)}
    if record["phase"] == "verified":
        if stage.exists() and not target.exists():
            _verify_move_tree(stage, entries)
            current_source, current_entries, _ = _move_tree_manifest(source)
            if current_source != source or current_entries != entries:
                raise MoveDataError("The source changed after the interrupted copy; both source and staging data were preserved.")
            forecast = storage_preflight(target.parent, sum(item["size"] for item in entries if item["kind"] == "file"))
            if forecast["status"] == "insufficient":
                raise MoveDataError("Space is no longer sufficient to activate the verified data copy.")
            if target.exists() or target.is_symlink():
                raise MoveDataError("The destination now exists; the verified staging folder was preserved.")
            _activate_move_stage(stage, target); fsync_directory(target.parent)
        if not target.exists() or stage.exists():
            raise MoveDataError("The interrupted move has an inconsistent state; source and staging data were preserved.")
        _verify_move_tree(target, entries)
        current_source, current_entries, _ = _move_tree_manifest(source)
        if current_source != source or current_entries != entries:
            raise MoveDataError("The source changed after activation; both copies were preserved for review.")
        persist_active_location(target)
        record["phase"] = "committed"
        _write_move_journal(source, root, record)
    elif record["phase"] == "committed":
        if not target.exists() or stage.exists():
            raise MoveDataError("The committed data-move destination is unavailable or inconsistent.")
        _verify_move_tree(target, entries)
        persist_active_location(target)
    else:
        raise ValueError("Unsupported data-move recovery state.")
    try:
        _durable_unlink(journal)
    except OSError:
        return {"status": "recovery_required", "source": str(source), "target": str(target),
                "journal": str(journal), "retained_backup": True}
    return {"status": "completed", "source": str(source), "target": str(target), "retained_backup": True}

def resolve_data_move_before_signin(root: bytes) -> Optional[_MoveRecoveryResult]:
    move = recover_authenticated_data_move(root)
    if move is None:
        return None
    if move["status"] != "completed":
        raise MoveDataError(
            f"The data move is not fully recovered ({move['status']}); preserve the source, staging data, and recovery journal."
        )
    set_home(Path(move["target"]))
    return move

def recover_authenticated_data_move(root: bytes) -> Optional[_MoveRecoveryResult]:
    alternate = (Path.home() / ".unknwn") if HOME == PORT else PORT
    for source in (HOME, alternate):
        if not _move_journal_path(source).exists():
            continue
        return recover_data_move(root, source)
    return None

class EncryptedStreamWriter:
    """Non-seekable encrypted output for streaming containers such as ZIP."""
    def __init__(self, path: Union[os.PathLike[str], str], key: bytes) -> None:
        self.file = open(path, "xb"); info = os.fstat(self.file.fileno())
        self.identity = (info.st_dev, info.st_ino)
        self.aes = AESGCM(key); self.buffer = bytearray(); self.index = 0; self.size = 0; self.closed = False
    def write(self, data: bytes) -> int:
        if self.closed: raise ValueError("write to closed encrypted stream")
        view = memoryview(data); length = len(view); self.size += length
        while view:
            take = min(CH - len(self.buffer), len(view)); self.buffer.extend(view[:take]); view = view[take:]
            if len(self.buffer) == CH and view:
                self.emit(False)
        return length
    def emit(self, last: bool) -> None:
        iv = os.urandom(12); encrypted = self.aes.encrypt(iv, bytes(self.buffer), struct.pack(">QB", self.index, last))
        self.file.write(struct.pack(">I", len(encrypted) + 12)); self.file.write(iv); self.file.write(encrypted)
        self.index += 1; self.buffer.clear()
    def tell(self) -> int: return self.size
    def seekable(self) -> bool: return False
    def writable(self) -> bool: return True
    def flush(self) -> None: self.file.flush()
    def close(self) -> None:
        if self.closed: return
        try:
            self.emit(True); self.file.flush(); os.fsync(self.file.fileno())
        finally:
            self.file.close(); self.closed = True

def folder_entries(
    folder: Union[os.PathLike[str], str],
) -> tuple[Path, list[tuple[Path, str, bool, tuple[int, int, int, int]]]]:
    """Snapshot regular files and empty directories without following symlinks."""
    root = Path(folder).resolve(strict=True)
    if not root.is_dir(): raise ValueError("The selected path is not a folder.")
    entries: list[tuple[Path, str, bool, tuple[int, int, int, int]]] = []
    def onerror(error: OSError) -> NoReturn: raise error
    for current, dirs, files in os.walk(root, topdown=True, followlinks=False, onerror=onerror):
        current_path = Path(current)
        dirs[:] = sorted(name for name in dirs if not (current_path / name).is_symlink())
        for name in dirs:
            path = current_path / name
            relative = path.relative_to(root.parent).as_posix().rstrip("/") + "/"
            entries.append((path, relative, True, _folder_identity(path)))
        for name in sorted(files):
            path = current_path / name
            if path.is_symlink(): continue
            if not path.is_file(): continue
            relative = path.relative_to(root.parent).as_posix()
            entries.append((path, relative, False, _folder_identity(path)))
    return root, entries

def _folder_identity(path: Path) -> tuple[int, int, int, int]:
    info = path.stat()
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns


_PRECOMPRESSED_ARCHIVE_SUFFIXES = frozenset({
    ".7z", ".aac", ".avif", ".avi", ".bz2", ".docx", ".flac", ".gif",
    ".gz", ".heic", ".jpeg", ".jpg", ".m4a", ".m4v", ".mkv", ".mov",
    ".mp3", ".mp4", ".ods", ".odt", ".ogg", ".opus", ".pdf", ".png",
    ".pptx", ".rar", ".webm", ".webp", ".wmv", ".xlsx", ".xz", ".zip",
})


def enc_folder(
    folder: Union[os.PathLike[str], str],
    dst: Union[os.PathLike[str], str],
    key: bytes,
    cb: Callable[[int, int], None],
    cancel: Optional[threading.Event] = None,
    on_stage_created: Optional[Callable[[tuple[int, int]], None]] = None,
    resume: Optional[threading.Event] = None,
) -> tuple[Path, list[tuple[Path, str, bool, tuple[int, int, int, int]]], int]:
    """Create a compressed ZIP folder item directly inside the authenticated encrypted stream."""
    root, entries = folder_entries(folder)
    total_bytes = sum(snapshot[2] for _, _, is_dir, snapshot in entries if not is_dir)
    total_work = max(total_bytes, len(entries), 1); completed = 0
    Path(dst).parent.mkdir(parents=True, exist_ok=True)
    target = EncryptedStreamWriter(dst, key)
    try:
        if on_stage_created is not None:
            on_stage_created(target.identity)
        with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6, allowZip64=True) as archive:
            for path, relative, is_dir, snapshot in entries:
                _encryption_checkpoint(cancel, resume)
                if is_dir:
                    if path.is_symlink() or _folder_identity(path) != snapshot:
                        raise OSError(f"Folder entry changed while sealing: {relative}")
                    info = zipfile.ZipInfo(relative); info.external_attr = 0o40755 << 16
                    archive.writestr(info, b"")
                    if not total_bytes: completed += 1; cb(completed, total_work)
                    continue
                if path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(root):
                    raise OSError(f"Folder entry changed while sealing: {relative}")
                info = zipfile.ZipInfo(relative)
                info.compress_type = (zipfile.ZIP_STORED
                                      if Path(relative).suffix.casefold() in _PRECOMPRESSED_ARCHIVE_SUFFIXES
                                      else zipfile.ZIP_DEFLATED)
                info.external_attr = 0o100644 << 16
                before = completed
                with open(path, "rb") as source, archive.open(info, "w", force_zip64=True) as member:
                    opened = os.fstat(source.fileno())
                    if (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns) != snapshot:
                        raise OSError(f"Folder entry changed while sealing: {relative}")
                    while True:
                        _encryption_checkpoint(cancel, resume)
                        chunk = source.read(CH)
                        if not chunk: break
                        member.write(chunk); completed += len(chunk); cb(completed, total_work)
                        _encryption_checkpoint(cancel, resume)
                    final = os.fstat(source.fileno())
                    if (final.st_dev, final.st_ino, final.st_size, final.st_mtime_ns) != snapshot:
                        raise OSError(f"Folder entry changed while sealing: {relative}")
                if completed == before and not total_bytes:
                    completed += 1; cb(completed, total_work)
        _encryption_checkpoint(cancel, resume)
        target.close()
        if not entries: cb(1, 1)
        return root, entries, target.size
    except BaseException:
        if not target.closed:
            try:
                target.file.close()
                target.closed = True
            except OSError:
                pass
        try:
            _remove_owned_seal_stage(dst, target.identity)
        except OSError as cleanup_error:
            raise OSError(f"Folder sealing failed and its staged output needs recovery at {dst}.") from cleanup_error
        raise

def remove_folder_sources(
    root: Path,
    entries: list[tuple[Path, str, bool, tuple[int, int, int, int]]],
    passes: int = 3,
) -> None:
    """Best-effort remove only unchanged files captured in the folder snapshot."""
    for path, _relative, is_dir, snapshot in entries:
        if is_dir or path.is_symlink() or not path.is_file(): continue
        try:
            if _folder_identity(path) == snapshot: shred(path, passes)
        except OSError: continue
    for path, _, is_dir, snapshot in reversed(entries):
        if not is_dir or path.is_symlink(): continue
        try:
            path.rmdir()
        except OSError: continue
    try: root.rmdir()
    except OSError: pass

def iter_dec(
    p: Path,
    k: bytes,
    cancel: Optional[threading.Event] = None,
) -> Iterator[tuple[bytes, bool, int, int]]:
    """Streaming authenticated decrypt: yields (plaintext chunk, is_last, bytes_read, total). Any tamper/truncation raises InvalidTag."""
    a = AESGCM(k); size = p.stat().st_size; pos = i = 0
    if size == 0: raise InvalidTag()   # an empty file is never a valid sealed file (full truncation must not pass as "empty")
    with open(p, "rb") as f:
        while pos < size:
            if cancel is not None and cancel.is_set():
                raise MoveDataCancelled("Vault analysis was cancelled at an authenticated chunk boundary.")
            h = f.read(4)
            if len(h) < 4: raise InvalidTag()
            L = struct.unpack(">I", h)[0]; blob = f.read(L)
            if len(blob) != L or L < 12: raise InvalidTag()
            pos += 4 + L
            plaintext = a.decrypt(blob[:12], blob[12:], struct.pack(">QB", i, pos >= size))
            if cancel is not None and cancel.is_set():
                raise MoveDataCancelled("Vault analysis was cancelled at an authenticated chunk boundary.")
            yield plaintext, pos >= size, pos, size; i += 1
def dec_file(
    p: Path,
    k: bytes,
    cb: Optional[Callable[[int, int], None]] = None,
) -> bytes:
    out: list[bytes] = []
    if cb: cb(0, 1)
    for pl, _last, pos, size in iter_dec(p, k):
        out.append(pl)
        if cb: cb(pos, size)
    return b"".join(out)
@overload
def dec_file_to_temp(
    p: Path,
    k: bytes,
    name: str,
    *,
    with_digest: Literal[True],
) -> tuple[Path, int, str]: ...
@overload
def dec_file_to_temp(
    p: Path,
    k: bytes,
    name: str,
    cb: Optional[Callable[[int, int], None]],
    with_digest: Literal[True],
) -> tuple[Path, int, str]: ...
@overload
def dec_file_to_temp(
    p: Path,
    k: bytes,
    name: str,
    cb: Optional[Callable[[int, int], None]] = None,
    with_digest: Literal[False] = False,
) -> tuple[Path, int]: ...
@overload
def dec_file_to_temp(
    p: Path,
    k: bytes,
    name: str,
    cb: Optional[Callable[[int, int], None]] = None,
    with_digest: bool = False,
) -> Union[tuple[Path, int], tuple[Path, int, str]]: ...
def dec_file_to_temp(
    p: Path,
    k: bytes,
    name: str,
    cb: Optional[Callable[[int, int], None]] = None,
    with_digest: bool = False,
) -> Union[tuple[Path, int], tuple[Path, int, str]]:
    target = tmp_media_path(name); created = False
    try:
        with open(target, "xb") as output:
            created = True
            if cb: cb(0, 1)
            total = 0; digest = hashlib.sha256()
            for plaintext, _last, pos, size in iter_dec(p, k):
                output.write(plaintext); total += len(plaintext); digest.update(plaintext)
                if cb: cb(pos, size)
            output.flush(); os.fsync(output.fileno())
        return (target, total, digest.hexdigest()) if with_digest else (target, total)
    except BaseException:
        if created:
            try: _durable_unlink(target)
            except FileNotFoundError: pass
            except OSError as exc: log_security_event("temp_create_cleanup_failed", error=type(exc).__name__)
        raise
def recrypt(
    src: Path,
    ok: bytes,
    dst: Path,
    nk: bytes,
    cb: Optional[Callable[[int, int], None]] = None,
) -> int:
    """Re-encrypt one sealed file under a new key, chunk by chunk (never plaintext on disk), then verify the result. Returns plaintext length."""
    a = AESGCM(nk); n = i = 0
    with open(dst, "wb") as o:
        for pl, last, pos, size in iter_dec(src, ok):
            iv = os.urandom(12); c = a.encrypt(iv, pl, struct.pack(">QB", i, last)); o.write(struct.pack(">I", len(c) + 12) + iv + c); i += 1; n += len(pl)
            if cb: cb(pos, size)
        o.flush(); os.fsync(o.fileno())
    if sum(len(pl) for pl, *_ in iter_dec(dst, nk)) != n: raise InvalidTag()
    return n
def rotate_vault(
    old: bytes,
    pw: str,
    cb: Optional[Callable[[float, str], None]] = None,
) -> tuple[bytes, str]:
    """New random vault key; every file re-encrypted under it; new password wrapper and NEW recovery words. Old copies of the data folder stop
    opening new data. Phase 1 writes *.new files (nothing live changes). The journal is the commit point; rotate_commit() then rolls forward."""
    new = os.urandom(32); phrase = " ".join(random.SystemRandom().sample(WORDS, NW)); s1, s2 = os.urandom(16), os.urandom(16)
    rids = sorted(idx); nidx: dict[str, _VaultMetadata] = {}; made: list[str] = []; jp = HOME / "rotate.json"
    try:
        for n_, rid in enumerate(rids):
            m = idx[rid]; salt = os.urandom(16); ok, nk = file_key(old, b64d(m["s"])), file_key(new, salt); name = unseal(ok, b64d(m["nm"]))
            made.append(rid); VAULT.mkdir(parents=True, exist_ok=True)
            recrypt(VAULT / f"{rid}.cdr", ok, VAULT / f"{rid}.cdr.new", nk, (lambda d, t, n_=n_: cb((n_ + d / max(1, t)) / len(rids), f"Re-encrypting {n_ + 1}/{len(rids)}")) if cb else None)
            e = cast(_VaultMetadata, dict(m)); e["s"] = b64e(salt); e["nm"] = b64e(seal(nk, name)); nidx[rid] = e
        lg = None
        try: lg = unseal(file_key(old, b"unknwn-log"), LOG.read_bytes())
        except Exception: pass
        if lg is not None: atomic_write_bytes(HOME / "log.bin.new", seal(file_key(new, b"unknwn-log"), lg))
        c = dict(s1=b64e(s1), s2=b64e(s2), wp=b64e(seal(kdf(pw, s1), new)), wr=b64e(seal(kdf(phrase, s2), new)))
        if unseal(kdf(pw, s1), b64d(c["wp"])) != new or unseal(kdf(phrase, s2), b64d(c["wr"])) != new: raise InvalidTag()
        if cfg.get("slk") and cfg.get("slc"): c["slc"] = b64e(seal(new, b"slk:" + b64d(cfg["slk"]["h"])))
        c["sc"] = IG.snap_make(new, secset())
        hashes: dict[str, str] = {rid: file_digest(vault_file_path(rid, ".cdr.new")) for rid in made}
        if lg is not None: hashes["log.bin"] = file_digest(HOME / "log.bin.new")
        jsave(jp, dict(idx_blob=encode_idx(new, nidx), cfg=c, files=made, log=lg is not None, hashes=hashes))   # COMMIT POINT
    except BaseException:
        if not jp.exists():
            for rid in made:
                try: (VAULT / f"{rid}.cdr.new").unlink()
                except OSError: pass
            for n in (HOME / "log.bin.new",):
                try: n.unlink()
                except OSError: pass
        raise
    rotate_commit(); cfg.update(c); idx.clear(); idx.update(nidx)
    return new, phrase
COMMON = {"password", "passw", "welcome", "qwerty", "qwertyuiop", "letmein", "admin", "administrator", "iloveyou", "monkey", "dragon", "football", "baseball", "master", "summer", "winter",
          "spring", "autumn", "sunshine", "princess", "login", "abc", "abcdef", "trustno", "shadow", "superman", "batman", "michael", "ahmed", "mohamed", "mohammed", "hello", "secret",
          "freedom", "whatever", "starwars", "pokemon", "minecraft", "google", "facebook", "unknwn", "vault", "default", "changeme", "asdf", "zxcv", "liverpool", "egypt", "cairo"}
def check_pw(p: str) -> tuple[int, str]:
    if len(p) < 12: return 0, "Use at least 12 characters."
    if sum(bool(re.search(r, p)) for r in ("[a-z]", "[A-Z]", "[0-9]", "[^A-Za-z0-9]")) < 3: return 0, "Mix at least 3 of: lowercase, UPPERCASE, numbers, symbols."
    core = re.sub(r"[^a-z]", "", p.lower())
    if core and any(core == w or (w in core and len(core) - len(w) <= 3) for w in COMMON): return 0, "Too predictable: a common word with digits or symbols added."
    if len(set(p)) < 7 or re.search(r"(.)\1{3,}", p) or p.lower() in ("password1234", "qwertyuiop12", "123456789012"): return 0, "Too predictable: avoid repeats and common patterns."
    return 1, ""
def strength(p: str) -> tuple[str, str]:
    pool = sum(n for r, n in (("[a-z]", 26), ("[A-Z]", 26), ("[0-9]", 10), ("[^A-Za-z0-9]", 33)) if re.search(r, p))
    b = len(p) * math.log2(pool or 1) * (len(set(p)) / max(1, len(p))) ** .5
    ok, why = check_pw(p)
    if not p: return "", MUT
    if not ok: return why, "#ff8a65"
    return ("Okay", "#ffb347") if b < 70 else ("Strong", "#4ade80") if b < 95 else ("Excellent", "#22d3ee")

def shred(
    path: Union[os.PathLike[str], str],
    passes: int = 3,
    cb: Optional[Callable[[int, int], None]] = None,
) -> None:
    """Overwrite with random data, fsync, delete. (SSD wear-levelling can still keep remnants.)"""
    path = Path(path)
    try:
        info = path.lstat()
    except FileNotFoundError:
        return
    if (stat.S_ISLNK(info.st_mode)
            or getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
            or not stat.S_ISREG(info.st_mode)):
        raise ValueError("Refusing to overwrite a non-regular or linked file")
    if getattr(info, "st_nlink", 1) > 1:
        raise ValueError("Refusing to overwrite a multiply-linked file")
    try:
        n = info.st_size
        with open(path, "r+b") as f:
            for ps in range(passes):
                f.seek(0); left = n
                while left > 0:
                    k = min(left, 1 << 20); f.write(os.urandom(k)); left -= k
                    if cb: cb(ps * n + (n - left), max(1, passes * n))
                f.flush(); os.fsync(f.fileno())
    except FileNotFoundError:
        return
    except OSError:
        try: _durable_unlink(path)
        except FileNotFoundError: return
        except OSError as delete_error:
            raise OSError(f"Could not remove {path} after overwrite failed") from delete_error
        return
    _durable_unlink(path)
def wipe(
    path: Union[os.PathLike[str], str],
    rm: bool = False,
    passes: int = 3,
) -> None:
    path = Path(path)
    try:
        root_info = path.lstat()
    except FileNotFoundError:
        return
    if (stat.S_ISLNK(root_info.st_mode)
            or getattr(root_info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
            or not stat.S_ISDIR(root_info.st_mode)):
        raise ValueError("Refusing to wipe an unsafe or non-directory root")
    def raise_walk_error(error: OSError) -> NoReturn: raise error
    directories: list[Path] = []
    for root, dirs, files in os.walk(path, topdown=True, onerror=raise_walk_error, followlinks=False):
        directory = Path(root)
        directory_info = directory.lstat()
        if (stat.S_ISLNK(directory_info.st_mode)
                or getattr(directory_info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)):
            raise ValueError("Refusing to traverse a linked or reparse-point directory")
        directories.append(directory)
        for name in list(dirs):
            child = directory / name
            info = child.lstat()
            if (stat.S_ISLNK(info.st_mode)
                    or getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)):
                dirs.remove(name)
                os.rmdir(child) if stat.S_ISDIR(info.st_mode) else _durable_unlink(child)
        for name in files:
            child = directory / name
            info = child.lstat()
            if (stat.S_ISLNK(info.st_mode)
                    or getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)):
                _durable_unlink(child)
            elif stat.S_ISREG(info.st_mode):
                if getattr(info, "st_nlink", 1) > 1:
                    raise ValueError("Refusing to overwrite a multiply-linked file")
                shred(child, passes)
            else:
                raise ValueError("Refusing to clean an unsupported filesystem entry")
    if rm:
        for directory in reversed(directories):
            directory.rmdir()
            fsync_directory(directory.parent)


def wipe_all_vault_data(
    current_home: Union[os.PathLike[str], str],
    passes: int = 3,
    remove_roots: bool = False,
) -> None:
    if type(remove_roots) is not bool:
        raise TypeError("remove_roots must be a boolean.")
    home = Path.home()
    managed_root = home / ".unknwn-profiles"
    failures: list[str] = []
    try:
        profiles = _read_profiles()
    except Exception as exc:
        profiles = []
        failures.append(f"profile registry could not be validated ({type(exc).__name__})")

    allowed_profile_paths = {
        os.path.normcase(os.path.abspath(Path(PORT))),
        os.path.normcase(os.path.abspath(home / ".unknwn")),
    }
    managed_root_key = os.path.normcase(os.path.abspath(managed_root))
    for profile in profiles:
        path = Path(profile["path"])
        key = os.path.normcase(os.path.abspath(path))
        managed_profile = (os.path.normcase(os.path.abspath(path.parent)) == managed_root_key
                           and path.name == profile["id"])
        if key not in allowed_profile_paths and not managed_profile:
            failures.append(f"unrecognized profile location was preserved: {path}")
        else:
            allowed_profile_paths.add(key)

    targets: list[Path] = []
    seen: set[str] = set()
    for target in (Path(current_home), Path(PORT), home / ".unknwn"):
        key = os.path.normcase(os.path.abspath(target))
        if key not in seen and key in allowed_profile_paths:
            targets.append(target)
            seen.add(key)
        elif key not in allowed_profile_paths:
            failures.append(f"unrecognized active vault location was preserved: {target}")
    state_artifacts: list[Path] = [
        PROFILE_REGISTRY,
        PROFILE_REGISTRY.with_name(PROFILE_REGISTRY.name + ".bak"),
        PROFILE_REGISTRY.with_name(PROFILE_REGISTRY.name + ".tmp"),
        _active_location_state_path(),
    ]
    for pattern in (PROFILE_REGISTRY.name + ".*.tmp",
                    ".unknwn-location.*.tmp",
                    DESTRUCT_JOURNAL + ".*.tmp"):
        try:
            state_artifacts.extend(home.glob(pattern))
        except OSError as exc:
            failures.append(f"UNKNWN state temporary files could not be listed ({type(exc).__name__})")
    for target in targets:
        try:
            try:
                info = target.lstat()
            except FileNotFoundError:
                continue
            if (stat.S_ISLNK(info.st_mode)
                    or getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
                    or not stat.S_ISDIR(info.st_mode)):
                raise ValueError("refusing an unsafe vault data location")
            wipe(target, remove_roots, passes)
        except Exception as exc:
            failures.append(f"{target}: {type(exc).__name__}")

    try:
        try:
            info = managed_root.lstat()
        except FileNotFoundError:
            info = None
        if info is not None:
            if (stat.S_ISLNK(info.st_mode)
                    or getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
                    or not stat.S_ISDIR(info.st_mode)):
                raise ValueError("refusing an unsafe managed profile location")
            wipe(managed_root, True, passes)
    except Exception as exc:
        failures.append(f"{managed_root}: {type(exc).__name__}")

    if not failures:
        location_state = _active_location_state_path()
        try:
            info = location_state.lstat()
        except FileNotFoundError:
            info = None
        if info is not None:
            try:
                if (stat.S_ISLNK(info.st_mode)
                        or getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)):
                    _durable_unlink(location_state)
                elif stat.S_ISREG(info.st_mode):
                    if getattr(info, "st_nlink", 1) > 1:
                        raise ValueError("refusing a multiply-linked active-location state file")
                    shred(location_state, passes)
                else:
                    raise ValueError("refusing an unsupported active-location state file")
            except Exception as exc:
                failures.append(f"{location_state}: {type(exc).__name__}")

    if not failures:
        for artifact in dict.fromkeys(state_artifacts):
            try:
                try:
                    info = artifact.lstat()
                except FileNotFoundError:
                    continue
                if (stat.S_ISLNK(info.st_mode)
                        or getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)):
                    _durable_unlink(artifact)
                elif stat.S_ISREG(info.st_mode):
                    if getattr(info, "st_nlink", 1) > 1:
                        raise ValueError("refusing a multiply-linked profile registry artifact")
                    shred(artifact, passes)
                else:
                    raise ValueError("refusing an unsupported profile registry artifact")
            except Exception as exc:
                failures.append(f"{artifact}: {type(exc).__name__}")
    if remove_roots:
        required_absent = list(dict.fromkeys([*targets, managed_root, *state_artifacts]))
        for path in required_absent:
            try:
                path.lstat()
            except FileNotFoundError:
                continue
            except OSError as exc:
                failures.append(f"{path}: {type(exc).__name__}")
            else:
                failures.append(f"{path}: cleanup target remains")
    if failures:
        raise OSError("Vault wipe incomplete; remaining state was preserved where cleanup failed: "
                      + "; ".join(failures))

def remote_session() -> bool:
    return sys.platform == "win32" and bool(ctypes.windll.user32.GetSystemMetrics(0x1000))
def clear_clipboard() -> None:
    clipboard = QApplication.clipboard()
    if clipboard is not None:
        clipboard.clear()


def nocap(w: QWidget, on: bool) -> None:
    if sys.platform != "win32": return
    try:
        import ctypes; u = ctypes.windll.user32; h = int(w.winId())
        if on and not u.SetWindowDisplayAffinity(h, 0x11): u.SetWindowDisplayAffinity(h, 1)
        elif not on: u.SetWindowDisplayAffinity(h, 0)
    except Exception: pass

def fmt(n: Union[int, float]) -> str:
    return f"{n} B" if n < 1024 else f"{n/1024:.1f} KB" if n < 1048576 else f"{n/1048576:.1f} MB"
def fmt_storage_size(value: object) -> str:
    return fmt(value) if isinstance(value, (int, float)) else "unavailable"

def cdt(sec: Union[int, float]) -> str:
    sec = int(max(0, sec) + .999); d, r = divmod(sec, 86400); h, r = divmod(r, 3600); m, s = divmod(r, 60)
    return f"{d}d {h}h" if d else f"{h}h {m}m" if h else f"{m}m {s}s" if m else f"{s}s"
def vtxt(m: Mapping[str, object]) -> str:
    return f"{m['views']} view(s) left" if m["views"] is not None else "Unlimited views"
def tfmt(t: Union[int, float]) -> str:
    return time.strftime("%d %b %Y  %H:%M:%S", time.localtime(t))
def event_time(record: Mapping[str, object]) -> float:
    timestamp = record.get("t")
    return float(timestamp) if isinstance(timestamp, (int, float)) else 0.0
SUPPORT_CONTACT = "unknown1soldier"
def support_message(text: str) -> str:
    return f"{text}\n\nNeed help? Contact {SUPPORT_CONTACT} on Discord."
def lbl(
    t: str,
    size: int = 14,
    color: str = "#ece8ff",
    bold: bool = False,
    center: bool = False,
) -> QLabel:
    l = QLabel(t); l.setWordWrap(True)
    fam = "font-family:Georgia,'Times New Roman',serif;" if size >= 26 else ""
    l.setStyleSheet(f"{fam}font-size:{size}px;color:{color};font-weight:{700 if bold else 400}")
    if center: l.setAlignment(Qt.AlignmentFlag.AlignCenter)
    return l

def loading_egg_label() -> QLabel:
    message = lbl(EASTER_EGGS.message("loading"), 11, MUT)
    message.setObjectName("easterEggLoadingMessage")
    return message

def cancellation_egg_label() -> QLabel:
    message = lbl("", 11, MUT)
    message.setObjectName("easterEggCancellationMessage")
    message.hide()
    return message

def show_cancellation_egg(dialog: QWidget, message: QLabel) -> None:
    if getattr(dialog, "_cancellation_egg_shown", False):
        return
    setattr(dialog, "_cancellation_egg_shown", True)
    message.setText(EASTER_EGGS.message("cancellation"))
    message.show()

def btn(t: str, name: Optional[str] = None) -> QPushButton:
    b = Btn(t)
    if name: b.setObjectName(name)
    return b

def _clicked_slot(
    callback: Callable[..., object],
    *args: object,
) -> Callable[[bool], None]:
    def invoke(_checked: bool = False) -> None:
        callback(*args)
    return invoke

def _index_changed_slot(callback: Callable[[], object]) -> Callable[[int], None]:
    def invoke(_index: int) -> None:
        callback()
    return invoke

def _noarg_slot(callback: Callable[[], object]) -> Callable[[], None]:
    def invoke() -> None:
        callback()
    return invoke

def nothing_egg_button(callback: Callable[[], object]) -> QPushButton:
    button = QPushButton("Nothing")
    button.setObjectName("nothingEggButton")
    button.setAccessibleName("Harmless Nothing Easter Egg")
    button.setToolTip("Does nothing useful.")
    button.clicked.connect(_noarg_slot(callback))
    return button

def _path_name_key(path: Path) -> str:
    return path.name.casefold()

def profile_action_button(
    text: str,
    callback: Callable[[], object],
    style: Optional[str] = None,
) -> QPushButton:
    button = btn(text, style)
    button.clicked.connect(_clicked_slot(callback))
    return button

BIG = 1 << 20   # files from 1 MB up get the "% loaded" window when opened or burned
def tlbl(
    t: str,
    size: int = 13,
    color: str = "#33ff66",
    bold: bool = False,
) -> QLabel:
    l = QLabel(t); l.setWordWrap(True); weight = ";font-weight:bold" if bold else ""; l.setStyleSheet(f"font-family:Consolas,'DejaVu Sans Mono',monospace;font-size:{size}px;color:{color};background:transparent{weight}"); return l
def terminal_confirm(
    parent: Optional[QWidget],
    title: str,
    command: str,
    details: Iterable[str],
    acknowledge: bool = False,
) -> bool:
    dialog = QDialog(parent); dialog.setWindowTitle(title)
    screen = parent.screen() if parent is not None else QApplication.primaryScreen()
    available = screen.availableGeometry() if screen is not None else QRectF(0, 0, 900, 700)
    dialog.setMinimumWidth(int(min(500, max(320, available.width() - 32))))
    dialog.setMaximumWidth(int(max(320, available.width() - 16)))
    layout = QVBoxLayout(dialog); frame = QFrame(); frame.setObjectName("term"); inside = QVBoxLayout(frame)
    inside.addWidget(tlbl(f"root@unknwn:~$ {command}", 13, "#ff8a65"))
    for detail in details: inside.addWidget(tlbl("> " + detail, 12, "#d8d3c3"))
    layout.addWidget(frame)
    check = None
    if acknowledge:
        check = QCheckBox("I understand this action cannot be undone.")
        layout.addWidget(check)
    row = QHBoxLayout(); cancel = btn("ABORT"); execute = btn("EXECUTE", "danger")
    if check: execute.setEnabled(False); check.toggled.connect(execute.setEnabled)
    cancel.clicked.connect(dialog.reject); execute.clicked.connect(dialog.accept)
    row.addWidget(cancel); row.addWidget(execute); layout.addLayout(row)
    return dialog.exec_() == QDialog.DialogCode.Accepted
QSS = """QWidget{color:#ece8ff;font-size:13px;font-family:Consolas,'Cascadia Mono','DejaVu Sans Mono',monospace}
QLineEdit,QComboBox,QKeySequenceEdit{background:#0b0816;border:1px solid #2a2145;border-radius:2px;padding:9px 11px}
QLineEdit:focus,QComboBox:focus,QKeySequenceEdit:focus{border:1px solid #8b5cff}
QComboBox QAbstractItemView,QListWidget{background:#0b0816;color:#ece8ff;border:1px solid #2a2145;selection-background-color:#6d3df0;selection-color:#ffffff}
QListWidget::item{padding:6px 8px;color:#ece8ff}
QListWidget::item:selected{background:#6d3df0;color:#ffffff}
QMenu{background:rgba(20,14,36,.88);color:#ece8ff;border:1px solid #2a2145;padding:4px}
QMenu::item{background:transparent;color:#ece8ff;padding:6px 28px 6px 12px}
QMenu::item:selected{background:#6d3df0;color:#ffffff}
QMenu::item:disabled{color:#6b6390}
QPushButton{background:rgba(255,255,255,.05);border:1px solid #2a2145;border-radius:2px;padding:9px 16px}
QPushButton:checked{border-color:#22d3ee;color:#b7f7ff}
QPushButton:hover{border-color:#8b5cff}QPushButton:focus{border:1px solid #22d3ee}QPushButton:disabled{color:#5b5378}
QPushButton#go{background:qlineargradient(x1:0,y1:0,x2:1,y2:1,stop:0 #8b5cff,stop:1 #22a6d8);border:0;font-weight:700;color:#fff}
QPushButton#danger{background:#2d0b14;border:1px solid #ff3b5c;color:#ffb3c0;font-weight:700}
QPushButton#tab{background:transparent;border:0;border-bottom:2px solid transparent;border-radius:0;padding:8px 20px;color:#8a82a8}
QPushButton#tab:checked{color:#fff;border-bottom:2px solid #8b5cff}
QPushButton#flat{background:transparent;border:0;color:#8a82a8;text-decoration:underline}
QCheckBox::indicator{width:16px;height:16px;border:1px solid #3a2e66;border-radius:4px;background:#0b0816}
QCheckBox::indicator:checked{background:#8b5cff;border-color:#8b5cff}
QFrame#card{background:rgba(20,14,36,.88);border:1px solid #2a2145;border-radius:2px}
QFrame#folderHeader{background:rgba(20,14,36,.55);border:1px solid #2a2145;border-left:3px solid #8b5cff;border-radius:2px}
QScrollArea,QScrollArea>QWidget,QScrollArea>QWidget>QWidget{background:transparent;border:0}
QDialog,QMessageBox{background:#140e24}
QPlainTextEdit{background:#0b0816;border:1px solid #2a2145;border-radius:2px}
QFrame#term{background:#020a04;border:1px solid #1f9d45;border-radius:2px}QFrame#term QLineEdit{background:#000;border:1px solid #1f9d45;color:#33ff66}QFrame#term QCheckBox{color:#33ff66}"""
def _tstyle(t: str) -> str:
    if S("tstyle"): return t
    return t.replace("border-radius:2px", "border-radius:8px").replace("font-family:Consolas,'Cascadia Mono','DejaVu Sans Mono',monospace", "").replace("font-size:13px", "font-size:14px")
def qss() -> str:
    c = _QC(TH["panel"]); return _tstyle(th(QSS)).replace("color:#fff}", f"color:{TH['on']}}}").replace("color:#fff;", f"color:{TH['fg']};").replace("rgba(20,14,36,.88)", f"rgba({c.red()},{c.green()},{c.blue()},.88)")


def _refresh_theme() -> None:
    set_theme()
    application = QApplication.instance()
    if not isinstance(application, QApplication):
        return
    application.setStyleSheet(qss())
    for widget in QApplication.allWidgets():
        if isinstance(widget, OperationCenterDialog):
            OperationCenterDialog.apply_theme(widget)
        widget.update()


# ---------- animated widgets ----------
QUOTES = ["The more you become silent, the more you are able to hear.", "What no one can see, no one can take.", "A locked door says nothing. That is its strength.",
    "Be the shadow that leaves no footprints.", "Silence is not empty. It is full of answers.", "The deepest secrets are kept by those who never speak of them.",
    "Not everything that matters needs an audience.", "To be unseen is to be free.", "Some doors open only from the inside.", "The quieter the room, the louder the truth.",
    "Let them wonder. Mystery is a kind of armor.", "You owe the world your work, not your whole story.", "What burns leaves no witness.",
    "Peace is a closed curtain and an open mind.", "Even the moon keeps its far side to itself.", "Those who guard their silence guard their strength.",
    "Forget the crowd. Remember yourself.", "A secret shared is a secret half lost.", "Walk softly. Leave nothing but quiet.", "The unknown is not empty. It is protected.",
    "Somewhere between the signal and the silence, a choice is made.",
    "A calm mind can hear the lock turn before the door moves.",
    "Keep your own counsel; let your actions speak clearly.",
    "The safest path is often the one you choose with care.",
    "A quiet boundary is still a boundary.",
    "What you protect today can become room to grow tomorrow.",
    "Not every light is meant to be seen from the road.",
    "Patience is a key that does not break in the lock.",
    "Make space for the things that deserve to stay private.",
    "The signal fades; the choice remains.",
    "A steady hand makes fewer doors than noise ever could.",
    "When the room grows quiet, listen for what matters.",
    "A good keeper knows what to carry and what to leave.",
    "The night is wide, but a clear purpose finds its way.",
    "No map can replace knowing where you stand.",
    "Protect what matters; give the rest room to breathe.",
    "Every boundary begins with a decision.",
    "The smallest light can still mark a way home.",
    "Leave the noise outside. Bring only what is yours.",
    "A private moment is still a life fully lived.",
    "Some answers arrive only after the signal stops.",
    "The door remembers every careful hand.",
    "Keep your center when the outside world shifts.",
    "A little distance can make the important things clear.",
    "Quiet is not absence; it is a place to think.",
    "Choose your own direction before the horizon chooses for you.",
    "Even in the dark, a deliberate step is still a step."]

class Btn(QPushButton):
    """Every button: animated hover glow + light sweep, and a ripple where you click."""
    def __init__(self, t: str) -> None:
        super().__init__(t); self._raw_text = t; self._h = self._r = 0.0; self.pt = QPointF(); self.setCursor(Qt.CursorShape.PointingHandCursor)
        self._fit_text()
        self.ah = QPropertyAnimation(self, b"hv", self); self.ah.setDuration(240); self.ar = QPropertyAnimation(self, b"rp", self); self.ar.setDuration(560); self.ar.setStartValue(0.0); self.ar.setEndValue(1.0)
    def setText(self, text: Optional[str]) -> None:
        text = text or ""
        self._raw_text = text
        self._fit_text()
    def _fit_text(self) -> None:
        if not hasattr(self, "_raw_text"): return
        text = " ".join(str(self._raw_text).split())
        width = max(1, self.width() - 32)
        metrics = QFontMetrics(self.font()); lines: list[str] = []; line = ""
        for word in text.split():
            candidate = f"{line} {word}".strip()
            if line and metrics.horizontalAdvance(candidate) > width:
                lines.append(line); line = word
            else: line = candidate
        if line: lines.append(line)
        rendered = "\n".join(lines) if lines else ""
        if rendered != QPushButton.text(self): QPushButton.setText(self, rendered)
        self.setMinimumHeight(max(38, metrics.height() * max(1, len(lines)) + 16))
    def resizeEvent(self, a0: Any) -> None:
        self._fit_text(); super().resizeEvent(a0)
    def geth(self) -> float: return self._h
    def seth(self, v: float) -> None: self._h = v; self.update()
    hv = pyqtProperty(float, geth, seth)
    def getr(self) -> float: return self._r
    def setr(self, v: float) -> None: self._r = v; self.update()
    def reset_animation(self) -> None:
        self.ah.stop(); self.ar.stop(); self._h = self._r = 0.0; self.update()
    rp = pyqtProperty(float, getr, setr)
    def enterEvent(self, a0: Any) -> None:
        if not S("reduce_motion"): self.ah.stop(); self.ah.setEndValue(1.0); self.ah.start()
        super().enterEvent(a0)
    def leaveEvent(self, a0: Any) -> None:
        if not S("reduce_motion"): self.ah.stop(); self.ah.setEndValue(0.0); self.ah.start()
        super().leaveEvent(a0)
    def mousePressEvent(self, e: Optional[QMouseEvent]) -> None:
        if e is None:
            super().mousePressEvent(e)
            return
        if not S("reduce_motion"): self.pt = QPointF(e.pos()); self.ar.stop(); self.ar.start()
        super().mousePressEvent(e)
    def paintEvent(self, a0: Any) -> None:
        super().paintEvent(a0)
        if not self.isEnabled() or (self._h <= 0 and self._r <= 0): return
        g = QPainter(self); g.setRenderHint(QPainter.RenderHint.Antialiasing); a = QColor(TH["acc"]); w, h = self.width(), self.height(); p = QPainterPath(); p.addRoundedRect(QRectF(self.rect()).adjusted(1, 1, -1, -1), 8, 8); g.setClipPath(p)
        if self._h > 0:
            x = -w * .5 + self._h * w * 1.5; sh = QLinearGradient(x, 0, x + w * .5, h); sh.setColorAt(0, QColor(255, 255, 255, 0)); sh.setColorAt(.5, QColor(255, 255, 255, 46)); sh.setColorAt(1, QColor(255, 255, 255, 0))
            g.fillRect(self.rect(), sh); g.setPen(QPen(QColor(a.red(), a.green(), a.blue(), int(210 * self._h)), 2)); g.setBrush(Qt.BrushStyle.NoBrush); g.drawPath(p)
        if self._r > 0: rr = self._r * max(w, h) * 1.3; g.setPen(Qt.PenStyle.NoPen); g.setBrush(QColor(a.red(), a.green(), a.blue(), int(120 * (1 - self._r)))); g.drawEllipse(self.pt, rr, rr)

class Term(QWidget):
    """Terminal screen: types its script line by line (text, colour, chars/sec, pause ms). Used by the intro and the unlock sequence."""
    BG, FG, DIM, WHT, AMB = "#020a04", "#33ff66", "#1f9d45", "#e8ffe8", "#ffb347"; overlay = False
    def __init__(
        self,
        p: Optional[QWidget],
        script: list[tuple[str, str, int, int]],
        done: Optional[Callable[[], object]],
        skippable: bool = True,
    ) -> None:
        super().__init__(p); self.sc, self.done, self.skippable = script, done, skippable
        self.out: list[list[str]] = []; self.i = self.c = self.wait = 0; self.acc = 0.0; self.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        self.label = getattr(type(self), "label", "VAULT ACCESS"); self.tone = getattr(type(self), "tone", self.FG)
        self.tm = QTimer(self); self.tm.timeout.connect(self.step); self.tm.start(30)
    def step(self) -> None:
        self.update()
        if self.wait > 0: self.wait -= 30; return
        if self.i >= len(self.sc): self.tm.stop(); return self.end()
        txt, col, cps, pause = self.sc[self.i]
        if self.c == 0: self.out.append(["", col])
        self.acc += cps * .03; k = int(self.acc); self.acc -= k; self.c = min(len(txt), self.c + k); self.out[-1][0] = txt[:self.c]
        if self.c >= len(txt): self.i += 1; self.c = 0; self.wait = pause
    def end(self) -> None:
        if self.done:
            d, self.done = self.done, None
            if self.overlay: self.hide(); self.deleteLater()
            d()
    def mousePressEvent(self, a0: Any) -> None:
        if self.skippable: self.tm.stop(); self.end()
    def keyPressEvent(self, a0: Any) -> None:
        if self.skippable: self.tm.stop(); self.end()
    def paintEvent(self, a0: Any) -> None:
        g = QPainter(self); w, h = self.width(), self.height(); g.fillRect(self.rect(), _QC(self.BG)); f = QFont("Consolas", 12); f.setStyleHint(QFont.StyleHint.Monospace); g.setFont(f)
        g.setPen(QPen(_QC(self.DIM), 1)); g.setBrush(Qt.BrushStyle.NoBrush); g.drawRect(QRectF(self.rect()).adjusted(8, 8, -9, -9))
        hud = QFont("Consolas", 9); hud.setStyleHint(QFont.StyleHint.Monospace); g.setFont(hud); g.setPen(_QC(self.tone))
        g.drawText(24, 29, "UNKNWN  //  " + self.label); g.drawText(max(24, w - 170), 29, "LOCAL  |  OFFLINE")
        g.setPen(QPen(_QC(self.DIM), 1)); g.drawLine(22, 36, w - 22, 36)
        f.setPointSize(12); g.setFont(f)
        fm = g.fontMetrics(); lh = int(fm.height() * 1.5); n = max(1, (h - 112) // lh); lines = self.out[-n:]; x = max(24, int(w * .08)); y = 56 + fm.ascent(); typing = self.i < len(self.sc)
        for i, (t, col) in enumerate(lines): g.setPen(_QC(col)); g.drawText(x, y + i * lh, t + ("\u2588" if typing and i == len(lines) - 1 and int(time.time() * 2.5) % 2 else ""))
        scan_y = int((time.monotonic() * 95) % max(1, h))
        scan_color = _QC(self.tone); scan_color.setAlpha(30)
        scan = QLinearGradient(0, scan_y - 8, 0, scan_y + 8); scan.setColorAt(0, _QC(0, 0, 0, 0)); scan.setColorAt(.5, scan_color); scan.setColorAt(1, _QC(0, 0, 0, 0))
        g.fillRect(10, scan_y - 8, w - 20, 16, scan)
        progress = (self.i + (self.c / max(1, len(self.sc[self.i][0])) if self.i < len(self.sc) else 0)) / max(1, len(self.sc))
        g.setPen(QPen(_QC(self.DIM), 1)); g.drawLine(22, h - 38, w - 22, h - 38)
        g.setPen(QPen(_QC(self.DIM), 2)); g.drawLine(24, h - 23, w - 24, h - 23)
        g.setPen(QPen(_QC(self.tone), 2)); g.drawLine(24, h - 23, int(24 + (w - 48) * progress), h - 23)
        g.setPen(_QC(self.DIM)); g.setFont(hud)
        g.drawText(24, h - 44, f"PHASE {min(self.i + 1, len(self.sc)):02d}/{len(self.sc):02d}  |  {int(progress * 100):02d}%")
        if self.skippable: g.drawText(max(24, w - 230), h - 44, "CLICK / KEY TO CONTINUE")

class Intro(Term):
    """Cinematic local-vault boot sequence, followed by a short quote."""
    overlay = True
    label = "SECURE BOOT"
    def __init__(
        self,
        p: QWidget,
        n: int,
        done: Callable[[], object],
        startup_checks: Optional[Mapping[str, str]] = None,
    ) -> None:
        sc = startup_script(n, startup_checks)
        super().__init__(p, sc, done, True); self.setGeometry(p.rect()); self.show(); self.raise_(); self.setFocus()

class SecurityFailurePulse(QLabel):
    """Persistent animated indicator created only for a blocked startup state."""
    def __init__(self, parent: QWidget) -> None:
        super().__init__("STARTUP BLOCKED", parent)
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setStyleSheet("color:#ff6b6b;font-size:18px;font-weight:700;letter-spacing:2px")
        opacity = QGraphicsOpacityEffect(self)
        self.setGraphicsEffect(opacity)
        self.animation = QPropertyAnimation(opacity, b"opacity", self)
        self.animation.setDuration(900)
        self.animation.setStartValue(0.35)
        self.animation.setEndValue(1.0)
        self.animation.setEasingCurve(QEasingCurve.Type.InOutSine)
        self.animation.setLoopCount(-1)
        self.animation.start()

class LockSequence(Term):
    """Low-cost terminal lock sequence: typed status lines, a short hold, then removal."""
    overlay = True
    label = "SESSION LOCK"
    tone = Term.AMB
    def __init__(self, parent: QWidget) -> None:
        clipboard = "cleared" if S("clip") or S("ghost") else "preserved by policy"
        script = [("> SESSION CLOSING", Term.AMB, 110, 180),
                  ("> active viewer .......... released", Term.DIM, 115, 130),
                  (f"> clipboard .............. {clipboard}", Term.DIM, 115, 130),
                  ("> session key ............ locked", Term.WHT, 100, 220),
                  ("", Term.DIM, 50, 90),
                  ("  [  SESSION SEALED  ]", Term.AMB, 80, 1100)]
        super().__init__(parent, script, lambda: None, False)
        self.setGeometry(parent.rect()); self.show(); self.raise_()

class ProfileSwitchSequence(Term):
    """A distinct terminal handoff shown after the current vault has been locked."""
    overlay = True
    label = "PROFILE HANDOFF"
    tone = "#22d3ee"
    def __init__(
        self,
        parent: QWidget,
        done: Callable[[], object],
        profile_count: Optional[int] = None,
    ) -> None:
        registry_status = (
            f"verified; {profile_count} profile(s) available"
            if profile_count is not None else "verification pending"
        )
        script = [("> PROFILE SWITCH REQUESTED", Term.AMB, 130, 180),
                  ("> active session ........... locked", Term.WHT, 125, 160),
                  ("> current profile key ...... released", Term.DIM, 125, 180),
                  (f"> profile registry ......... {registry_status}", Term.DIM, 125, 200),
                  ("", Term.DIM, 60, 100),
                  ("  [  SELECT THE NEXT VAULT  ]", Term.FG, 110, 650)]
        super().__init__(parent, script, done, True)
        self.setGeometry(parent.rect()); self.show(); self.raise_()

class PanicSequence(Term):
    """Terminal-style, non-skippable wipe status before the existing wipe routine runs."""
    overlay = True
    label = "VAULT WIPE"
    tone = "#ff8a65"
    def __init__(
        self,
        parent: QWidget,
        done: Callable[[], object],
        mode: str = "full",
    ) -> None:
        script = [("> WIPE SEQUENCE ACCEPTED", Term.AMB, 150, 160),
                  ("> sealed catalog .......... queued", Term.DIM, 150, 120),
                  ("> encrypted files ......... deletion queued", Term.DIM, 150, 140),
                  ("> physical erasure ........ not guaranteed", Term.DIM, 150, 140),
                  ("> cleanup journal .......... committed", Term.WHT, 145, 180),
                  ("", Term.DIM, 50, 100),
                  ("  [  JOURNALED CLEANUP :: RECOVERY PROTECTED  ]", Term.AMB, 120, 500)]
        scale = {"full": 1.0, "short": 2.0, "none": 5.0}.get(mode, 1.0)
        script = [(text, color, int(cps * scale), int(pause / scale)) for text, color, cps, pause in script]
        super().__init__(parent, script, done, False)
        self.setGeometry(parent.rect()); self.show(); self.raise_()

def startup_script(
    detail: int = 3,
    startup_checks: Optional[Mapping[str, str]] = None,
) -> list[tuple[str, str, int, int]]:
    integrity = {
        "ok": "verified",
        "dev": "not enforced (development/source run)",
        "fail": "FAILED - package untrusted",
    }.get(release_integrity_state, "unavailable")
    runtime = {
        "clear": "verified",
        "debugger": "FAILED - debugger/tracer detected",
        "unavailable": "FAILED - required probe unavailable",
        "not_enforced": "not enforced (development/source run)",
        "not_run": "not run (release integrity failed)",
    }.get(runtime_trust_state, "unavailable - startup blocked")
    gate = {
        "ok": "trusted",
        "dev": "development (not enforced)",
        "fail": f"FAILED - startup blocked ({integ_error})",
    }.get(INTEG[0], "unavailable - startup blocked")
    checks = startup_checks or {}
    location = checks.get("location", startup_location_state)
    config = checks.get("config", startup_config_state)
    cleanup = checks.get("cleanup", "not run")
    def state_text(value: str, labels: Mapping[str, str]) -> str:
        return labels.get(value, "unavailable")
    sc = [("UNKNWN :: LOCAL RELEASE", Term.FG, 160, 35),
          ("> signed package signature/inventory " + integrity, Term.DIM, 260, 25),
          ("> protected manifest ............. " +
           {
               "ok": "authenticated, parsed; inventory verified",
               "dev": "not applicable (development/source run)",
               "fail": "FAILED - authentication or inventory",
           }.get(release_integrity_state, "unavailable"), Term.DIM, 260, 25),
          ("> runtime debugger/tracing ....... " + runtime, Term.DIM, 260, 25),
          ("> persisted location ............. " + state_text(location, {
              "validated": "validated", "failed": "FAILED",
              "not_run": "not run (earlier gate blocked)",
              "unavailable": "unavailable; startup blocked",
          }), Term.DIM, 260, 25),
          ("> persisted config ............... " + state_text(config, {
              "loaded": "parsed; vault authentication still required",
              "recovered_backup": "primary unavailable; valid backup selected",
              "empty": "no recognized vault config; setup/sign-in flow decides",
              "damaged": "FAILED; configuration recovery required",
              "not_run": "not run (earlier gate blocked)",
              "unavailable": "unavailable; startup blocked",
          }), Term.DIM, 260, 25),
          ("> cleanup recovery journal ....... " + state_text(cleanup, {
              "clear": "validated; none pending",
              "pending": "validated; recovery is required",
              "invalid": "FAILED; recovery screen required",
              "not_run": "not run",
              "not applicable": "not applicable",
              "unavailable": "unavailable; recovery screen required",
          }), Term.DIM, 260, 25),
          ("> profile/storage recovery ....... deferred until profile/authentication", Term.DIM, 260, 25),
          ("> startup security policy ........ " + gate, Term.AMB, 260, 35)]
    if detail >= 3:
        sc += [("> encrypted vault index .......... not read before authentication", Term.DIM, 260, 20),
               ("> WARDEN display ................. visual only; no security decision", Term.DIM, 260, 20)]
    final_access = (
        "> password/unlock readiness ....... BLOCKED"
        if INTEG[0] == "fail"
        else "> password/unlock readiness ....... authentication required"
    )
    sc += [(final_access, Term.AMB, 260, 30),
           ("  [ STARTUP BLOCKED :: ACKNOWLEDGMENT REQUIRED ]" if INTEG[0] == "fail"
            else "  [ VAULT SEALED :: AUTHENTICATION REQUIRED ]", Term.FG, 210, 180)]
    return [(text, color, max(30, int(cps * .6)), pause) for text, color, cps, pause in sc]

def unlock_script() -> list[tuple[str, str, int, int]]:
    F, D, A = Term.FG, Term.DIM, Term.AMB
    return [("> CREDENTIAL ACCEPTED", F, 110, 120),
            ("> vault key authenticated ............... ok", D, 130, 150),
            ("> security policy verified .............. ok", D, 130, 150),
            ("> private session established ........... ok", D, 130, 150),
            ("", F, 60, 80),
            ("   +----------------------------------+", A, 130, 40),
            ("   |   SEALED VAULT  ::  ACCESS GRANTED |", A, 130, 40),
            ("   +----------------------------------+", A, 130, 450)]

class Unlock(Term):
    """After a correct password: a terminal that appears to decrypt and load everything, then hands over to the vault."""
    def __init__(self, done: Callable[[], object], parent: QWidget) -> None:
        super().__init__(parent, unlock_script(), done, False)

_LAST_WARDEN_ART: Optional[str] = None

def random_warden_art() -> str:
    global _LAST_WARDEN_ART
    choices = WARDEN_ART if _LAST_WARDEN_ART is None else tuple(art for art in WARDEN_ART if art != _LAST_WARDEN_ART)
    if not choices: choices = WARDEN_ART
    _LAST_WARDEN_ART = random.choice(choices)  # pyright: ignore[reportConstantRedefinition]
    assert _LAST_WARDEN_ART is not None
    return _LAST_WARDEN_ART

def warden_script() -> list[tuple[str, str, int, int]]:
    art = random_warden_art().splitlines()
    while art and not art[0].strip(): art.pop(0)
    while art and not art[-1].strip(): art.pop()
    art = [line.expandtabs(4)[:140] for line in art[:100]]
    lines = [("> WARDEN ONLINE  ::  LOCAL SESSION", Term.AMB, 180, 110),
             ("> local identity ............ verified", Term.DIM, 180, 35),
             ("", Term.DIM, 100, 20)]
    lines.extend((line, Term.AMB if i < len(art) // 2 else Term.WHT, 5000, 6) for i, line in enumerate(art))
    lines.extend([("", Term.DIM, 100, 25),
                  ("> " + EASTER_EGGS.message("warden"), Term.DIM, 180, 60),
                  ("> sealed catalog ........... ready", Term.DIM, 200, 55),
                  ("  [  WARDEN  /  ACCESS RESTORED  ]", Term.FG, 180, 2600)])
    return lines

class Warden(Term):
    """Brief terminal identity sequence after the successful password transition."""
    label = "WARDEN // ACCESS"
    tone = Term.AMB
    def __init__(self, done: Callable[[], object], parent: QWidget) -> None:
        script = warden_script(); self.art_start = 3; self.art_count = max(0, len(script) - 7)
        super().__init__(parent, script, done, True)
        self.quip_script_index = self.art_start + self.art_count + 1
        self.quip_label = QLabel("", self)
        self.quip_label.setObjectName("wardenIntroQuip")
        self.quip_label.setWordWrap(True)
        self.quip_label.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        self.quip_label.setStyleSheet(
            "color:#b2e8bd;background:transparent;font-family:Consolas,monospace;font-size:10pt;")
        self.quip_label.setAccessibleName("WARDEN decorative intro message")
        self.quip_label.hide()
        self._position_quip_label()
    def _position_quip_label(self) -> None:
        height = self.height()
        top = max(42, height - 128)
        self.quip_label.setGeometry(24, top, max(1, self.width() - 48),
                                    max(24, height - top - 48))
    def step(self) -> None:
        super().step()
        if self.quip_script_index < len(self.out):
            self.quip_label.setText(self.out[self.quip_script_index][0])
            self.quip_label.show()
    def resizeEvent(self, a0: Any) -> None:
        super().resizeEvent(a0)
        self._position_quip_label()
    def paintEvent(self, a0: Any) -> None:
        g = QPainter(self); w, h = self.width(), self.height()
        g.fillRect(self.rect(), _QC(self.BG)); g.setPen(QPen(_QC(self.DIM), 1)); g.setBrush(Qt.BrushStyle.NoBrush)
        g.drawRect(QRectF(self.rect()).adjusted(8, 8, -9, -9))
        hud = QFont("Consolas", 9); hud.setStyleHint(QFont.StyleHint.Monospace); g.setFont(hud); g.setPen(_QC(self.tone))
        g.drawText(24, 29, "UNKNWN  //  " + self.label); g.drawText(max(24, w - 170), 29, "LOCAL  |  OFFLINE")
        g.setPen(QPen(_QC(self.DIM), 1)); g.drawLine(22, 36, w - 22, 36)
        art = self.out[self.art_start:self.art_start + self.art_count]
        source = self.sc[self.art_start:self.art_start + self.art_count]
        max_chars = max((len(line) for line, _, _, _ in source), default=1)
        art_top = 48
        art_bottom = max(art_top + 1, h - 145)
        art_height = art_bottom - art_top
        px = max(4, min(14, int((w - 64) / max(1, max_chars * .62)),
                        int(art_height / max(1, self.art_count * 1.12))))
        font = QFont("Consolas"); font.setStyleHint(QFont.StyleHint.Monospace); font.setPixelSize(px); g.setFont(font)
        metrics = g.fontMetrics(); line_h = max(px, metrics.height())
        y = max(50, int(art_top + (art_height - line_h * self.art_count) / 2))
        width = max_chars * px * .62; x = max(24, int((w - width) / 2))
        for i, (line, color) in enumerate(art):
            g.setPen(_QC(color)); g.drawText(x, y + i * line_h + metrics.ascent(), line)
        g.setPen(QPen(_QC(self.DIM), 1)); g.drawLine(22, h - 38, w - 22, h - 38)
        g.setPen(_QC(self.tone)); g.drawText(24, h - 17, "WARDEN // IDENTITY DISPLAY")
        if self.skippable: g.drawText(max(24, w - 230), h - 17, "CLICK / KEY TO CONTINUE")

def tmp_media_path(name: str) -> Path:
    d = HOME / "tmp"; d.mkdir(parents=True, exist_ok=True)
    p = d / (secrets.token_hex(16) + re.sub(r"[^.a-z0-9]", "", Path(name).suffix.lower())[:8])
    if not tmp_path_owned(p): raise ValueError("Temporary media path escaped the app temp directory")
    return p
def tmp_media(name: str, data: bytes, chunk_size: int = 1 << 20) -> Path:
    """Write decrypted media to an app-owned temp file; cleanup is best-effort."""
    p = tmp_media_path(name)
    mv = memoryview(data)
    created = False
    try:
        with open(p, "xb") as f:
            created = True
            for i in range(0, len(mv), chunk_size):
                f.write(mv[i:i + chunk_size])
            f.flush(); os.fsync(f.fileno())
    except Exception:
        if created:
            try: p.unlink()
            except FileNotFoundError: pass
            except OSError: log_security_event("temp_create_cleanup_failed", error="OSError")
        raise
    return p
def tmp_path_owned(p: Union[os.PathLike[str], str]) -> bool:
    base = HOME.resolve(strict=False) / "tmp"
    directory = HOME / "tmp"
    try: return directory.resolve(strict=False) == base and Path(p).parent.resolve(strict=False) == base
    except OSError: return False
def tmp_wipe(p: Union[os.PathLike[str], str], tries: int = 12) -> None:
    p = Path(p)
    if not tmp_path_owned(p): return
    try:
        if p.is_symlink(): p.unlink()
        elif p.exists(): shred(p)
    except OSError as e:
        log_security_event("temp_cleanup_retry", error=type(e).__name__)
    try: remains = p.exists() or p.is_symlink()
    except OSError:
        remains = True
    if remains:
        log_security_event("temp_cleanup_retry", error="file_still_present")
        QTimer.singleShot(500, lambda: tmp_wipe(p, max(0, tries - 1)))
def tmp_sweep() -> None:   # leftovers from a crash
    d = HOME / "tmp"
    if not d.is_dir(): return
    for p in d.iterdir():
        try:
            if p.is_file() or p.is_symlink(): tmp_wipe(p)
        except OSError as e: log_security_event("temp_sweep_failed", error=type(e).__name__)
def cleanup_temp_files() -> None:
    d = HOME / "tmp"
    if not d.exists() or not d.is_dir(): return
    for p in list(d.iterdir()):
        try:
            if p.is_file() or p.is_symlink(): tmp_wipe(p)
        except OSError as e: log_security_event("temp_cleanup_failed", error=type(e).__name__)

def draw_lock(
    g: QPainter,
    cx: Union[int, float],
    cy: Union[int, float],
    sc: float,
    ang: float,
    heat: float,
    crack: float = 0.0,
) -> None:
    """A padlock drawn from code. heat 0..1: cold steel -> orange -> white-hot. ang: degrees the shackle is swung open. crack: glowing fractures 0..1."""
    def mixc(
        a: tuple[int, int, int],
        b: tuple[int, int, int],
        t: float,
    ) -> tuple[int, int, int]:
        factor = max(0.0, min(1.0, t))
        return (
            int(a[0] + (b[0] - a[0]) * factor),
            int(a[1] + (b[1] - a[1]) * factor),
            int(a[2] + (b[2] - a[2]) * factor),
        )
    hc = mixc((58, 62, 76), (255, 120, 20), heat * 2) if heat < .5 else mixc((255, 120, 20), (255, 244, 210), (heat - .5) * 2)
    g.save(); g.translate(cx, cy); g.scale(sc, sc)
    if heat > .15:
        g.setCompositionMode(QPainter.CompositionMode.CompositionMode_Plus); rg = QRadialGradient(0, 14, 130); rg.setColorAt(0, _QC(255, 140, 30, int(200 * heat))); rg.setColorAt(1, _QC(255, 60, 0, 0))
        g.setPen(Qt.PenStyle.NoPen); g.setBrush(rg); g.drawEllipse(QPointF(0, 14), 130, 130); g.setCompositionMode(QPainter.CompositionMode.CompositionMode_SourceOver)
    bg = QLinearGradient(0, -14, 0, 44); bg.setColorAt(0, _QC(*mixc(hc, (255, 255, 255), .25))); bg.setColorAt(1, _QC(*mixc(hc, (0, 0, 0), .45)))
    g.setPen(QPen(_QC(*mixc(hc, (0, 0, 0), .3)), 2)); g.setBrush(bg); g.drawRoundedRect(QRectF(-38, -14, 76, 58), 12, 12)
    sh = QPainterPath(); sh.moveTo(0, 0); sh.lineTo(0, -28); sh.arcTo(QRectF(0, -50, 44, 44), 180, -180); sh.lineTo(44, -6)
    pen = QPen(_QC(*mixc(hc, (255, 255, 255), .15)), 10); pen.setCapStyle(Qt.PenCapStyle.RoundCap); pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
    g.save(); g.translate(-22, -14); g.rotate(-ang); g.setPen(pen); g.setBrush(Qt.BrushStyle.NoBrush); g.drawPath(sh); g.restore()
    g.setPen(Qt.PenStyle.NoPen); g.setBrush(_QC(*mixc((16, 8, 6), (255, 250, 230), (heat - .6) / .4))); g.drawEllipse(QPointF(0, 12), 7, 7); g.drawRect(QRectF(-3, 14, 6, 16))
    if crack > 0:   # glowing fractures spreading from the keyhole
        rr = random.Random(7); g.setCompositionMode(QPainter.CompositionMode.CompositionMode_Plus); g.setPen(QPen(_QC(255, 220, 120, int(230 * min(1, crack * 2))), 2))
        for _ in range(7):
            a = rr.uniform(0, 6.283); x, y = 0.0, 12.0
            for _ in range(5): a += rr.uniform(-.7, .7); x2 = x + math.cos(a) * 11 * crack; y2 = y + math.sin(a) * 11 * crack; g.drawLine(QPointF(x, y), QPointF(x2, y2)); x, y = x2, y2
        g.setCompositionMode(QPainter.CompositionMode.CompositionMode_SourceOver)
    g.restore()

class Seal(QWidget):
    """Locking animation: the window spirals into a glowing lock, the shackle slams shut in a white-hot flash, the metal cools, SEALED."""
    def __init__(self, p: QWidget) -> None:
        super().__init__(p); self.pm = p.grab(); self._t = 0.0; self.f: list[list[float]] = []; self.hit = False; self.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents); self.setGeometry(p.rect()); self.show(); self.raise_()
        a = QPropertyAnimation(self, b"t", self); a.setDuration(2300); a.setStartValue(0.0); a.setEndValue(1.0); a.finished.connect(self.deleteLater); self.a = a; a.start()
        self.tm = QTimer(self); self.tm.timeout.connect(self.step); self.tm.start(33 if perf() == "full" else 50)
    def gett(self) -> float: return self._t
    def sett(self, v: float) -> None: self._t = v; self.update()
    t = pyqtProperty(float, gett, sett)
    def step(self) -> None:
        w, h = self.width(), self.height(); cx, cy = w / 2, h * .40; t = self._t; n = 14 if perf() == "full" else 6; r = random.uniform
        if t < .30:   # vortex of embers streaming off the collapsing window into the lock
            e = t / .30; e = e * e * (3 - 2 * e); px = w / 2 + (cx - w / 2) * e; py = h / 2 + (cy - h / 2) * e; hw = w / 2 * (1 - .96 * e); hh = h / 2 * (1 - .96 * e)
            for _ in range(n): a = r(0, 6.283); self.f.append([px + math.cos(a) * hw, py + math.sin(a) * hh, 0.0, 0.0, 1.0, r(.02, .035), r(2, 6), 1])
        if t >= .5 and not self.hit:   # impact: sparks fly
            self.hit = True
            for _ in range(80 if perf() == "full" else 30): a = r(0, 6.283); sp = r(2, 10); self.f.append([cx, cy + 10, math.cos(a) * sp, math.sin(a) * sp - 1, 1.0, r(.018, .04), r(2, 6), 0])
        if .5 < t < .82:
            for _ in range(3): self.f.append([cx + r(-34, 34), cy + r(-10, 40), r(-.5, .5), -r(.6, 2.2), 1.0, r(.015, .03), r(1.5, 3.5), 0])
        for q in self.f:
            if q[7]: q[2] += (cx - q[0]) * .02 - (cy - q[1]) * .012; q[3] += (cy - q[1]) * .02 + (cx - q[0]) * .012; q[2] *= .93; q[3] *= .93
            q[0] += q[2]; q[1] += q[3]; q[4] -= q[5]
            if q[7] and abs(cx - q[0]) + abs(cy - q[1]) < 14: q[4] = 0
        self.f = [q for q in self.f if q[4] > 0]; self.update()
    def paintEvent(self, a0: Any) -> None:
        g = QPainter(self); g.setRenderHint(QPainter.RenderHint.Antialiasing); w, h = self.width(), self.height(); cx, cy = w / 2, h * .40; t = self._t
        fade = max(0.0, (t - .86) / .14)
        def ramp(x: float, a: float, b: float) -> float:
            return max(0.0, min(1.0, (x - a) / (b - a)))
        g.setOpacity(1 - fade); g.fillRect(self.rect(), _QC(8, 4, 3, int(228 * ramp(t, 0, .1))))   # dark veil over the screen underneath
        if t < .30:   # the whole window spirals into the lock, its rim burning
            e2 = t / .30; e2 = e2 * e2 * (3 - 2 * e2); sc = 1 - .96 * e2
            g.save(); g.translate(w / 2 + (cx - w / 2) * e2, h / 2 + (cy - h / 2) * e2); g.rotate(e2 * 40); g.scale(sc, sc); g.setOpacity((1 - fade) * (1 - .5 * e2)); g.drawPixmap(int(-w / 2), int(-h / 2), self.pm)
            g.setOpacity(1.0); pen = QPen(_QC(255, 140, 20, int(60 + 190 * e2)), 6); pen.setCosmetic(True); g.setCompositionMode(QPainter.CompositionMode.CompositionMode_Plus); g.setPen(pen); g.setBrush(Qt.BrushStyle.NoBrush); g.drawRect(QRectF(-w / 2, -h / 2, w, h)); g.restore()
        g.setOpacity(1 - fade); g.setCompositionMode(QPainter.CompositionMode.CompositionMode_Plus); g.setPen(Qt.PenStyle.NoPen)
        for x, y, _, _, l, _, rr, _ in self.f: g.setBrush(_QC(255, int(40 + 215 * l * l), int(200 * l ** 4), int(200 * min(1, l)))); g.drawEllipse(QPointF(x, y), rr * (.35 + .65 * l), rr * (.35 + .65 * l))
        g.setCompositionMode(QPainter.CompositionMode.CompositionMode_SourceOver)
        if t > .2:   # lock pops in, heats up as it closes, slams shut, then cools from white-hot to steel
            grow = ramp(t, .2, .36); sc = grow * (1 + .25 * math.sin(grow * math.pi)); slam = ramp(t, .38, .5); heat = .55 + .45 * slam if t < .5 else max(0.0, 1 - (t - .5) / .32)
            draw_lock(g, cx, cy, sc, 35 * (1 - slam ** 3), heat)
        g.setCompositionMode(QPainter.CompositionMode.CompositionMode_Plus); g.setBrush(Qt.BrushStyle.NoBrush)
        for i in range(3):   # shockwaves from the impact
            p = (t - .5 - i * .04) / .22
            if 0 < p < 1: rad = p * max(w, h) * .45; g.setPen(QPen(_QC(255, int(200 - 120 * p), 40, int(230 * (1 - p))), 2 + 8 * (1 - p))); g.drawEllipse(QPointF(cx, cy + 10), rad, rad)
        g.setCompositionMode(QPainter.CompositionMode.CompositionMode_SourceOver)
        if .5 <= t < .58: g.fillRect(self.rect(), _QC(255, 240, 210, int(170 * (1 - (t - .5) / .08))))
        if t > .56:
            al = ramp(t, .56, .66); heat = max(0.0, 1 - (t - .5) / .32); f = QFont("Georgia", max(16, min(30, w // 28)), QFont.Weight.Bold); f.setLetterSpacing(QFont.SpacingType.AbsoluteSpacing, 10); g.setFont(f); box = QRectF(0, cy + 78, w, 50)
            g.setCompositionMode(QPainter.CompositionMode.CompositionMode_Plus)
            for dy, c in ((-3, (255, 210, 70)), (-8, (255, 120, 0)), (-14, (255, 45, 0))): g.setPen(_QC(c[0], c[1], c[2], int(120 * al * heat))); g.drawText(box.translated(random.uniform(-2, 2), dy * random.uniform(.6, 1.3)), Qt.AlignmentFlag.AlignCenter, "SEALED")
            g.setCompositionMode(QPainter.CompositionMode.CompositionMode_SourceOver); g.setPen(_QC(255, 244, 228, int(255 * al))); g.drawText(box, Qt.AlignmentFlag.AlignCenter, "SEALED")

BGS = [("Code rain (animated)", "glyphs"), ("Radar (animated)", "radar"), ("Terminal log (animated)", "termlog"), ("Digital rain (animated)", "rain"), ("Starfield (animated)", "stars"), ("Aurora (animated)", "aurora"), ("Waves (animated)", "waves"),
       ("Bubbles (animated)", "bubbles"), ("Retro grid (animated)", "grid"),
       ("Orbit map (animated)", "orbit"), ("Scan sweep (animated)", "scan"),
       ("Vector drift (animated)", "vectors"), ("Data stream (animated)", "datastream"),
       ("Cipher bars (animated)", "cipherbars"),
       ("Rain on glass (animated)", "glassrain"), ("Tape reels (animated)", "reels"), ("Midnight beacon (animated)", "beacon"),
       ("Operator console (still)", "termart"), ("Noir sentinel (still)", "sigil"), ("Case file (still)", "casefile"),
       ("Paper dossier (still)", "paper"),
       ("Last train home (still)", "platform"), ("Midnight desk (still)", "desk"), ("Signal room (still)", "signalroom"),
       ("Quiet field (still)", "tiredfield"),
       ("Gradient (still)", "gradient"), ("Solid (still)", "solid"), ("Dots (still)", "dots"), ("My photo (still)", "photo")]
ANIM = {"rain", "stars", "aurora", "waves", "bubbles", "grid", "glyphs", "radar", "termlog"}
ANIM.update({"orbit", "scan", "vectors", "datastream", "cipherbars", "glassrain", "reels", "beacon"})
STILL = frozenset({"termart", "sigil", "casefile", "paper", "platform", "desk", "signalroom",
                   "tiredfield", "gradient", "solid", "dots", "photo"})
GLY = "01ABCDEF0123456789<>{}[]#$%&=+*/|\uFF71\uFF72\uFF73\uFF74\uFF75\uFF76\uFF77\uFF78\uFF79\uFF7A\uFF7B\uFF7C\uFF7D\uFF7E\uFF7F\uFF80\uFF81\uFF82\uFF83\uFF84\uFF85\uFF86\uFF87\uFF88\uFF89"
LOGT = ["[ ok ] mount /vault", "aes-gcm tag verified", "scrypt n=2^17 r=8 p=1", "derive session key", "chunk 0x%04x sealed", "0x%08x", "zeroizing buffer", "integrity manifest ok",
        "shred pass 2/3", "tmp cleared", "idle watchdog armed", "nonce 0x%08x", "index synced", "lock engaged", "no network. ever."]
def logline() -> str:
    t = random.choice(LOGT); return t % random.getrandbits(32 if "08x" in t else 16) if "%" in t else t
def perf() -> str:
    m = S("perf"); return ("lite" if (os.cpu_count() or 4) <= 2 else "full") if m == "auto" else m

class Stage(QWidget):
    """Background renderer for animated and still styles; static backgrounds stop the animation timer."""
    def __init__(self) -> None:
        super().__init__(); self.d: list[list[Any]] = []; self.bgm: Optional[tuple[str, float]] = None; self.ph = 0.0; self.px: Union[QPixmap, bool, None] = None; self.sl: Optional[QPixmap] = None; self.tired_image: Optional[QPixmap] = None; self.tired_scaled: Optional[QPixmap] = None; self.fc = 0; self.tm = QTimer(self); self.tm.timeout.connect(self.step); self.setfps()
    def bgname(self) -> str: return S("bg") if S("bg") not in ("fire", "embers") else "termlog"
    def setfps(self) -> None:
        app = QApplication.instance()
        focused = app is not None and QApplication.applicationState() == Qt.ApplicationState.ApplicationActive
        window = self.window()
        minimized = window is not None and window.isMinimized()
        if (self.isVisible() and not minimized and self.bgname() in ANIM and perf() != "min"
                and not S("reduce_motion") and (focused or not S("bgfocus"))):
            self.tm.start({"full": 33, "lite": 66, "min": 100}.get(perf(), 33))
        else:
            self.tm.stop()
    def reset_background(self) -> None:
        self.tm.stop()
        self.d.clear()
        self.bgm = None
        self.ph = 0.0
        self.sl = None
        self.fc = 0
        self.setfps()
        self.update()
    def stop_animation(self) -> None:
        self.tm.stop()
    def closeEvent(self, a0: Optional[QCloseEvent]) -> None:
        self.stop_animation()
        super().closeEvent(a0)
    def showEvent(self, a0: Any) -> None:
        super().showEvent(a0)
        self.setfps()
    def resizeEvent(self, a0: Any) -> None: self.px = self.sl = self.bgm = self.tired_scaled = None; super().resizeEvent(a0)
    def photo(self) -> Union[QPixmap, bool]:
        if self.px is None:
            pm = QPixmap(str(HOME / "bg.img")); self.px = False if pm.isNull() else pm.scaled(self.size(), Qt.AspectRatioMode.KeepAspectRatioByExpanding, Qt.TransformationMode.SmoothTransformation if perf() == "full" else Qt.TransformationMode.FastTransformation)
        return self.px
    def mk(self, bg: str, w: int, h: int, n: int) -> list[list[Any]]:
        r = random.random
        if bg == "rain": return [[r() * w, r() * h, 2 + r() * 5, 6 + int(r() * 10), r() * 1000] for _ in range(n)]
        if bg == "glassrain": return [[r() * w, r() * h, 1.5 + r() * 3.5, 16 + r() * 54, r() * 1.8] for _ in range(max(12, n))]
        if bg == "stars": return [[r() * 2 - 1, r() * 2 - 1, r() * .95 + .05] for _ in range(n * 2)]
        if bg == "bubbles": return [[r() * w, r() * h, 6 + r() * 26, .3 + r() * .9, r() * 6] for _ in range(n // 2)]
        if bg == "glyphs":
            cols = list(range(8, max(9, w), 20)); random.shuffle(cols); return [[x, r() * h, 2 + r() * 4, 8 + int(r() * 10), r() * 1000] for x in cols[:max(6, int(n * .9))]]
        if bg == "radar": return [[r() * 360, .15 + r() * .8] for _ in range(max(4, n // 8))]
        if bg == "termlog": return [[r() * max(1, w - 260), r() * h, .4 + r() * .9, logline()] for _ in range(max(6, n // 4))]
        return []
    def sync_background_data(self, bg: str, mode: Optional[str] = None) -> None:
        mode = perf() if mode is None else mode
        if mode == "min" or bg not in ANIM:
            return
        density = S("bgden") / 100
        state = (bg, density)
        if self.bgm != state:
            count = int((70 if mode == "full" else 30) * density)
            self.d = self.mk(bg, self.width(), self.height(), count)
            self.bgm = state
    def step(self) -> None:
        m = perf(); bg = self.bgname(); w, h = self.width(), self.height(); an = m != "min" and bg in ANIM
        if not an:
            self.tm.stop(); return
        window = self.window()
        if (not self.isVisible() or (window is not None and window.isMinimized())
                or (S("bgfocus") and QApplication.applicationState() != Qt.ApplicationState.ApplicationActive)):
            self.tm.stop(); return
        k = (1 if m == "full" else 2) * S("bgspd") / 100; self.ph += .033 * k; r = random.random
        self.sync_background_data(bg, m)
        for q in self.d:
            if bg == "rain":
                q[1] += q[2] * k
                if q[1] - q[3] > h: q[0], q[1] = r() * w, 0
            elif bg == "glassrain":
                q[1] += q[2] * k
                q[0] += math.sin(self.ph * .8 + q[4]) * .35
                if q[1] - q[3] > h: q[0], q[1] = r() * w, -q[3]
            elif bg == "stars":
                q[2] -= .01 * k
                if q[2] <= .04: q[0], q[1], q[2] = r() * 2 - 1, r() * 2 - 1, 1.0
            elif bg == "glyphs":
                q[1] += q[2] * k
                if q[1] - q[3] * 15 > h: q[1] = 0; q[4] = r() * 1000
            elif bg == "termlog":
                q[1] -= q[2] * k
                if q[1] < -20: q[1] = h + 10; q[3] = logline()
            elif bg == "bubbles":
                q[1] -= q[3] * k; q[0] += math.sin(self.ph + q[4]) * .5
                if q[1] < -q[2]: q[1] = h + q[2]
        self.update()
    def paintEvent(self, a0: Any) -> None:
        g = QPainter(self); w, h = self.width(), self.height(); m = perf(); bg = self.bgname(); full = m == "full"; g.setRenderHint(QPainter.RenderHint.Antialiasing, full)
        secret_image = getattr(self.window(), "_easter_theme_image", None)
        if isinstance(secret_image, QPixmap) and not secret_image.isNull():
            scaled = secret_image.scaled(
                self.size(), Qt.AspectRatioMode.KeepAspectRatioByExpanding,
                Qt.TransformationMode.SmoothTransformation)
            g.drawPixmap((w - scaled.width()) // 2, (h - scaled.height()) // 2, scaled)
            g.fillRect(self.rect(), _QC(255, 224, 241, 112))
            return
        a, b, ph = _QC(TH["acc"]), _QC(TH["acc2"]), self.ph
        def sc(color: _QC, alpha: int) -> _QC:
            return _QC(color.red(), color.green(), color.blue(), alpha)
        self.sync_background_data(bg, m)
        if m == "min" and bg in ANIM: bg = "gradient"
        photo = self.photo() if bg == "photo" else False
        if bg == "photo" and isinstance(photo, QPixmap):
            g.drawPixmap((w - photo.width()) // 2, (h - photo.height()) // 2, photo)
            g.fillRect(self.rect(), sc(_QC(TH["bg0"]), 165))
        elif bg == "solid": g.fillRect(self.rect(), _QC(TH["bg0"]))
        else: gr = QLinearGradient(0, 0, 0, h); gr.setColorAt(0, _QC(TH["bg0"])); gr.setColorAt(1, _QC(TH["bg1"])); g.fillRect(self.rect(), gr)
        if bg == "dots":
            g.setPen(QPen(sc(_QC(TH["fg"]), 45), 2))
            for x in range(14, w, 28):
                for y in range(14, h, 28): g.drawPoint(x, y)
        elif bg == "tiredfield":
            asset_root = APP.parent if PACKAGED else Path(__file__).resolve().parent
            if self.tired_image is None:
                image = QPixmap(str(asset_root / "assets" / "im_tired.jpg"))
                self.tired_image = None if image.isNull() else image
            if self.tired_image is not None:
                if (self.tired_scaled is None or self.tired_scaled.size() != self.size()):
                    self.tired_scaled = self.tired_image.scaled(
                        self.size(), Qt.AspectRatioMode.KeepAspectRatioByExpanding,
                        Qt.TransformationMode.SmoothTransformation if full
                        else Qt.TransformationMode.FastTransformation)
                image = self.tired_scaled
                g.drawPixmap((w - image.width()) // 2, (h - image.height()) // 2, image)
                shade = QLinearGradient(0, 0, 0, h)
                shade.setColorAt(0, _QC(8, 5, 6, 34))
                shade.setColorAt(.68, _QC(8, 7, 6, 86))
                shade.setColorAt(1, _QC(5, 7, 6, 135))
                g.fillRect(self.rect(), shade)
            else:
                g.fillRect(self.rect(), _QC(16, 11, 12))
        elif bg == "termart":
            f = QFont("Consolas", 11); f.setStyleHint(QFont.StyleHint.Monospace); g.setFont(f); g.setPen(sc(a, 185))
            art = ["/ NIGHT SHIFT / OPERATOR CONSOLE / DISPLAY ONLY /",
                   "-----------------------------------------------",
                   "drawer 07: spare keys for locks that no longer exist",
                   "weather: rain on the east window, coffee gone cold",
                   "memo: the lift stops between floors when it is lonely",
                   "inventory: one brass button, two bent paperclips",
                   "maintenance: listen for the pipes before sunrise",
                   "case note: nobody remembers who named the archive",
                   "route: back stairs -> narrow hall -> unmarked door",
                   "reminder: return the borrowed umbrella (blue handle)",
                   "-----------------------------------------------",
                   "Every room keeps a little of the voice that left it.",
                   "A city is mostly doors, and the light beneath them.",
                   "The clock above the desk is three minutes slow.",
                   "There is a map here, but it only shows the way back.",
                   "Somewhere a train is crossing the river in the fog.",
                   "No entry is required. No record is being checked.",
                   "This panel is decoration; it reports no vault state."]
            x, y = max(28, w * .075), max(42, h * .13); lh = max(17, min(23, h // 27))
            for i, line in enumerate(art[:max(1, (h - int(y) - 24) // lh)]): g.drawText(int(x), int(y + i * lh), line)
        elif bg == "sigil":
            cx, cy = w * .69, h * .59; unit = min(w / 900, h / 600)
            ink, amber = _QC(7, 11, 14, 255), _QC(179, 139, 84, 255)
            night = QLinearGradient(0, 0, w, h); night.setColorAt(0, _QC(11, 17, 21)); night.setColorAt(.55, _QC(25, 27, 27)); night.setColorAt(1, _QC(6, 9, 12)); g.fillRect(self.rect(), night)
            g.fillRect(self.rect(), _QC(4, 8, 12, 65))
            glow = QRadialGradient(cx, cy - 34 * unit, min(w, h) * .68)
            glow.setColorAt(0, _QC(a.red(), a.green(), a.blue(), 24))
            glow.setColorAt(.48, _QC(179, 139, 84, 13))
            glow.setColorAt(1, _QC(0, 0, 0, 0)); g.fillRect(self.rect(), glow)
            g.setPen(QPen(_QC(a.red(), a.green(), a.blue(), 24), max(1, unit)))
            for j in range(5):
                bx = w * (.06 + j * .105); bh = h * (.18 + (j % 3) * .09)
                g.drawLine(QPointF(bx, h * .66), QPointF(bx, h * .66 - bh))
                for wy in range(3):
                    g.setPen(QPen(_QC(amber.red(), amber.green(), amber.blue(), 23 + 5 * ((j + wy) % 2)), max(1, unit)))
                    g.drawPoint(QPointF(bx + 5 * unit, h * .66 - bh + (10 + wy * 13) * unit))
                    g.setPen(QPen(_QC(a.red(), a.green(), a.blue(), 24), max(1, unit)))
            g.setPen(QPen(_QC(amber.red(), amber.green(), amber.blue(), 30), max(1, unit)))
            g.drawLine(QPointF(0, h * .79), QPointF(w * .49, h * .79))
            g.setPen(QPen(_QC(a.red(), a.green(), a.blue(), 24), max(1, unit)))
            for j in range(5): g.drawLine(QPointF(w * (.08 + j * .075), h * .80), QPointF(w * (.12 + j * .065), h))
            beam = QPainterPath(); beam.moveTo(w * .43, 0); beam.lineTo(cx - 38 * unit, cy - 130 * unit); beam.lineTo(cx + 46 * unit, cy + 182 * unit); beam.lineTo(w * .59, 0); beam.closeSubpath()
            g.fillPath(beam, _QC(a.red(), a.green(), a.blue(), 13)); g.fillPath(beam, _QC(185, 170, 137, 17))
            g.setPen(QPen(_QC(215, 202, 177, 28), max(1, unit))); g.drawLine(QPointF(w * .53, 0), QPointF(cx - 25 * unit, cy + 180 * unit))
            g.setPen(Qt.PenStyle.NoPen); g.setBrush(ink)
            coat = QPainterPath(); coat.moveTo(cx - 40 * unit, cy - 58 * unit); coat.lineTo(cx - 102 * unit, cy - 8 * unit)
            coat.lineTo(cx - 155 * unit, cy + 184 * unit); coat.lineTo(cx + 143 * unit, cy + 184 * unit)
            coat.lineTo(cx + 103 * unit, cy + 2 * unit); coat.lineTo(cx + 42 * unit, cy - 60 * unit); coat.closeSubpath(); g.drawPath(coat)
            g.setBrush(_QC(11, 14, 17, 255))
            shoulders = QPainterPath(); shoulders.moveTo(cx - 51 * unit, cy + 14 * unit); shoulders.cubicTo(cx - 32 * unit, cy - 15 * unit, cx + 33 * unit, cy - 15 * unit, cx + 52 * unit, cy + 14 * unit); shoulders.lineTo(cx + 84 * unit, cy + 183 * unit); shoulders.lineTo(cx - 85 * unit, cy + 183 * unit); shoulders.closeSubpath(); g.drawPath(shoulders)
            g.setBrush(_QC(12, 15, 17, 255)); g.drawEllipse(QPointF(cx, cy - 82 * unit), 38 * unit, 53 * unit)
            g.setBrush(ink); brim = QPainterPath(); brim.moveTo(cx - 76 * unit, cy - 109 * unit); brim.quadTo(cx, cy - 137 * unit, cx + 77 * unit, cy - 106 * unit); brim.quadTo(cx + 47 * unit, cy - 93 * unit, cx, cy - 96 * unit); brim.quadTo(cx - 48 * unit, cy - 92 * unit, cx - 76 * unit, cy - 109 * unit); brim.closeSubpath(); g.drawPath(brim)
            crown = QPainterPath(); crown.moveTo(cx - 49 * unit, cy - 111 * unit); crown.quadTo(cx - 47 * unit, cy - 178 * unit, cx + 36 * unit, cy - 163 * unit); crown.lineTo(cx + 52 * unit, cy - 108 * unit); crown.closeSubpath(); g.drawPath(crown)
            g.setPen(QPen(amber, max(1, 1.4 * unit))); g.drawLine(QPointF(cx - 51 * unit, cy - 111 * unit), QPointF(cx + 51 * unit, cy - 108 * unit))
            g.setPen(QPen(_QC(225, 210, 175, 115), max(1, 1.5 * unit))); g.drawLine(QPointF(cx - 30 * unit, cy - 62 * unit), QPointF(cx - 13 * unit, cy - 65 * unit))
            g.setPen(QPen(_QC(225, 210, 175, 60), max(1, 1.2 * unit))); g.drawLine(QPointF(cx + 7 * unit, cy - 64 * unit), QPointF(cx + 23 * unit, cy - 61 * unit))
            g.setPen(QPen(_QC(188, 171, 139, 45), max(1, 1.2 * unit))); g.drawLine(QPointF(cx + 70 * unit, cy + 38 * unit), QPointF(cx + 118 * unit, cy + 179 * unit))
            lapel = QPainterPath(); lapel.moveTo(cx - 45 * unit, cy - 45 * unit); lapel.lineTo(cx - 8 * unit, cy + 31 * unit)
            lapel.lineTo(cx - 32 * unit, cy + 91 * unit); lapel.lineTo(cx - 82 * unit, cy + 14 * unit)
            lapel.moveTo(cx + 45 * unit, cy - 45 * unit); lapel.lineTo(cx + 10 * unit, cy + 31 * unit)
            lapel.lineTo(cx + 33 * unit, cy + 91 * unit); lapel.lineTo(cx + 82 * unit, cy + 14 * unit)
            g.setBrush(Qt.BrushStyle.NoBrush); g.setPen(QPen(_QC(190, 165, 121, 42), max(1, 1.2 * unit))); g.drawPath(lapel)
            g.setPen(QPen(_QC(a.red(), a.green(), a.blue(), 92), max(1, 1.6 * unit)))
            g.drawLine(QPointF(cx - 3 * unit, cy + 41 * unit), QPointF(cx + 2 * unit, cy + 46 * unit))
            g.drawLine(QPointF(cx - 3 * unit, cy + 52 * unit), QPointF(cx + 2 * unit, cy + 57 * unit))
            for j in range(7): 
                rx = w * (.10 + j * .055); ry = h * (.14 + (j % 3) * .19)
                g.setPen(QPen(_QC(200, 194, 175, 24), 1)); g.drawLine(QPointF(rx, ry), QPointF(rx + 12 * unit, ry + 24 * unit))
            g.setPen(_QC(196, 183, 158, 130)); f = QFont("Georgia", 11); g.setFont(f)
            g.drawText(30, h - 42, "NIGHT OFFICE     /     FILE 09     /     NO ENTRY RECORDED")
            grain = random.Random(70419)
            for _ in range(min(220, max(80, (w * h) // 9000))):
                gx, gy = grain.randrange(max(1, w)), grain.randrange(max(1, h))
                g.setPen(_QC(207, 190, 158, grain.randrange(5, 16))); g.drawPoint(gx, gy)
                if grain.random() < .18:
                    g.setPen(QPen(_QC(207, 190, 158, grain.randrange(5, 13)), 1))
                    g.drawLine(gx, gy, gx + grain.randrange(-5, 6), gy + grain.randrange(2, 9))
            edge = QPainterPath(); edge.moveTo(w * .015, h * .02); edge.lineTo(w * .39, h * .018); edge.lineTo(w * .395, h * .022)
            edge.moveTo(w * .83, h * .018); edge.lineTo(w * .985, h * .02); edge.lineTo(w * .981, h * .31)
            edge.moveTo(w * .982, h * .78); edge.lineTo(w * .985, h * .98); edge.lineTo(w * .68, h * .982)
            edge.moveTo(w * .28, h * .981); edge.lineTo(w * .015, h * .98); edge.lineTo(w * .019, h * .72)
            g.setBrush(Qt.BrushStyle.NoBrush); g.setPen(QPen(_QC(193, 175, 143, 18), max(1, unit))); g.drawPath(edge)
        elif bg == "blueprint":
            g.setPen(QPen(sc(a, 36), 1))
            for x in range(0, w, 32): g.drawLine(x, 0, x, h)
            for y in range(0, h, 32): g.drawLine(0, y, w, y)
            cx, cy = w * .73, h * .52; g.setBrush(Qt.BrushStyle.NoBrush); g.setPen(QPen(sc(a, 105), 2))
            for radius in (36, 74, 112): g.drawEllipse(QPointF(cx, cy), radius, radius)
            g.drawLine(QPointF(cx - 145, cy), QPointF(cx + 145, cy)); g.drawLine(QPointF(cx, cy - 145), QPointF(cx, cy + 145))
            f = QFont("Consolas", 12); f.setStyleHint(QFont.StyleHint.Monospace); g.setFont(f); g.setPen(sc(a, 195))
            for i, line in enumerate(("UNKNWN // SYSTEM BLUEPRINT", "LOCAL STORAGE  |  NO NETWORK", "AES-256-GCM  /  SCRYPT KDF")): g.drawText(28, 48 + i * 24, line)
        elif bg == "alley":
            base = QLinearGradient(0, 0, 0, h); base.setColorAt(0, _QC(23, 28, 31)); base.setColorAt(.58, _QC(8, 12, 15)); base.setColorAt(1, _QC(4, 6, 8)); g.fillRect(self.rect(), base)
            cx, horizon = w * .55, h * .68
            g.setPen(Qt.PenStyle.NoPen); g.setBrush(_QC(184, 174, 145, 20)); g.drawEllipse(QPointF(cx, horizon), w * .19, h * .20)
            g.setBrush(_QC(10, 13, 15)); left_building = QPainterPath(); left_building.moveTo(0, 0); left_building.lineTo(w * .27, 0); left_building.lineTo(w * .46, horizon); left_building.lineTo(w * .31, h); left_building.lineTo(0, h); left_building.closeSubpath(); g.drawPath(left_building)
            right_building = QPainterPath(); right_building.moveTo(w, 0); right_building.lineTo(w * .80, 0); right_building.lineTo(w * .62, horizon); right_building.lineTo(w * .76, h); right_building.lineTo(w, h); right_building.closeSubpath(); g.drawPath(right_building)
            g.setPen(QPen(_QC(180, 169, 142, 32), 1))
            for step in range(7):
                y = horizon + (h - horizon) * (step / 7) ** 2
                g.drawLine(QPointF(w * .31, y), QPointF(w * .76, y))
            g.setPen(Qt.PenStyle.NoPen); g.setBrush(_QC(4, 7, 9)); g.drawRect(QRectF(w * .73, h * .18, w * .012, h * .49))
            g.setBrush(_QC(188, 166, 119, 210)); g.drawRoundedRect(QRectF(w * .695, h * .17, w * .085, h * .025), 3, 3)
            cone = QPainterPath(); cone.moveTo(w * .70, h * .195); cone.lineTo(w * .52, horizon); cone.lineTo(w * .82, horizon); cone.closeSubpath(); g.fillPath(cone, _QC(186, 170, 130, 13))
            g.setPen(_QC(191, 179, 151, 145)); g.setFont(QFont("Georgia", 12)); g.drawText(28, h - 34, "NORTH QUAY  /  AFTER MIDNIGHT")
        elif bg == "casefile":
            g.fillRect(self.rect(), _QC(19, 22, 23))
            card = QRectF(w * .16, h * .10, w * .68, h * .80); g.setPen(QPen(_QC(190, 177, 147, 90), 1)); g.setBrush(_QC(40, 40, 35)); g.drawRoundedRect(card, 3, 3)
            g.setPen(_QC(198, 183, 148, 180)); f = QFont("Georgia", 17, QFont.Weight.Bold); g.setFont(f); g.drawText(QRectF(card.left() + 28, card.top() + 24, card.width() - 56, 32), Qt.AlignmentFlag.AlignLeft, "FIELD NOTES  /  09")
            g.setFont(QFont("Consolas", 10)); g.setPen(_QC(174, 164, 141, 175))
            notes = ("DISTRICT: RIVERSIDE, EAST END", "WEATHER: LIGHT RAIN / LOW CLOUD", "SUBJECT: UNKNOWN, LEFT-HANDED", "LAST SEEN: PLATFORM FOUR, 23:18",
                     "OBSERVATION: NEVER USED THE FRONT DOOR", "LEAD: BLUE UMBRELLA, WOOD HANDLE", "STATUS: OPEN, NO CONCLUSION")
            for i, line in enumerate(notes): g.drawText(int(card.left() + 30), int(card.top() + 92 + i * 25), line)
            g.setPen(QPen(_QC(147, 88, 68, 150), 2)); g.drawLine(QPointF(card.left() + 30, card.bottom() - 42), QPointF(card.right() - 30, card.bottom() - 42))
            note_font = QFont("Georgia", 10); note_font.setItalic(True); g.setFont(note_font); g.setPen(_QC(183, 153, 120, 150)); g.drawText(int(card.left() + 30), int(card.bottom() - 20), "Nothing in this file describes vault contents.")
        elif bg == "archive":
            g.setPen(QPen(sc(_QC(TH["fg"]), 24), 1))
            for y in (h * .28, h * .56, h * .84):
                g.drawLine(QPointF(w * .08, y), QPointF(w * .92, y))
                for i in range(7):
                    x = w * (.11 + i * .115); box_h = h * (.12 + (i % 3) * .025)
                    g.setBrush(_QC(a.red(), a.green(), a.blue(), 12 + i * 2)); g.setPen(QPen(sc(a, 65), 1))
                    g.drawRoundedRect(QRectF(x, y - box_h, w * .085, box_h), 2, 2)
                    g.drawLine(QPointF(x + 5, y - box_h + 12), QPointF(x + w * .07, y - box_h + 12))
            g.setPen(sc(_QC(TH["fg"]), 125)); g.setFont(QFont("Consolas", 10)); g.drawText(24, 32, "ARCHIVE ROOM  /  UNINDEXED")
        elif bg == "nightglass":
            g.fillRect(self.rect(), _QC(6, 12, 18))
            g.setPen(Qt.PenStyle.NoPen); g.setBrush(_QC(205, 198, 174, 26)); g.drawEllipse(QPointF(w * .76, h * .2), min(w, h) * .09, min(w, h) * .09)
            window = QRectF(w * .56, h * .12, w * .34, h * .66); g.setBrush(_QC(13, 21, 28, 220)); g.setPen(QPen(sc(a, 110), 2)); g.drawRect(window)
            g.drawLine(QPointF(window.center().x(), window.top()), QPointF(window.center().x(), window.bottom()))
            g.drawLine(QPointF(window.left(), window.center().y()), QPointF(window.right(), window.center().y()))
            g.setPen(QPen(_QC(195, 186, 160, 35), 1))
            for i in range(9): g.drawLine(QPointF(w * (.08 + i * .045), h * .88), QPointF(w * (.48 + i * .035), h * .6))
            g.setPen(sc(_QC(TH["fg"]), 125)); g.setFont(QFont("Georgia", 12)); g.drawText(26, h - 30, "A QUIET ROOM ABOVE THE STREET")
        elif bg == "map":
            g.setPen(QPen(sc(a, 35), 1))
            roads = (((.04, .12), (.28, .88)), ((.22, .02), (.48, .98)), ((.43, .05), (.69, .95)), ((.68, .02), (.91, .9)),
                     ((.05, .3), (.95, .18)), ((.02, .56), (.98, .43)), ((.04, .8), (.94, .69)), ((.18, .97), (.88, .88)))
            for start, end in roads: g.drawLine(QPointF(w * start[0], h * start[1]), QPointF(w * end[0], h * end[1]))
            route = QPainterPath(); route.moveTo(w * .12, h * .72); route.cubicTo(w * .32, h * .58, w * .4, h * .78, w * .58, h * .47); route.lineTo(w * .81, h * .34)
            g.setPen(QPen(sc(b, 150), 2)); g.drawPath(route); g.setBrush(_QC(TH["acc"])); g.drawEllipse(QPointF(w * .81, h * .34), 4, 4)
            g.setPen(sc(_QC(TH["fg"]), 125)); g.setFont(QFont("Consolas", 10)); g.drawText(24, 32, "CITY GRID  /  ROUTE UNMARKED")
        elif bg == "paper":
            g.fillRect(self.rect(), _QC(27, 27, 25)); card = QRectF(w * .13, h * .08, w * .74, h * .84)
            g.setBrush(_QC(53, 50, 43)); g.setPen(QPen(_QC(182, 166, 136, 80), 1)); g.drawRect(card)
            grain = random.Random(9107)
            for _ in range(min(180, max(60, (w * h) // 14000))):
                gx = grain.randrange(max(1, w)); gy = grain.randrange(max(1, h))
                g.setPen(_QC(225, 209, 174, grain.randrange(4, 14))); g.drawPoint(gx, gy)
            g.setPen(_QC(200, 185, 155, 160)); g.setFont(QFont("Georgia", 16, QFont.Weight.Bold)); g.drawText(int(card.left() + 24), int(card.top() + 42), "PRIVATE NOTES")
            g.setPen(_QC(164, 155, 137, 115))
            for i in range(8): g.drawLine(int(card.left() + 24), int(card.top() + 78 + i * 31), int(card.right() - 24 - (i % 3) * 18), int(card.top() + 78 + i * 31))
            g.setPen(_QC(194, 139, 105, 105)); g.drawLine(QPointF(card.left() + 25, card.bottom() - 34), QPointF(card.right() - 25, card.bottom() - 34))
            g.setPen(_QC(190, 177, 147, 130)); g.setFont(QFont("Consolas", 9)); g.drawText(int(card.left() + 24), int(card.bottom() - 16), "UNKNWN  /  DISPLAY ONLY")
        elif bg == "platform":
            g.fillRect(self.rect(), _QC(8, 13, 18))
            haze = QRadialGradient(w * .50, h * .52, h * .68); haze.setColorAt(0, _QC(177, 142, 91, 34)); haze.setColorAt(1, _QC(6, 11, 16, 0)); g.fillRect(self.rect(), haze)
            g.setPen(QPen(_QC(181, 158, 119, 45), 1))
            for x in (w * .08, w * .22, w * .78, w * .92):
                g.drawLine(QPointF(x, h * .1), QPointF(w * .5 + (x - w * .5) * .12, h * .73))
            g.setPen(QPen(_QC(184, 161, 121, 55), 2)); g.drawLine(QPointF(0, h * .73), QPointF(w, h * .73))
            g.setPen(Qt.PenStyle.NoPen); g.setBrush(_QC(4, 7, 10)); train = QPainterPath(); train.moveTo(w * .60, h * .29); train.lineTo(w * .98, h * .33); train.lineTo(w, h * .69); train.lineTo(w * .55, h * .69); train.closeSubpath(); g.drawPath(train)
            g.setBrush(_QC(208, 177, 119, 135))
            for i in range(4): g.drawRoundedRect(QRectF(w * (.65 + i * .085), h * .39, w * .055, h * .11), 3, 3)
            g.setBrush(_QC(194, 161, 105, 26)); g.drawRect(QRectF(w * .08, h * .12, w * .23, h * .13))
            g.setPen(_QC(207, 183, 139, 165)); g.setFont(QFont("Consolas", max(9, int(h / 34)))); g.drawText(QRectF(w * .095, h * .145, w * .21, h * .09), Qt.AlignmentFlag.AlignCenter, "LAST TRAIN  /  00:17")
            g.setPen(_QC(176, 160, 137, 112)); g.setFont(QFont("Georgia", 11)); g.drawText(26, int(h * .92), "PLATFORM 9     //     NO DESTINATION LISTED")
        elif bg == "desk":
            g.fillRect(self.rect(), _QC(20, 20, 19))
            table = QLinearGradient(0, h * .44, w, h); table.setColorAt(0, _QC(49, 39, 30)); table.setColorAt(1, _QC(20, 21, 20)); g.fillRect(QRectF(0, h * .43, w, h * .57), table)
            g.setPen(QPen(_QC(193, 165, 121, 35), 1))
            for y in range(int(h * .48), h, 19): g.drawLine(0, y, w, y + int(h * .025))
            page = QPainterPath(); page.moveTo(w * .16, h * .20); page.lineTo(w * .62, h * .15); page.lineTo(w * .67, h * .76); page.lineTo(w * .20, h * .81); page.closeSubpath()
            g.setPen(QPen(_QC(184, 163, 128, 90), 1)); g.setBrush(_QC(68, 61, 49)); g.drawPath(page)
            g.setPen(QPen(_QC(193, 177, 146, 55), 1))
            for i in range(9): g.drawLine(QPointF(w * .24, h * (.29 + i * .048)), QPointF(w * (.57 - (i % 3) * .025), h * (.28 + i * .048)))
            g.setPen(QPen(_QC(7, 9, 10), 2)); g.setBrush(_QC(14, 17, 18)); g.drawEllipse(QPointF(w * .79, h * .39), w * .085, h * .12)
            g.setPen(QPen(_QC(164, 141, 105, 145), 3)); g.drawEllipse(QPointF(w * .79, h * .39), w * .065, h * .095)
            g.setPen(_QC(188, 169, 138, 145)); g.setFont(QFont("Georgia", 10)); g.drawText(24, h - 24, "NOTES LEFT OPEN     /     MORNING NOT YET ARRIVED")
        elif bg == "rooftop":
            night = QLinearGradient(0, 0, 0, h); night.setColorAt(0, _QC(10, 18, 29)); night.setColorAt(.7, _QC(25, 27, 30)); night.setColorAt(1, _QC(8, 10, 12)); g.fillRect(self.rect(), night)
            g.setPen(Qt.PenStyle.NoPen); g.setBrush(_QC(6, 9, 12))
            buildings = ((0, .58, .16, .42), (.13, .47, .14, .53), (.29, .62, .18, .38), (.48, .51, .13, .49), (.61, .59, .17, .41), (.80, .43, .20, .57))
            for i, (x, y, bw, bh) in enumerate(buildings):
                g.drawRect(QRectF(w * x, h * y, w * bw, h * bh))
                g.setPen(QPen(_QC(191, 161, 112, 70), 1))
                for row in range(3):
                    for col in range(max(1, int(bw * 12))):
                        if (i * 7 + row * 3 + col) % 4 == 0: g.drawPoint(QPointF(w * (x + .025 + col * .025), h * (y + .06 + row * .07)))
                g.setPen(Qt.PenStyle.NoPen); g.setBrush(_QC(6, 9, 12))
            g.setPen(QPen(_QC(177, 167, 142, 120), 2)); g.drawLine(QPointF(w * .51, h * .49), QPointF(w * .51, h * .17)); g.drawLine(QPointF(w * .46, h * .28), QPointF(w * .56, h * .28))
            g.setPen(QPen(_QC(199, 168, 110, 170), 2)); g.drawEllipse(QPointF(w * .51, h * .16), 4, 4)
            g.setPen(_QC(190, 177, 149, 145)); g.setFont(QFont("Consolas", 10)); g.drawText(24, h - 24, "ROOFTOP  /  FREQUENCY UNKNOWN")
        elif bg == "signalroom":
            g.fillRect(self.rect(), _QC(12, 17, 18))
            g.setPen(QPen(_QC(183, 165, 128, 60), 2)); g.setBrush(_QC(19, 26, 27)); g.drawRoundedRect(QRectF(w * .08, h * .10, w * .84, h * .76), 8, 8)
            for i in range(3):
                panel = QRectF(w * (.13 + i * .25), h * .20, w * .21, h * .48); g.setPen(QPen(sc(a, 75), 1)); g.setBrush(_QC(8, 13, 15)); g.drawRoundedRect(panel, 3, 3)
                g.setPen(QPen(sc(a if i != 1 else b, 140), 1))
                for j in range(4): g.drawLine(QPointF(panel.left() + 10, panel.top() + 22 + j * 21), QPointF(panel.right() - 10, panel.top() + 22 + j * 21))
                g.setPen(Qt.PenStyle.NoPen); g.setBrush(sc(a if i != 1 else b, 120))
                for j in range(3): g.drawEllipse(QPointF(panel.left() + 16 + j * 27, panel.bottom() - 20), 3, 3)
            g.setPen(_QC(190, 175, 143, 150)); g.setFont(QFont("Consolas", 10)); g.drawText(24, h - 22, "RELAY ROOM  /  LOCAL SIGNAL ONLY")
        elif bg == "orbit":
            cx, cy, radius = w * .72, h * .52, min(w, h) * .3; g.setBrush(Qt.BrushStyle.NoBrush)
            for i, tilt in enumerate((0, 55, -55)):
                g.save(); g.translate(cx, cy); g.rotate(tilt); g.setPen(QPen(sc(a if i != 1 else b, 66), 1.2)); g.drawEllipse(QRectF(-radius, -radius * .34, radius * 2, radius * .68))
                angle = ph * (.55 + i * .17) + i * 2.1; g.setBrush(sc(a if i != 1 else b, 205)); g.setPen(Qt.PenStyle.NoPen)
                g.drawEllipse(QPointF(math.cos(angle) * radius, math.sin(angle) * radius * .34), 3.5, 3.5); g.restore()
            g.setBrush(sc(_QC(TH["fg"]), 175)); g.drawEllipse(QPointF(cx, cy), 4, 4)
        elif bg == "scan":
            x = (ph * 64) % max(1, w); beam = QLinearGradient(x - 48, 0, x + 48, 0)
            beam.setColorAt(0, sc(a, 0)); beam.setColorAt(.5, sc(a, 32)); beam.setColorAt(1, sc(a, 0)); g.fillRect(self.rect(), beam)
            g.setPen(QPen(sc(a, 55), 1))
            for y in range(30, h, 48): g.drawLine(18, y, w - 18, y)
            g.setPen(sc(_QC(TH["fg"]), 145)); g.setFont(QFont("Consolas", 10)); g.drawText(24, 32, "OPTICAL SWEEP  /  PASSIVE DISPLAY")
        elif bg == "constellation":
            points = ((.12,.2),(.24,.34),(.35,.18),(.48,.39),(.59,.25),(.72,.37),(.84,.2),(.19,.72),(.34,.61),(.51,.78),(.66,.62),(.81,.76))
            g.setPen(QPen(sc(a, 35), 1))
            for i in range(len(points) - 1):
                if i not in (5, 6): g.drawLine(QPointF(w * points[i][0], h * points[i][1]), QPointF(w * points[i + 1][0], h * points[i + 1][1]))
            for i, (x, y) in enumerate(points):
                alpha = int(75 + 95 * (math.sin(ph * .8 + i) + 1) / 2); g.setPen(Qt.PenStyle.NoPen); g.setBrush(sc(b if i % 3 == 0 else a, alpha))
                g.drawEllipse(QPointF(w * x, h * y), 2.2, 2.2)
        elif bg == "vectors":
            g.setPen(QPen(sc(a, 50), 1))
            offset = (ph * 34) % 72
            for i in range(-2, int(h / 72) + 3):
                y = i * 72 + offset; path = QPainterPath(); path.moveTo(0, y)
                path.cubicTo(w * .28, y - 24, w * .6, y + 24, w, y - 4); g.drawPath(path)
            g.setPen(QPen(sc(b, 100), 1))
            for i in range(10):
                x = (i * w / 9 + ph * 22) % max(1, w); g.drawLine(QPointF(x, 0), QPointF(x - w * .12, h))
        elif bg == "datastream":
            f = QFont("Consolas", 10); f.setStyleHint(QFont.StyleHint.Monospace); g.setFont(f)
            step_x, step_y = 27, 28; shift = int(ph * 4)
            for col in range(1, max(2, w // step_x)):
                for row in range(1, max(2, h // step_y)):
                    if (col * 13 + row * 7) % 5: continue
                    char = GLY[(col * 17 + row * 29 + shift) % len(GLY)]
                    g.setPen(sc(b if (col + row) % 7 == 0 else a, 95 if (row + shift) % 4 else 180))
                    g.drawText(col * step_x, row * step_y, char)
        elif bg == "echo":
            cx, cy = w * .72, h * .52; g.setBrush(Qt.BrushStyle.NoBrush)
            for i in range(5):
                radius = min(w, h) * (.1 + ((ph * .22 + i * .19) % 1) * .35)
                g.setPen(QPen(sc(a if i % 2 else b, 60 + i * 8), 1)); g.drawEllipse(QPointF(cx, cy), radius, radius * .72)
        elif bg == "horizon":
            hz = h * .48; g.setPen(QPen(sc(a, 62), 1))
            for i in range(-9, 10):
                g.drawLine(QPointF(w * .5 + i * 8, hz), QPointF(w * .5 + i * w / 11, h))
            shift = (ph * 18) % 38
            for i in range(12):
                depth = (i + shift / 38) / 12
                y = hz + (h - hz) * depth * depth
                g.drawLine(QPointF(0, y), QPointF(w, y))
        elif bg == "cipherbars":
            bar_w = max(4, w / 70)
            for i in range(52):
                x = w * (i + .5) / 52; strength = (math.sin(ph * .75 + i * .71) + 1) * .5
                bar_h = h * (.08 + strength * .62); g.setPen(Qt.PenStyle.NoPen); g.setBrush(sc(a if i % 4 else b, int(22 + strength * 48)))
                g.drawRoundedRect(QRectF(x - bar_w / 2, h - bar_h, bar_w, bar_h), 2, 2)
        elif bg == "harmonics":
            count = 4 if full else 3
            for i in range(count):
                g.setPen(QPen(sc(a if i % 2 else b, 72), 1.6)); previous = None
                for x in range(0, w + 12, 12):
                    y = h * (.32 + i * .105) + math.sin(x / (82 + i * 19) + ph * (.7 + i * .12)) * h * .035
                    point = QPointF(x, y)
                    if previous is not None: g.drawLine(previous, point)
                    previous = point
        elif bg == "cipher":
            cx, cy, radius = w * .72, h * .52, min(w, h) * .32
            g.setBrush(Qt.BrushStyle.NoBrush); g.setPen(QPen(sc(a, 45), 1))
            for r0 in (radius, radius * .84, radius * .31): g.drawEllipse(QPointF(cx, cy), r0, r0)
            for i in range(36):
                angle = math.radians(i * 10); inner = radius * (.9 if i % 3 else .84); outer = radius
                g.setPen(QPen(sc(a, 95 if i % 3 == 0 else 42), 1))
                g.drawLine(QPointF(cx + math.cos(angle) * inner, cy + math.sin(angle) * inner),
                           QPointF(cx + math.cos(angle) * outer, cy + math.sin(angle) * outer))
            angle = self.ph * .65; g.setPen(QPen(sc(_QC(TH["fg"]), 145), 2))
            g.drawLine(QPointF(cx, cy), QPointF(cx + math.cos(angle) * radius * .72, cy + math.sin(angle) * radius * .72))
            g.setPen(sc(a, 185)); g.setFont(QFont("Consolas", 11)); g.drawText(28, 44, "CIPHER WHEEL  /  DISPLAY ONLY")
        elif bg == "rain":
            f = QFont("Consolas", 10); f.setStyleHint(QFont.StyleHint.Monospace); g.setFont(f)
            for x, y, _, ln, seed in self.d:
                bits = "".join("1" if (int(seed + i + ph * 8) % 2) else "0" for i in range(ln))
                g.setPen(sc(a, 115)); g.drawText(int(x), int(y - ln * 14), bits)
                g.setPen(sc(b, 225)); g.drawText(int(x), int(y), "1" if int(seed + ph * 8) % 2 else "0")
        elif bg == "stars":
            cx, cy = w / 2, h / 2; g.setPen(QPen(sc(_QC(TH["fg"]), 170), 1.5))
            for x, y, z in self.d: g.drawLine(QPointF(cx + x / (z + .06) * cx, cy + y / (z + .06) * cy), QPointF(cx + x / z * cx, cy + y / z * cy))
        elif bg == "aurora":
            for i, c in enumerate((a, b, _QC(TH["fg"]))):
                rg = QRadialGradient(w * (.5 + .35 * math.sin(ph * .6 + i * 2.1)), h * (.45 + .25 * math.cos(ph * .5 + i * 1.7)), max(w, h) * .55); rg.setColorAt(0, sc(c, 80)); rg.setColorAt(1, sc(c, 0)); g.fillRect(self.rect(), rg)
        elif bg == "waves":
            for i in range(5 if full else 3):
                g.setPen(QPen(sc(a if i % 2 else b, 90), 2)); pv = None
                for x in range(0, w + 16, 16):
                    pt = QPointF(x, h * (.35 + .1 * i) + math.sin(x / 90 + ph * (1 + i * .3) + i) * 26)
                    if pv is not None: g.drawLine(pv, pt)
                    pv = pt
        elif bg == "bubbles":
            g.setBrush(Qt.BrushStyle.NoBrush)
            for x, y, rr, _, _ in self.d: g.setPen(QPen(sc(a, 80), 1.5)); g.drawEllipse(QPointF(x, y), rr, rr)
        elif bg == "grid":
            hz = h * .55; g.setPen(QPen(sc(a, 90), 1))
            for i in range(10): y = hz + (h - hz) * ((i + ph % 1) / 10) ** 2; g.drawLine(0, int(y), w, int(y))
            for k in range(-12, 13): g.drawLine(QPointF(w / 2 + k * 10, hz), QPointF(w / 2 + k * w / 14, h))
            gl = QLinearGradient(0, hz - 60, 0, hz); gl.setColorAt(0, sc(a, 0)); gl.setColorAt(1, sc(a, 70)); g.fillRect(0, int(hz - 60), w, 60, gl)
        elif bg == "glyphs":
            f = QFont("Consolas", 11); f.setStyleHint(QFont.StyleHint.Monospace); g.setFont(f)
            for x, y, _v, ln, sd in self.d:
                for j in range(ln):
                    yy = y - j * 15
                    if yy < -15 or yy > h + 15: continue
                    row = int(yy // 15); ch = GLY[(int(sd) + row * 31 + (int(ph * 12) if j == 0 else 0)) % len(GLY)]
                    g.setPen(_QC(225, 255, 235, 235) if j == 0 else sc(a, int(210 * (1 - j / ln)))); g.drawText(int(x), int(yy), ch)
        elif bg == "radar":
            cx, cy = w / 2, h * .55; R = min(w, h * 1.1) * .48; g.setBrush(Qt.BrushStyle.NoBrush); g.setPen(QPen(sc(a, 60), 1))
            for i in range(1, 5): g.drawEllipse(QPointF(cx, cy), R * i / 4, R * i / 4)
            g.drawLine(QPointF(cx - R, cy), QPointF(cx + R, cy)); g.drawLine(QPointF(cx, cy - R), QPointF(cx, cy + R))
            sw = (ph * 70) % 360; g.setPen(Qt.PenStyle.NoPen)
            for i in range(24): g.setBrush(sc(a, int(70 * (1 - i / 24)))); g.drawPie(QRectF(cx - R, cy - R, 2 * R, 2 * R), int(-(sw - i * 3) * 16), 3 * 16)
            for ang, rad in self.d:
                al = int(255 * max(0.0, 1 - ((sw - ang) % 360) / 200))
                if al > 5: g.setBrush(sc(b, al)); g.drawEllipse(QPointF(cx + math.cos(math.radians(ang)) * R * rad, cy + math.sin(math.radians(ang)) * R * rad), 3.5, 3.5)
        elif bg == "termlog":
            f = QFont("Consolas", 9); f.setStyleHint(QFont.StyleHint.Monospace); g.setFont(f)
            for x, y, _v, tx in self.d: g.setPen(sc(a, int(max(20, min(130, 130 * y / max(1, h)))))); g.drawText(int(x), int(y), tx)
        elif bg == "glassrain":
            g.setPen(QPen(_QC(120, 161, 174, 20), 1))
            for x in range(0, w, max(24, w // 22)): g.drawLine(x, 0, x - int(w * .03), h)
            for x, y, _speed, length, _sway in self.d:
                g.setPen(QPen(sc(b, 48), 1)); g.drawLine(QPointF(x - length * .18, y - length), QPointF(x, y))
                g.setPen(QPen(sc(a, 115), 1.5)); g.drawLine(QPointF(x, y - length * .25), QPointF(x + 1.5, y))
        elif bg == "reels":
            unit = min(w / 900, h / 540)
            deck = QRectF(w * .11, h * .12, w * .78, h * .76)
            panel = QLinearGradient(deck.topLeft(), deck.bottomRight())
            panel.setColorAt(0, _QC(19, 25, 28, 235)); panel.setColorAt(1, _QC(6, 10, 13, 235))
            g.setBrush(panel); g.setPen(QPen(sc(a, 85), max(1, unit)))
            g.drawRoundedRect(deck, 8 * unit, 8 * unit)
            g.setPen(QPen(sc(_QC(TH["fg"]), 32), max(1, unit)))
            g.drawLine(QPointF(deck.left() + 14 * unit, deck.top() + 34 * unit),
                       QPointF(deck.right() - 14 * unit, deck.top() + 34 * unit))
            g.setPen(sc(_QC(TH["fg"]), 145)); g.setFont(QFont("Consolas", max(7, int(9 * unit))))
            g.drawText(QRectF(deck.left() + 16 * unit, deck.top() + 7 * unit, deck.width() * .55, 22 * unit),
                      Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter, "REEL-TO-REEL  /  ARCHIVE 07")
            cy = h * .47; radius = min(w * .155, h * .255); centers = (w * .34, w * .66)
            g.setBrush(_QC(4, 8, 11, 150)); g.setPen(QPen(sc(b, 54), max(1, unit)))
            g.drawRoundedRect(QRectF(w * .20, h * .25, w * .60, h * .45), 6 * unit, 6 * unit)
            for i, cx in enumerate(centers):
                color = a if i == 0 else b; angle = ph * (0.7 if i == 0 else -0.55)
                g.setBrush(Qt.BrushStyle.NoBrush); g.setPen(QPen(sc(color, 105), max(1, 1.5 * unit)))
                g.drawEllipse(QPointF(cx, cy), radius, radius)
                for ring in (.88, .69, .23):
                    g.setPen(QPen(sc(color, 42 if ring != .23 else 105), max(1, unit)))
                    g.drawEllipse(QPointF(cx, cy), radius * ring, radius * ring)
                g.save(); g.translate(cx, cy); g.rotate(math.degrees(angle))
                for _ in range(6):
                    g.setPen(QPen(sc(color, 92), max(1, 1.4 * unit)))
                    g.drawLine(QPointF(0, -radius * .18), QPointF(0, -radius * .8))
                    g.setPen(Qt.PenStyle.NoPen); g.setBrush(sc(color, 28)); g.drawEllipse(QPointF(0, -radius * .52), radius * .105, radius * .105)
                    g.rotate(60)
                g.setPen(Qt.PenStyle.NoPen); g.setBrush(sc(color, 175)); g.drawEllipse(QPointF(0, 0), radius * .12, radius * .12)
                g.setBrush(_QC(7, 11, 14)); g.drawEllipse(QPointF(0, 0), radius * .045, radius * .045)
                g.restore()
            tape = QPainterPath(); tape.moveTo(centers[0] + radius * .68, cy - radius * .48)
            tape.cubicTo(w * .47, h * .35, w * .46, h * .57, w * .51, h * .53)
            tape.cubicTo(w * .55, h * .49, w * .53, h * .39, centers[1] - radius * .68, cy - radius * .48)
            g.setPen(QPen(sc(_QC(TH["fg"]), 90), max(1, 2 * unit))); g.setBrush(Qt.BrushStyle.NoBrush); g.drawPath(tape)
            for i in range(3):
                x = w * (.46 + i * .04); y = h * (.58 + (i % 2) * .025)
                g.setPen(QPen(sc(a if i != 1 else b, 105), max(1, unit))); g.setBrush(_QC(9, 13, 15))
                g.drawEllipse(QPointF(x, y), 4 * unit, 4 * unit)
            meter = QRectF(w * .38, h * .75, w * .24, max(5, h * .025))
            g.setPen(QPen(sc(_QC(TH["fg"]), 42), max(1, unit))); g.setBrush(_QC(3, 7, 9))
            g.drawRoundedRect(meter, 2 * unit, 2 * unit)
            level = .35 + .28 * (math.sin(ph * 1.7) + 1) / 2
            g.setPen(Qt.PenStyle.NoPen); g.setBrush(sc(a, 150))
            g.drawRoundedRect(QRectF(meter.left() + 2 * unit, meter.top() + 2 * unit,
                                    (meter.width() - 4 * unit) * level, max(1, meter.height() - 4 * unit)), 1, 1)
            g.setPen(sc(_QC(TH["fg"]), 118)); g.setFont(QFont("Consolas", max(7, int(8 * unit))))
            g.drawText(QRectF(deck.left() + 14 * unit, deck.bottom() - 22 * unit, deck.width() - 28 * unit, 16 * unit),
                      Qt.AlignmentFlag.AlignCenter, "TAPE LOOP  /  SIDE B  /  PLAYING QUIETLY")
        elif bg == "beacon":
            cx, cy = w * .73, h * .48; radius = min(w, h) * .37; phase = (ph * .28) % 1
            g.setPen(QPen(sc(a, 35), 1))
            for i in range(5): g.drawLine(QPointF(cx - radius + i * radius * .5, cy), QPointF(cx, cy - radius + i * radius * .5))
            g.setBrush(Qt.BrushStyle.NoBrush)
            for i in range(4):
                r0 = radius * ((phase + i / 4) % 1); alpha = int(100 * (1 - r0 / max(1, radius)))
                g.setPen(QPen(sc(b if i % 2 else a, alpha), 1.5)); g.drawEllipse(QPointF(cx, cy), r0, r0 * .45)
            glow = QRadialGradient(cx, cy, radius * .24); glow.setColorAt(0, sc(_QC(TH["fg"]), 155)); glow.setColorAt(.3, sc(a, 80)); glow.setColorAt(1, sc(a, 0)); g.fillRect(self.rect(), glow)
            g.setPen(sc(_QC(TH["fg"]), 145)); g.setFont(QFont("Consolas", 10)); g.drawText(24, h - 24, "BEACON  //  NO RESPONSE REQUIRED")
        if bg in STILL:
            margin = max(8, min(w, h) * .025)
            g.save()
            vignette = QRadialGradient(w * .5, h * .46, max(w, h) * .72)
            vignette.setColorAt(.46, _QC(0, 0, 0, 0)); vignette.setColorAt(1, _QC(0, 0, 0, 56))
            g.fillRect(self.rect(), vignette)
            g.setBrush(Qt.BrushStyle.NoBrush); g.setPen(QPen(sc(a, 38), 1))
            g.drawRect(QRectF(margin, margin, max(1, w - 2 * margin), max(1, h - 2 * margin)))
            tick = max(8, min(w, h) * .035)
            for x, y, sx, sy in ((margin, margin, 1, 1), (w - margin, margin, -1, 1),
                                 (margin, h - margin, 1, -1), (w - margin, h - margin, -1, -1)):
                g.setPen(QPen(sc(a, 105), 1.2))
                g.drawLine(QPointF(x, y), QPointF(x + sx * tick, y))
                g.drawLine(QPointF(x, y), QPointF(x, y + sy * tick))
            g.setPen(sc(_QC(TH["fg"]), 88)); g.setFont(QFont("Consolas", 8))
            g.drawText(QRectF(margin + 10, margin + 4, min(250, w * .46), 18),
                       Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter, "UNKNWN  /  ATMOSPHERE STUDY")
            g.restore()
        if full and bg in ANIM and S("crt"):   # scanlines (cached) + rare glitch band
            if self.sl is None:
                self.sl = QPixmap(w, h); self.sl.fill(Qt.GlobalColor.transparent); sp = QPainter(self.sl); sp.setPen(_QC(255, 255, 255, 9))
                for y in range(0, h, 4): sp.drawLine(0, y, w, y)
                sp.end()
            g.drawPixmap(0, 0, self.sl); self.fc += 1
            if self.fc % 150 < 5 and random.random() < .7: y = random.randint(0, h); g.fillRect(0, y, w, random.randint(2, 14), sc(a, 38)); g.fillRect(random.randint(-30, 30), y + 3, w, 2, _QC(255, 255, 255, 25))

THEMES = [("Mono", "mono"), ("Violet", "violet"), ("Matrix", "matrix"), ("Blood", "blood"), ("Ice", "ice"), ("Amber terminal", "amber"), ("Cyber", "cyber"), ("Ocean", "ocean"), ("I'm Tired", "tired"), ("Custom", "custom")]
class Preview(Stage):
    """Live preview strip for the Look Studio: the real background renderer at small size."""
    def __init__(self) -> None: super().__init__(); self.setFixedHeight(200)
class Swatch(QWidget):
    def __init__(self, key: str, name: str, on_click: Callable[[str], object], active: bool) -> None:
        super().__init__(); self.key, self.name, self.cb, self.active = key, name, on_click, active; self.setFixedSize(122, 64); self.setCursor(QCursor(Qt.CursorShape.PointingHandCursor))
    def paintEvent(self, a0: Any) -> None:
        theme = self.key if self.key in PRE or self.key == "custom" else None
        bg, fg, ac = _resolve_theme_palette(theme)
        g = QPainter(self); g.fillRect(self.rect(), _QC(bg))
        g.setPen(QPen(_QC(ac) if self.active else _QC(mix(bg, fg, .25)), 3 if self.active else 1)); g.setBrush(Qt.BrushStyle.NoBrush); g.drawRect(QRectF(self.rect()).adjusted(1, 1, -1, -1))
        g.fillRect(8, 10, 40, 6, _QC(ac)); g.fillRect(8, 21, 70, 4, _QC(fg)); g.fillRect(8, 29, 52, 4, _QC(mix(bg, fg, .5)))
        f = QFont("Consolas", 8); g.setFont(f); g.setPen(_QC(fg)); g.drawText(QRectF(8, 40, 108, 18), Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter, ("* " if self.active else "") + self.name)
    def mousePressEvent(self, a0: Any) -> None: self.cb(self.key)

class Glitch(QLabel):
    """Quiet title with brief, low-frequency chromatic glitch ticks."""
    def __init__(
        self,
        t: str,
        size: int = 44,
        on_triple_click: Optional[Callable[[], object]] = None,
    ) -> None:
        super().__init__(t); self.orig = t; self.n = 0; self.click_count = 0; self.last_click = 0; self.on_triple_click = on_triple_click; self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setStyleSheet(f"font-family:Georgia,serif;font-size:{size}px;font-weight:700;letter-spacing:4px;color:#d9d2c2")
        self.setToolTip("You found the quiet door.")
        self.tm = QTimer(self); self.tm.setSingleShot(True); self.tm.timeout.connect(self.tk); self.tm.start(random.randint(2800, 6200))
    def mousePressEvent(self, ev: Any) -> None:
        now = time.monotonic()
        self.click_count = self.click_count + 1 if now - self.last_click <= 1.35 else 1
        self.last_click = now
        if self.click_count == 3:
            self.click_count = 0
            if self.on_triple_click: self.on_triple_click()
        super().mousePressEvent(ev)
    def tk(self) -> None:
        if self.n == 0:
            self.n = 3
        else:
            self.n -= 1
        self.setText(self.orig if self.n == 0 else "".join(random.choice("01#=+") if random.random() < .18 else c for c in self.orig))
        self.update()
        self.tm.start(85 if self.n else random.randint(2800, 6200))
    def paintEvent(self, a0: Any) -> None:
        if self.n > 0:
            g = QPainter(self); g.setFont(self.font())
            for dx, c in ((-2, _QC(128, 185, 190, 75)), (2, _QC(190, 125, 96, 75))):
                g.setPen(c); g.drawText(self.rect().translated(dx, 0), Qt.AlignmentFlag.AlignCenter, self.text())
            g.end()
        super().paintEvent(a0)

class ProfileGreeting(QLabel):
    def __init__(self, text: str, on_art: Callable[[], object]) -> None:
        super().__init__(text); self.on_art = on_art; self.click_count = 0
        self.setCursor(Qt.CursorShape.PointingHandCursor); self.setToolTip("Local profile")
    def register_click(self) -> None:
        self.click_count += 1
        if self.click_count == 10:
            self.click_count = 0
            self.on_art()
    def mousePressEvent(self, ev: Any) -> None:
        self.register_click()
        super().mousePressEvent(ev)

class ClockBadge(QLabel):
    def __init__(
        self,
        on_toggle: Callable[[], object],
        parent: Optional[QWidget] = None,
    ) -> None:
        super().__init__(parent)
        self.on_toggle = on_toggle
        self._long_press_fired = False
        self._press_position = QPoint()
        self.setObjectName("clockBadge")
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setAccessibleName("Local clock")
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setToolTip("Click to change clock format; hold to see clock help.")
        self.setWhatsThis("Local clock. Click to switch between 12-hour and 24-hour time. Hold the mouse button for a clock-format hint.")
        self.setStyleSheet(f"color:{TH['acc']};font-size:13px;font-weight:700;letter-spacing:1px;"
                        f"background:rgba(0,0,0,.18);border:1px solid {TH['line']};padding:5px 9px;border-radius:2px")
        self.setFont(QFont("Consolas", 12, QFont.Weight.Bold))
        self._hold_timer = QTimer(self); self._hold_timer.setSingleShot(True)
        self._hold_timer.timeout.connect(self.show_clock_hint)
        self.refresh()
    def refresh(self) -> None:
        is_24_hour = bool(S("clock24"))
        pattern = "%H:%M:%S" if is_24_hour else "%I:%M:%S %p"
        self.setText(time.strftime(pattern))
        sample = "00:00:00" if is_24_hour else "00:00:00 PM"
        self.setFixedWidth(QFontMetrics(self.font()).horizontalAdvance(sample) + 30)
        self.setAccessibleDescription("24-hour local time" if is_24_hour else "12-hour local time")
    def show_clock_hint(self) -> None:
        self._long_press_fired = True
        QToolTip.showText(self._press_position, "Change clock format\nClick to switch between 12-hour and 24-hour time.",
                          self, self.rect(), 2500)
    def mousePressEvent(self, ev: Any) -> None:
        if ev.button() == Qt.MouseButton.LeftButton:
            self._long_press_fired = False
            self._press_position = ev.globalPos()
            self._hold_timer.start(650)
        super().mousePressEvent(ev)
    def mouseReleaseEvent(self, ev: Any) -> None:
        if ev.button() == Qt.MouseButton.LeftButton:
            self._hold_timer.stop()
            if self._long_press_fired:
                QToolTip.hideText()
            elif self.rect().contains(ev.pos()):
                self.on_toggle()
        super().mouseReleaseEvent(ev)

class Keypad(QDialog):
    """Normal on-screen QWERTY keyboard. Your physical keyboard still works everywhere; this just lets you type with the mouse. Scramble is optional."""
    ROWS = ["1234567890", "qwertyuiop", "asdfghjkl", "zxcvbnm", "!@#$%^&*()-_=+.,?"]
    def __init__(self, parent: Optional[QWidget], start: str = "") -> None:
        super().__init__(parent); self.setWindowTitle("On-screen keyboard"); nocap(self, S("nocap") or S("ghost")); self.v = start; self.up = False; self.sc = False
        screen = parent.screen() if parent is not None else QApplication.primaryScreen(); area = screen.availableGeometry() if screen is not None else QRect(0, 0, 900, 700)
        width = min(540, max(300, area.width() - 24)); height = min(350, max(220, area.height() - 48)); self.resize(width, height)
        self.key_cols = max(1, min(17, (width - 58) // 44)); self.key_width = max(22, min(40, (width - 58) // self.key_cols))
        row_count = sum(math.ceil(len(row) / self.key_cols) for row in self.ROWS)
        self.key_height = max(24, min(38, (height - 120) // max(1, row_count)))
        lo = QVBoxLayout(self); self.dots = lbl("\u25CF" * len(start), 20, ACC, center=True); lo.addWidget(self.dots)
        keys = QWidget(); self.gr = QGridLayout(keys); self.gr.setSpacing(4); sc = QScrollArea(); sc.setWidgetResizable(True); sc.setWidget(keys); lo.addWidget(sc, 1); r = QHBoxLayout()
        for t, f in (("Shift", self.sh), ("Scramble", self.scr), ("Backspace", self.bk), ("Clear", self.cl), ("Done", self.accept)): b = btn(t, "go" if t == "Done" else None); b.clicked.connect(f); r.addWidget(b)
        lo.addLayout(r); self.build()
    def build(self) -> None:
        while self.gr.count():
            layout_item = self.gr.takeAt(0)
            if layout_item is not None:
                widget = layout_item.widget()
                if widget is not None:
                    widget.deleteLater()
        rows = [list(r) for r in self.ROWS]
        if self.sc: allc = [c for r in rows for c in r]; random.SystemRandom().shuffle(allc); it = iter(allc); rows = [[next(it) for _ in r] for r in rows]
        rows = [part for row in rows for part in (row[i:i + self.key_cols] for i in range(0, len(row), self.key_cols))]
        for i, r in enumerate(rows):
            for j, c in enumerate(r):
                b = btn(c.upper() if self.up else c); b.setMinimumSize(self.key_width, self.key_height)
                b.clicked.connect(_clicked_slot(self.add, b.text())); self.gr.addWidget(b, i, j)
    def show_dots(self) -> None: self.dots.setText("\u25CF" * len(self.v))
    def add(self, c: str) -> None: self.v += c; self.show_dots()
    def bk(self) -> None: self.v = self.v[:-1]; self.show_dots()
    def cl(self) -> None: self.v = ""; self.show_dots()
    def sh(self) -> None: self.up = not self.up; self.build()
    def scr(self) -> None: self.sc = not self.sc; self.build()

class Inferno(QWidget):
    """Panic / self-destruct: optional 3-2-1, then YOUR window burns away from the bottom up, a burning word appears, then a close."""
    def __init__(
        self,
        p: QWidget,
        ms: int,
        word: str,
        c0: float,
        crt: bool,
        rv: bool = False,
    ) -> None:
        super().__init__(p); self.pm = p.grab(); self.word, self.c0, self.crt, self.rv = word, c0, crt, rv; self.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents, rv); self._t = 0.0; self.f: list[list[float]] = []; self.setGeometry(p.rect()); self.show(); self.raise_()
        a = QPropertyAnimation(self, b"t", self); a.setDuration(max(60, ms)); a.setStartValue(0.0); a.setEndValue(1.0); self.a = a; a.start()
        self.tm = QTimer(self); self.tm.timeout.connect(self.step); self.tm.start(33 if perf() == "full" else 50)
    def gett(self) -> float: return self._t
    def sett(self, v: float) -> None: self._t = v; self.update()
    t = pyqtProperty(float, gett, sett)
    def front(self) -> float: return max(0.0, min(1.0, (self._t - self.c0) / (.7 - self.c0)))
    def step(self) -> None:
        w, h, b = self.width(), self.height(), self.front(); y = h * (1 - b); n = 15 if perf() == "full" else 6
        if 0 < b < 1: self.f += [[random.uniform(0, w), y + random.uniform(-8, 30), random.uniform(-.8, .8), random.uniform(-6.5, -2), 1.0, random.uniform(.016, .035), random.uniform(8, 28)] for _ in range(n)]
        elif b >= 1 and self._t < .9: self.f += [[random.uniform(-20, w + 20), h + 8, random.uniform(-.8, .8), random.uniform(-6.5, -2.5), 1.0, random.uniform(.018, .04), random.uniform(8, 26)] for _ in range(n // 2)]
        for q in self.f: q[0] += q[2] + math.sin(q[1] / 37 + q[6]) * 1.2; q[1] += q[3]; q[4] -= q[5]
        self.f = [q for q in self.f if q[4] > 0]; self.update()
    def paintEvent(self, a0: Any) -> None:
        g = QPainter(self); g.setRenderHint(QPainter.RenderHint.Antialiasing); w, h, t = self.width(), self.height(), self._t; b = self.front(); y = h * (1 - b)
        if not self.rv: g.fillRect(self.rect(), _QC(0, 0, 0))
        if t >= .92 and self.crt:   # CRT close: collapse to a line, then a dot
            u = (t - .92) / .08
            if u < .55: lh = max(3, h * (1 - u / .55) ** 3); g.fillRect(QRectF(0, (h - lh) / 2, w, lh), _QC(255, 255, 255, 240))
            elif u < .9: lw = max(4, w * (1 - (u - .55) / .35) ** 2); g.fillRect(QRectF((w - lw) / 2, h / 2 - 1.5, lw, 3), _QC(255, 255, 255, 240))
            return
        if b < 1:   # your real window, still intact above the burn line
            g.save(); g.setClipRect(0, 0, w, int(y)); g.drawPixmap(0, 0, self.pm)
            if t < self.c0: g.fillRect(0, 0, w, h, _QC(255, 0, 0, int(55 + 45 * math.sin(t * 80))))
            g.restore()
            if b > 0:
                cg = QLinearGradient(0, y - 90, 0, y); cg.setColorAt(0, _QC(0, 0, 0, 0)); cg.setColorAt(.7, _QC(40, 8, 0, 170)); cg.setColorAt(1, _QC(0, 0, 0, 255)); g.fillRect(0, int(y - 90), w, 90, cg)
                g.setCompositionMode(QPainter.CompositionMode.CompositionMode_Plus); gl = QLinearGradient(0, y - 30, 0, y + 80); gl.setColorAt(0, _QC(255, 120, 0, 0)); gl.setColorAt(.4, _QC(255, 190, 60, 230)); gl.setColorAt(.6, _QC(255, 70, 0, 200)); gl.setColorAt(1, _QC(0, 0, 0, 0))
                g.fillRect(0, int(y - 30), w, 110, gl); g.setCompositionMode(QPainter.CompositionMode.CompositionMode_SourceOver)
        g.setCompositionMode(QPainter.CompositionMode.CompositionMode_Plus); g.setPen(Qt.PenStyle.NoPen)
        for x, py, _, _, l, _, r in self.f: g.setBrush(_QC(255, int(40 + 215 * l * l), int(200 * l ** 4), int(170 * l))); g.drawEllipse(QPointF(x, py), r * (.35 + .65 * l), r * (.35 + .65 * l))
        g.setCompositionMode(QPainter.CompositionMode.CompositionMode_SourceOver)
        if t < self.c0:   # 3 - 2 - 1
            g.setFont(QFont("Georgia", max(60, min(150, w // 6)), QFont.Weight.Bold)); g.setPen(_QC(255, 70, 50, 240)); g.drawText(QRectF(0, 0, w, h), Qt.AlignmentFlag.AlignCenter, str(3 - min(2, int(t / self.c0 * 3))))
            fn = QFont("Georgia", max(11, min(18, w // 55))); fn.setLetterSpacing(QFont.SpacingType.AbsoluteSpacing, 4); g.setFont(fn); g.setPen(_QC(255, 210, 200, 230)); g.drawText(QRectF(0, h * .68, w, 40), Qt.AlignmentFlag.AlignHCenter, "SELF-DESTRUCT SEQUENCE")
        burn = max(0.0, (t - .84) / .08)
        if t > .66 and self.word:   # the burning word
            fnt = QFont("Georgia", max(26, min(70, w // 13)), QFont.Weight.Bold); fnt.setLetterSpacing(QFont.SpacingType.AbsoluteSpacing, 10); g.setFont(fnt); box = QRectF(0, h * .3, w, h * .22); tx = self.word; a = min(1.0, (t - .66) * 9) * (1 - burn)
            if random.random() < .18 or burn > 0: tx = "".join(random.choice("\u2593\u2592\u2591#@") if random.random() < .25 + burn * .5 else c for c in tx)
            g.setCompositionMode(QPainter.CompositionMode.CompositionMode_Plus)
            for dy, c in ((-6, (255, 220, 60)), (-14, (255, 110, 0)), (-24, (255, 40, 0))): g.setPen(_QC(*c, int(120 * a))); g.drawText(box.translated(random.uniform(-5, 5), dy * random.uniform(.5, 1.4) - burn * 40), Qt.AlignmentFlag.AlignCenter, tx)
            g.setCompositionMode(QPainter.CompositionMode.CompositionMode_SourceOver); g.setPen(_QC(255, 245, 235, int(255 * a))); g.drawText(box.translated(0, -burn * 30), Qt.AlignmentFlag.AlignCenter, tx)
            if self.crt and t > .74: fnt = QFont("Georgia", max(11, min(20, w // 48))); fnt.setItalic(True); g.setFont(fnt); g.setPen(_QC(255, 190, 130, int(210 * min(1, (t - .74) * 8) * (1 - burn)))); g.drawText(QRectF(0, h * .52, w, 40), Qt.AlignmentFlag.AlignHCenter, "What was known is now unknown.")

class Card(QFrame):
    """File row. Animating 'burn' (0..1) dissolves it in a rising neon fire."""
    name: str
    rid: str
    meta: _VaultMetadata
    vl: QLabel
    filter_text: str

    def __init__(self) -> None: super().__init__(); self._b = 0.0
    def getb(self) -> float: return self._b
    def setb(self, v: float) -> None: self._b = v; self.update()
    burn = pyqtProperty(float, getb, setb)
    def paintEvent(self, a0: Any) -> None:
        super().paintEvent(a0)
        if self._b > 0:   # pixel-dissolve: blocks glow in the accent color, then vanish
            g = QPainter(self); B = 14; bg = _QC(TH["bg0"]); rg = random.Random(id(self) & 0xffff); b = self._b * 1.3; W = max(1, self.width())
            for i in range(0, self.width(), B):
                for j in range(0, self.height(), B):
                    d = b - rg.random() * .85 * (.65 + .35 * i / W)
                    if d > .14: g.fillRect(i, j, B, B, bg)
                    elif d > 0: g.fillRect(i, j, B, B, _QC(255, int(70 + 150 * (1 - d / .14)), 10, int(255 * (1 - d / .14))))

class Flash(QWidget):
    """Full-window flash used by the panic wipe (violet) and the self-destruct (red)."""
    def __init__(self, p: QWidget, hot: bool = False) -> None: super().__init__(p); self._a = 0.0; self.hot = hot; self.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
    def geta(self) -> float: return self._a
    def seta(self, v: float) -> None: self._a = v; self.update()
    amt = pyqtProperty(float, geta, seta)
    def paintEvent(self, a0: Any) -> None:
        c = ((255, 40, 60), (255, 210, 190)) if self.hot else ((139, 92, 255), (235, 225, 255))
        g = QPainter(self); rg = QRadialGradient(self.width() / 2, self.height(), self.height() * 1.1)
        rg.setColorAt(0, QColor(*c[1], int(220 * self._a))); rg.setColorAt(.4, QColor(*c[0], int(235 * self._a))); rg.setColorAt(1, QColor(0, 0, 0, int(255 * self._a)))
        g.fillRect(self.rect(), rg)

class Upload(QWidget):
    """In-app progress overlay used for long vault work."""
    WARN = "Heads up: a very large file can freeze this window for a bit. It is still working and will continue, so you can still read or delete it afterwards. Do NOT close the app until it finishes: closing now can corrupt data."
    def __init__(self, parent: QWidget) -> None:
        super().__init__(parent)
        screen = parent.screen(); area = screen.availableGeometry() if screen is not None else QRect(0, 0, 900, 700)
        width = min(540, max(300, area.width() - 24))
        self.target = self.shown = 0.0; self.ph = 0; self.txt = "Preparing..."; self.hx = ""; self.fast = False
        self.loading_message = EASTER_EGGS.message("loading")
        self.loading_message_label = QLabel(self.loading_message, self)
        self.loading_message_label.setObjectName("easterEggLoadingMessage")
        self.loading_message_label.setWordWrap(True)
        message_font = QFont("Consolas", 8)
        self.loading_message_label.setFont(message_font)
        self.loading_message_label.setStyleSheet("color:#b2e8bd;background:transparent;")
        message_bounds = QFontMetrics(message_font).boundingRect(
            QRect(0, 0, width - 40, 4096),
            Qt.TextFlag.TextWordWrap,
            self.loading_message,
        )
        message_height = max(22, message_bounds.height())
        self._loading_message_extra_height = message_height - 22
        self.resize(width, 250 + self._loading_message_extra_height)
        self.loading_message_label.setGeometry(20, 34, width - 40, message_height)
        self._show_timer: Optional[QTimer] = None
        self.move(parent.rect().center() - self.rect().center()); t = QTimer(self); t.timeout.connect(self.step); t.start(16)
    def show_after(self, delay_ms: int = 250) -> None:
        if type(delay_ms) is not int or delay_ms < 0:
            raise ValueError("Progress-window delay must be a non-negative integer.")
        self._show_timer = QTimer(self)
        self._show_timer.setSingleShot(True)
        self._show_timer.timeout.connect(self.show)
        self._show_timer.start(delay_ms)
    def step(self) -> None:
        if self.target > self.shown: self.shown = min(self.target, self.shown + max((self.target - self.shown) * (.3 if self.fast else .08), .02 if self.fast else .004))
        self.ph += 1
        if self.ph % 3 == 0: self.hx = "".join(random.choice("0123456789abcdef") for _ in range(52))
        self.update()
    def pump(self, target: float, txt: str) -> None: self.target = target; self.txt = txt; QApplication.processEvents()
    def finish(self, msg: str = "Sealed. It is unknown now.") -> None:
        if self._show_timer is not None:
            self._show_timer.stop()
            self._show_timer = None
        if not self.isVisible():
            self.shown = 1.0; self.target = 1.0; self.txt = msg
            return
        self.fast = True; self.target = 1.0; self.txt = msg
        while self.shown < .999: QApplication.processEvents(); time.sleep(.008)
        for _ in range(35): QApplication.processEvents(); time.sleep(.008)
    def closeEvent(self, a0: Optional[QCloseEvent]) -> None:
        if self._show_timer is not None:
            self._show_timer.stop()
            self._show_timer = None
        super().closeEvent(a0)
    def keyPressEvent(self, a0: Any) -> None: pass   # Esc must not dismiss it mid-operation (do NOT override reject(): close() calls it)
    def paintEvent(self, a0: Any) -> None:
        g = QPainter(self); g.fillRect(self.rect(), _QC("#020a04")); g.setPen(QPen(_QC("#33ff66"), 2)); g.setBrush(Qt.BrushStyle.NoBrush); g.drawRect(QRectF(self.rect()).adjusted(1, 1, -1, -1))
        f = QFont("Consolas", 10); f.setStyleHint(QFont.StyleHint.Monospace); g.setFont(f); g.setPen(_QC("#33ff66")); g.drawText(QRectF(20, 12, 500, 20), Qt.AlignmentFlag.AlignLeft, "> " + self.txt[:54])
        offset = self._loading_message_extra_height
        n = int(self.shown * 30); f.setPointSize(12); f.setBold(True); g.setFont(f); g.setPen(_QC("#33ff66")); g.drawText(QRectF(20, 62 + offset, 510, 26), Qt.AlignmentFlag.AlignLeft, "[" + "#" * n + "-" * (30 - n) + f"] {int(self.shown * 100)}% loaded")
        f.setBold(False); f.setPointSize(8); g.setFont(f); g.setPen(_QC("#157a35")); g.drawText(QRectF(20, 96 + offset, 500, 18), Qt.AlignmentFlag.AlignLeft, self.hx)
        f.setPointSize(9); g.setFont(f); g.setPen(_QC("#ffb347")); g.drawText(QRectF(20, 126 + offset, 500, 112), Qt.AlignmentFlag.AlignLeft | Qt.TextFlag.TextWordWrap, "! " + self.WARN)

class HK(QAbstractNativeEventFilter):
    """Windows global hotkey receiver."""
    def __init__(self, cb: Callable[[], object]) -> None: super().__init__(); self.cb = cb
    def nativeEventFilter(
        self,
        eventType: QByteArray,
        message: object,
    ) -> tuple[bool, int]:
        if bytes(eventType) == b"windows_generic_MSG":
            import ctypes.wintypes as w
            if isinstance(message, int):
                g = w.MSG.from_address(message)
            else:
                return False, 0
            if g.message == 0x0312 and g.wParam == 1: self.cb(); return True, 0
        return False, 0
def vk(k: int) -> int:
    if 0x30 <= k <= 0x39 or 0x41 <= k <= 0x5a: return k
    if k in (int(Qt.Key.Key_Tab), int(Qt.Key.Key_Backtab)): return 9
    if int(Qt.Key.Key_F1) <= k <= int(Qt.Key.Key_F12): return 0x70 + k - int(Qt.Key.Key_F1)
    return {int(Qt.Key.Key_Escape): 27, int(Qt.Key.Key_Space): 32,
            int(Qt.Key.Key_Backspace): 8, int(Qt.Key.Key_Delete): 46}.get(k, 0)

class PhotoCanvas(QLabel):
    """Image surface with in-memory marks and scroll-area dragging."""
    def __init__(self, scroll: QScrollArea) -> None:
        super().__init__(); self.scroll_area = scroll; self.tool = "pan"; self.marks: list[_PhotoMark] = []; self.drag: Optional[tuple[QPoint, int, int]] = None
        self.zoom_callback: Optional[Callable[[float, Optional[QPoint]], None]] = None
        self.source_pixmap: Optional[QPixmap] = None
        self.setAlignment(cast(Any, Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop)); self.setMouseTracking(True); self.set_tool("pan")
    def set_tool(self, tool: str) -> None:
        self.tool = tool; self.setCursor(QCursor(Qt.CursorShape.OpenHandCursor if tool == "pan" else Qt.CursorShape.CrossCursor))
    def image_point(self, point: QPoint) -> tuple[float, float]:
        return (min(1.0, max(0.0, point.x() / max(1, self.width()))),
                min(1.0, max(0.0, point.y() / max(1, self.height()))))
    def mousePressEvent(self, ev: Any) -> None:
        if ev.button() != Qt.MouseButton.LeftButton: return super().mousePressEvent(ev)
        point = self.image_point(ev.pos())
        if self.tool == "pan":
            horizontal, vertical = self.scroll_area.horizontalScrollBar(), self.scroll_area.verticalScrollBar()
            if horizontal is None or vertical is None: return
            self.drag = (ev.globalPos(), horizontal.value(), vertical.value())
            self.setCursor(QCursor(Qt.CursorShape.ClosedHandCursor))
        elif self.tool == "pin":
            self.marks.append({"kind": "pin", "point": point}); self.update()
        elif self.tool == "highlight":
            self.marks.append({"kind": "highlight", "points": [point]}); self.update()
        elif self.tool == "erase":
            self.erase_at(point)
        ev.accept()
    def mouseMoveEvent(self, ev: Any) -> None:
        if self.drag is not None:
            origin, x, y = self.drag; delta = ev.globalPos() - origin
            horizontal, vertical = self.scroll_area.horizontalScrollBar(), self.scroll_area.verticalScrollBar()
            if horizontal is None or vertical is None: return
            horizontal.setValue(x - delta.x()); vertical.setValue(y - delta.y())
        elif (self.tool == "highlight"
              and bool(int(ev.buttons()) & int(Qt.MouseButton.LeftButton))
              and self.marks and self.marks[-1]["kind"] == "highlight"):
            self.marks[-1]["points"].append(self.image_point(ev.pos())); self.update()
        ev.accept()
    def mouseReleaseEvent(self, ev: Any) -> None:
        if self.drag is not None: self.drag = None; self.setCursor(QCursor(Qt.CursorShape.OpenHandCursor))
        ev.accept()
    def wheelEvent(self, a0: Any) -> None:
        if self.zoom_callback and a0.angleDelta().y():
            self.zoom_callback(1.25 if a0.angleDelta().y() > 0 else 1 / 1.25, a0.pos())
            a0.accept()
        else: super().wheelEvent(a0)
    def erase_at(self, point: tuple[float, float]) -> None:
        x, y = point; nearest = None; distance = 30
        for i, mark in enumerate(self.marks):
            pts = [mark["point"]] if mark["kind"] == "pin" else mark["points"]
            for px, py in pts:
                d = (((px - x) * self.width()) ** 2 + ((py - y) * self.height()) ** 2) ** .5
                if d < distance: nearest, distance = i, d
        if nearest is not None: self.marks.pop(nearest); self.update()
    def clear_marks(self) -> None:
        self.marks.clear(); self.update()
    def draw_marks(self, painter: QPainter, width: int, height: int) -> None:
        painter.save(); painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        for index, mark in enumerate(self.marks, 1):
            if mark["kind"] == "pin":
                x, y = mark["point"]; x *= width; y *= height
                painter.setPen(QPen(QColor(34, 211, 238), 2)); painter.setBrush(QColor(11, 17, 21, 220)); painter.drawEllipse(QPointF(x, y), 10, 10)
                painter.setPen(QColor(234, 249, 250)); painter.setFont(QFont("Consolas", 8)); painter.drawText(QRectF(x - 7, y - 7, 14, 14), Qt.AlignmentFlag.AlignCenter, str(index))
            elif len(mark["points"]) > 1:
                path = QPainterPath()
                for point_index, (x, y) in enumerate(mark["points"]):
                    (path.moveTo if point_index == 0 else path.lineTo)(x * width, y * height)
                painter.setBrush(Qt.BrushStyle.NoBrush); painter.setPen(QPen(QColor(255, 218, 92, 105), max(12, min(width, height) * .025), Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap, Qt.PenJoinStyle.RoundJoin)); painter.drawPath(path)
        painter.restore()
    def paintEvent(self, a0: Any) -> None:
        super().paintEvent(a0); painter = QPainter(self); self.draw_marks(painter, self.width(), self.height()); painter.end()
    def marked_image(self) -> QImage:
        source = self.source_pixmap if self.source_pixmap is not None else self.pixmap()
        if source is None:
            raise RuntimeError("Cannot render image annotations without a source image.")
        image = source.toImage().convertToFormat(QImage.Format.Format_ARGB32); painter = QPainter(image)
        self.draw_marks(painter, image.width(), image.height()); painter.end(); return image

class Viewer(QDialog):
    """View-only preview. File-backed playback uses an app-owned temp file that is wiped after playback or when the viewer closes."""
    closed = False
    def __init__(
        self,
        name: str,
        data: Optional[bytes],
        last: bool,
        parent: Optional[QWidget],
        media_path: Optional[Union[os.PathLike[str], str]] = None,
        media_digest: Optional[str] = None,
        limited_access: bool = False,
    ) -> None:
        super().__init__(parent)
        self.pm: Optional[QPixmap] = None; self.mp: Any = None; self.mv: Optional[QMovie] = None
        self.sv: Optional[QPushButton] = None; self.buf: Optional[QBuffer] = None
        self.lb: Optional[Union[PhotoCanvas, QLabel]] = None; self.media: Any = None
        self.tmp: Optional[Path] = None; self.pb: Optional[QPushButton] = None
        self.zoom_label: Optional[QLabel] = None; self.pdf_doc: Optional[_PdfDocumentLike] = None
        self.photo_tool_buttons: dict[str, QPushButton] = {}
        self.photo_scroll: Optional[QScrollArea] = None; self.volume_slider: Optional[QSlider] = None
        self.speed_label: Optional[QLabel] = None
        self.media_controls: list[QWidget] = []; self.image_zoom = 1.0; self.pdf_zoom = 1.0; self.pdf_page = 0; self.closed = False
        self.archive_name: str = ""; self.archive_data: bytes = b""; self.archive_path: str = ""; self.archive_history: list[str] = []
        self.tmp = Path(media_path) if media_path is not None else None
        self.export_name = name; self.export_data = data if media_path is None else None; self.media_digest = media_digest
        self.limited_access = limited_access
        self.setWindowTitle("Viewer" if S("hidename") else name); screen = parent.screen() if parent is not None else None
        width = screen.availableGeometry().width() if screen is not None else 900; height = screen.availableGeometry().height() if screen is not None else 700
        self.resize(min(820, max(360, width - 32)), min(600, max(320, height - 56))); nocap(self, S("nocap")); v = QVBoxLayout(self)
        self.left = S("vclose") * 1000; self.tot = max(1, self.left)
        if self.left: tm = QTimer(self); tm.timeout.connect(self.cd); tm.start(40)
        if data is None and media_path is not None:
            with open(media_path, "rb") as source: preview = source.read(8192)
            k = MD.kind(name, preview)
        else:
            k = MD.kind(name, data if data is not None else b"")
        preview_data = data if data is not None else b""
        try: ok = self.render_media(v, name, preview_data, k, media_path)
        except Exception: ok = False; self.release_media(); self.release_pdf(); self.pm = self.mp = self.mv = self.lb = None
        if not ok: self.info(v, name, preview_data, k)
        if self.limited_access:
            self.sv = btn("Decrypt")
            self.sv.setToolTip(
                "A copy cannot be exported from an item with an expiry or view limit.")
            self.sv.clicked.connect(self.show_limited_export_message)
            v.addWidget(self.sv)
        elif S("export"):
            if self.export_data is not None:
                self.sv = btn("Save a decrypted copy...")
                self.sv.clicked.connect(_clicked_slot(self.save, self.export_name, self.export_data))
                v.addWidget(self.sv)
            elif self.tmp is not None and self.media_digest is not None:
                self.sv = btn("Save a decrypted copy...")
                self.sv.clicked.connect(_clicked_slot(self.save_temp_copy))
                v.addWidget(self.sv)
        c = btn("Close and burn" if last else "Close", "danger" if last else None); c.clicked.connect(self.accept); v.addWidget(c)
    def show_limited_export_message(self) -> None:
        notice = QDialog(self)
        notice.setWindowTitle("UNKNWN // NICE TRY")
        notice.setWindowModality(Qt.WindowModality.NonModal)
        notice.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose, True)
        notice.setMinimumWidth(280)
        notice.setMaximumWidth(520)
        layout = QVBoxLayout(notice)
        message = QLabel("HAHAHAAH GET FOOLED")
        message.setWordWrap(True)
        message.setAlignment(Qt.AlignmentFlag.AlignCenter)
        message.setStyleSheet(f"color:{TH['acc']};font-size:18px;font-weight:700;padding:18px")
        layout.addWidget(message)
        detail = QLabel("This limited item cannot be saved as a decrypted copy. Closing this notice will also close the preview.")
        detail.setWordWrap(True)
        layout.addWidget(detail)
        notice.adjustSize()
        notice.setFixedSize(notice.sizeHint())
        notice_timer = QTimer(notice)
        notice_timer.setSingleShot(True)
        def dismiss_limited_preview() -> None:
            notice.close()
            self.accept()
        notice_timer.timeout.connect(dismiss_limited_preview)
        notice_timer.start(3000)
        def stop_notice_timer(_result: int) -> None:
            notice_timer.stop()
        notice.finished.connect(stop_notice_timer)
        notice.show()
    def render_media(
        self,
        v: QVBoxLayout,
        name: str,
        data: bytes,
        k: str,
        media_path: Optional[Union[os.PathLike[str], str]] = None,
    ) -> bool:
        if k == "archive" and MD.is_zip_data(data):
            return self.render_zip_browser(v, name, data)
        parsed = MD.preview_content(name, data, k)
        if parsed is not None:
            heading = {
                "archive": "ARCHIVE DIRECTORY PREVIEW",
                "office": "OFFICE DOCUMENT PREVIEW",
                "epub": "E-BOOK PREVIEW",
                "midi": "MIDI SEQUENCE PREVIEW",
                "program": "PROGRAM METADATA PREVIEW",
                "disk": "DISK IMAGE DIRECTORY PREVIEW",
            }.get(k, "FILE PREVIEW")
            v.addWidget(lbl(heading, 12, ACC))
            self.edit(v, parsed, True)
            return True
        if k == "gif":
            self.buf = QBuffer(self); self.buf.setData(QByteArray(data)); self.buf.open(QIODevice.OpenModeFlag.ReadOnly); mv = QMovie(self.buf, QByteArray(b"gif"), self)
            if mv.isValid() and mv.frameCount() != 1:   # a real animation
                mv.jumpToFrame(0); sz = mv.currentImage().size(); z = sz.scaled(780, 480, Qt.AspectRatioMode.KeepAspectRatio)
                if z.width() < sz.width(): mv.setScaledSize(z)
                self.lb = QLabel(); self.lb.setAlignment(Qt.AlignmentFlag.AlignCenter); self.lb.setMovie(mv); v.addWidget(self.lb, 1); mv.start(); self.mv = mv; return True
            self.buf = None   # one frame: show it as a normal picture
        if k in ("gif", "image"):
            pm = QPixmap()
            if not pm.loadFromData(data): return False
            o = MD.exif_orientation(data)
            if o > 1:
                a, sx, sy = MD.ORIENT[o]
                pm = pm.transformed(QTransform().scale(sx, sy).rotate(a), Qt.TransformationMode.SmoothTransformation)   # phone photos: honor the EXIF rotation
            self.pm = pm; self.photo_scroll = QScrollArea(); self.photo_scroll.setWidgetResizable(False); photo_canvas = PhotoCanvas(self.photo_scroll); self.lb = photo_canvas; photo_canvas.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed); photo_canvas.zoom_callback = self.change_zoom; photo_canvas.source_pixmap = pm
            photo_canvas.setPixmap(pm.scaled(780, 480, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation))
            rendered_pixmap = photo_canvas.pixmap()
            if rendered_pixmap is None: return False
            photo_canvas.setFixedSize(rendered_pixmap.size()); self.photo_scroll.setWidget(photo_canvas); v.addWidget(self.photo_scroll, 1)
            tools = QVBoxLayout(); tools.addWidget(lbl("MARKS", 10, MUT, center=True)); self.photo_tool_buttons = {}
            for text, tool in (("Pan", "pan"), ("Pin", "pin"), ("Highlight", "highlight"), ("Erase mark", "erase")):
                control = btn(text); control.setCheckable(True)
                def select_tool(_checked: bool = False, selected_tool: str = tool) -> None:
                    self.select_photo_tool(selected_tool)
                control.clicked.connect(select_tool); self.photo_tool_buttons[tool] = control; tools.addWidget(control)
            self.select_photo_tool("pan")
            clear = btn("Clear marks"); clear.clicked.connect(photo_canvas.clear_marks); tools.addWidget(clear)
            if S("export"):
                save_marked = btn("Save marked copy"); save_marked.clicked.connect(_clicked_slot(self.save_marked, name)); tools.addWidget(save_marked)
            tools.addStretch()
            body = QHBoxLayout(); body.addWidget(self.photo_scroll, 1); side = QWidget(); side.setLayout(tools); side.setMaximumWidth(128); body.addWidget(side); v.addLayout(body, 1)
            zoom = QHBoxLayout(); out = btn("Zoom -"); self.zoom_label = lbl("100%", 12, MUT); inc = btn("Zoom +"); reset = btn("Reset")
            zoom.addWidget(out); zoom.addWidget(self.zoom_label); zoom.addWidget(inc); zoom.addWidget(reset); v.addLayout(zoom)
            out.clicked.connect(_clicked_slot(self.change_zoom, 1 / 1.25)); inc.clicked.connect(_clicked_slot(self.change_zoom, 1.25)); reset.clicked.connect(self.reset_zoom)
            self.bind_shortcut("+", lambda: self.change_zoom(1.25)); self.bind_shortcut("-", lambda: self.change_zoom(1 / 1.25)); self.bind_shortcut("0", self.reset_zoom)
            self.bind_shortcut("Escape", lambda: photo_canvas.set_tool("pan"))
            return True   # resizeEvent refines this to the real window size
        if k == "pdf":
            return self.render_pdf(v, data)
        if k in ("video", "audio"):
            vm = S("vmode"); vm = "mem" if vm == "file" and S("ghost") else vm   # ghost mode never writes a decrypted file
            if vm == "off" or QMediaPlayer is None or QMediaContent is None or QVideoWidget is None: return False
            if vm == "file":
                self.tmp = Path(media_path) if media_path is not None else tmp_media(name, data)
                self.media = (QMediaContent(QUrl.fromLocalFile(str(self.tmp))),)
            else: self.buf = QBuffer(self); self.buf.setData(QByteArray(data)); self.buf.open(QIODevice.OpenModeFlag.ReadOnly); self.media = (QMediaContent(), self.buf)
            mp = QMediaPlayer(self)
            if k == "video": vw = QVideoWidget(); cast(Any, mp).setVideoOutput(vw); v.addWidget(vw, 1)
            else: v.addWidget(lbl("\u266A", 64, center=True), 1)
            st = lbl("", 12, MUT); sl = QSlider(Qt.Orientation.Horizontal); sl.setRange(0, 0); pb = btn("Pause"); slower = btn("Speed -"); self.speed_label = lbl("1x", 12, MUT); faster = btn("Speed +")
            self.pb = pb; self.speed = 1.0; self.volume = 70; self.media_controls = [pb, slower, faster, sl]
            time_label = lbl("00:00 / 00:00", 11, MUT); seek_back = btn("-5s"); seek_forward = btn("+5s"); volume = QSlider(Qt.Orientation.Horizontal); volume.setRange(0, 100); volume.setValue(self.volume); self.volume_slider = volume
            self.media_controls.extend((seek_back, seek_forward, volume))
            row = QHBoxLayout(); row.addWidget(pb); row.addWidget(seek_back); row.addWidget(seek_forward); row.addWidget(slower); row.addWidget(self.speed_label); row.addWidget(faster); row.addWidget(sl, 1); row.addWidget(time_label); row.addWidget(lbl("VOL", 10, MUT)); row.addWidget(volume)
            if k == "video":
                mute = btn("Mute"); full = btn("Fullscreen"); row.addWidget(mute); row.addWidget(full)
                self.media_controls.extend((mute, full))
                mute.clicked.connect(_clicked_slot(self.toggle_mute, mute)); full.clicked.connect(_clicked_slot(self.toggle_fullscreen))
                def volume_label_changed(value: int) -> None:
                    mute.setText("Mute" if value else "Unmute")
                volume.valueChanged.connect(volume_label_changed)
                self.bind_shortcut("F", self.toggle_fullscreen); self.bind_shortcut("M", lambda: self.toggle_mute(mute))
            v.addLayout(row); v.addWidget(st)
            def duration_changed(duration: int) -> None:
                sl.setRange(0, duration)
                self.update_time(time_label, mp.position(), duration)
            def position_changed(position: int) -> None:
                if not sl.isSliderDown():
                    sl.setValue(position)
                self.update_time(time_label, position, mp.duration())
            mp.durationChanged.connect(duration_changed)
            mp.positionChanged.connect(position_changed)
            sl.sliderMoved.connect(mp.setPosition); volume.valueChanged.connect(mp.setVolume); mp.setVolume(self.volume)
            def media_error_slot(_error: object) -> None:
                self.media_error(st, mp)
            mp.error.connect(media_error_slot); pb.clicked.connect(_clicked_slot(self.toggle, pb))
            slower.clicked.connect(_clicked_slot(self.change_speed, -0.25)); faster.clicked.connect(_clicked_slot(self.change_speed, 0.25))
            seek_back.clicked.connect(_clicked_slot(self.seek_by, -5000)); seek_forward.clicked.connect(_clicked_slot(self.seek_by, 5000))
            self.bind_shortcut("Space", lambda: self.toggle(pb)); self.bind_shortcut("Ctrl+Left", lambda: self.change_speed(-0.25)); self.bind_shortcut("Ctrl+Right", lambda: self.change_speed(0.25))
            self.bind_shortcut("Left", lambda: self.seek_by(-5000)); self.bind_shortcut("Right", lambda: self.seek_by(5000))
            self.bind_shortcut("Up", lambda: volume.setValue(min(100, volume.value() + 5))); self.bind_shortcut("Down", lambda: volume.setValue(max(0, volume.value() - 5)))
            self.mp = mp; QTimer.singleShot(150, self.start_media); return True   # start only once the window is on screen: the media backend must never block the first paint
        if k == "svg":
            if QSvgWidget is None: return self.text(v, data)
            w = QSvgWidget(); w.load(QByteArray(data)); v.addWidget(w, 1); return True
        if k == "text": return self.text(v, data)
        return False   # archives, programs...: the info page
    def render_zip_browser(self, v: QVBoxLayout, name: str, data: bytes) -> bool:
        self.archive_name = name; self.archive_data = data; self.archive_path = ""; self.archive_history = []
        v.addWidget(lbl("ARCHIVE // IN-APP BROWSER", 12, ACC))
        controls = QHBoxLayout()
        self.archive_back = btn("Back"); self.archive_up = btn("Up")
        self.archive_path_label = lbl("/", 11, MUT)
        self.archive_open = btn("Open", "go")
        self.archive_stats = btn("Stats")
        controls.addWidget(self.archive_back); controls.addWidget(self.archive_up); controls.addWidget(self.archive_path_label, 1); controls.addWidget(self.archive_stats); controls.addWidget(self.archive_open)
        v.addLayout(controls)
        browse_options = QHBoxLayout()
        self.archive_search = QLineEdit()
        self.archive_search.setPlaceholderText("Filter this folder")
        self.archive_sort = QComboBox()
        self.archive_sort.addItems(["Name", "Size", "Type"])
        browse_options.addWidget(self.archive_search, 1); browse_options.addWidget(self.archive_sort)
        v.addLayout(browse_options)
        self.archive_list = QListWidget(); self.archive_list.setObjectName("archiveBrowser"); self.archive_list.setAlternatingRowColors(True)
        row_hover = mix(TH["panel"], TH["acc"], .16)
        row_selected = mix(TH["panel"], TH["acc"], .34)
        self.archive_list.setStyleSheet(
            f"QListWidget#archiveBrowser {{ background-color:{TH['panel']}; color:{TH['fg']}; "
            f"border:1px solid {TH['line']}; outline:0; }}"
            f"QListWidget#archiveBrowser::viewport {{ background-color:{TH['panel']}; }}"
            f"QListWidget#archiveBrowser::item {{ color:{TH['fg']}; padding:7px 9px; "
            f"border-bottom:1px solid {TH['line']}; }}"
            f"QListWidget#archiveBrowser::item:alternate {{ background-color:{TH['field']}; }}"
            f"QListWidget#archiveBrowser::item:hover {{ background-color:{row_hover}; }}"
            f"QListWidget#archiveBrowser::item:selected {{ background-color:{row_selected}; "
            f"color:{TH['fg']}; border-left:2px solid {TH['acc']}; }}"
            f"QListWidget#archiveBrowser QScrollBar:vertical {{ background:{TH['field']}; "
            f"width:10px; margin:0; }}"
            f"QListWidget#archiveBrowser QScrollBar::handle:vertical {{ background:{TH['line']}; "
            f"min-height:24px; }}"
            f"QListWidget#archiveBrowser QScrollBar::add-line:vertical, "
            f"QListWidget#archiveBrowser QScrollBar::sub-line:vertical {{ height:0; }}"
        )
        def archive_item_activated(item: QListWidgetItem) -> None:
            self.open_archive_item(item)
        self.archive_list.itemActivated.connect(archive_item_activated)
        def archive_selection_changed() -> None:
            self.archive_open.setEnabled(self.archive_list.currentItem() is not None)
            self.update_archive_details()
        self.archive_list.itemSelectionChanged.connect(archive_selection_changed)
        v.addWidget(self.archive_list, 1)
        self.archive_details = lbl("Select a file or folder to view its details.", 10, MUT)
        v.addWidget(self.archive_details)
        self.archive_back.clicked.connect(self.back_archive)
        self.archive_up.clicked.connect(self.up_archive)
        self.archive_open.clicked.connect(self.open_selected_archive_item)
        self.archive_stats.clicked.connect(_clicked_slot(self.show_archive_statistics))
        self.archive_search.textChanged.connect(self.populate_archive)
        self.archive_sort.currentTextChanged.connect(self.populate_archive)
        self.populate_archive()
        return True
    def populate_archive(self) -> None:
        self.archive_list.clear()
        self.archive_path_label.setText("/" + (self.archive_path.replace("/", " / ") if self.archive_path else ""))
        self.archive_back.setEnabled(bool(self.archive_history))
        self.archive_up.setEnabled(bool(self.archive_path))
        try:
            entries = MD.zip_directory_entries(self.archive_data, self.archive_path)
        except (OSError, ValueError, zipfile.BadZipFile) as exc:
            self.archive_path_label.setText(f"Archive listing unavailable: {exc}")
            self.archive_open.setEnabled(False)
            return
        self.archive_open.setEnabled(False)
        entries = MD.filter_sort_zip_entries(
            entries, self.archive_search.text(), self.archive_sort.currentText().casefold())
        self.archive_path_label.setText(
            "/" + (self.archive_path.replace("/", " / ") if self.archive_path else "") +
            f"  ·  {len(entries):,} item(s)")
        for entry in entries:
            label = (f"[DIR]  {entry['name']}" if entry["is_dir"] else
                     f"{fmt(entry['size']):>10}  {entry['name']}")
            item = QListWidgetItem(label); item.setData(Qt.ItemDataRole.UserRole, entry); self.archive_list.addItem(item)
        self.update_archive_details()
    def update_archive_details(self) -> None:
        item = self.archive_list.currentItem()
        entry_value: object = item.data(Qt.ItemDataRole.UserRole) if item is not None else None
        if not isinstance(entry_value, dict):
            self.archive_details.setText("Select a file or folder to view its details.")
        elif cast(dict[str, object], entry_value).get("is_dir") is True:
            entry = cast(dict[str, object], entry_value)
            name = entry.get("name")
            self.archive_details.setText(f"Folder · {name if isinstance(name, str) else 'Unknown folder'}")
        else:
            entry = cast(dict[str, object], entry_value)
            name = entry.get("name")
            size = entry.get("size")
            compressed_size = entry.get("compressed_size", 0)
            self.archive_details.setText(
                f"File · {name if isinstance(name, str) else 'Unknown file'} · "
                f"{fmt(size if isinstance(size, int) else 0)} uncompressed · "
                f"{fmt(compressed_size if isinstance(compressed_size, int) else 0)} compressed")
    def show_archive_statistics(self) -> Optional[int]:
        try:
            statistics = MD.zip_archive_statistics(self.archive_data)
        except (OSError, ValueError, zipfile.BadZipFile) as exc:
            return QMessageBox.warning(self, "Archive statistics unavailable", str(exc))
        by_type = sorted(statistics["type_bytes"].items(), key=lambda entry: entry[0])
        breakdown = "\n".join(f"{extension}: {fmt(size)}" for extension, size in by_type[:20])
        if len(by_type) > 20:
            breakdown += f"\n... and {len(by_type) - 20:,} more file type(s)"
        details = (
            f"Files: {statistics['files']:,}\nFolders: {statistics['directories']:,}\n"
            f"Uncompressed: {fmt(statistics['logical_bytes'])}\n"
            f"Compressed: {fmt(statistics['compressed_bytes'])}\n\n"
            f"Uncompressed size by file type:\n{breakdown or 'No files'}\n\n"
            "Statistics use ZIP metadata only; no members were extracted or read."
        )
        QMessageBox.information(self, "Archive statistics", details)
    def navigate_archive(self, path: str) -> None:
        if path == self.archive_path: return
        self.archive_history.append(self.archive_path)
        self.archive_path = path
        self.populate_archive()
    def back_archive(self) -> None:
        if not self.archive_history: return
        self.archive_path = self.archive_history.pop()
        self.populate_archive()
    def up_archive(self) -> None:
        if self.archive_path:
            parent = self.archive_path.rsplit("/", 1)[0] if "/" in self.archive_path else ""
            self.navigate_archive(parent)
    def open_selected_archive_item(self) -> None:
        item = self.archive_list.currentItem()
        if item is not None: self.open_archive_item(item)
    def open_archive_item(
        self, item: QListWidgetItem,
    ) -> Optional[QMessageBox.StandardButton]:
        entry_value: object = item.data(Qt.ItemDataRole.UserRole)
        if not isinstance(entry_value, dict): return
        entry = cast(dict[str, object], entry_value)
        entry_path = entry.get("path")
        if not isinstance(entry_path, str): return
        if entry.get("is_dir") is True:
            self.navigate_archive(entry_path)
            return
        member_index = entry.get("member_index")
        if type(member_index) is not int:
            return QMessageBox.warning(self, "Cannot open archive item", "The selected archive entry is invalid.")
        try:
            data = MD.zip_member_data(self.archive_data, member_index)
        except (OSError, ValueError, RuntimeError, NotImplementedError, EOFError, zlib.error, zipfile.BadZipFile) as exc:
            return QMessageBox.warning(self, "Cannot open archive item", str(exc))
        child = Viewer(entry_path, data, False, self)
        child.exec_()
    def render_pdf(self, v: QVBoxLayout, data: bytes) -> bool:
        renderer = cast(Optional[_PdfRendererLike], fitz)
        if renderer is None:
            v.addWidget(lbl(
                "PDF preview is unavailable because PyMuPDF is missing from this app build. "
                "For a source run, install the requirements.txt dependencies and restart; "
                "packaged builds must include PyMuPDF. The original remains encrypted in the vault.",
                13, center=True)); return True
        try: doc = renderer.open(stream=bytes(data), filetype="pdf")
        except Exception:
            log_security_event("pdf_open_failed"); v.addWidget(lbl("This PDF is damaged or uses an unsupported format. The original remains encrypted in the vault.", 13, center=True)); return True
        if doc.needs_pass:
            doc.close(); v.addWidget(lbl("This PDF is password-protected and cannot be previewed here. The original remains encrypted in the vault.", 13, center=True)); return True
        if doc.page_count < 1:
            doc.close(); v.addWidget(lbl("This PDF contains no pages to display.", 13, center=True)); return True
        self.pdf_doc = doc; self.pdf_page = 0; self.pdf_zoom = 1.0; self.pdf_search_rects: list[Any] = []
        self.pdf_scroll: QScrollArea = QScrollArea(); self.pdf_scroll.setWidgetResizable(False)
        self.pdf_image: QLabel = QLabel(); self.pdf_image.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.pdf_scroll.setWidget(cast(Any, self.pdf_image)); v.addWidget(self.pdf_scroll, 1)
        row = QHBoxLayout(); first = btn("|<"); prev = btn("Prev"); self.pdf_page_label = lbl("", 11, MUT); self.pdf_page_input = QSpinBox(); self.pdf_page_input.setRange(1, doc.page_count); self.pdf_page_input.setAccessibleName("PDF page number"); nxt = btn("Next"); last_page = btn(">|")
        minus = btn("Zoom -"); self.pdf_zoom_label = lbl("100%", 11, MUT); plus = btn("Zoom +")
        fit_page = btn("Fit page"); fit_width = btn("Fit width")
        for control in (first, prev, self.pdf_page_input, self.pdf_page_label, nxt, last_page): row.addWidget(control)
        v.addLayout(row)
        zoom_row = QHBoxLayout()
        for control in (minus, self.pdf_zoom_label, plus, fit_page, fit_width): zoom_row.addWidget(control)
        v.addLayout(cast(Any, zoom_row))
        first.clicked.connect(_clicked_slot(self.go_pdf_page, 0)); prev.clicked.connect(_clicked_slot(self.change_pdf_page, -1)); nxt.clicked.connect(_clicked_slot(self.change_pdf_page, 1)); last_page.clicked.connect(_clicked_slot(self.go_pdf_page, doc.page_count - 1))
        def page_input_changed(page: int) -> None:
            self.go_pdf_page(page - 1)
        self.pdf_page_input.valueChanged.connect(page_input_changed)
        minus.clicked.connect(_clicked_slot(self.change_pdf_zoom, 1 / 1.25)); plus.clicked.connect(_clicked_slot(self.change_pdf_zoom, 1.25))
        fit_page.clicked.connect(self.fit_pdf_page); fit_width.clicked.connect(self.fit_pdf_width)
        search_row = QHBoxLayout(); self.pdf_search_input = QLineEdit(); self.pdf_search_input.setPlaceholderText("Find text in PDF…"); self.pdf_search_input.setAccessibleName("Find text in PDF")
        find = btn("Find"); self.pdf_search_status = lbl("", 10, MUT)
        search_row.addWidget(self.pdf_search_input, 1); search_row.addWidget(find); search_row.addWidget(self.pdf_search_status); v.addLayout(search_row)
        find.clicked.connect(_clicked_slot(self.find_pdf_text))
        self.pdf_search_input.returnPressed.connect(self.find_pdf_text)
        self.bind_shortcut("PageUp", lambda: self.change_pdf_page(-1)); self.bind_shortcut("PageDown", lambda: self.change_pdf_page(1))
        self.bind_shortcut("-", lambda: self.change_pdf_zoom(1 / 1.25)); self.bind_shortcut("+", lambda: self.change_pdf_zoom(1.25))
        self.bind_shortcut("Ctrl+f", lambda: self.pdf_search_input.setFocus())
        self.render_pdf_page(); return True
    def render_pdf_page(self) -> None:
        if self.pdf_doc is None or self.closed: return
        renderer = cast(Optional[_PdfRendererLike], fitz)
        if renderer is None:
            self.pdf_image.clear(); self.pdf_page_label.setText("PDF renderer is unavailable")
            return
        try:
            page = self.pdf_doc.load_page(self.pdf_page); rect = page.rect
            scale = min(self.pdf_zoom, 1800 / max(1, rect.width, rect.height))
            pix = page.get_pixmap(matrix=renderer.Matrix(scale, scale), colorspace=renderer.csRGB, alpha=False)
            image = QImage(pix.samples, pix.width, pix.height, pix.stride, QImage.Format.Format_RGB888).copy()
            if self.pdf_search_rects:
                painter = QPainter(image); painter.setPen(Qt.PenStyle.NoPen); painter.setBrush(QColor(255, 220, 70, 90))
                for rect in self.pdf_search_rects:
                    painter.drawRect(QRectF(rect.x0 * scale, rect.y0 * scale,
                                            rect.width * scale, rect.height * scale))
                painter.end()
            self.pdf_image.setPixmap(QPixmap.fromImage(image)); self.pdf_image.adjustSize()
            self.pdf_page_label.setText(f"PAGE {self.pdf_page + 1} / {self.pdf_doc.page_count}")
            self.pdf_page_input.blockSignals(True); self.pdf_page_input.setValue(self.pdf_page + 1); self.pdf_page_input.blockSignals(False)
            self.pdf_zoom_label.setText(f"{round(self.pdf_zoom * 100)}%")
        except Exception:
            log_security_event("pdf_render_failed"); self.pdf_image.clear(); self.pdf_page_label.setText("PDF render error")
    def change_pdf_page(self, delta: int) -> None:
        if self.pdf_doc is None: return
        self.pdf_page = min(self.pdf_doc.page_count - 1, max(0, self.pdf_page + delta)); self.render_pdf_page()
    def change_pdf_zoom(self, factor: float) -> None:
        if self.pdf_doc is None: return
        self.pdf_zoom = min(3.0, max(.5, self.pdf_zoom * factor)); self.render_pdf_page()
    def go_pdf_page(self, page: int) -> None:
        if self.pdf_doc is None: return
        self.pdf_page = min(self.pdf_doc.page_count - 1, max(0, int(page))); self.pdf_search_rects = []; self.render_pdf_page()
    def fit_pdf_width(self) -> None:
        if self.pdf_doc is None: return
        page = self.pdf_doc.load_page(self.pdf_page)
        viewport = self.pdf_scroll.viewport()
        if viewport is None: return
        available = max(1, viewport.width() - 24)
        self.pdf_zoom = min(3.0, max(.1, available / max(1, page.rect.width)))
        self.pdf_search_rects = []; self.render_pdf_page()
    def fit_pdf_page(self) -> None:
        if self.pdf_doc is None: return
        page = self.pdf_doc.load_page(self.pdf_page)
        viewport = self.pdf_scroll.viewport()
        if viewport is None: return
        available_width = max(1, viewport.width() - 24)
        available_height = max(1, viewport.height() - 24)
        self.pdf_zoom = min(3.0, max(.1, min(
            available_width / max(1, page.rect.width),
            available_height / max(1, page.rect.height))))
        self.pdf_search_rects = []; self.render_pdf_page()
    def find_pdf_text(self) -> None:
        if self.pdf_doc is None: return
        query = self.pdf_search_input.text().strip()
        self.pdf_search_rects = []
        if not query:
            self.pdf_search_status.setText("Enter text to search.")
            self.render_pdf_page()
            return
        try:
            page_count = self.pdf_doc.page_count
            for offset in range(1, page_count + 1):
                candidate = (self.pdf_page + offset) % page_count
                matches = self.pdf_doc.load_page(candidate).search_for(query)
                if matches:
                    self.pdf_page = candidate; self.pdf_search_rects = matches
                    self.pdf_search_status.setText(f"Found on page {candidate + 1}")
                    self.render_pdf_page()
                    return
            self.pdf_search_status.setText("No matches.")
            self.render_pdf_page()
        except Exception:
            self.pdf_search_status.setText("Search unavailable for this PDF.")
            log_security_event("pdf_search_failed")
    def release_pdf(self) -> None:
        if self.pdf_doc is not None:
            try: self.pdf_doc.close()
            finally: self.pdf_doc = None
    def text(self, v: QVBoxLayout, data: bytes) -> bool:
        r = MD.decode_text(data)
        if r is None: return False
        t, enc, cut = r; self.edit(v, t)
        note = (f"Showing the first {MD.MAXTEXT:,} characters. " if cut else "") + (f"Encoding: {enc}" if enc not in ("utf-8", "utf-8-sig") else "")
        if note.strip(): v.addWidget(lbl(note, 12, MUT))
        return True
    def edit(self, v: QVBoxLayout, text: str, mono: bool = False) -> QPlainTextEdit:
        t = QPlainTextEdit(text); t.setReadOnly(True); v.addWidget(t, 1)
        if mono: t.setFont(QFont("Consolas", 10))
        if S("nocopy"): t.setContextMenuPolicy(Qt.ContextMenuPolicy.NoContextMenu); t.setTextInteractionFlags(Qt.TextInteractionFlag.NoTextInteraction)
        return t
    def info(self, v: QVBoxLayout, name: str, data: bytes, k: str) -> None:
        what, sha = MD.describe(name, data, k)
        v.addWidget(lbl(f"{what}. No preview here, but it stays safely encrypted in the vault.", 14, center=True))
        self.edit(v, f"Type:    {what}\nSize:    {fmt(len(data))}\nSHA-256: {sha}\n\n{MD.hexdump(data)}", True)
    def toggle(self, b: QPushButton) -> None:
        mp = self.mp
        if self.closed or mp is None or QMediaPlayer is None: return
        if mp.state() == QMediaPlayer.State.PlayingState: mp.pause(); b.setText("Play")
        else: mp.play(); b.setText("Pause")
    def bind_shortcut(self, key: str, callback: Callable[[], object]) -> None:
        shortcut = QShortcut(QKeySequence(key), self); shortcut.activated.connect(_noarg_slot(callback))
    def select_photo_tool(self, tool: str) -> None:
        if not isinstance(self.lb, PhotoCanvas): return
        cast(Any, self.lb).set_tool(tool)
        for name, control in getattr(self, "photo_tool_buttons", {}).items(): control.setChecked(name == tool)
    def format_time(self, milliseconds: int) -> str:
        seconds = max(0, int(milliseconds / 1000)); hours, remainder = divmod(seconds, 3600); minutes, seconds = divmod(remainder, 60)
        return f"{hours:02d}:{minutes:02d}:{seconds:02d}" if hours else f"{minutes:02d}:{seconds:02d}"
    def update_time(self, label: QLabel, position: int, duration: int) -> None:
        label.setText(f"{self.format_time(position)} / {self.format_time(duration)}")
    def seek_by(self, milliseconds: int) -> None:
        if self.closed or self.mp is None: return
        position = max(0, self.mp.position() + milliseconds); duration = self.mp.duration()
        self.mp.setPosition(min(position, duration) if duration > 0 else position)
    def toggle_mute(self, button: QPushButton) -> None:
        if self.closed or self.mp is None: return
        slider = self.volume_slider
        if slider is None: return
        if slider.value():
            self.volume = slider.value(); slider.setValue(0); button.setText("Unmute")
        else:
            slider.setValue(self.volume or 70); button.setText("Mute")
    def toggle_fullscreen(self) -> None:
        if self.isFullScreen(): self.showNormal()
        else: self.showFullScreen()
    def change_speed(self, delta: float) -> None:
        if self.closed or self.mp is None: return
        self.speed = min(2.0, max(0.5, round(self.speed + delta, 2)))
        self.mp.setPlaybackRate(self.speed)
        if self.speed_label is not None: self.speed_label.setText(f"{self.speed:g}x")
    def change_zoom(self, factor: float, anchor: "Optional[QPoint]" = None) -> None:
        pixmap, canvas, zoom_label = self.pm, self.lb, self.zoom_label
        if pixmap is None or canvas is None or zoom_label is None: return
        keep_point: Optional[tuple[float, float, int, int]] = None
        scroll = self.photo_scroll
        if anchor is not None:
            if scroll is None: return
            horizontal, vertical = scroll.horizontalScrollBar(), scroll.verticalScrollBar()
            if horizontal is None or vertical is None: return
            keep_point = (anchor.x() / max(1, canvas.width()),
                          anchor.y() / max(1, canvas.height()),
                          anchor.x() - horizontal.value(), anchor.y() - vertical.value())
        self.image_zoom = min(8.0, max(0.2, self.image_zoom * factor))
        zoom_label.setText(f"{round(self.image_zoom * 100)}%"); self.refresh_image()
        if keep_point is not None:
            assert scroll is not None
            def restore_anchor() -> None:
                if self.closed: return
                x, y, viewport_x, viewport_y = keep_point
                canvas_width = canvas.width(); canvas_height = canvas.height()
                horizontal_bar, vertical_bar = scroll.horizontalScrollBar(), scroll.verticalScrollBar()
                if horizontal_bar is None or vertical_bar is None: return
                horizontal_bar.setValue(round(x * canvas_width - viewport_x))
                vertical_bar.setValue(round(y * canvas_height - viewport_y))
            QTimer.singleShot(0, restore_anchor)
    def reset_zoom(self) -> None:
        if self.pm is None or self.lb is None or self.zoom_label is None: return
        self.image_zoom = 1.0; self.zoom_label.setText("100%"); self.refresh_image()
    def refresh_image(self) -> None:
        pixmap, canvas = self.pm, self.lb
        if pixmap is None or canvas is None: return
        size = pixmap.size()
        try:
            scroll = self.photo_scroll
            if scroll is None: raise AttributeError
            viewport = scroll.viewport()
            if viewport is None: raise AttributeError
            width, height = viewport.width(), viewport.height()
        except AttributeError: width, height = canvas.width(), canvas.height()
        width, height = max(60, width), max(60, height)
        fit = min(width / size.width(), height / size.height(), 1.0)
        scale = fit * self.image_zoom
        scaled = pixmap.scaled(round(size.width() * scale), round(size.height() * scale), Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation)
        canvas.setPixmap(scaled); canvas.setFixedSize(scaled.size())
    def start_media(self) -> None:
        try:
            if not self.closed and self.mp is not None and self.media: self.mp.setMedia(*self.media); self.mp.play()
        except Exception as e:
            log_security_event("media_start_failed", error=type(e).__name__)
            self.release_media()
    def wipe_tmp(self) -> None:
        if self.tmp is not None: tmp_wipe(self.tmp); self.tmp = None
    def stop_media(self) -> None:
        try:
            if self.mp is not None: self.mp.stop()
            if self.mv is not None: self.mv.stop()
        except Exception: pass
    def release_media(self) -> None:
        for control in self.media_controls: control.setEnabled(False)
        self.stop_media()
        mp = self.mp
        if mp is not None:
            try:
                if QMediaContent is not None:
                    mp.setMedia(QMediaContent())
            except Exception: pass
            try: mp.deleteLater()
            except Exception: pass
        if self.buf is not None:
            try: self.buf.close()
            except Exception: pass
        self.mp = self.buf = self.media = None
        self.wipe_tmp()
    def media_error(self, label: QLabel, mp: "_MediaPlayerLike") -> None:
        if self.mp is not mp: return
        try: label.setText("This computer can not play this video/audio format (" + mp.errorString() + "). Windows needs a codec for it, for example the free LAV Filters.")
        except Exception: label.setText("This computer can not play this video/audio format.")
        log_security_event("media_playback_failed")
        self.release_media()
    def done(self, a0: int) -> None:
        self.closed = True; self.release_media(); self.release_pdf(); super().done(a0)
    def closeEvent(self, a0: "Any") -> None:
        self.closed = True; self.release_media(); self.release_pdf(); super().closeEvent(a0)
    def resizeEvent(self, a0: "Any") -> None:
        super().resizeEvent(a0)
        self.refresh_image()
    def cd(self) -> None:
        self.left -= 40; self.update()
        if self.left <= 0: self.accept()
    def paintEvent(self, a0: "Any") -> None:
        super().paintEvent(a0)
        if self.tot > 1 and self.left > 0: QPainter(self).fillRect(0, 0, int(self.width() * self.left / self.tot), 4, QColor("#8b5cff"))
    def save(self, name: str, data: bytes) -> None:
        p, _ = QFileDialog.getSaveFileName(self, "Save decrypted copy", name)
        if not p: return
        target = Path(p)
        try:
            try:
                info = target.lstat()
            except FileNotFoundError:
                info = None
            if info is not None and (stat.S_ISLNK(info.st_mode)
                    or getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)):
                raise ValueError("Choose a regular file path, not a link.")
            resolved = target.resolve(strict=False)
            vault_root = (HOME / "vault").resolve(strict=False)
            if resolved == vault_root or vault_root in resolved.parents:
                raise ValueError("Decrypted copies cannot be saved inside the encrypted vault folder.")
            atomic_write_bytes(target, bytes(data))
        except (OSError, ValueError) as exc:
            QMessageBox.warning(self, "Could not save decrypted copy",
                                f"The file was not saved ({type(exc).__name__}): {sanitize_text(exc, 240)}")
    def save_temp_copy(self) -> None:
        if self.tmp is None or self.media_digest is None: return
        p, _ = QFileDialog.getSaveFileName(self, "Save decrypted copy", self.export_name)
        if not p: return
        try:
            save_verified_temp_copy(self.tmp, Path(p), self.media_digest)
        except (OSError, ValueError) as exc:
            QMessageBox.warning(self, "Could not save decrypted copy",
                                f"The file was not saved ({type(exc).__name__}): {sanitize_text(exc, 240)}")
    def save_marked(self, name: str) -> None:
        if not isinstance(self.lb, PhotoCanvas):
            return
        p, _ = QFileDialog.getSaveFileName(self, "Save marked copy", Path(name).stem + "-marked.png", "Images (*.png *.jpg *.jpeg *.bmp)")
        if not p: return
        if not cast(Any, self.lb).marked_image().save(p):
            QMessageBox.warning(self, "Could not save", "The marked image could not be written to that location.")

class DropFeedbackOverlay(QFrame):
    def __init__(self, parent: QWidget) -> None:
        super().__init__(parent)
        self._trace: list[QPointF] = []
        self._cursor = QPointF(-100, -100)
        self.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents, True)

    def track_position(self, point: QPointF) -> None:
        position = QPointF(point)
        if not self._trace or (self._trace[-1] - position).manhattanLength() >= 4:
            self._trace.append(position)
            if len(self._trace) > 32:
                del self._trace[:-32]
        self._cursor = position
        self.update()

    def clear_trace(self) -> None:
        self._trace.clear()
        self._cursor = QPointF(-100, -100)
        self.update()

    @property
    def trace_points(self) -> tuple[QPointF, ...]:
        return tuple(self._trace)

    @property
    def cursor_position(self) -> QPointF:
        return QPointF(self._cursor)

    def paintEvent(self, a0: Any) -> None:
        super().paintEvent(a0)
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        points = self._trace
        for index in range(1, len(points)):
            color = _QC(TH["acc"] if index % 2 else TH["acc2"])
            color.setAlpha(max(18, int(190 * index / len(points))))
            painter.setPen(QPen(color, 1.5 + index / max(1, len(points))))
            painter.drawLine(points[index - 1], points[index])
        if self._cursor.x() < 0 or self._cursor.y() < 0:
            return
        center = self._cursor
        accent = _QC(TH["acc"])
        phase = time.monotonic() * 2.4
        pulse = (math.sin(phase) + 1.0) * 0.5
        orbit_radius = 25 + pulse * 4
        painter.setBrush(Qt.BrushStyle.NoBrush)
        outer = _QC(accent)
        outer.setAlpha(35 + int(45 * pulse))
        painter.setPen(QPen(outer, 1.5))
        painter.drawEllipse(center, orbit_radius + 9, orbit_radius + 9)
        painter.setPen(QPen(_QC(accent.red(), accent.green(), accent.blue(), 100), 1))
        painter.drawEllipse(center, orbit_radius, orbit_radius)
        painter.setPen(QPen(_QC(accent.red(), accent.green(), accent.blue(), 65), 4))
        painter.drawEllipse(center, 17 + pulse * 2, 17 + pulse * 2)
        painter.setPen(QPen(accent, 1.5))
        painter.drawEllipse(QRectF(center.x() - 14, center.y() - 8, 28, 16))
        painter.drawLine(QPointF(center.x() - 22, center.y()), QPointF(center.x() - 8, center.y()))
        painter.drawLine(QPointF(center.x() + 8, center.y()), QPointF(center.x() + 22, center.y()))
        painter.drawLine(QPointF(center.x(), center.y() - 20), QPointF(center.x(), center.y() - 11))
        painter.drawLine(QPointF(center.x(), center.y() + 11), QPointF(center.x(), center.y() + 20))
        for index in range(3):
            angle = phase + index * (math.tau / 3)
            spark = QPointF(center.x() + math.cos(angle) * orbit_radius,
                            center.y() + math.sin(angle) * orbit_radius)
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(_QC(accent.red(), accent.green(), accent.blue(),
                                 110 + int(100 * pulse)))
            painter.drawEllipse(spark, 2.2, 2.2)
        painter.setBrush(accent)
        painter.drawEllipse(center, 3, 3)


class CommandPaletteDialog(QDialog):
    def __init__(
        self,
        parent: QWidget,
        entries: list[tuple[str, str, Callable[[], object]]],
    ) -> None:
        super().__init__(parent)
        self._entries = entries
        self.setWindowTitle("UNKNWN // Local Search & Commands")
        self.setMinimumSize(520, 380)
        self.setStyleSheet(
            f"QDialog{{background:{TH['bg0']};color:{TH['fg']};}}"
            f"QLineEdit,QListWidget{{background:{TH['field']};color:{TH['fg']};"
            f"border:1px solid {TH['line']};selection-background-color:{TH['acc']};}}"
        )
        layout = QVBoxLayout(self)
        layout.addWidget(lbl("LOCAL SEARCH / COMMANDS", 16, TH["acc"], True))
        self.search = QLineEdit()
        self.search.setPlaceholderText("Search vault items, groups, profiles, operations, or actions…")
        self.search.setAccessibleName("Search locally available UNKNWN items and commands")
        self.search.installEventFilter(self)
        layout.addWidget(self.search)
        self.results = QListWidget()
        self.results.setAccessibleName("Local search results and commands")
        layout.addWidget(self.results, 1)
        footer = QLabel("Search is local to this app. Enter opens the selected result; Esc closes.")
        footer.setStyleSheet(f"color:{TH['mut']};background:transparent;")
        layout.addWidget(footer)
        self.search.textChanged.connect(self.refresh_results)
        self.search.returnPressed.connect(self.activate_current)
        self.results.itemActivated.connect(self.activate_item)
        self.refresh_results()

    def refresh_results(self, query: str = "") -> None:
        needle = query.strip().casefold()
        self.results.clear()
        for index, (label_text, searchable, _callback) in enumerate(self._entries):
            if needle and needle not in (label_text + " " + searchable).casefold():
                continue
            item = QListWidgetItem(label_text)
            item.setData(Qt.ItemDataRole.UserRole, index)
            self.results.addItem(item)
        if self.results.count():
            self.results.setCurrentRow(0)

    def eventFilter(self, a0: Any, a1: Any) -> bool:
        if (a0 is self.search and a1.type() == QEvent.Type.KeyPress
                and a1.key() == Qt.Key.Key_Down and self.results.count()):
            self.results.setFocus()
            return True
        return super().eventFilter(a0, a1)

    def activate_current(self) -> None:
        self.activate_item(self.results.currentItem())

    def activate_item(self, item: Optional[QListWidgetItem]) -> None:
        if item is None:
            return
        entry_index = item.data(Qt.ItemDataRole.UserRole)
        if not isinstance(entry_index, int) or not 0 <= entry_index < len(self._entries):
            return
        callback = self._entries[entry_index][2]
        self.accept()
        QTimer.singleShot(0, _noarg_slot(callback))


main_window_flags: Qt.WindowFlags = Qt.WindowFlags(Qt.WindowType.Window)
main_window_flags |= Qt.WindowType.WindowTitleHint
main_window_flags |= Qt.WindowType.WindowSystemMenuHint
main_window_flags |= Qt.WindowType.WindowMinimizeButtonHint
main_window_flags |= Qt.WindowType.WindowMaximizeButtonHint
main_window_flags |= Qt.WindowType.WindowCloseButtonHint
MAIN_WINDOW_FLAGS: Qt.WindowFlags = main_window_flags
WINDOW_FRAME_REFRESH_FLAGS = 0x0001 | 0x0002 | 0x0004 | 0x0010 | 0x0020


def configure_main_window_frame(window: QWidget) -> None:
    window.setWindowFlags(MAIN_WINDOW_FLAGS)


class App(Stage):
    def __init__(self) -> None:
        super().__init__()
        configure_main_window_frame(self)
        self.setfps(); self.setWindowTitle(S("title")); screen = QApplication.primaryScreen(); g = screen.availableGeometry() if screen is not None else QRect(0, 0, 900, 700); self.setMinimumSize(min(600, g.width()), min(480, g.height())); self.resize(min(900, int(g.width() * .92)), min(700, int(g.height() * .92))); self.move(g.center() - self.rect().center())
        self.setAcceptDrops(True)
        self._drop_previous_title: Optional[str] = None
        self._drop_feedback_phase = False
        self._drop_overlay = DropFeedbackOverlay(self)
        self._drop_overlay.setObjectName("dropOverlay")
        self._drop_overlay.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents, True)
        self._drop_overlay_layout = QVBoxLayout(self._drop_overlay)
        self._drop_overlay_layout.addStretch()
        self._drop_overlay_label = lbl("DROP FILES OR FOLDERS TO SEAL", 17, TH["fg"], True)
        self._drop_overlay_label.setAlignment(cast(Any, Qt.AlignmentFlag.AlignCenter))
        self._drop_overlay_layout.addWidget(self._drop_overlay_label)
        self._drop_overlay_layout.addStretch()
        self._drop_opacity = QGraphicsOpacityEffect(self._drop_overlay)
        self._drop_opacity.setOpacity(1.0)
        self._drop_overlay.setGraphicsEffect(self._drop_opacity)
        self._drop_fade: Optional[QPropertyAnimation] = None
        self._drop_overlay.hide()
        self._drop_feedback_timer = QTimer(self)
        self._drop_feedback_timer.setInterval(180)
        self._drop_feedback_timer.timeout.connect(self._pulse_drop_feedback)
        self.box = QVBoxLayout(self); self.box.setContentsMargins(0, 0, 0, 0)
        self.cur: Optional[QWidget] = None; self.root: Optional[bytes] = None; self.lk: Optional[QLabel] = None
        self.viewing: Optional[str] = None; self.dlg: Optional[Viewer] = None; self.hkf: Optional[HK] = None
        self.mode = ""; self.cards: dict[str, Card] = {}; self.cds: dict[str, QLabel] = {}; self.dying: set[str] = set(); self.scs: list[QShortcut] = []
        self.settings_undo_stack: list[list[tuple[str, object, object]]] = []
        self.settings_redo_stack: list[list[tuple[str, object, object]]] = []
        self._settings_history_group: Optional[list[tuple[str, object, object]]] = None; self._settings_history_replay = False
        self._easter_theme_snapshot: Optional[ThemeSnapshot] = None
        self._easter_theme_timer: Optional[QTimer] = None
        self._easter_theme_image: Optional[QPixmap] = None
        self._empty_search_message_query: Optional[str] = None
        self.shortcut_status: Optional[str] = None; self.hk_edit: Optional[QKeySequenceEdit] = None
        self.ro = False; self.busy = False; self.owner = False; self.relocked = False
        self.hold = 0; self.act = time.time(); self.prev: Optional[float] = None; self.nf = 0
        self.session_activity: list[dict[str, Any]] = []; self.session_started: Optional[float] = None; self.session_id: Optional[str] = None
        self.session_stored_names: list[str] = []; self.session_stored_count = 0; self.session_setting_changes = 0; self.session_activity_omitted = 0
        self.session_history_error: Optional[str] = None; self._tab_animation: Optional[QPropertyAnimation] = None; self._tab_effect: Optional[QGraphicsOpacityEffect] = None
        self.fixed: list[str] = []; self.tabs: list[QPushButton] = []
        self.package_dialog: Optional[PackageProgressDialog] = None
        self._package_context: Optional[dict[str, Any]] = None
        self._seal_queue: list[_SealQueueJob] = []
        self._seal_queue_active = False
        self._seal_active_cleanup: Optional[Callable[[], None]] = None
        self.seal_dialog: Optional[_SealProgressDialog] = None
        ap_value = QApplication.instance()
        if ap_value is None: raise RuntimeError("The Qt application is unavailable")
        ap = cast(QApplication, ap_value)
        if INTEG[0] == "fail":
            ap.installEventFilter(self)
            self.integ_fail()
            return
        ap.installEventFilter(self); ap.applicationStateChanged.connect(self.appstate); self.apply_hk()
        self.command_palette_shortcut = QShortcut(QKeySequence("Ctrl+K"), self)
        self.command_palette_shortcut.setContext(
            Qt.ShortcutContext.WidgetWithChildrenShortcut)
        if QKeySequence(str(S("hk"))) == QKeySequence("Ctrl+K"):
            self.command_palette_shortcut.setEnabled(False)
            log_security_event("command_palette_shortcut_conflict")
        self.command_palette_shortcut.activated.connect(
            _noarg_slot(self.open_command_palette))
        t = QTimer(self); t.timeout.connect(_clicked_slot(self.tick)); t.start(1000)
        self.startup_cleanup_record: Optional[_DestructJournal] = None
        self.startup_cleanup_error: Optional[Exception] = None
        if INTEG[0] == "fail":
            cleanup_state = "not_run"
        else:
            try:
                self.startup_cleanup_record = read_destruct_journal()
                cleanup_state = "pending" if self.startup_cleanup_record is not None else "clear"
            except Exception as exc:
                self.startup_cleanup_error = exc
                cleanup_state = "invalid"
        startup_checks = {
            "location": startup_location_state,
            "config": startup_config_state,
            "cleanup": cleanup_state,
        }
        if S("reduce_motion"):
            self.setWindowOpacity(S("winop") / 100)
        else:
            self.setWindowOpacity(0); a = QPropertyAnimation(self, b"windowOpacity"); a.setDuration(900); a.setStartValue(0.0); a.setEndValue(S("winop") / 100); a.start(); self._fade = a
        QTimer.singleShot(300, self.ghost_apply)
        clipboard = QApplication.clipboard()
        if clipboard is not None:
            clipboard.dataChanged.connect(self.clipchg)
        QTimer.singleShot(0, _noarg_slot(lambda: nocap(self, S("nocap"))))
        tmp_sweep()
        if DEV_BUILD: self.devl = QLabel("DEVELOPMENT BUILD: release integrity checks are off", self); self.devl.setStyleSheet("color:#ffb347;font-size:11px;background:transparent"); self.devl.adjustSize(); self.devl.show()
        def go() -> None:
            if INTEG[0] == "fail": return self.integ_fail()
            if self.startup_cleanup_error is not None:
                return self.destructive_recovery_screen(self.startup_cleanup_error)
            if self.startup_cleanup_record is not None:
                return self.recover_destructive_cleanup()
            if STARTUP_RECOVERY_ERROR is not None: return self.storage_recovery_screen(STARTUP_RECOVERY_ERROR)
            self.profile_chooser()
        n = 0 if S("ghost") else (S("intro") if has_vault_config() else 3)
        if n: self.intro = Intro(self, n, go, startup_checks)
        else: go()

    # ---------- helpers ----------
    def eventFilter(self, a0: Any, a1: Any) -> bool:
        o, e = a0, a1
        if e.type() == QEvent.Type.Show and isinstance(o, QDialog):
            self.prepare_popup_help(o)
        if (self.mode == "blocked"
                and e.type() == QEvent.Type.KeyPress
                and not e.isAutoRepeat()):
            self.acknowledge_integrity_failure()
            return True
        if e.type() in (QEvent.Type.MouseMove, QEvent.Type.KeyPress, QEvent.Type.MouseButtonPress): self.act = time.time()
        if e.type() == QEvent.Type.KeyPress and e.key() == Qt.Key.Key_Escape and S("boss") and self.mode == "vault":   # boss key: Esc twice
            if time.time() - getattr(self, "esc", 0) < .6:
                if self.dlg: self.dlg.reject()
                def lock_and_minimize() -> None:
                    self.lock()
                    self.showMinimized()
                QTimer.singleShot(60, lock_and_minimize)
            self.esc = time.time()
        return False
    def handle_vault_search_command(self, query: str) -> None:
        if query == SECRET_THEME_PHRASE:
            profile_key = active_profile_id or str(Path(HOME).resolve())
            snapshot = EASTER_EGGS.activate_secret_theme(
                profile_key, query, S("th"), TH)
            if snapshot is not None:
                self.apply_secret_theme(snapshot)
            self.search_edit.clear()
            return
        command = query.strip().casefold()
        if command == "!meow":
            self.search_edit.clear()
            self.show_meow_easter_egg()
        elif command == "!secret":
            self.search_edit.clear()
            QMessageBox.information(
                self, "UNKNWN // SECRET",
                "so uhm , contact this user on telegram : unknown1soldier")
    def apply_secret_theme(self, snapshot: ThemeSnapshot) -> None:
        self._easter_theme_snapshot = snapshot
        image_path = resource_path("assets/uwu_kawaii.jpg")
        image = QPixmap(str(image_path))
        if not image.isNull():
            self._easter_theme_image = image
        TH.update(SECRET_THEME_PALETTE)
        application = QApplication.instance()
        if isinstance(application, QApplication):
            application.setStyleSheet(qss())
        self.update()
        timer = QTimer(self)
        timer.setSingleShot(True)
        timer.timeout.connect(self.restore_secret_theme)
        self._easter_theme_timer = timer
        timer.start(SECRET_THEME_DURATION_MS)
    def restore_secret_theme(self) -> None:
        snapshot = self._easter_theme_snapshot
        profile_key = snapshot.profile_key if snapshot is not None else (
            active_profile_id or str(Path(HOME).resolve()))
        if self._easter_theme_timer is not None:
            self._easter_theme_timer.stop()
            self._easter_theme_timer = None
        restored = EASTER_EGGS.restore_secret_theme(profile_key)
        if restored is None:
            return
        self._easter_theme_snapshot = None
        self._easter_theme_image = None
        TH.clear()
        TH.update(restored.palette)
        application = QApplication.instance()
        if isinstance(application, QApplication):
            application.setStyleSheet(qss())
        self.update()
    def show_nothing_easter_egg(self) -> None:
        QMessageBox.information(
            self, "Nothing", EASTER_EGGS.message("hidden_nothing"))
    def show_meow_easter_egg(self) -> None:
        asset_root = APP.parent if PACKAGED else Path(__file__).resolve().parent
        image = QPixmap(str(asset_root / "assets" / "meow.jpg"))
        if image.isNull():
            log_security_event("easter_egg_image_unavailable")
            QMessageBox.warning(self, "Photo unavailable",
                                "The bundled easter-egg photo could not be loaded.")
            return
        dialog = QDialog(self)
        dialog.setWindowTitle("UNKNWN // M-E-O-W")
        layout = QVBoxLayout(dialog)
        photo = QLabel()
        photo.setAlignment(Qt.AlignmentFlag.AlignCenter)
        screen = self.screen()
        area = screen.availableGeometry() if screen is not None else QRect(0, 0, 900, 700)
        target = image.scaled(
            min(640, max(240, area.width() - 80)),
            min(640, max(240, area.height() - 120)),
            Qt.AspectRatioMode.KeepAspectRatio,
            Qt.TransformationMode.SmoothTransformation)
        photo.setPixmap(target)
        layout.addWidget(photo)
        close_button = btn("Close")
        close_button.clicked.connect(dialog.accept)
        layout.addWidget(close_button, 0, Qt.AlignmentFlag.AlignRight)
        dialog.resize(target.width() + 36, target.height() + 76)
        dialog.exec_()
    def prepare_popup_help(self, dialog: QDialog) -> None:
        title = sanitize_text(dialog.windowTitle() or "UNKNWN dialog", 100)
        dialog.setWhatsThis(
            f"{title}. This popup belongs to UNKNWN. Read its message before choosing an action; "
            "the question-mark button provides help for the control you select."
        )
        controls = dialog.findChildren(QWidget)
        for control in controls:
            if control.whatsThis():
                continue
            if isinstance(control, QPushButton):
                action: str = str(cast(Any, control).text()).replace("&", "").strip() or "Action"
                if action.casefold() in {"cancel", "no", "abort", "close", "back"}:
                    description = f"{action} closes or cancels this popup without confirming its requested action."
                elif action.casefold() in {"yes", "ok", "execute", "continue", "unlock", "create", "change"}:
                    description = f"{action} confirms the action described in this popup. Review its message before proceeding."
                else:
                    description = f"{action} is an available action in this popup. Review its message before proceeding."
            elif isinstance(control, QLineEdit):
                description = ("Password entry for this popup. The field is masked while typing."
                               if cast(Any, control).echoMode() == QLineEdit.EchoMode.Password
                               else "Enter the requested value in this field.")
            elif isinstance(control, QCheckBox):
                description = "Optional choice for this popup. Read its label to understand what enabling it changes."
            elif isinstance(control, (QPlainTextEdit, QTextBrowser)):
                description = "Read-only information for this popup. Scroll to review the complete text."
            elif isinstance(control, QLabel):
                description = "Information for this popup. Read it before choosing an action."
            else:
                description = "Control belonging to this popup. Use the nearby labels and message to understand its purpose."
            control.setWhatsThis(description)
    def route_startup_config(self) -> None:
        try:
            pending_cleanup = read_destruct_journal()
        except Exception as exc:
            return self.destructive_recovery_screen(exc)
        if pending_cleanup is not None:
            return self.recover_destructive_cleanup()
        if not has_vault_config():
            return self.damaged_screen() if (CFG.exists() or any(VAULT.glob("*.cdr"))) else self.setup_screen()
        self.login_screen()
        if S("dead") and time.time() - cfg["last"] > S("dead") * 86400:
            def handle_deadman_expiry() -> None:
                self.panic(False)
            QTimer.singleShot(600, handle_deadman_expiry)
    def profile_chooser(self) -> None:
        try:
            profiles = _ensure_initial_profile()
        except Exception as exc:
            quit_button = btn("Quit")
            quit_button.clicked.connect(lambda: _close_widget(self))
            self.show_w(self.panel(self.logo(), tlbl("UNKNWN :: PROFILE LIST UNAVAILABLE", 20, "#ff6b61"),
                             lbl(support_message(f"Vault profiles could not be loaded safely ({type(exc).__name__}). No profile was opened."), 13, MUT),
                             quit_button, w=560), "profile-error")
            return
        pending_error = None
        try:
            pending_imports = _pending_profile_imports()
        except Exception as exc:
            pending_imports = []
            pending_error = f"Interrupted import recovery is unavailable ({type(exc).__name__}). No pending import was resumed."
        widgets = [tlbl("CHOOSE A VAULT", 23, TH["acc"], True),
                   lbl("Each profile has its own files and master password.", 12, MUT, center=True)]
        if profiles:
            count = len(profiles)
            widgets.append(lbl(f"{count} vault profile{'s' if count != 1 else ''} on this device.",
                               11, MUT, center=True))
        else:
            widgets.append(lbl("No vault profiles yet. Create a vault or import an existing one.",
                               12, TH["acc"], center=True))
        if pending_error:
            widgets.append(lbl(support_message(pending_error), 12, "#ffb347"))
        for index, profile in enumerate(profiles):
            prefix = "DEFAULT  /  " if index == 0 else "OPEN  /  "
            button = btn(f"{prefix}{profile['name']}")
            if index == 0:
                button.setToolTip("Preferred profile. UNKNWN still requires its own password at sign-in.")
            button.clicked.connect(_clicked_slot(self.open_profile, profile))
            widgets.append(button)
        for record in pending_imports:
            resume_button = btn(f"Resume interrupted import  /  {record['name']}")
            resume_button.clicked.connect(_clicked_slot(self.import_profile_dialog, record))
            widgets.append(resume_button)
        import_button = profile_action_button("Import vault", self.import_profile_dialog)
        create_button = btn("New vault", "flat")
        create_button.clicked.connect(self.create_profile_folder)
        widgets.extend((create_button, import_button))
        if profiles:
            close_button = btn("Quit")
            close_button.clicked.connect(lambda: _close_widget(self))
            widgets.append(close_button)
        current_profile = next(
            (profile for profile in profiles if profile.get("id") == active_profile_id),
            None,
        )
        if current_profile is not None:
            back_button = btn(f"Back to {current_profile['name']}", "flat")
            back_button.setAccessibleName("Back to current vault profile")
            back_button.setToolTip("Return to the current profile's sign-in screen. Authentication is still required.")
            back_button.clicked.connect(_noarg_slot(self.route_startup_config))
            widgets.insert(2, back_button)
        self.show_w(self.panel(self.logo(), *widgets, w=560), "profiles")
    def open_profile(self, profile: dict[str, str]) -> None:
        try:
            same_profile = (
                profile.get("id") == active_profile_id
                and os.path.normcase(os.path.abspath(HOME))
                    == os.path.normcase(os.path.abspath(profile.get("path", "")))
            )
            if not same_profile:
                activate_profile(profile)
                normalize_look_settings()
                _refresh_theme()
                application_value = QApplication.instance()
                if application_value is not None:
                    cast(QApplication, application_value).setStyleSheet(qss())
                self.setWindowTitle(S("title"))
                self.setWindowOpacity(S("winop") / 100)
                self.apply_hk()
                self.setfps()
                self.ghost_apply()
        except Exception as exc:
            QMessageBox.warning(self, "Profile unavailable",
                                f"The selected profile could not be opened safely ({type(exc).__name__}). No profile data was changed.")
            return
        if STARTUP_RECOVERY_ERROR is not None:
            return self.storage_recovery_screen(STARTUP_RECOVERY_ERROR)
        self.route_startup_config()
    def rename_profile_dialog(self) -> None:
        global active_profile_name
        profile_id = active_profile_id
        if self.ro or self.root is None or profile_id is None or not self.sec_ok():
            return
        name, accepted = QInputDialog.getText(
            self, "Rename vault profile", "Profile name:",
            QLineEdit.EchoMode.Normal, active_profile_name or "")
        if not accepted:
            return
        try:
            profile = _rename_profile(profile_id, name)
        except (OSError, ValueError) as exc:
            QMessageBox.warning(
                self, "Profile name not changed",
                f"The profile could not be renamed ({type(exc).__name__}): {exc}")
            return
        active_profile_name = profile["name"]
        self.sp.setWidget(self.build_settings())
        self.changes.setWidget(self.build_changes())
    def set_default_profile(self) -> None:
        profile_id = active_profile_id
        if self.ro or self.root is None or profile_id is None or not self.sec_ok():
            return
        try:
            _set_default_profile(profile_id)
        except (OSError, ValueError) as exc:
            QMessageBox.warning(
                self, "Preferred profile not changed",
                f"The profile could not be made preferred ({type(exc).__name__}): {exc}")
            return
        self.sp.setWidget(self.build_settings())
    def _managed_profile_path(self, profile_id: str) -> Path:
        return _managed_profiles_root() / profile_id
    def create_profile_folder(self) -> None:
        name, accepted = QInputDialog.getText(self, "Create vault profile", "Profile name:")
        if not accepted: return
        profile_id = uuid.uuid4().hex
        path = None
        try:
            path = self._managed_profile_path(profile_id)
            path.mkdir(parents=False, exist_ok=False)
            profile = _register_profile(name, path, profile_id)
            activate_profile(profile)
        except Exception as exc:
            if path is not None:
                try: path.rmdir()
                except OSError: pass
            QMessageBox.warning(self, "Profile not created",
                                f"The new profile could not be created ({type(exc).__name__}). No existing vault was changed.")
            return
        self.route_startup_config()
    def _start_package_worker(
        self, operation: Literal["export", "import"], arguments: dict[str, Any],
        title: str, context: dict[str, Any],
    ) -> Optional[QMessageBox.StandardButton]:
        if self.working():
            return QMessageBox.warning(self, "Vault operation in progress",
                                       "Finish or cancel the current vault operation before starting another.")
        worker = _PackageWorker(operation, arguments)
        dialog = PackageProgressDialog(self, worker, title, self.finish_package_operation)
        self.package_dialog = dialog; self._package_context = context; self.hold += 1
        try:
            _start_qrunnable(worker)
            dialog.exec_()
        except Exception as exc:
            worker.cancel.set(); worker.pause.clear()
            worker.lifecycle.fail(type(exc).__name__)
            self.hold = max(0, self.hold - 1); self.package_dialog = None; self._package_context = None
            QMessageBox.warning(self, "Operation could not start",
                                f"The background operation could not start ({type(exc).__name__}). No vault data was changed.")
    def export_profile_dialog(
        self, resume_record: Optional[dict[str, Any]] = None,
    ) -> Optional[QMessageBox.StandardButton]:
        root = self.root
        if self.ro or root is None or not self.sec_ok(): return
        modes = ["Use this vault’s master password", "Set a separate password (this becomes the imported vault’s master password)"]
        mode, ok = QInputDialog.getItem(self, "Export vault profile", "Choose the password for this export:", modes, 0, False)
        if not ok: return
        package_password = None
        if mode == modes[0]:
            password, ok = QInputDialog.getText(self, "Confirm master password", "Enter this vault’s master password:", QLineEdit.EchoMode.Password)
            if not ok: return
            try:
                confirmed = unseal(kdf(password, b64d(cfg["s1"])), b64d(cfg["wp"]))
            except (InvalidTag, ValueError, MemoryError):
                return QMessageBox.warning(self, "Password not confirmed", "That master password could not be verified. No package was created.")
            if not hmac.compare_digest(confirmed, root):
                return QMessageBox.warning(self, "Password not confirmed", "That master password does not unlock this vault. No package was created.")
        else:
            package_password, ok = QInputDialog.getText(self, "Set export password", "New password (12+ characters):", QLineEdit.EchoMode.Password)
            if not ok: return
            good, why = check_pw(package_password)
            if not good: return QMessageBox.warning(self, "Password too weak", why)
            repeat, ok = QInputDialog.getText(self, "Confirm export password", "Type the new password again:", QLineEdit.EchoMode.Password)
            if not ok or repeat != package_password:
                return QMessageBox.warning(self, "Password mismatch", "The two passwords did not match. No package was created.")
        destination, _ = QFileDialog.getSaveFileName(self, "Save encrypted vault package", "UNKNWN-vault.unknwn", "UNKNWN vault package (*.unknwn)")
        if not destination: return
        destination = Path(destination)
        if not destination.suffix: destination = destination.with_suffix(".unknwn")
        explanation = (
            f"UNKNWN will create a verified copy of the encrypted vault at:\n{destination}\n\n"
            "Your current vault will not be moved or changed. The package contains the encrypted files and authenticated vault state. "
            + ("The separate password becomes the imported profile’s master password." if package_password is not None
               else "The imported profile will keep this vault’s current master password.")
            + "\n\nThe export runs in the background. You can pause, resume, or cancel it. The containing folder will open after success."
        )
        if resume_record is not None:
            explanation += "\n\nThis restarts the interrupted export from the beginning; UNKNWN does not save or reuse your password."
        if QMessageBox.question(self, "Review vault export", explanation, cast(Any, QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No), QMessageBox.StandardButton.No) != QMessageBox.StandardButton.Yes:
            return
        operation_id = uuid.uuid4().hex
        journal = _export_journal_path(operation_id)
        journals = [journal]
        if resume_record is not None:
            journals.append(_export_journal_path(resume_record["operation_id"]))
        try:
            atomic_write_bytes(journal, canonical_json({"version": 1, "operation_id": operation_id,
                                                        "profile_id": active_profile_id}))
        except OSError as exc:
            return QMessageBox.warning(self, "Export could not start", f"The recovery record could not be saved ({type(exc).__name__}).")
        self._start_package_worker("export", {"root": bytes(root), "destination": destination,
                                           "package_password": package_password},
                                "Export vault package", {"operation": "export", "destination": destination,
                                                         "journals": journals})
    def import_profile_dialog(
        self, resume_record: Optional[dict[str, Any]] = None,
    ) -> Optional[QMessageBox.StandardButton]:
        if not self.sec_ok(): return
        if resume_record is None:
            source_start = ""
            profile_name, ok = QInputDialog.getText(self, "Import vault profile", "Name for the new vault profile:")
            if not ok: return
            profile_id = uuid.uuid4().hex
            resume = False
        else:
            source_start = str(Path.home() / "Downloads")
            profile_name = resume_record["name"]
            profile_id = resume_record["profile_id"]
            resume = True
        profile_name = str(profile_name).strip()
        if not profile_name or len(profile_name) > 64 or any(ord(char) < 32 for char in profile_name):
            return QMessageBox.warning(self, "Invalid profile name", "Choose a profile name between 1 and 64 printable characters.")
        try:
            if any(item["name"].casefold() == profile_name.casefold() for item in _read_profiles()):
                return QMessageBox.warning(self, "Name already in use", "Choose a name not already used by another vault profile.")
            profile_root = self._managed_profile_path(profile_id)
            destination = profile_root
        except Exception as exc:
            return QMessageBox.warning(self, "Profile location unavailable",
                                       f"The managed profile folder could not be prepared safely ({type(exc).__name__}).")
        package_path, _ = QFileDialog.getOpenFileName(self, "Choose encrypted UNKNWN vault package", source_start,
                                                       "UNKNWN vault package (*.unknwn);;All files (*)")
        if not package_path: return
        source = Path(package_path)
        try:
            source_info = source.lstat()
            if (stat.S_ISLNK(source_info.st_mode)
                    or getattr(source_info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
                    or not stat.S_ISREG(source_info.st_mode)):
                raise ValueError("The selected package is not a safe regular file.")
        except OSError as exc:
            return QMessageBox.warning(self, "Package unavailable", f"The selected package could not be inspected ({type(exc).__name__}).")
        password, ok = QInputDialog.getText(self, "Unlock import package", "Package password:", QLineEdit.EchoMode.Password)
        if not ok: return
        delete_package = QMessageBox.question(
            self, "Keep original package?",
            "After the new profile has been independently verified, should UNKNWN delete the selected import package?\n\n"
            "No is recommended. The imported vault becomes a separate managed profile; the package is not needed to open it.",
            cast(Any, QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No), QMessageBox.StandardButton.No) == QMessageBox.StandardButton.Yes
        explanation = (
            f"UNKNWN will verify and copy this package into a new profile named “{profile_name}” under its managed user-data folder:\n"
            f"{destination}\n\nThe profile has its own files and master password. The currently selected vault remains untouched. "
            "The import is staged and authenticated before activation. You can pause/resume or cancel while it runs. "
            "After successful import, the app will ask you to run UNKNWN again so the profile chooser can open the new vault. "
            + ("The original package will be deleted only after successful verification." if delete_package
               else "The original package will be kept.")
        )
        if QMessageBox.question(self, "Review vault import", explanation, cast(Any, QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No), QMessageBox.StandardButton.No) != QMessageBox.StandardButton.Yes:
            return
        journal = _import_journal_path(profile_id)
        try:
            atomic_write_bytes(journal, canonical_json({"version": 1, "profile_id": profile_id,
                                                        "name": profile_name, "package": str(source.absolute())}))
        except OSError as exc:
            return QMessageBox.warning(self, "Import could not start", f"The recovery record could not be saved ({type(exc).__name__}).")
        context: dict[str, Any] = {"operation": "import", "profile_id": profile_id, "name": profile_name,
                   "package": source, "package_stat": (source_info.st_dev, source_info.st_ino, source_info.st_size, source_info.st_mtime_ns),
                   "journal": journal, "delete_package": delete_package}
        selfargs: dict[str, Any] = {"package_password": password, "package_path": source, "destination": destination,
                    "profile_name": profile_name, "profile_id": profile_id, "resume": resume}
        self._start_package_worker("import", selfargs, "Import vault profile", context)
    def finish_package_operation(self, result: Mapping[str, Any]) -> None:
        self.hold = max(0, self.hold - 1)
        context = self._package_context or {}
        self.package_dialog = None; self._package_context = None
        operation = context.get("operation")
        if result.get("status") == "cancelled":
            if operation == "import":
                try: context["journal"].unlink(missing_ok=True)
                except OSError: pass
            elif operation == "export":
                for journal in context.get("journals", []):
                    if journal == context.get("journals", [None])[0]:
                        try: journal.unlink(missing_ok=True)
                        except OSError: pass
            QMessageBox.information(self, "Operation cancelled",
                                    "The operation was cancelled. The active vault was not changed.")
            return
        if result.get("status") != "completed":
            QMessageBox.warning(self, "Operation failed",
                                f"The operation did not complete ({result.get('error', 'Error')}).\n\n"
                                f"{result.get('detail', 'No success was reported.')}\n\n"
                                "The active vault was not changed. If this was an import interrupted by closing the process, use Resume interrupted import from the profile chooser.")
            return
        if operation == "export":
            for journal in context.get("journals", []):
                try: journal.unlink(missing_ok=True)
                except OSError: pass
            QMessageBox.information(self, "Vault export verified",
                                    f"Encrypted vault package created and verified:\n{context['destination']}\n\n"
                                    "The original vault was not changed.")
            return
        try:
            _register_profile(context["name"], Path(result["path"]), context["profile_id"])
        except Exception as exc:
            QMessageBox.warning(self, "Import verified; profile registration needs recovery",
                                f"The imported files were verified and preserved at:\n{result['path']}\n\n"
                                f"The profile could not be added to the chooser ({type(exc).__name__}). Do not delete this folder.")
            return
        try:
            (Path(result["path"]) / ".import-owned.json").unlink()
            fsync_directory(Path(result["path"]))
        except OSError:
            pass
        try:
            context["journal"].unlink(missing_ok=True)
        except OSError:
            pass
        if context["delete_package"]:
            source = context["package"]
            try:
                info = source.lstat()
                snapshot = context["package_stat"]
                if (stat.S_ISREG(info.st_mode) and not stat.S_ISLNK(info.st_mode)
                        and (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns) == snapshot):
                    source.unlink()
                else:
                    raise OSError("The selected package changed during import; it was preserved.")
            except OSError as exc:
                QMessageBox.warning(self, "Imported; package kept",
                                    f"The new profile is ready, but the original package could not be safely deleted ({exc}).")
        QMessageBox.information(self, "Import complete",
                                f"Vault profile “{context['name']}” was imported and verified.\n\n"
                                "Please run UNKNWN again to choose and open the new imported vault.")
        self.close()
    def appstate(self, st: int) -> None:
        for stage in QApplication.allWidgets():
            if isinstance(stage, Stage):
                cast(Any, stage).setfps()
        if st != Qt.ApplicationState.ApplicationActive and (S("blur") or S("ghost")) and self.mode == "vault" and not self.hold and not self.busy: self.lock()
    def closeEvent(self, a0: Any) -> None:
        if self.mode == "blocked":
            if self.working():
                self.acknowledge_integrity_failure()
                a0.ignore()
                return
            self._integrity_exit_started = True
            super().closeEvent(a0)
            return
        if self.working(): a0.ignore(); return   # closing mid-operation can corrupt data
        self._hide_drop_feedback()
        if self.mode == "vault" and getattr(self, "session_started", None) is not None:
            self.record_session_event("session_ended")
        if self.dlg:
            self.dlg.reject()
            QApplication.processEvents()
        if S("clip"): clear_clipboard()
        if S("logwipe"): shred(LOG)
        if S("exitclean"):
            try: shred(HOME / "error.log")
            except Exception: pass
            shutil.rmtree(APP.parent / "__pycache__", ignore_errors=True)
        cleanup_temp_files()
        super().closeEvent(a0)
    def resizeEvent(self, a0: Any) -> None:
        super().resizeEvent(a0)
        overlay = getattr(self, "_drop_overlay", None)
        if isinstance(overlay, QFrame) and overlay.isVisible():
            overlay.setGeometry(self.rect())
        for w in self.findChildren(Intro): w.setGeometry(self.rect())
        if getattr(self, "devl", None): self.devl.move(10, self.height() - self.devl.height() - 6); self.devl.raise_()
    def changeEvent(self, a0: Any) -> None:
        if a0.type() == QEvent.Type.WindowStateChange and self.isMinimized() and (S("minlock") or S("ghost")) and self.mode == "vault" and not self.hold and not self.busy: QTimer.singleShot(0, self.lock)
        if a0.type() == QEvent.Type.WindowStateChange:
            for stage in QApplication.allWidgets():
                if isinstance(stage, Stage):
                    cast(Any, stage).setfps()
        super().changeEvent(a0)
    def show_w(self, w: QWidget, mode: str) -> None:
        if INTEG[0] == "fail" and mode != "blocked":
            return
        self.mode = mode; self.owner = self.owner and mode == "vault"
        if self.cur: self.box.removeWidget(self.cur); self.cur.deleteLater()
        self.cur = w; self.box.addWidget(w)
    def animate_tab(self) -> None:
        if S("reduce_motion"):
            previous = getattr(self, "_tab_animation", None)
            if previous is not None: previous.stop()
            self.stack.setGraphicsEffect(None); self._tab_animation = self._tab_effect = None
            return
        previous = getattr(self, "_tab_animation", None)
        if previous is not None: previous.stop()
        effect = QGraphicsOpacityEffect(self.stack); effect.setOpacity(0)
        self.stack.setGraphicsEffect(effect)
        animation = QPropertyAnimation(effect, b"opacity", self.stack)
        animation.setDuration(280); animation.setStartValue(0.0); animation.setEndValue(1.0)
        animation.setEasingCurve(QEasingCurve.Type.OutCubic)
        def clear() -> None:
            if getattr(self, "_tab_animation", None) is animation and self.stack.graphicsEffect() is effect:
                self.stack.setGraphicsEffect(None); self._tab_animation = None; self._tab_effect = None
        animation.finished.connect(clear)
        self._tab_animation = animation; self._tab_effect = effect; animation.start()
    def record_session_event(self, kind: str, **fields: Any) -> None:
        events_value: object = getattr(self, "session_activity", None)
        if not isinstance(events_value, list):
            self.session_activity = []
        events = self.session_activity
        event: dict[str, Any] = {"t": time.time(), "kind": kind, **fields}
        events.append(event)
        if kind == "files_stored":
            names_value: object = fields.get("names", [])
            names = ([name for name in cast(list[object], names_value) if isinstance(name, str)]
                     if isinstance(names_value, list) else [])
            self.session_stored_names.extend(names)
            count_value: object = fields.get("count", len(names))
            count = count_value if isinstance(count_value, int) else len(names)
            self.session_stored_count += max(0, count)
        elif kind == "setting_changed":
            self.session_setting_changes += 1
        if len(events) > 1000:
            del events[:-1000]
            self.session_activity_omitted += 1
        App.persist_session_event(self)
    def logs(self) -> list[dict[str, object]]:
        root = self.root
        if root is None:
            self.session_history_error = None
            return []
        if not LOG.exists():
            self.session_history_error = None
            return []
        try:
            entries = json.loads(unseal(file_key(root, b"unknwn-log"), LOG.read_bytes()))
            if not isinstance(entries, list):
                raise ValueError("unsupported encrypted activity history format")
            entry_values = cast(list[object], entries)
            if any(not isinstance(entry, dict) for entry in entry_values):
                raise ValueError("unsupported encrypted activity history format")
            self.session_history_error = None
            return [cast(dict[str, object], entry) for entry in entry_values]
        except (OSError, InvalidTag, json.JSONDecodeError, TypeError, ValueError) as exc:
            self.session_history_error = type(exc).__name__
            return []
    def persist_session_event(self) -> None:
        attrs = self.__dict__
        sid = attrs.get("session_id")
        root = self.root
        if (not S("log") or S("ghost") or root is None
                or not isinstance(sid, str) or len(sid) != 32):
            return
        previous_error = attrs.get("session_history_error")
        entries = App.logs(self)
        if attrs.get("session_history_error"):
            if previous_error is None:
                log_security_event("session_history_read_failed", error=self.session_history_error)
            return
        events: list[dict[str, object]] = []
        allowed_kinds = {"vault_unlocked", "vault_locked", "files_stored", "file_opened",
                         "file_burned", "setting_changed", "profile_switch", "session_ended"}
        activity_value: object = attrs.get("session_activity", [])
        activities = cast(list[dict[str, object]], activity_value) if isinstance(activity_value, list) else []
        for event in activities:
            if event.get("kind") not in allowed_kinds:
                continue
            safe: Optional[dict[str, object]] = {"t": event["t"], "kind": event["kind"]} if isinstance(event.get("t"), (int, float)) else None
            if safe is None:
                continue
            kind = event["kind"]
            if kind == "vault_unlocked" and event.get("method") in ("password", "recovery"):
                safe["method"] = event["method"]
            elif kind == "files_stored":
                count = event.get("count")
                if isinstance(count, int) and not isinstance(count, bool):
                    safe["count"] = max(0, min(count, 100000))
                names = event.get("names")
                if isinstance(names, list):
                    safe["names"] = [name[:255] for name in cast(list[object], names)[:100] if isinstance(name, str)]
            elif kind in ("file_opened", "file_burned") and isinstance(event.get("name"), str):
                name = event.get("name")
                if isinstance(name, str): safe["name"] = name[:255]
            elif kind == "setting_changed" and isinstance(event.get("key"), str):
                key = event.get("key")
                if not isinstance(key, str): continue
                safe["key"] = key[:64]
                for field in ("before", "after"):
                    value = event.get(field)
                    if isinstance(value, (bool, int, float)):
                        safe[field] = value
                    elif isinstance(value, str):
                        safe[field] = value[:100]
            events.append(safe)
        sid_record: Optional[dict[str, object]] = next((entry for entry in entries
                           if entry.get("type") == "session" and entry.get("sid") == sid), None)
        if sid_record is None:
            started_value: object = attrs.get("session_started")
            started_time = started_value if isinstance(started_value, (int, float)) else time.time()
            sid_record = {"type": "session", "sid": sid, "t": started_time}
            entries.append(sid_record)
        sid_record["events"] = events[-MAX_SESSION_EVENTS:]
        if events and events[-1]["kind"] == "session_ended":
            sid_record["ended"] = events[-1]["t"]
        signins = [entry for entry in entries if entry.get("type") != "session"][-MAX_SIGNIN_HISTORY:]
        sessions = [entry for entry in entries if entry.get("type") == "session"][-MAX_SESSION_HISTORY:]
        try:
            HOME.mkdir(parents=True, exist_ok=True)
            atomic_write_bytes(LOG, seal(file_key(root, b"unknwn-log"),
                                         json.dumps(signins + sessions, separators=(",", ":"), ensure_ascii=False).encode("utf-8")))
            self.session_history_error = None
        except (OSError, TypeError, ValueError) as exc:
            self.session_history_error = type(exc).__name__
            if previous_error is None:
                log_security_event("session_history_write_failed", error=self.session_history_error)
    def panel(self, *ws: QWidget, w: int = 380) -> QScrollArea:
        p = QWidget(); p.setMaximumWidth(w); v = QVBoxLayout(p); v.setSpacing(12)
        for x in ws: v.addWidget(x)
        o = QWidget(); l = QVBoxLayout(o); l.addStretch(2); hl = QHBoxLayout(); hl.addStretch(1); hl.addWidget(p, 40); hl.addStretch(1); l.addLayout(hl); l.addStretch(3)
        sa = QScrollArea(); sa.setWidgetResizable(True); sa.setFrameShape(QFrame.Shape.NoFrame); sa.setWidget(o); return sa
    def clock_label(self) -> ClockBadge:
        clock = ClockBadge(self.toggle_clock_format, self)
        timer = QTimer(clock); timer.timeout.connect(clock.refresh); timer.start(1000); clock._clock_timer = timer
        return clock
    def toggle_clock_format(self) -> None:
        settings = cfg.setdefault("set", {})
        previous = settings.get("clock24", DEF["clock24"])
        settings["clock24"] = not bool(previous)
        try:
            jsave(CFG, cfg)
        except OSError as exc:
            settings["clock24"] = previous
            QMessageBox.warning(self, "Clock format not saved",
                                f"The clock format could not be saved ({type(exc).__name__}).")
            return
        for clock in self.findChildren(ClockBadge):
            clock.refresh()
    def profile_display_name(self) -> str:
        profile = os.environ.get("USERPROFILE") or str(Path.home())
        return Path(profile).name.strip() or platform.node() or "there"
    def vault_avatar_path(self) -> Path:
        return HOME / "vault-avatar.enc"
    def _write_vault_avatar(self, image_data: bytes) -> None:
        root = self.root
        if root is None:
            raise RuntimeError("Unlock this Vault before saving an encrypted profile photo.")
        if not image_data or len(image_data) > _AVATAR_MAX_BYTES:
            raise ValueError("The profile photo must be smaller than 5 MiB.")
        salt = os.urandom(16)
        encrypted = _AVATAR_MAGIC + salt + seal(file_key(root, salt), image_data)
        HOME.mkdir(parents=True, exist_ok=True)
        atomic_write_bytes(self.vault_avatar_path(), encrypted)
    def _vault_avatar_data(self) -> Optional[bytes]:
        root = self.root
        if root is None:
            return None
        path = self.vault_avatar_path()
        try:
            info = path.lstat()
        except FileNotFoundError:
            return self._migrate_legacy_vault_avatar(root)
        attributes = getattr(info, "st_file_attributes", 0)
        reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        if (not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)
                or attributes & reparse or info.st_size > _AVATAR_MAX_BYTES + 128):
            log_security_event("vault_avatar_rejected", reason="unsafe_file")
            return None
        try:
            encrypted = path.read_bytes()
            if not encrypted.startswith(_AVATAR_MAGIC):
                log_security_event("vault_avatar_rejected", reason="invalid_format")
                return None
            salt_start = len(_AVATAR_MAGIC)
            salt = encrypted[salt_start:salt_start + 16]
            if len(salt) != 16:
                raise ValueError("The encrypted profile photo header is incomplete.")
            data = unseal(file_key(root, salt), encrypted[salt_start + 16:])
            if not data or len(data) > _AVATAR_MAX_BYTES:
                raise ValueError("The decrypted profile photo size is invalid.")
            return data
        except (OSError, ValueError, InvalidTag) as exc:
            log_security_event("vault_avatar_read_failed", error=type(exc).__name__)
            return None
    def _migrate_legacy_vault_avatar(self, root: bytes) -> Optional[bytes]:
        legacy_path = HOME / "vault-avatar.png"
        try:
            info = legacy_path.lstat()
        except FileNotFoundError:
            return None
        attributes = getattr(info, "st_file_attributes", 0)
        reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        if (not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)
                or attributes & reparse or info.st_size > _AVATAR_MAX_BYTES):
            log_security_event("vault_avatar_migration_rejected", reason="unsafe_file")
            return None
        try:
            image_data = legacy_path.read_bytes()
            image = QPixmap()
            if not image.loadFromData(image_data):
                log_security_event("vault_avatar_migration_rejected", reason="invalid_image")
                return None
            self._write_vault_avatar(image_data)
            legacy_path.unlink()
            return image_data
        except OSError as exc:
            log_security_event("vault_avatar_migration_failed", error=type(exc).__name__)
            return None
    def avatar_label(self, size: int = 40) -> QLabel:
        avatar = QLabel()
        avatar.setFixedSize(size, size)
        avatar.setAlignment(Qt.AlignmentFlag.AlignCenter)
        avatar.setObjectName("vaultAvatar")
        image_data = self._vault_avatar_data()
        image = QPixmap()
        if image_data is not None and image.loadFromData(image_data):
            scaled = image.scaled(
                size, size, Qt.AspectRatioMode.KeepAspectRatioByExpanding,
                Qt.TransformationMode.SmoothTransformation)
            overflow_x = max(0, scaled.width() - size)
            overflow_y = max(0, scaled.height() - size)
            crop = str(S("avatar_crop"))
            horizontal = "left" if crop.endswith("left") else (
                "right" if crop.endswith("right") else "center")
            vertical = "top" if crop.startswith("top") else (
                "bottom" if crop.startswith("bottom") else "center")
            x = 0 if horizontal == "left" else overflow_x if horizontal == "right" else overflow_x // 2
            y = 0 if vertical == "top" else overflow_y if vertical == "bottom" else overflow_y // 2
            cropped = scaled.copy(x, y, size, size)
            circular = QPixmap(size, size)
            circular.fill(Qt.GlobalColor.transparent)
            painter = QPainter(circular)
            painter.setRenderHint(QPainter.RenderHint.Antialiasing)
            circle = QPainterPath()
            circle.addEllipse(QRectF(1, 1, size - 2, size - 2))
            painter.setClipPath(circle)
            painter.drawPixmap(0, 0, cropped)
            painter.end()
            avatar.setPixmap(circular)
        try:
            avatar.setStyleSheet(
                f"background:{TH['panel']};border:1px solid {TH['line']};border-radius:{size // 2}px;")
        except KeyError:
            avatar.setStyleSheet(f"background:{TH['panel']};border-radius:{size // 2}px;")
        avatar.setAccessibleName("Vault profile photo")
        avatar.setToolTip("Vault profile photo; encrypted with this Vault's key on this device.")
        return avatar
    def pick_vault_avatar(self) -> None:
        selected, _ = QFileDialog.getOpenFileName(
            self, "Choose Vault profile photo", "",
            "Images (*.png *.jpg *.jpeg *.bmp *.webp)")
        if not selected:
            return
        image_file = Path(selected)
        try:
            info = image_file.lstat()
            attributes = getattr(info, "st_file_attributes", 0)
            reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
            if (not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)
                    or attributes & reparse or info.st_size > _AVATAR_MAX_BYTES):
                raise OSError("Choose a regular image smaller than 5 MiB; links are not accepted.")
            source_data = image_file.read_bytes()
        except OSError as exc:
            QMessageBox.warning(self, "Photo unavailable", str(exc))
            return
        image = QPixmap()
        if not image.loadFromData(source_data):
            QMessageBox.warning(self, "Photo unavailable",
                                "The selected file could not be loaded as an image.")
            return
        normalized = image.scaled(
            512, 512, Qt.AspectRatioMode.KeepAspectRatio,
            Qt.TransformationMode.SmoothTransformation)
        buffer = QBuffer()
        if not buffer.open(QIODevice.OpenModeFlag.WriteOnly) or not normalized.save(buffer, "PNG"):
            buffer.close()
            QMessageBox.warning(self, "Photo not saved",
                                "The selected profile photo could not be encoded.")
            return
        try:
            self._write_vault_avatar(bytes(buffer.data()))
        except (OSError, ValueError, RuntimeError) as exc:
            QMessageBox.warning(self, "Photo not saved",
                                f"The profile photo could not be saved ({type(exc).__name__}).")
            return
        finally:
            buffer.close()
        self._refresh_profile_photo()
    def remove_vault_avatar(self) -> None:
        paths = (self.vault_avatar_path(), HOME / "vault-avatar.png")
        try:
            for path in paths:
                try:
                    info = path.lstat()
                except FileNotFoundError:
                    continue
                attributes = getattr(info, "st_file_attributes", 0)
                reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
                if (not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)
                        or attributes & reparse):
                    raise OSError("The profile photo path is not a regular file; it was left unchanged.")
                path.unlink()
        except OSError as exc:
            QMessageBox.warning(self, "Photo not removed",
                                f"The profile photo could not be removed ({type(exc).__name__}): {exc}")
            return
        self._refresh_profile_photo()
    def _refresh_profile_photo(self) -> None:
        for avatar in self.findChildren(QLabel, "vaultAvatar"):
            size = min(avatar.width(), avatar.height())
            replacement = self.avatar_label(size)
            replacement_pixmap = replacement.pixmap()
            if replacement_pixmap is None:
                avatar.clear()
            else:
                avatar.setPixmap(replacement_pixmap)
            avatar.setStyleSheet(replacement.styleSheet())
    def login_greeting(self) -> ProfileGreeting:
        name = "operator" if S("hideuser") else self.profile_display_name()
        greeting = ProfileGreeting(f"Welcome back, {name}", self.show_profile_art)
        greeting.setAlignment(cast(Any, Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter))
        return greeting
    def logo(self) -> QWidget:
        row = QWidget(); layout = QHBoxLayout(row); layout.setContentsMargins(0, 2, 0, 2); layout.setSpacing(12)
        mark = Glitch("UNKNWN", 22, self.logo_quote); mark.setObjectName("brandMark"); mark.setToolTip("of course nothing suspsious here :3"); mark.setAlignment(cast(Any, Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter))
        greeting = ProfileGreeting(f"Hi, {'operator' if S('hideuser') else self.profile_display_name()}", self.show_profile_art)
        timer = QTimer(greeting)
        timer.timeout.connect(lambda: greeting.setText(
            f"Hi, {'operator' if S('hideuser') else self.profile_display_name()}"))
        timer.start(1000); greeting._greeting_timer = timer
        layout.addWidget(self.avatar_label(36)); layout.addWidget(mark); layout.addWidget(greeting); layout.addStretch()
        return row
    def show_profile_art(self) -> None:
        art = random_warden_art().splitlines()
        while art and not art[0].strip(): art.pop(0)
        while art and not art[-1].strip(): art.pop()
        art = [line.expandtabs(4)[:140] for line in art[:100]]
        d = QDialog(self); d.setWindowTitle("UNKNWN // PROFILE SIGNAL")
        screen = self.screen(); area = screen.availableGeometry() if screen is not None else QRect(0, 0, 900, 700)
        width = min(1000, max(320, int(area.width() * .86)))
        height = min(760, max(320, int(area.height() * .86)))
        d.resize(width, height)
        layout = QVBoxLayout(d); layout.setContentsMargins(16, 14, 16, 14); layout.setSpacing(10)
        frame = QFrame(); frame.setObjectName("term"); inside = QVBoxLayout(frame)
        inside.addWidget(lbl("UNKNWN", 22, ACC, center=True))
        inside.addWidget(lbl("PROFILE SIGNAL // LOCAL DISPLAY", 10, MUT, center=True))
        illustration = QLabel("\n".join(art)); illustration.setAlignment(Qt.AlignmentFlag.AlignCenter)
        illustration.setTextFormat(Qt.TextFormat.PlainText); illustration.setWordWrap(False)
        font = QFont("Consolas"); font.setStyleHint(QFont.StyleHint.Monospace)
        max_chars = max((len(line) for line in art), default=1)
        px = max(4, min(15, int((width - 80) / max(1, max_chars * .62)),
                        int((height - 150) / max(1, len(art) * 1.12))))
        font.setPixelSize(px); illustration.setFont(font); illustration.setStyleSheet(f"color:{ACC}")
        inside.addWidget(illustration, 1); layout.addWidget(frame, 1)
        close = btn("Close"); close.clicked.connect(d.accept); layout.addWidget(close)
        d.exec_()
    def logo_quote(self) -> None:
        quotes: tuple[str, ...] = (
            'Some friends keep your secrets; the rare ones help you keep yourself.',
            'Trust is a door you open slowly, even for people you love.',
            'Betrayal changes the story, but it does not get to write your ending.',
            'Privacy is room to become yourself before the world asks who you are.',
            'Life is shorter than the grudges we carry and longer than the apologies we fear.',
            'A loyal friend guards your name when you are not in the room.',
            'Being understood is a kind of shelter; being private is choosing its door.',
            'You can forgive the past without handing it the keys to tomorrow.',
            'The people who stay gentle after learning your sharp edges are rare.',
            'Keep a little mystery for yourself; not every quiet thing needs an audience.',
            'A steady heart can find its way through a noisy night.',
            'The best boundaries leave room for the right people to stay.',
            'What is private can still be generous, bright, and alive.',
            'Do not confuse a quiet answer with an empty one.',
            'The horizon does not hurry, and still it arrives.',
            'A careful beginning is its own kind of courage.',
            'Leave a little room for wonder behind the locked door.',
            'You can be kind without giving every part of yourself away.',
            'Keep the promise you made to your future self.',
            'A small light is enough to begin finding the way.',
            'The world can wait while you decide what matters.',
            'Some things grow better outside the spotlight.',
            'A good question is sometimes the first safe place.',
            'The signal is only noise until you choose what to hear.',
            'Carry your values farther than your fears.',
            'A pause can be the strongest move in the room.',
            'Make a home for calm, even when the weather changes.',
            'There is strength in knowing when a door is yours to close.',
            'Let your next step belong to you.',
            'The quiet route still leads somewhere.',
            'What you keep safe can still help you become more.',
            'No one else gets to measure the worth of your peace.',
            'Listen closely; the right answer rarely needs to shout.',
            'Keep the key. Choose the door. Set your own pace.',
            'You can make room for the things words cannot explain without even when nobody notices.',
            'You can guide the peace you worked for without long after the noise has passed.',
            'A guarded heart can protect what matters most long after the noise has passed.',
            'A hidden hope can restore a better tomorrow without asking the world for permission.',
            'A calm answer can survive a future worth reaching without needing to be understood by everyone.',
            'Sometimes a second chance is the beginning of the freedom to choose.',
            'Sometimes a clear boundary is the beginning of the trust you built slowly.',
            'Sometimes a thoughtful pause is the beginning of the things words cannot explain.',
            'You can carry a future worth reaching without even when nobody notices.',
            'Sometimes a trusted friend is the beginning of the peace you worked for.',
            'A patient soul can survive the freedom to choose even when nobody notices.',
            'Let a second chance remain quiet; not everything needs a defense.',
            'Let an honest promise remain quiet; not everything needs a label.',
            'A private life can reveal the space to grow without needing to be understood by everyone.',
            'A quiet courage can guide the trust you built slowly long after the noise has passed.',
            'You can survive the peace you worked for without even when the answer takes time.',
            'A clear boundary is not solitude; it is loneliness.',
            'You can carry what matters most without when the right moment finally arrives.',
            'Let a steady heart remain uncertain; not everything needs a deadline.',
            'You can carry the courage to begin again without when the right moment finally arrives.',
            'Sometimes a trusted friend is the beginning of the space to grow.',
            'Let a quiet mind remain gentle; not everything needs a defense.',
            'You can make room for the things words cannot explain without without surrendering what makes you yourself.',
            'Let a guarded heart remain yours; not everything needs a deadline.',
            'You can reveal the person you are becoming without one careful step at a time.',
            'You can become the person you are becoming without one careful step at a time.',
            'A second chance is not privacy; it is distance.',
            'You can protect the people who truly matter without long after the noise has passed.',
            'Let an honest promise remain unseen; not everything needs a defense.',
            'A thoughtful pause is not a boundary; it is a rejection.',
            'A private life can restore the people who truly matter even when nobody notices.',
            'You can guide the person you are becoming without one careful step at a time.',
            'You can make room for a better tomorrow without even when nobody notices.',
            'You can survive a future worth reaching without one careful step at a time.',
            'Sometimes a clear boundary is the beginning of the person you are becoming.',
            'A steady heart can protect a life that feels like your own without asking the world for permission.',
            'A guarded heart is not quiet; it is absence.',
            'A gentle truth can soften a future worth reaching when the right moment finally arrives.',
            'Let a private life remain unspoken; not everything needs a deadline.',
            'Sometimes a quiet courage is the beginning of the things words cannot explain.',
            'A closed door can outlast a better tomorrow without surrendering what makes you yourself.',
            'A calm answer can restore a life that feels like your own without asking the world for permission.',
            'A calm answer can restore what matters most without asking the world for permission.',
            'Sometimes a brave question is the beginning of the people who truly matter.',
            'A gentle truth can become the people who truly matter even when nobody notices.',
            'A little distance is not mystery; it is deception.',
            'A trusted friend can survive a future worth reaching when the right moment finally arrives.',
            'A thoughtful pause can protect a future worth reaching even when the answer takes time.',
            'A gentle truth is not mystery; it is deception.',
            'You can soften a path through uncertainty without when the right moment finally arrives.',
            'Let a gentle truth remain unfinished; not everything needs a label.',
            'You can outlast a life that feels like your own without while leaving room for tomorrow.',
            'You can reveal a future worth reaching without without needing to be understood by everyone.',
            'Let a gentle truth remain uncertain; not everything needs a label.',
            'Let a thoughtful pause remain unspoken; not everything needs an audience.',
            'You can restore a future worth reaching without even when the answer takes time.',
            'A careful choice is not a pause; it is a surrender.',
            'A small beginning can reveal a path through uncertainty while leaving room for tomorrow.',
            'A closed door can make room for a future worth reaching long after the noise has passed.',
            'Sometimes a guarded heart is the beginning of the truth beneath the noise.',
            'Let a quiet mind remain uncertain; not everything needs a label.',
            'A little distance is not patience; it is weakness.',
            'Let a brave question remain unseen; not everything needs an audience.',
            'Let a clear boundary remain gentle; not everything needs an audience.',
            'You can protect the space to grow without without surrendering what makes you yourself.',
            'You can soften the person you are becoming without without becoming smaller for anyone.',
            'A guarded heart is not patience; it is weakness.',
            'Sometimes a clear boundary is the beginning of the people who truly matter.',
            'A closed door can restore the things words cannot explain without needing to be understood by everyone.',
            'You can reveal a better tomorrow without without asking the world for permission.',
            'You can protect the person you are becoming without one careful step at a time.',
            'Sometimes a second chance is the beginning of the space to grow.',
            'Sometimes a calm answer is the beginning of the things words cannot explain.',
            'A quiet mind can carry a life that feels like your own one careful step at a time.',
            'Sometimes a peaceful room is the beginning of the people who truly matter.',
            'A brave question can restore a path through uncertainty without becoming smaller for anyone.',
            'A hidden hope can soften the space to grow one careful step at a time.',
            'Let a quiet courage remain unfinished; not everything needs a label.',
            'A calm answer can guide the trust you built slowly long after the noise has passed.',
            'A trusted friend can carry the courage to begin again without becoming smaller for anyone.',
            'A peaceful room can guide a better tomorrow even when the answer takes time.',
            'A private life can become the people who truly matter one careful step at a time.',
            'Let a private life remain uncertain; not everything needs a witness.',
            'A little distance can make room for the freedom to choose without becoming smaller for anyone.',
            'A gentle truth can reveal a life that feels like your own without asking the world for permission.',
            'A hidden hope can reveal the things words cannot explain even when nobody notices.',
            'An honest promise is not privacy; it is distance.',
            'Let a closed door remain private; not everything needs an explanation.',
            'A peaceful room can make room for the trust you built slowly without asking the world for permission.',
            'You can reveal a path through uncertainty without without needing to be understood by everyone.',
            'A clear boundary can guide the parts worth keeping even when the answer takes time.',
            'A closed door is not patience; it is weakness.',
            'A quiet mind is not forgiveness; it is forgetting.',
            'A careful choice is not quiet; it is absence.',
            'Let a peaceful room remain unfinished; not everything needs an explanation.',
            'Sometimes a closed door is the beginning of a path through uncertainty.',
            'An honest promise can reveal the space to grow without asking the world for permission.',
            'Sometimes a quiet courage is the beginning of the people who truly matter.',
            'Let a quiet mind remain private; not everything needs a deadline.',
            'A quiet mind can restore a future worth reaching without asking the world for permission.',
            'Let a little distance remain quiet; not everything needs an explanation.',
            'A brave question can survive the parts worth keeping even when the answer takes time.',
            'Sometimes a trusted friend is the beginning of the person you are becoming.',
            'Sometimes a calm answer is the beginning of a better tomorrow.',
            'Let a patient soul remain gentle; not everything needs a witness.',
            'A clear boundary can guide the person you are becoming without surrendering what makes you yourself.',
            'A little distance can reveal the person you are becoming long after the noise has passed.',
            'A calm answer can protect the things words cannot explain one careful step at a time.',
            'A little distance can survive the courage to begin again even when the answer takes time.',
            'Let a little distance remain uncertain; not everything needs a label.',
            'A brave question can protect the people who truly matter without asking the world for permission.',
            'A quiet courage can restore a life that feels like your own one careful step at a time.',
            'A trusted friend can protect the parts worth keeping without surrendering what makes you yourself.',
            'A clear boundary can reveal a better tomorrow when the right moment finally arrives.',
            'A peaceful room can reveal the truth beneath the noise one careful step at a time.',
            'A gentle truth can reveal the courage to begin again one careful step at a time.',
            'You can make room for the person you are becoming without without becoming smaller for anyone.',
            'A steady heart can carry the peace you worked for without becoming smaller for anyone.',
            'Sometimes a brave question is the beginning of a path through uncertainty.',
            'A little distance can become a future worth reaching without asking the world for permission.',
            'A patient soul can soften the peace you worked for even when nobody notices.',
            'You can carry the freedom to choose without even when nobody notices.',
            'You can become the things words cannot explain without without asking the world for permission.',
            'An honest promise can survive the courage to begin again without needing to be understood by everyone.',
            'A patient soul is not a boundary; it is a rejection.',
            'A careful choice can become the peace you worked for long after the noise has passed.',
            'A clear boundary is not privacy; it is distance.',
            'A little distance can guide a better tomorrow one careful step at a time.',
            'You can restore a future worth reaching without without becoming smaller for anyone.',
            'Sometimes a peaceful room is the beginning of the person you are becoming.',
            'You can outlast the person you are becoming without even when the answer takes time.',
            'A gentle truth can soften the people who truly matter one careful step at a time.',
            'Let a second chance remain unspoken; not everything needs a deadline.',
            'A steady heart can become the space to grow even when the answer takes time.',
            'Let a careful choice remain uncertain; not everything needs a label.',
            'A hidden hope can protect the freedom to choose one careful step at a time.',
            'A hidden hope can reveal a better tomorrow without surrendering what makes you yourself.',
            'A small beginning is not a pause; it is a surrender.',
            'A patient soul can restore what matters most even when nobody notices.',
            'A trusted friend is not caution; it is fear.',
            'A clear boundary is not a boundary; it is a rejection.',
            'You can guide a life that feels like your own without even when the answer takes time.',
            'A gentle truth is not patience; it is weakness.',
            'A little distance can survive the things words cannot explain long after the noise has passed.',
            'You can make room for a life that feels like your own without one careful step at a time.',
            'A thoughtful pause can soften the things words cannot explain even when the answer takes time.',
            'Let a peaceful room remain gentle; not everything needs a defense.',
            'A patient soul can protect the things words cannot explain without asking the world for permission.',
            'You can reveal what matters most without without surrendering what makes you yourself.',
            'Let a trusted friend remain uncertain; not everything needs a defense.',
            'You can survive the courage to begin again without without needing to be understood by everyone.',
            'Let a careful choice remain quiet; not everything needs an explanation.',
            'Let a small beginning remain unspoken; not everything needs a defense.',
            'A patient soul can outlast the trust you built slowly long after the noise has passed.',
            'You can outlast the people who truly matter without without needing to be understood by everyone.',
            'Sometimes a steady heart is the beginning of a better tomorrow.',
            'Let a closed door remain private; not everything needs a defense.',
            'Let a calm answer remain gentle; not everything needs a label.',
            'A clear boundary can carry a life that feels like your own one careful step at a time.',
            'Let a small beginning remain private; not everything needs a witness.',
            'A careful choice can survive the space to grow while leaving room for tomorrow.',
            'A thoughtful pause is not quiet; it is absence.',
            'Let a quiet courage remain gentle; not everything needs a witness.',
            'You can reveal a life that feels like your own without while leaving room for tomorrow.',
            'Let a small beginning remain uncertain; not everything needs an audience.',
            'Sometimes a careful choice is the beginning of the things words cannot explain.',
            'A small beginning can restore the parts worth keeping without becoming smaller for anyone.',
            'You can reveal the peace you worked for without while leaving room for tomorrow.',
            'Let a private life remain yours; not everything needs an audience.',
            'You can become the courage to begin again without without surrendering what makes you yourself.',
            'A private life can guide a life that feels like your own while leaving room for tomorrow.',
            'A guarded heart can carry a path through uncertainty when the right moment finally arrives.',
            'Sometimes a second chance is the beginning of a better tomorrow.',
            'A trusted friend can make room for the courage to begin again without surrendering what makes you yourself.',
            'Sometimes a guarded heart is the beginning of the people who truly matter.',
            'A guarded heart can carry the freedom to choose while leaving room for tomorrow.',
            'Let a small beginning remain quiet; not everything needs a defense.',
            'A careful choice can protect a life that feels like your own without needing to be understood by everyone.',
            'A guarded heart can protect a path through uncertainty without needing to be understood by everyone.',
            'A careful choice can restore a life that feels like your own when the right moment finally arrives.',
            'A second chance is not quiet; it is absence.',
            'A steady heart is not patience; it is weakness.',
            'You can survive a life that feels like your own without even when nobody notices.',
            'Let a trusted friend remain quiet; not everything needs a label.',
            'A careful choice can soften the people who truly matter without asking the world for permission.',
            'You can restore the parts worth keeping without without needing to be understood by everyone.',
            'You can soften the freedom to choose without without surrendering what makes you yourself.',
            'A clear boundary can restore what matters most one careful step at a time.',
            'A closed door can carry the parts worth keeping even when the answer takes time.',
            'An honest promise can reveal a future worth reaching without asking the world for permission.',
            'A brave question can protect the parts worth keeping long after the noise has passed.',
            'A guarded heart is not solitude; it is loneliness.',
            'You can make room for the things words cannot explain without one careful step at a time.',
            'A private life can become the space to grow while leaving room for tomorrow.',
            'You can restore the things words cannot explain without long after the noise has passed.',
            'Let a patient soul remain uncertain; not everything needs a defense.',
            'A quiet courage is not a boundary; it is a rejection.',
            'A private life can guide the peace you worked for one careful step at a time.',
            'Sometimes a clear boundary is the beginning of the things words cannot explain.',
            'Sometimes a thoughtful pause is the beginning of the truth beneath the noise.',
            'Let a patient soul remain yours; not everything needs a label.',
            'A closed door is not solitude; it is loneliness.',
            'A small beginning can outlast the freedom to choose even when the answer takes time.',
            'A second chance can outlast the space to grow even when nobody notices.',
            'You can guide the courage to begin again without long after the noise has passed.',
            'Sometimes an honest promise is the beginning of the peace you worked for.',
            'A quiet courage is not a pause; it is a surrender.',
            'You can make room for the parts worth keeping without even when the answer takes time.',
            'A clear boundary can carry the courage to begin again without needing to be understood by everyone.',
            'A closed door is not quiet; it is absence.',
            'A patient soul can survive a path through uncertainty without surrendering what makes you yourself.',
            'You can survive the trust you built slowly without without becoming smaller for anyone.',
            'Sometimes a steady heart is the beginning of the person you are becoming.',
            'Let a private life remain quiet; not everything needs an audience.',
            'Sometimes a second chance is the beginning of the trust you built slowly.',
            'An honest promise is not a pause; it is a surrender.',
            'Let an honest promise remain gentle; not everything needs a deadline.',
            'A closed door is not caution; it is fear.',
            'Let a trusted friend remain gentle; not everything needs an audience.',
            'A small beginning can restore the person you are becoming even when the answer takes time.',
            'Let a peaceful room remain uncertain; not everything needs an explanation.',
            'Sometimes a clear boundary is the beginning of the parts worth keeping.',
            'A steady heart can reveal a life that feels like your own long after the noise has passed.',
            'Sometimes a clear boundary is the beginning of the courage to begin again.',
            'A second chance can reveal the person you are becoming when the right moment finally arrives.',
            'A calm answer can guide the truth beneath the noise without becoming smaller for anyone.',
            'A peaceful room is not patience; it is weakness.',
            'A trusted friend is not patience; it is weakness.',
            'Sometimes a thoughtful pause is the beginning of a path through uncertainty.',
            'A guarded heart can reveal the space to grow while leaving room for tomorrow.',
            'You can outlast a future worth reaching without while leaving room for tomorrow.',
            'You can restore the freedom to choose without while leaving room for tomorrow.',
            'You can outlast the people who truly matter without without surrendering what makes you yourself.',
            'A hidden hope is not a pause; it is a surrender.',
            'A careful choice can protect the courage to begin again without becoming smaller for anyone.',
            'Let a gentle truth remain unfinished; not everything needs a witness.',
            'You can survive the truth beneath the noise without when the right moment finally arrives.',
            'A second chance can guide the courage to begin again even when nobody notices.',
            'Sometimes a little distance is the beginning of the truth beneath the noise.',
            'Sometimes a second chance is the beginning of the courage to begin again.',
            'A little distance can soften a better tomorrow when the right moment finally arrives.',
            'Sometimes a little distance is the beginning of the parts worth keeping.',
            'A careful choice can guide what matters most while leaving room for tomorrow.',
            'Let a careful choice remain private; not everything needs a deadline.',
            'You can survive the truth beneath the noise without long after the noise has passed.',
            'A thoughtful pause is not privacy; it is distance.',
            'A clear boundary is not patience; it is weakness.',
            'A little distance can restore a path through uncertainty long after the noise has passed.',
            'A quiet mind is not caution; it is fear.',
            'A careful choice can reveal a better tomorrow while leaving room for tomorrow.',
            'A quiet mind can carry the peace you worked for without becoming smaller for anyone.',
            'A quiet mind can outlast the parts worth keeping even when nobody notices.',
            'Sometimes a peaceful room is the beginning of the space to grow.',
            'You can survive the peace you worked for without without becoming smaller for anyone.',
            'A peaceful room is not a pause; it is a surrender.',
            'A peaceful room can survive the courage to begin again when the right moment finally arrives.',
            'A clear boundary can protect a better tomorrow without becoming smaller for anyone.',
            'Let a trusted friend remain private; not everything needs an explanation.',
            'A private life can soften the trust you built slowly without needing to be understood by everyone.',
            'A calm answer is not quiet; it is absence.',
            'A closed door can make room for a better tomorrow even when the answer takes time.',
            'A quiet courage can protect the people who truly matter while leaving room for tomorrow.',
            'A trusted friend is not solitude; it is loneliness.',
            'Let a thoughtful pause remain private; not everything needs a witness.',
            'A patient soul can restore the parts worth keeping even when the answer takes time.',
            'A thoughtful pause is not a pause; it is a surrender.',
            'A brave question can carry the people who truly matter without needing to be understood by everyone.',
            'Sometimes a gentle truth is the beginning of the parts worth keeping.',
            'A peaceful room can soften a path through uncertainty even when nobody notices.',
            'A hidden hope is not patience; it is weakness.',
            'A gentle truth is not solitude; it is loneliness.',
            'A clear boundary can guide the people who truly matter without surrendering what makes you yourself.',
            'Sometimes a little distance is the beginning of the things words cannot explain.',
            'A peaceful room can outlast the truth beneath the noise without needing to be understood by everyone.',
            'A careful choice can carry the space to grow when the right moment finally arrives.',
            'Let a peaceful room remain quiet; not everything needs an explanation.',
            'A private life can survive the courage to begin again one careful step at a time.',
            'A small beginning can make room for a life that feels like your own when the right moment finally arrives.',
            'A calm answer can restore what matters most one careful step at a time.',
            'Let a closed door remain unspoken; not everything needs a defense.',
            'A quiet mind can soften a life that feels like your own without becoming smaller for anyone.',
            'You can protect the freedom to choose without without becoming smaller for anyone.',
            'A closed door can carry a better tomorrow while leaving room for tomorrow.',
            'A little distance is not quiet; it is absence.',
            'You can protect a better tomorrow without long after the noise has passed.',
            'You can protect a life that feels like your own without long after the noise has passed.',
            'Let a careful choice remain uncertain; not everything needs a witness.',
            'Sometimes an honest promise is the beginning of a path through uncertainty.',
            'Let a closed door remain yours; not everything needs a defense.',
            'You can guide the parts worth keeping without without becoming smaller for anyone.',
            'A thoughtful pause can carry the people who truly matter without surrendering what makes you yourself.',
            'A peaceful room is not silence; it is emptiness.',
            'A closed door can outlast a path through uncertainty while leaving room for tomorrow.',
            'Sometimes a trusted friend is the beginning of the freedom to choose.',
            'A quiet courage can become the person you are becoming one careful step at a time.',
            'Let a quiet mind remain uncertain; not everything needs an explanation.',
            'You can carry the peace you worked for without without surrendering what makes you yourself.',
            'You can soften what matters most without long after the noise has passed.',
            'A quiet mind can make room for a life that feels like your own even when nobody notices.',
            'A guarded heart can restore what matters most even when nobody notices.',
            'You can make room for a life that feels like your own without even when the answer takes time.',
            'A small beginning can outlast the parts worth keeping even when nobody notices.',
            'You can become the courage to begin again without when the right moment finally arrives.',
            'A small beginning is not privacy; it is distance.',
            'You can soften a life that feels like your own without when the right moment finally arrives.',
            'Let a patient soul remain gentle; not everything needs an explanation.',
            'You can become the courage to begin again without one careful step at a time.',
            'You can make room for a life that feels like your own without even when nobody notices.',
            'A gentle truth can survive the truth beneath the noise when the right moment finally arrives.',
            'A quiet mind is not patience; it is weakness.',
            'A second chance can become a future worth reaching without needing to be understood by everyone.',
            'You can survive the people who truly matter without long after the noise has passed.',
            'You can survive the space to grow without even when the answer takes time.',
            'Let a peaceful room remain gentle; not everything needs a witness.',
            'You can protect a better tomorrow without even when nobody notices.',
            'Let a guarded heart remain uncertain; not everything needs an audience.',
            'Let a quiet courage remain private; not everything needs a deadline.',
            'You can make room for the truth beneath the noise without even when the answer takes time.',
            'You can protect a better tomorrow without while leaving room for tomorrow.',
            'A steady heart can become the people who truly matter without becoming smaller for anyone.',
            'A peaceful room is not forgiveness; it is forgetting.',
            'Let a steady heart remain quiet; not everything needs an explanation.',
            'You can guide a future worth reaching without when the right moment finally arrives.',
            'Sometimes a little distance is the beginning of what matters most.',
            'You can guide the parts worth keeping without even when the answer takes time.',
            'A trusted friend can carry the trust you built slowly long after the noise has passed.',
            'Sometimes a quiet courage is the beginning of the courage to begin again.',
            'Let a hidden hope remain unseen; not everything needs a defense.',
            'A clear boundary can outlast what matters most even when nobody notices.',
            'A thoughtful pause is not caution; it is fear.',
            'Sometimes a careful choice is the beginning of the freedom to choose.',
            'Let a small beginning remain unseen; not everything needs an explanation.',
            'Let a quiet mind remain quiet; not everything needs a deadline.',
            'You can outlast a future worth reaching without when the right moment finally arrives.',
            'A quiet courage can guide the peace you worked for long after the noise has passed.',
            'You can outlast the space to grow without without becoming smaller for anyone.',
            'A guarded heart is not forgiveness; it is forgetting.',
            'A patient soul can soften the peace you worked for long after the noise has passed.',
            'A thoughtful pause can guide the freedom to choose while leaving room for tomorrow.',
            'A brave question can soften the truth beneath the noise without needing to be understood by everyone.',
            'Let a trusted friend remain unseen; not everything needs an audience.',
            'Let a hidden hope remain unseen; not everything needs a witness.',
            'A quiet mind is not solitude; it is loneliness.',
            'Let a trusted friend remain unspoken; not everything needs an audience.',
            'You can outlast a future worth reaching without even when nobody notices.',
            'A guarded heart can become the courage to begin again one careful step at a time.',
            'Sometimes a quiet mind is the beginning of the peace you worked for.',
            'A guarded heart can guide a better tomorrow even when the answer takes time.',
            'A patient soul can soften the people who truly matter long after the noise has passed.',
            'You can outlast the peace you worked for without without surrendering what makes you yourself.',
            'A calm answer can guide the person you are becoming while leaving room for tomorrow.',
            'Let a calm answer remain uncertain; not everything needs an audience.',
            'Let a quiet courage remain private; not everything needs an audience.',
            'You can become the freedom to choose without without becoming smaller for anyone.',
            'Sometimes a calm answer is the beginning of the people who truly matter.',
            'Sometimes a steady heart is the beginning of the peace you worked for.',
            'Let a steady heart remain unfinished; not everything needs an explanation.',
            'Sometimes a brave question is the beginning of the peace you worked for.',
            'You can become the courage to begin again without even when nobody notices.',
            'Sometimes a calm answer is the beginning of the peace you worked for.',
            'A clear boundary can reveal the things words cannot explain one careful step at a time.',
            'You can make room for a future worth reaching without one careful step at a time.',
            'A second chance can soften what matters most without needing to be understood by everyone.',
            'An honest promise can make room for a life that feels like your own without surrendering what makes you yourself.',
            'Let a second chance remain quiet; not everything needs a witness.',
            'A hidden hope is not mystery; it is deception.',
            'A private life can guide the courage to begin again without needing to be understood by everyone.',
            'A careful choice can soften a life that feels like your own while leaving room for tomorrow.',
            'Let a peaceful room remain unfinished; not everything needs a defense.',
            'You can restore a life that feels like your own without without needing to be understood by everyone.',
            'Let a trusted friend remain gentle; not everything needs a deadline.',
            'A quiet courage is not quiet; it is absence.',
            'Let a peaceful room remain uncertain; not everything needs a deadline.',
            'Let a hidden hope remain unseen; not everything needs an audience.',
            'Sometimes a private life is the beginning of the things words cannot explain.',
            'A brave question can soften what matters most without becoming smaller for anyone.',
            'A brave question can protect the space to grow long after the noise has passed.',
            'An honest promise can soften the peace you worked for while leaving room for tomorrow.',
            'You can make room for the trust you built slowly without one careful step at a time.',
            'A patient soul can become the parts worth keeping without surrendering what makes you yourself.',
            'A guarded heart can survive a better tomorrow one careful step at a time.',
            'A calm answer can restore a future worth reaching long after the noise has passed.',
            'You can make room for the person you are becoming without without needing to be understood by everyone.',
            'Let a closed door remain unfinished; not everything needs an audience.',
            'Let a brave question remain gentle; not everything needs a deadline.',
            'A trusted friend can make room for the things words cannot explain without asking the world for permission.',
            'A private life can carry a future worth reaching without asking the world for permission.',
            'A gentle truth can reveal the person you are becoming long after the noise has passed.',
            'A thoughtful pause can guide the space to grow even when the answer takes time.',
            'A patient soul is not a pause; it is a surrender.',
            'A trusted friend can protect the person you are becoming even when the answer takes time.',
            'You can outlast the freedom to choose without even when the answer takes time.',
            'You can become the space to grow without even when nobody notices.',
            'A clear boundary is not mystery; it is deception.',
            'An honest promise can become the people who truly matter even when the answer takes time.',
            'Let an honest promise remain unspoken; not everything needs a deadline.',
            'Sometimes a hidden hope is the beginning of a life that feels like your own.',
            'A calm answer can become a path through uncertainty when the right moment finally arrives.',
            'A quiet mind is not quiet; it is absence.',
            'A quiet courage can survive a better tomorrow even when the answer takes time.',
            'You can reveal the courage to begin again without even when nobody notices.',
            'A private life can make room for the people who truly matter even when the answer takes time.',
            'A careful choice can make room for the things words cannot explain even when nobody notices.',
            'Sometimes a thoughtful pause is the beginning of the people who truly matter.',
            'An honest promise can outlast the trust you built slowly without surrendering what makes you yourself.',
            'A quiet mind can become the person you are becoming while leaving room for tomorrow.',
            'You can guide the trust you built slowly without without becoming smaller for anyone.',
            'A small beginning can soften the courage to begin again without needing to be understood by everyone.',
            'You can make room for what matters most without while leaving room for tomorrow.',
            'Let an honest promise remain unfinished; not everything needs a witness.',
            'A second chance is not a boundary; it is a rejection.',
            'Sometimes a little distance is the beginning of the person you are becoming.',
            'Sometimes a guarded heart is the beginning of the person you are becoming.',
            'You can become a future worth reaching without even when the answer takes time.',
            'A private life can become the trust you built slowly even when the answer takes time.',
            'Sometimes a quiet courage is the beginning of a path through uncertainty.',
            'A closed door can outlast the courage to begin again while leaving room for tomorrow.',
            'A patient soul can restore the trust you built slowly without becoming smaller for anyone.',
            'A hidden hope can make room for the parts worth keeping without surrendering what makes you yourself.',
            'You can guide a better tomorrow without without becoming smaller for anyone.',
            'A brave question can restore the people who truly matter without asking the world for permission.',
            'A guarded heart can outlast what matters most without surrendering what makes you yourself.',
            'A hidden hope can soften the trust you built slowly long after the noise has passed.',
            'Let a private life remain uncertain; not everything needs an audience.',
            'A clear boundary is not a pause; it is a surrender.',
            'You can guide the people who truly matter without without asking the world for permission.',
            'Let a closed door remain unspoken; not everything needs a label.',
            'A hidden hope can outlast a better tomorrow long after the noise has passed.',
            'You can soften a path through uncertainty without even when nobody notices.',
            'Sometimes a patient soul is the beginning of the people who truly matter.',
            'A thoughtful pause can carry a future worth reaching long after the noise has passed.',
            'Sometimes a small beginning is the beginning of a better tomorrow.',
            'A closed door can protect what matters most when the right moment finally arrives.',
            'You can guide the courage to begin again without even when nobody notices.',
            'A private life is not privacy; it is distance.',
            'You can protect what matters most without even when nobody notices.',
            'Let a patient soul remain uncertain; not everything needs an audience.',
            'Let a calm answer remain unspoken; not everything needs an explanation.',
            'A steady heart can outlast the person you are becoming even when the answer takes time.',
            'A peaceful room is not quiet; it is absence.',
            'A private life can reveal the truth beneath the noise even when the answer takes time.',
            'Sometimes a second chance is the beginning of the things words cannot explain.',
            'Let a trusted friend remain unseen; not everything needs a witness.',
            'Let a careful choice remain unspoken; not everything needs an explanation.',
            'A thoughtful pause is not forgiveness; it is forgetting.',
            'A guarded heart can outlast the space to grow without becoming smaller for anyone.',
            'Sometimes a careful choice is the beginning of a life that feels like your own.',
            'Sometimes an honest promise is the beginning of a better tomorrow.',
            'A careful choice can become a future worth reaching one careful step at a time.',
            'Let a brave question remain unspoken; not everything needs an audience.',
            'Let a steady heart remain uncertain; not everything needs a witness.',
            'Let a quiet courage remain unspoken; not everything needs a witness.',
            'A patient soul is not privacy; it is distance.',
            'Let a peaceful room remain unseen; not everything needs a defense.',
            'Sometimes a peaceful room is the beginning of the trust you built slowly.',
            'A gentle truth can survive a path through uncertainty even when the answer takes time.',
            'Let a gentle truth remain unseen; not everything needs an audience.',
            'A second chance is not a pause; it is a surrender.',
            'Let a careful choice remain unfinished; not everything needs a witness.',
            'A thoughtful pause can make room for the freedom to choose without surrendering what makes you yourself.',
            'You can carry what matters most without even when the answer takes time.',
            'You can reveal the truth beneath the noise without one careful step at a time.',
            'Sometimes a gentle truth is the beginning of a path through uncertainty.',
            'A second chance can carry the trust you built slowly even when the answer takes time.',
            'A second chance can reveal the truth beneath the noise without needing to be understood by everyone.',
            'You can restore the freedom to choose without when the right moment finally arrives.',
            'Let a quiet mind remain unseen; not everything needs a defense.',
            'You can carry the people who truly matter without without asking the world for permission.',
            'Sometimes a clear boundary is the beginning of a better tomorrow.',
            'Sometimes a trusted friend is the beginning of a better tomorrow.',
            'A steady heart can outlast the truth beneath the noise even when nobody notices.',
            'A careful choice can restore the people who truly matter even when the answer takes time.',
            'Sometimes a quiet mind is the beginning of the things words cannot explain.',
            'A closed door can become the courage to begin again without needing to be understood by everyone.',
            'Sometimes a brave question is the beginning of what matters most.',
            'You can make room for what matters most without one careful step at a time.',
            'Sometimes a calm answer is the beginning of the space to grow.',
            'A second chance can guide a life that feels like your own when the right moment finally arrives.',
            'A hidden hope can protect a path through uncertainty even when the answer takes time.',
            'A thoughtful pause can carry a life that feels like your own without surrendering what makes you yourself.',
            'An honest promise is not mystery; it is deception.',
            'Let a peaceful room remain private; not everything needs a deadline.',
            'A trusted friend is not a boundary; it is a rejection.',
            'You can soften the trust you built slowly without long after the noise has passed.',
            'A quiet courage is not forgiveness; it is forgetting.',
            'A gentle truth can carry the person you are becoming even when the answer takes time.',
            'Let a guarded heart remain unseen; not everything needs a label.',
            'You can protect a better tomorrow without one careful step at a time.',
            'Let a steady heart remain gentle; not everything needs an explanation.',
            'Let a private life remain quiet; not everything needs a deadline.',
            'A thoughtful pause can carry the truth beneath the noise when the right moment finally arrives.',
            'Let a quiet courage remain uncertain; not everything needs an audience.',
            'A trusted friend can guide the people who truly matter while leaving room for tomorrow.',
            'Let a peaceful room remain unfinished; not everything needs a deadline.',
            'Let a brave question remain unspoken; not everything needs a witness.',
            'A guarded heart is not privacy; it is distance.',
            'You can carry the truth beneath the noise without even when nobody notices.',
            'Sometimes a guarded heart is the beginning of a path through uncertainty.',
            'Sometimes a thoughtful pause is the beginning of the parts worth keeping.',
            'You can make room for the freedom to choose without without needing to be understood by everyone.',
            'An honest promise is not a boundary; it is a rejection.',
            'A closed door can soften the trust you built slowly when the right moment finally arrives.',
            'You can reveal what matters most without even when nobody notices.',
            'A guarded heart can outlast the trust you built slowly one careful step at a time.',
            'Sometimes a clear boundary is the beginning of a path through uncertainty.',
            'Sometimes a hidden hope is the beginning of the freedom to choose.',
            'Sometimes a gentle truth is the beginning of the peace you worked for.',
            'A small beginning can protect the courage to begin again when the right moment finally arrives.',
            'A thoughtful pause can carry the peace you worked for without asking the world for permission.',
            'A guarded heart is not mystery; it is deception.',
            'Sometimes a little distance is the beginning of the people who truly matter.',
            'Sometimes a guarded heart is the beginning of the parts worth keeping.',
            'Sometimes a gentle truth is the beginning of the truth beneath the noise.',
            'A patient soul can guide the truth beneath the noise without asking the world for permission.',
            'Sometimes an honest promise is the beginning of the person you are becoming.',
            'A private life is not quiet; it is absence.',
            'You can make room for the parts worth keeping without one careful step at a time.',
            'Sometimes a steady heart is the beginning of a life that feels like your own.',
            'A hidden hope can soften the freedom to choose without surrendering what makes you yourself.',
            'A calm answer can guide the courage to begin again even when the answer takes time.',
            'You can protect the space to grow without without asking the world for permission.',
            'A trusted friend can restore a better tomorrow while leaving room for tomorrow.',
            'Sometimes a guarded heart is the beginning of a better tomorrow.',
            'Sometimes a little distance is the beginning of a better tomorrow.',
            'A private life can outlast the parts worth keeping even when the answer takes time.',
            'A quiet courage can soften the things words cannot explain long after the noise has passed.',
            'Sometimes a second chance is the beginning of the parts worth keeping.',
            'A closed door can become the truth beneath the noise while leaving room for tomorrow.',
            'You can guide a life that feels like your own without long after the noise has passed.',
            'Let a brave question remain quiet; not everything needs an explanation.',
            'Let a closed door remain unfinished; not everything needs a deadline.',
            'A calm answer can guide the freedom to choose while leaving room for tomorrow.',
            'You can guide a path through uncertainty without even when the answer takes time.',
            'A guarded heart can soften the parts worth keeping one careful step at a time.',
            'Let a steady heart remain unseen; not everything needs a witness.',
            'A small beginning is not silence; it is emptiness.',
            'Sometimes a quiet mind is the beginning of what matters most.',
            'A quiet mind can guide the parts worth keeping without surrendering what makes you yourself.',
            'A clear boundary is not caution; it is fear.',
            'You can survive the person you are becoming without while leaving room for tomorrow.',
            'You can guide the things words cannot explain without while leaving room for tomorrow.',
            'A quiet courage can survive the trust you built slowly without becoming smaller for anyone.',
            'Let a calm answer remain unfinished; not everything needs an audience.',
            'You can reveal a better tomorrow without even when nobody notices.',
            'An honest promise can reveal a path through uncertainty long after the noise has passed.',
            'Let a trusted friend remain unseen; not everything needs a label.',
            'A calm answer is not patience; it is weakness.',
            'A calm answer can make room for the parts worth keeping without becoming smaller for anyone.',
            'Sometimes a small beginning is the beginning of the things words cannot explain.',
            'Let a little distance remain gentle; not everything needs a defense.',
            'Let a little distance remain private; not everything needs a witness.',
            'A closed door is not privacy; it is distance.',
            'A patient soul can become the parts worth keeping when the right moment finally arrives.',
            'You can survive the person you are becoming without one careful step at a time.',
            'A patient soul can survive a path through uncertainty long after the noise has passed.',
            'A guarded heart can outlast the parts worth keeping long after the noise has passed.',
            'You can outlast the truth beneath the noise without without surrendering what makes you yourself.',
            'A trusted friend is not silence; it is emptiness.',
            'Let a little distance remain private; not everything needs an audience.',
            'Sometimes a brave question is the beginning of the person you are becoming.',
            'A patient soul can carry the courage to begin again without asking the world for permission.',
            'Sometimes a small beginning is the beginning of the people who truly matter.',
            'Let a steady heart remain yours; not everything needs a witness.',
            'A guarded heart can guide the courage to begin again when the right moment finally arrives.',
            'Sometimes a hidden hope is the beginning of the things words cannot explain.',
            'Sometimes a private life is the beginning of the space to grow.',
            'A small beginning is not a boundary; it is a rejection.',
            'Let a gentle truth remain yours; not everything needs a deadline.',
            'Sometimes a trusted friend is the beginning of a path through uncertainty.',
            'Sometimes a steady heart is the beginning of the parts worth keeping.',
            'A patient soul can make room for what matters most without needing to be understood by everyone.',
            'A private life can make room for the person you are becoming while leaving room for tomorrow.',
            'You can make room for a future worth reaching without even when the answer takes time.',
            'You can survive the things words cannot explain without without asking the world for permission.',
            'Sometimes a second chance is the beginning of the person you are becoming.',
            'A peaceful room can guide the freedom to choose long after the noise has passed.',
            'A hidden hope is not a boundary; it is a rejection.',
            'An honest promise can restore the courage to begin again without becoming smaller for anyone.',
            'A careful choice can survive the trust you built slowly without needing to be understood by everyone.',
            'Sometimes a guarded heart is the beginning of the peace you worked for.',
            'You can protect the space to grow without even when nobody notices.',
            'A trusted friend can outlast a path through uncertainty when the right moment finally arrives.',
            'You can guide the courage to begin again without without needing to be understood by everyone.',
            'Sometimes a steady heart is the beginning of a future worth reaching.',
            'A clear boundary can carry a path through uncertainty while leaving room for tomorrow.',
            'A patient soul can outlast the peace you worked for without becoming smaller for anyone.',
            'A brave question is not a pause; it is a surrender.',
            'You can guide the peace you worked for without when the right moment finally arrives.',
            'A peaceful room is not privacy; it is distance.',
            'A trusted friend can become a life that feels like your own while leaving room for tomorrow.',
            'Let a trusted friend remain yours; not everything needs a label.',
            'A second chance is not solitude; it is loneliness.',
            'A quiet mind can reveal the space to grow even when nobody notices.',
            'Let a steady heart remain uncertain; not everything needs an audience.',
            'Let a brave question remain gentle; not everything needs a label.',
            'A quiet mind can make room for the space to grow without becoming smaller for anyone.',
            'A patient soul can protect the space to grow without surrendering what makes you yourself.',
            'You can become a path through uncertainty without without asking the world for permission.',
            'You can protect a path through uncertainty without even when nobody notices.',
            'Sometimes a hidden hope is the beginning of the parts worth keeping.',
            'A guarded heart can outlast the peace you worked for without needing to be understood by everyone.',
            'Let a trusted friend remain gentle; not everything needs a defense.',
            'A trusted friend can outlast a future worth reaching even when the answer takes time.',
            'A trusted friend can restore the person you are becoming while leaving room for tomorrow.',
            'A brave question can protect the things words cannot explain without needing to be understood by everyone.',
            'Let a gentle truth remain yours; not everything needs a label.',
            'You can guide the people who truly matter without without surrendering what makes you yourself.',
            'A hidden hope can guide the parts worth keeping without surrendering what makes you yourself.',
            'A small beginning can protect the things words cannot explain without surrendering what makes you yourself.',
            'A private life can soften a path through uncertainty when the right moment finally arrives.',
            'You can soften a life that feels like your own without without becoming smaller for anyone.',
            'A clear boundary can make room for the parts worth keeping without asking the world for permission.',
            'A small beginning can restore the space to grow without becoming smaller for anyone.',
            'Sometimes a quiet courage is the beginning of the truth beneath the noise.',
            'A small beginning can survive the courage to begin again while leaving room for tomorrow.',
            'You can outlast a life that feels like your own without even when nobody notices.',
            'A peaceful room can guide what matters most even when nobody notices.',
            'A brave question can reveal a life that feels like your own while leaving room for tomorrow.',
            'Let a quiet mind remain gentle; not everything needs a witness.',
            'A second chance can reveal a path through uncertainty without surrendering what makes you yourself.',
            'Let a second chance remain unfinished; not everything needs a label.',
            'Let an honest promise remain private; not everything needs a witness.',
            'A patient soul can become the person you are becoming when the right moment finally arrives.',
            'An honest promise is not quiet; it is absence.',
            'A second chance can outlast the peace you worked for even when nobody notices.',
            'Sometimes a second chance is the beginning of the peace you worked for.',
            'Sometimes an honest promise is the beginning of the truth beneath the noise.',
            'Let a peaceful room remain quiet; not everything needs an audience.',
            'You can guide the parts worth keeping without one careful step at a time.',
            'A second chance is not caution; it is fear.',
            'An honest promise can become the peace you worked for long after the noise has passed.',
            'A quiet courage can guide the peace you worked for one careful step at a time.',
            'You can outlast a path through uncertainty without when the right moment finally arrives.',
            'Let a quiet mind remain yours; not everything needs a witness.',
            'Let a second chance remain uncertain; not everything needs an explanation.',
            'A steady heart can soften the person you are becoming long after the noise has passed.',
            'Let a quiet courage remain private; not everything needs a defense.',
            'You can make room for the freedom to choose without long after the noise has passed.',
            'Let a guarded heart remain uncertain; not everything needs a witness.',
            'A careful choice is not silence; it is emptiness.',
            'Let a quiet mind remain uncertain; not everything needs an audience.',
            'A quiet courage can become a path through uncertainty without asking the world for permission.',
            'Let a careful choice remain yours; not everything needs a defense.',
            'Let a quiet mind remain uncertain; not everything needs a deadline.',
            'You can soften a future worth reaching without when the right moment finally arrives.',
            'A clear boundary is not forgiveness; it is forgetting.',
            'Let a second chance remain quiet; not everything needs an audience.',
            'Sometimes a peaceful room is the beginning of the things words cannot explain.',
            'A quiet courage is not silence; it is emptiness.',
            'A trusted friend can become the things words cannot explain without needing to be understood by everyone.',
            'Sometimes a hidden hope is the beginning of the trust you built slowly.',
            'Sometimes a quiet courage is the beginning of a better tomorrow.',
            'Let a little distance remain unfinished; not everything needs a defense.',
            'A brave question is not quiet; it is absence.',
            'Let a little distance remain gentle; not everything needs a witness.',
            'A trusted friend can protect the space to grow without needing to be understood by everyone.',
            'Let a thoughtful pause remain private; not everything needs an explanation.',
            'A careful choice can carry what matters most even when the answer takes time.',
            'A brave question can make room for the trust you built slowly while leaving room for tomorrow.',
            'Let a peaceful room remain yours; not everything needs a deadline.',
            'A hidden hope can survive a future worth reaching while leaving room for tomorrow.',
            'A brave question can restore the parts worth keeping long after the noise has passed.',
            'A calm answer can become the things words cannot explain when the right moment finally arrives.',
            'A private life can reveal the courage to begin again even when nobody notices.',
            'Sometimes a quiet mind is the beginning of a future worth reaching.',
            'Let a closed door remain unseen; not everything needs a witness.',
            'Let a clear boundary remain yours; not everything needs a label.',
            'Sometimes a small beginning is the beginning of the freedom to choose.',
            'A second chance can protect the trust you built slowly when the right moment finally arrives.',
            'A gentle truth is not silence; it is emptiness.',
            'You can soften a future worth reaching without long after the noise has passed.',
            'You can guide the peace you worked for without without surrendering what makes you yourself.',
            'A patient soul can become the courage to begin again without asking the world for permission.',
            'Let a calm answer remain unspoken; not everything needs a witness.',
            'Let a gentle truth remain gentle; not everything needs an audience.',
            'A hidden hope can make room for the space to grow without needing to be understood by everyone.',
            'A clear boundary can restore the people who truly matter without surrendering what makes you yourself.',
            'A trusted friend is not mystery; it is deception.',
            'A quiet courage can become the trust you built slowly without asking the world for permission.',
            'A patient soul can carry the freedom to choose without becoming smaller for anyone.',
            'A trusted friend can survive a better tomorrow even when nobody notices.',
            'A little distance is not a pause; it is a surrender.',
            'You can guide a future worth reaching without while leaving room for tomorrow.',
            'A small beginning can protect the space to grow without needing to be understood by everyone.',
            'Sometimes a guarded heart is the beginning of a future worth reaching.',
            'A gentle truth is not caution; it is fear.',
            'Sometimes a gentle truth is the beginning of the person you are becoming.',
            'Sometimes a patient soul is the beginning of the peace you worked for.',
            'You can guide the freedom to choose without while leaving room for tomorrow.',
            'Sometimes a quiet mind is the beginning of the people who truly matter.',
            'Sometimes a careful choice is the beginning of the space to grow.',
            'A private life can survive the trust you built slowly without needing to be understood by everyone.',
            'You can guide the things words cannot explain without when the right moment finally arrives.',
            'A guarded heart can survive a life that feels like your own without needing to be understood by everyone.',
            'You can restore a better tomorrow without even when nobody notices.',
            'A steady heart can become the freedom to choose even when the answer takes time.',
            'You can soften the peace you worked for without long after the noise has passed.',
            'Sometimes a patient soul is the beginning of a path through uncertainty.',
            'An honest promise can guide what matters most one careful step at a time.',
            'Sometimes a patient soul is the beginning of the trust you built slowly.',
            'Sometimes a clear boundary is the beginning of the space to grow.',
            'A steady heart can make room for the freedom to choose without needing to be understood by everyone.',
            'Let a gentle truth remain unspoken; not everything needs a label.',
            'A little distance can outlast a future worth reaching without becoming smaller for anyone.',
            'A brave question can carry the things words cannot explain without becoming smaller for anyone.',
            'A calm answer can restore the space to grow without surrendering what makes you yourself.',
            'You can survive the peace you worked for without while leaving room for tomorrow.',
            'A hidden hope can survive the trust you built slowly while leaving room for tomorrow.',
            'A careful choice is not patience; it is weakness.',
            'A private life can make room for the people who truly matter without needing to be understood by everyone.',
            'You can survive what matters most without long after the noise has passed.',
            'A careful choice is not mystery; it is deception.',
            'A little distance can outlast a better tomorrow without needing to be understood by everyone.',
            'A guarded heart can outlast the truth beneath the noise long after the noise has passed.',
            'Let a careful choice remain yours; not everything needs a label.',
            'Let a thoughtful pause remain unfinished; not everything needs an explanation.',
            'A guarded heart is not a pause; it is a surrender.',
            'Sometimes a brave question is the beginning of the parts worth keeping.',
            'A calm answer can outlast the space to grow while leaving room for tomorrow.',
            'You can guide the space to grow without without becoming smaller for anyone.',
            'A hidden hope is not silence; it is emptiness.',
            'A clear boundary is not silence; it is emptiness.',
            'A gentle truth is not a pause; it is a surrender.',
            'A guarded heart can protect the parts worth keeping even when nobody notices.',
            'A thoughtful pause can reveal a path through uncertainty even when the answer takes time.',
            'A closed door can carry the people who truly matter even when the answer takes time.',
            'Let a guarded heart remain unfinished; not everything needs a label.',
            'You can make room for the things words cannot explain without long after the noise has passed.',
            'A gentle truth can become the person you are becoming without surrendering what makes you yourself.',
            'A trusted friend can outlast a path through uncertainty even when the answer takes time.',
            'Sometimes a second chance is the beginning of a future worth reaching.',
            'A thoughtful pause can survive a future worth reaching without becoming smaller for anyone.',
            'A guarded heart can carry a life that feels like your own even when nobody notices.',
            'A trusted friend can become the parts worth keeping without needing to be understood by everyone.',
            'A quiet courage can make room for the person you are becoming even when nobody notices.',
            'You can soften the parts worth keeping without without surrendering what makes you yourself.',
            'A patient soul is not mystery; it is deception.',
            'A brave question can reveal the people who truly matter even when nobody notices.',
            'A clear boundary can reveal the courage to begin again when the right moment finally arrives.',
            'You can restore the trust you built slowly without without becoming smaller for anyone.',
            'A steady heart can restore the peace you worked for even when the answer takes time.',
            'A patient soul is not patience; it is weakness.',
            'A calm answer can guide the person you are becoming even when nobody notices.',
            'A patient soul can soften the space to grow without becoming smaller for anyone.',
            'A gentle truth can restore what matters most without asking the world for permission.',
            'You can soften the trust you built slowly without without surrendering what makes you yourself.',
            'Let a quiet mind remain unfinished; not everything needs a defense.',
            'A careful choice can soften a better tomorrow without surrendering what makes you yourself.',
            'A gentle truth can soften a path through uncertainty one careful step at a time.',
            'You can outlast the trust you built slowly without without surrendering what makes you yourself.',
            'Let a guarded heart remain quiet; not everything needs a deadline.',
            'Sometimes a careful choice is the beginning of what matters most.',
            'A patient soul can become the person you are becoming one careful step at a time.',
            'An honest promise can outlast the courage to begin again without becoming smaller for anyone.',
            'An honest promise can outlast a future worth reaching even when the answer takes time.',
            'A small beginning can make room for the freedom to choose while leaving room for tomorrow.',
            'A little distance is not forgiveness; it is forgetting.',
            'Sometimes a closed door is the beginning of the parts worth keeping.',
            'You can outlast the things words cannot explain without without needing to be understood by everyone.',
            'A gentle truth can become the courage to begin again even when the answer takes time.',
            'You can make room for the people who truly matter without when the right moment finally arrives.',
            'Sometimes a thoughtful pause is the beginning of what matters most.',
            'Let a quiet courage remain quiet; not everything needs an audience.',
            'Let a little distance remain uncertain; not everything needs an explanation.',
            'A private life is not solitude; it is loneliness.',
            'Sometimes a closed door is the beginning of the people who truly matter.',
            'You can soften a path through uncertainty without one careful step at a time.',
            'A guarded heart can outlast the person you are becoming without becoming smaller for anyone.',
            'A quiet courage is not caution; it is fear.',
            'A quiet mind can protect the peace you worked for without becoming smaller for anyone.',
            'You can outlast what matters most without long after the noise has passed.',
            'A second chance is not patience; it is weakness.',
            'A private life is not mystery; it is deception.',
            'A trusted friend can make room for the space to grow without asking the world for permission.',
            'A calm answer is not mystery; it is deception.',
            'Let a gentle truth remain unseen; not everything needs a deadline.',
            'Sometimes a quiet mind is the beginning of the courage to begin again.',
            'Sometimes a hidden hope is the beginning of what matters most.',
            'A small beginning can make room for a future worth reaching without surrendering what makes you yourself.',
            'A steady heart is not a boundary; it is a rejection.',
            'A quiet mind is not silence; it is emptiness.',
            'A little distance can reveal the peace you worked for even when nobody notices.',
            'A thoughtful pause can carry a better tomorrow without becoming smaller for anyone.',
            'Let a closed door remain unfinished; not everything needs an explanation.',
            'A patient soul can become the trust you built slowly while leaving room for tomorrow.',
            'Let a quiet courage remain uncertain; not everything needs a defense.',
            'Sometimes a little distance is the beginning of a path through uncertainty.',
            'A private life can carry the space to grow without surrendering what makes you yourself.',
            'Let a hidden hope remain private; not everything needs an explanation.',
            'Let a trusted friend remain uncertain; not everything needs an explanation.',
            'An honest promise can soften what matters most when the right moment finally arrives.',
            'A peaceful room can protect the freedom to choose one careful step at a time.',
            'You can outlast the courage to begin again without without becoming smaller for anyone.',
            'A small beginning is not solitude; it is loneliness.',
            'Sometimes a clear boundary is the beginning of the truth beneath the noise.',
            'Sometimes a second chance is the beginning of the people who truly matter.',
            'A peaceful room is not caution; it is fear.',
            'Sometimes a small beginning is the beginning of the truth beneath the noise.',
            'An honest promise can carry the freedom to choose one careful step at a time.',
            'Sometimes a quiet mind is the beginning of the person you are becoming.',
            'Sometimes a careful choice is the beginning of a future worth reaching.',
            'A gentle truth can outlast the peace you worked for while leaving room for tomorrow.',
            'A brave question can reveal what matters most when the right moment finally arrives.',
            'A steady heart can soften a future worth reaching without asking the world for permission.',
            'A quiet courage is not patience; it is weakness.',
            'You can make room for the space to grow without while leaving room for tomorrow.',
            'Let a patient soul remain gentle; not everything needs a defense.',
            'Let a second chance remain unseen; not everything needs a defense.',
            'Let a thoughtful pause remain unspoken; not everything needs a witness.',
            'Let a small beginning remain yours; not everything needs a deadline.',
            'A gentle truth can make room for the trust you built slowly even when the answer takes time.',
            'Let a private life remain unspoken; not everything needs an explanation.',
            'A clear boundary can protect a better tomorrow long after the noise has passed.',
            'Let a careful choice remain unseen; not everything needs a witness.',
            'A steady heart is not silence; it is emptiness.',
            'You can guide the things words cannot explain without even when nobody notices.',
            'A thoughtful pause is not silence; it is emptiness.',
            'A quiet courage can soften the person you are becoming when the right moment finally arrives.',
            'You can survive a life that feels like your own without while leaving room for tomorrow.',
            'A peaceful room can become the truth beneath the noise one careful step at a time.',
            'A guarded heart can make room for the people who truly matter without surrendering what makes you yourself.',
            'Sometimes a quiet mind is the beginning of the space to grow.',
            'A steady heart is not mystery; it is deception.',
            'A peaceful room is not mystery; it is deception.',
            'A hidden hope is not privacy; it is distance.',
            'A careful choice can restore the freedom to choose without surrendering what makes you yourself.',
            'Sometimes a clear boundary is the beginning of what matters most.',
            'A guarded heart can survive the freedom to choose without asking the world for permission.',
            'Sometimes a private life is the beginning of the people who truly matter.',
            'A trusted friend can survive a life that feels like your own even when the answer takes time.',
            'You can soften the people who truly matter without while leaving room for tomorrow.',
            'A steady heart can make room for a future worth reaching when the right moment finally arrives.',
            'A quiet mind can outlast the truth beneath the noise without needing to be understood by everyone.',
            'A little distance can make room for a path through uncertainty without needing to be understood by everyone.',
            'A closed door can protect a future worth reaching when the right moment finally arrives.',
            'A calm answer can survive the freedom to choose when the right moment finally arrives.',
            'A guarded heart is not silence; it is emptiness.',
            'Sometimes a quiet courage is the beginning of the trust you built slowly.',
            'A small beginning can make room for the freedom to choose when the right moment finally arrives.',
            'Sometimes a peaceful room is the beginning of the freedom to choose.',
            'You can soften the space to grow without when the right moment finally arrives.',
            'You can carry the space to grow without long after the noise has passed.',
            'Sometimes a gentle truth is the beginning of the freedom to choose.',
            'A calm answer can survive a path through uncertainty even when nobody notices.',
            'Let a gentle truth remain quiet; not everything needs an audience.',
            'Let a trusted friend remain yours; not everything needs an audience.',
            'A patient soul can survive a better tomorrow even when nobody notices.',
            'You can survive the truth beneath the noise without one careful step at a time.',
            'Let a thoughtful pause remain private; not everything needs an audience.',
            'A patient soul can reveal a future worth reaching long after the noise has passed.',
            'You can guide the freedom to choose without even when the answer takes time.',
            'You can make room for the trust you built slowly without without surrendering what makes you yourself.',
            'You can carry the person you are becoming without even when the answer takes time.',
            'A closed door can protect the people who truly matter while leaving room for tomorrow.',
            'A clear boundary can survive the people who truly matter even when nobody notices.',
            'A steady heart is not quiet; it is absence.',
            'Let an honest promise remain uncertain; not everything needs a defense.',
            'A patient soul is not silence; it is emptiness.',
            'A careful choice can protect the freedom to choose long after the noise has passed.',
            'Sometimes a trusted friend is the beginning of the courage to begin again.',
            'Let a clear boundary remain unfinished; not everything needs a deadline.',
            'A peaceful room can outlast a life that feels like your own while leaving room for tomorrow.',
            'You can make room for the peace you worked for without long after the noise has passed.',
            'You can reveal the trust you built slowly without without asking the world for permission.',
            'You can restore a path through uncertainty without even when the answer takes time.',
            'Let a brave question remain unfinished; not everything needs an audience.',
            'Sometimes a little distance is the beginning of the peace you worked for.',
            'You can outlast the person you are becoming without while leaving room for tomorrow.',
            'A quiet mind is not a pause; it is a surrender.',
            'A closed door can make room for the person you are becoming without needing to be understood by everyone.',
            'A second chance can make room for a better tomorrow without asking the world for permission.',
            'A little distance is not silence; it is emptiness.',
            'A private life is not patience; it is weakness.',
            'Sometimes a private life is the beginning of the trust you built slowly.',
            'You can reveal what matters most without when the right moment finally arrives.',
            'You can survive the truth beneath the noise without without surrendering what makes you yourself.',
            'A clear boundary can guide the freedom to choose without surrendering what makes you yourself.',
            'A trusted friend can carry what matters most even when nobody notices.',
            'A private life can make room for a life that feels like your own without surrendering what makes you yourself.',
            'Sometimes a thoughtful pause is the beginning of the space to grow.',
            'A small beginning can restore a better tomorrow without becoming smaller for anyone.',
            'You can protect the people who truly matter without without becoming smaller for anyone.',
            'A hidden hope can reveal a life that feels like your own even when nobody notices.',
            'You can survive the space to grow without without becoming smaller for anyone.',
            'You can restore the things words cannot explain without without needing to be understood by everyone.',
            'You can reveal the courage to begin again without without surrendering what makes you yourself.',
            'Sometimes a closed door is the beginning of what matters most.',
            'A trusted friend can soften a life that feels like your own long after the noise has passed.',
            'A brave question can survive the courage to begin again even when nobody notices.',
            'Let a hidden hope remain gentle; not everything needs a label.',
            'You can survive the parts worth keeping without even when nobody notices.',
            'You can survive the trust you built slowly without one careful step at a time.',
            'A peaceful room can outlast a path through uncertainty one careful step at a time.',
            'A careful choice is not caution; it is fear.',
            'You can restore a path through uncertainty without even when nobody notices.',
            'Let a quiet courage remain unseen; not everything needs an audience.',
            'A guarded heart can outlast the truth beneath the noise without asking the world for permission.',
            'Sometimes a patient soul is the beginning of the truth beneath the noise.',
            'A private life is not forgiveness; it is forgetting.',
            'A peaceful room can soften the parts worth keeping without needing to be understood by everyone.',
            'Let a private life remain uncertain; not everything needs a deadline.',
            'A steady heart is not privacy; it is distance.',
            'A calm answer can reveal the freedom to choose without asking the world for permission.',
            'You can outlast the peace you worked for without without needing to be understood by everyone.',
            'A careful choice can survive the freedom to choose even when the answer takes time.',
            'Let a quiet courage remain uncertain; not everything needs a label.',
            'A steady heart is not a pause; it is a surrender.',
            'You can become the things words cannot explain without long after the noise has passed.',
            'Sometimes a private life is the beginning of the courage to begin again.',
            'A steady heart is not solitude; it is loneliness.',
            'Let a trusted friend remain yours; not everything needs an explanation.',
            'Sometimes a peaceful room is the beginning of the parts worth keeping.',
            'You can carry the parts worth keeping without one careful step at a time.',
            'A little distance can restore the courage to begin again one careful step at a time.',
            'Let a hidden hope remain unfinished; not everything needs a witness.',
            'Sometimes a little distance is the beginning of a future worth reaching.',
            'A guarded heart can carry what matters most long after the noise has passed.',
            'A patient soul is not forgiveness; it is forgetting.',
            'A small beginning can carry a life that feels like your own without needing to be understood by everyone.',
            'A closed door can outlast a path through uncertainty without asking the world for permission.',
            'Sometimes a gentle truth is the beginning of the trust you built slowly.',
            'Sometimes a trusted friend is the beginning of the truth beneath the noise.',
            'Let a little distance remain unfinished; not everything needs an explanation.',
            'A brave question can guide a life that feels like your own even when nobody notices.',
            'A brave question is not silence; it is emptiness.',
            'Sometimes a peaceful room is the beginning of the truth beneath the noise.',
            'Sometimes a guarded heart is the beginning of the trust you built slowly.',
            'You can restore the space to grow without without asking the world for permission.',
            'Sometimes a steady heart is the beginning of what matters most.',
            'A private life can soften a future worth reaching one careful step at a time.',
            'A hidden hope can become a path through uncertainty without surrendering what makes you yourself.',
            'A steady heart can reveal the person you are becoming long after the noise has passed.',
            'Let a patient soul remain unfinished; not everything needs a deadline.',
            'Sometimes a quiet mind is the beginning of the truth beneath the noise.',
            'Let a steady heart remain yours; not everything needs an audience.',
            'Sometimes an honest promise is the beginning of the courage to begin again.',
            'A closed door can make room for the parts worth keeping even when nobody notices.',
            'Sometimes a thoughtful pause is the beginning of a future worth reaching.',
            'Sometimes a careful choice is the beginning of the truth beneath the noise.',
            'A patient soul can survive the people who truly matter even when nobody notices.',
            'Sometimes a little distance is the beginning of the freedom to choose.',
            'Sometimes a quiet courage is the beginning of what matters most.',
            'Sometimes a guarded heart is the beginning of the freedom to choose.',
            'A calm answer is not privacy; it is distance.',
            'Let a little distance remain uncertain; not everything needs a defense.',
            'An honest promise is not caution; it is fear.',
            'You can soften what matters most without without becoming smaller for anyone.',
            'You can soften what matters most without when the right moment finally arrives.',
            'Let a peaceful room remain yours; not everything needs a defense.',
            'You can restore the space to grow without without surrendering what makes you yourself.',
            'A small beginning is not mystery; it is deception.',
            'A peaceful room can guide the space to grow without becoming smaller for anyone.',
            'Sometimes a patient soul is the beginning of the freedom to choose.',
            'Let a thoughtful pause remain unfinished; not everything needs a deadline.',
            'An honest promise can reveal a better tomorrow while leaving room for tomorrow.',
            'A closed door can soften the person you are becoming one careful step at a time.',
            'You can restore a better tomorrow without while leaving room for tomorrow.',
            'Let a brave question remain quiet; not everything needs a label.',
            'A calm answer is not caution; it is fear.',
            'You can become the person you are becoming without without surrendering what makes you yourself.',
            'A calm answer can make room for a future worth reaching even when the answer takes time.',
            'A trusted friend can reveal the person you are becoming even when the answer takes time.',
            'Let a trusted friend remain private; not everything needs a deadline.',
            'A quiet mind can reveal the trust you built slowly even when the answer takes time.',
            'A peaceful room is not a boundary; it is a rejection.',
            'A brave question can become the parts worth keeping while leaving room for tomorrow.',
        )
        d = QDialog(self); d.setWindowTitle("A note from the quiet door")
        screen = self.screen(); area = screen.availableGeometry() if screen is not None else QRect(0, 0, 900, 700)
        d.setMinimumWidth(min(430, max(300, area.width() - 24))); d.resize(min(560, max(300, area.width() - 24)), min(260, max(200, area.height() - 48)))
        layout = QVBoxLayout(d); frame = QFrame(); frame.setObjectName("term"); inside = QVBoxLayout(frame)
        inside.addWidget(tlbl("root@unknwn:~$ fortune --quiet", 12, ACC))
        inside.addWidget(lbl(random.SystemRandom().choice(quotes), 16, "#e8e1d3", center=True))
        close = btn("Close"); close.clicked.connect(d.accept); layout.addWidget(frame); layout.addWidget(close); d.exec_()
    def shake(self, amp: int = 12, loops: int = 1) -> None:
        a = QPropertyAnimation(self, b"pos"); p = self.pos(); a.setDuration(420 * loops); n = 5 * loops
        for i in range(n + 1): a.setKeyValueAt(i / n, p if i in (0, n) else p + QPoint(amp * (-1) ** i, 0))
        self._sh = a; a.start()
    def combo(self, items: Iterable[tuple[str, object]]) -> QComboBox:
        c = QComboBox()
        for t, v in items: c.addItem(t, v)
        return c
    def pop(self, w: QWidget, d: int = 0) -> None:
        """Fade a widget in after d ms."""
        if S("reduce_motion"):
            w.setGraphicsEffect(None)
            return
        e = QGraphicsOpacityEffect(w); e.setOpacity(0); w.setGraphicsEffect(e)
        def go() -> None:
            try:
                if S("reduce_motion"):
                    w.setGraphicsEffect(None)
                    return
                a = QPropertyAnimation(e, b"opacity", w); a.setDuration(450); a.setStartValue(0.0); a.setEndValue(1.0); a.setEasingCurve(QEasingCurve.Type.OutCubic)
                a.finished.connect(lambda: w.setGraphicsEffect(None)); a.start(); w._pa = a
            except RuntimeError: pass
        QTimer.singleShot(d, go)
    def put(self, k: str, v: Any) -> None:
        if k in PROTKEYS and lock_on() and not self.owner and self.mode == "vault": return
        if k == "title" and not isinstance(v, str):
            QMessageBox.warning(self, "Invalid setting", "The window title must be text.")
            return
        if k == "nocap" and type(v) is not bool:
            QMessageBox.warning(self, "Invalid setting", "The clipboard protection setting must be enabled or disabled.")
            return
        if k == "winop":
            if type(v) not in (int, float) or not math.isfinite(float(v)):
                QMessageBox.warning(self, "Invalid setting", "Window opacity must be a finite number.")
                return
        candidate = copy.deepcopy(cfg)
        settings_value = candidate.setdefault("set", {})
        if not isinstance(settings_value, dict):
            QMessageBox.warning(self, "Settings unavailable",
                                "The settings section is damaged; no change was saved.")
            return
        settings = cast(dict[str, Any], settings_value)
        previous = settings.get(k, DEF.get(k)); changed = previous != v
        settings[k] = v
        advice = advise_settings(settings)
        if not advice.valid:
            can_confirm_ghost_requirements = (
                k == "ghost" and v is True
                and all(issue.setting == "ghost" and issue.required_changes
                        for issue in advice.issues)
            )
            if can_confirm_ghost_requirements:
                requirements = advice.required_changes
                required_text = "\n".join(
                    f"  • {setting} = {value!r}" for setting, value in requirements)
                answer = QMessageBox.question(
                    self, "Ghost mode requirements",
                    "Ghost mode requires these dependent settings:\n"
                    f"{required_text}\n\nApply all changes together?",
                    cast(
                        QMessageBox.StandardButtons,
                        QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No),
                    QMessageBox.StandardButton.No)
                if answer != QMessageBox.StandardButton.Yes:
                    return
                for setting, required_value in requirements:
                    settings[setting] = required_value
            else:
                reasons = "\n".join(f"• {issue.message}" for issue in advice.issues)
                QMessageBox.warning(
                    self, "Settings conflict",
                    f"The requested setting conflicts with required settings:\n{reasons}\n\n"
                    "No configuration changes were applied.")
                return
        changed_settings = [
            (key, copy.deepcopy(cfg.get("set", {}).get(key, DEF.get(key))),
             copy.deepcopy(value))
            for key, value in settings.items()
            if cfg.get("set", {}).get(key, DEF.get(key)) != value
        ]
        root = self.root
        if root is not None and k in SECKEYS:
            protected_settings = {key: settings.get(key, DEF[key]) for key in sorted(SECKEYS)}
            candidate["sc"] = IG.snap_make(root, protected_settings)
        if k == "bind" and v:
            candidate["fp"] = fp()
        try:
            commit_config_transaction(candidate)
        except (OSError, TypeError, ValueError) as exc:
            settings_panel = vars(self).get("sp")
            if isinstance(settings_panel, QScrollArea):
                settings_panel.setWidget(self.build_settings())
            QMessageBox.warning(
                self, "Settings not applied",
                f"UNKNWN could not confirm the configuration update ({type(exc).__name__}). "
                "The live setting was not changed; check available storage and try again.")
            return
        state = vars(self)
        if changed_settings and not state.get("_settings_history_replay", False):
            changes = [change for change in changed_settings if change[0] in UNDOABLE_SETTINGS]
            history_group = state.get("_settings_history_group")
            if changes and history_group is not None:
                history_group.extend(changes)
            elif changes:
                self.push_settings_history(changes)
        for setting, before, after in changed_settings:
            self.record_session_event("setting_changed", key=setting, before=before, after=after)
        if k == "nocap": nocap(self, cast(bool, v))
        if k == "tstyle":
            application_value = QApplication.instance()
            if application_value is not None:
                cast(QApplication, application_value).setStyleSheet(qss())
        if k == "title":
            self.setWindowTitle(cast(str, v))
        if k in ("bg", "perf", "reduce_motion", "bgfocus"):
            for widget in QApplication.allWidgets():
                if isinstance(widget, Stage):
                    Stage.reset_background(widget)
            if k == "reduce_motion":
                for widget in self.findChildren(Btn):
                    widget.reset_animation()
        if k == "ghost": self.ghost_apply()
        if k == "winop": self.setWindowOpacity(float(v) / 100)
        if k == "hk_glob":
            error = self.apply_hk()
            if changed and error:
                rollback = copy.deepcopy(cfg)
                rollback_settings = cast(dict[str, Any], rollback.setdefault("set", {}))
                rollback_settings[k] = previous
                if root is not None and k in SECKEYS:
                    protected_settings = {
                        key: rollback_settings.get(key, DEF[key]) for key in sorted(SECKEYS)}
                    rollback["sc"] = IG.snap_make(root, protected_settings)
                try:
                    commit_config_transaction(rollback)
                except (OSError, TypeError, ValueError) as exc:
                    QMessageBox.warning(
                        self, "Shortcut rollback needs attention",
                        f"Windows could not register the requested shortcut, and UNKNWN could not "
                        f"confirm restoring its previous setting ({type(exc).__name__}). "
                        "Review the shortcut and configuration before relying on it.")
                    return
                self.apply_hk()
                QMessageBox.warning(self, "Global shortcut unavailable", error)
        if k in ("hk", "hk_glob"): self.refresh_shortcut_status()
    def push_settings_history(self, changes: list[tuple[str, object, object]]) -> None:
        if not changes: return
        state = vars(self)
        if "settings_undo_stack" not in state: self.settings_undo_stack = []
        if "settings_redo_stack" not in state: self.settings_redo_stack = []
        self.settings_undo_stack.append(changes)
        if len(self.settings_undo_stack) > SETTINGS_HISTORY_LIMIT:
            del self.settings_undo_stack[:-SETTINGS_HISTORY_LIMIT]
        self.settings_redo_stack.clear()
        self.refresh_settings_history_controls()
    def refresh_settings_history_controls(self) -> None:
        state = vars(self)
        undo_button = state.get("settings_undo_button")
        redo_button = state.get("settings_redo_button")
        if undo_button is not None: undo_button.setEnabled(bool(self.settings_undo_stack) and not self.ro)
        if redo_button is not None: redo_button.setEnabled(bool(self.settings_redo_stack) and not self.ro)
    def replay_settings_history(self, undo: bool) -> Optional[int]:
        if self.ro:
            return
        source = self.settings_undo_stack if undo else self.settings_redo_stack
        destination = self.settings_redo_stack if undo else self.settings_undo_stack
        if not source:
            return
        changes = source[-1]
        ordered = list(reversed(changes)) if undo else changes
        for key, before, after in ordered:
            expected = after if undo else before
            if S(key) != expected:
                return QMessageBox.warning(
                    self, "Settings history is stale",
                    "A setting changed outside this session history. The undo/redo was not applied.")
        self._settings_history_replay = True
        try:
            for key, before, after in ordered:
                value = before if undo else after
                if key == "th": self.set_th(str(value))
                else: self.put(key, copy.deepcopy(value))
        finally:
            self._settings_history_replay = False
        source.pop()
        destination.append(changes)
        self.refresh_settings_history_controls()
        if getattr(self, "sp", None) is not None:
            cast(Any, self.sp).setWidget(self.build_settings())
    def undo_setting(self) -> None:
        self.replay_settings_history(True)
    def redo_setting(self) -> None:
        self.replay_settings_history(False)
    def reset_settings(self) -> Optional[int]:
        if self.ro:
            return
        if lock_on() and not self.owner and self.mode == "vault":
            return QMessageBox.warning(
                self, "Settings password",
                "Unlock protected settings before resetting preferences.")
        if not terminal_confirm(
                self, "Reset settings to defaults", "settings --reset",
                ["Restore every recognized UNKNWN setting to its built-in default.",
                 "This includes security policy, privacy, playback, appearance, and the panic shortcut; changes apply immediately.",
                 "Vault contents, profiles, credentials, and stored files are not deleted."],
                acknowledge=True):
            return
        changes: list[tuple[str, object, object]] = []
        self._settings_history_group = changes
        try:
            for key, value in DEF.items():
                 if key != "th":
                     self.put(key, value)
            self.set_th(str(DEF["th"]))
        finally:
            self._settings_history_group = None
            self.push_settings_history(changes)
        self.apply_hk()
        QMessageBox.information(
            self, "Settings reset",
            "Recognized settings have been restored to their built-in defaults.")

    # ---------- hotkey ----------
    def apply_hk(self) -> Optional[str]:
        for q in self.scs: q.setEnabled(False); q.deleteLater()
        self.scs = []; hk = str(S("hk"))
        for q in [hk] + ([hk.replace("Tab", "Backtab")] if "Shift" in hk and "Tab" in hk else []):
            c = QShortcut(QKeySequence(q), self); c.setContext(Qt.ShortcutContext.ApplicationShortcut); c.activated.connect(self.hotkey); self.scs.append(c)
        error = None
        if sys.platform == "win32":
            import ctypes
            try:
                u = ctypes.windll.user32
            except AttributeError:
                error = "Windows global shortcuts are unavailable in this runtime."
            else:
                try:
                    u.UnregisterHotKey(None, 1)
                    if self.hkf is None:
                        self.hkf = HK(lambda: QTimer.singleShot(0, self.hotkey))
                        application = QApplication.instance()
                        if application is None: raise RuntimeError("The Qt application is unavailable")
                        application.installNativeEventFilter(self.hkf)
                    ks = QKeySequence(hk)
                    if S("hk_glob") and not ks.isEmpty():
                        c = ks[0]; m = c & 0xFE000000; key = vk(c & 0x01FFFFFF)
                        mod = (2 if m & int(Qt.KeyboardModifier.ControlModifier) else 0) | (4 if m & int(Qt.KeyboardModifier.ShiftModifier) else 0) | (1 if m & int(Qt.KeyboardModifier.AltModifier) else 0) | (8 if m & int(Qt.KeyboardModifier.MetaModifier) else 0)
                        if not key or not mod:
                            error = "Windows cannot register this key as a global shortcut. Choose a supported key with Ctrl, Alt, or Windows."
                        elif not u.RegisterHotKey(None, 1, mod | 0x4000, key):
                            error = "Windows rejected the global shortcut because it is unsupported or already in use by another application."
                except OSError as exc:
                    error = f"Windows could not update the global shortcut ({exc})."
        elif S("hk_glob"):
            error = "Global shortcut capture is supported only on Windows."
        self.shortcut_status = error
        self.refresh_shortcut_status()
        if error:
            log_security_event("global_shortcut_registration_failed", detail=error)
        return error
    def shortcut_problem(self, sequence: QKeySequence) -> Optional[str]:
        if sequence.isEmpty(): return "Choose a non-empty shortcut."
        if sequence.count() != 1: return "Use exactly one key combination; multi-step shortcuts are not supported."
        portable_text_format: Any = getattr(QKeySequence, "PortableText")
        text = sequence.toString(portable_text_format)
        if not text.startswith(("Ctrl+", "Alt+", "Meta+")):
            return "Use Ctrl, Alt, or Windows together with a key so ordinary typing remains unaffected."
        if text in RESERVED_SHORTCUTS:
            return "That shortcut is reserved for a system or common editing action."
        for shortcut in self.findChildren(QShortcut):
            if shortcut in self.scs: continue
            if shortcut.key() == sequence:
                return f"That shortcut is already used inside UNKNWN ({text})."
        return None
    def refresh_shortcut_status(self) -> None:
        label = getattr(self, "shortcut_status_label", None)
        if label is None: return
        if self.shortcut_status:
            label.setText(f"Global capture unavailable: {self.shortcut_status}")
        elif S("hk_glob"):
            label.setText(f"Active globally on Windows: {S('hk')}")
        else:
            label.setText(f"Active only while UNKNWN is focused: {S('hk')}")
    def hotkey(self) -> None:
        if self.busy or self.mode == "blocked" or INTEG[0] == "fail": return
        a = S("hk_act")
        if a == "lock":
            if self.mode == "vault": self.lock()
        elif a == "wipe":
            if S("hk_notice"):
                QMessageBox.information(
                    self, "Panic shortcut",
                    "The configured shortcut is starting the vault-data wipe. "
                    "This notice does not cancel or confirm the action.")
            self.panic(False)
        else:
            if S("hk_notice"):
                QMessageBox.information(
                    self, "Panic shortcut",
                    "The configured shortcut is starting Full Self-Destruct. "
                    "Its normal validation and confirmation steps still apply.")
            self.destruct(True)

    # ---------- screens ----------
    def damaged_screen(self) -> None:
        b = btn("Quit"); b.clicked.connect(lambda: _close_widget(self)); nb = btn("Erase everything and start a NEW vault...", "flat"); nb.clicked.connect(self.fresh_start)
        self.show_w(self.panel(tlbl("UNKNWN :: ERROR", 22, "#ff6b61"), tlbl(support_message(f"config.json is missing or damaged and no usable backup (config.json.bak) was found.\n\nYour sealed files were NOT touched. Restore config.json or config.json.bak into:\n{HOME}\n\nCreating a new vault is blocked so your old files are not lost."), 12), b, nb, w=560), "damaged")
    def storage_recovery_screen(self, error: Exception) -> None:
        msg = lbl(support_message(f"UNKNWN stopped because an interrupted storage transaction could not be verified ({type(error).__name__}). No new vault changes will be made. Keep this data folder intact and retry recovery or quit."), 12)
        retry = btn("Retry recovery", "go"); retry.clicked.connect(lambda: self.retry_storage_recovery(msg, retry))
        quit_button = btn("Quit"); quit_button.clicked.connect(lambda: _close_widget(self))
        self.show_w(self.panel(self.logo(), tlbl("UNKNWN :: STORAGE RECOVERY", 20, "#ffb347"), msg, retry, quit_button, w=560), "recovery-error")
    def destructive_recovery_screen(self, error: Exception) -> None:
        msg = lbl(support_message(
            f"An authorized UNKNWN cleanup is incomplete or could not be verified ({type(error).__name__}). "
            "UNKNWN is blocked until cleanup completes; no vault or profile will be opened."), 12)
        retry = btn("Resume authorized cleanup", "danger")
        retry.clicked.connect(self.recover_destructive_cleanup)
        quit_button = btn("Quit"); quit_button.clicked.connect(lambda: _close_widget(self))
        self.show_w(self.panel(self.logo(), tlbl("UNKNWN :: CLEANUP RECOVERY", 20, "#ff6b61"),
                         msg, retry, quit_button, w=560), "destructive-recovery")
    def recover_destructive_cleanup(self) -> None:
        try:
            record = read_destruct_journal()
            if record is None:
                raise FileNotFoundError("There is no authorized UNKNWN cleanup operation to resume.")
            if (sys.platform == "win32" and record["operation"] == "self-destruct"
                    and record["install_target"] is not None
                    and Path(record["install_target"]).exists()):
                try:
                    destruct_runonce_command(0)
                except (FileNotFoundError, ValueError):
                    register_destruct_runonce(
                        record["install_target"], None, destruct_journal_path())
            record = resume_destructive_cleanup(HOME, S("shred"))
        except Exception as exc:
            return self.destructive_recovery_screen(exc)
        return self.finalize_destructive_cleanup(record)
    def retry_storage_recovery(self, msg: QLabel, button: QPushButton) -> None:
        button.setEnabled(False)
        try:
            rotate_commit()
            global STARTUP_RECOVERY_ERROR
            STARTUP_RECOVERY_ERROR = None  # pyright: ignore[reportConstantRedefinition]
        except Exception as exc:
            STARTUP_RECOVERY_ERROR = exc  # pyright: ignore[reportConstantRedefinition]
            msg.setText(support_message(f"Recovery is still blocked ({type(exc).__name__}). No files were deleted. Preserve the data folder and contact unknown1soldier on Discord."))
            button.setEnabled(True)
            return
        if INTEG[0] == "fail": return self.integ_fail()
        self.route_startup_config()
    def fresh_start(self) -> None:
        if terminal_confirm(self, "Fresh vault // erase old data", "vault --erase --fresh-start",
                ["This deletes the stored vault files and starts new setup; the old contents cannot be opened from this installation afterward.",
                 "Overwrite attempts, when enabled, cannot guarantee physical erasure on SSDs, flash storage, snapshots, or backups."]):
            wipe(HOME, False, S("shred")); self.setup_screen()
    def setup_screen(self) -> None:
        if not self.integ_ok(): return
        self.p1 = QLineEdit(); self.p2 = QLineEdit()
        for e, t in ((self.p1, "Master password (12+ characters)"), (self.p2, "Confirm password")): e.setEchoMode(QLineEdit.EchoMode.Password); e.setPlaceholderText(t)
        self.st = lbl("", 12, MUT)
        def update_password_strength(password: str) -> None:
            strength_label = self.st
            label, color = strength(password)
            strength_label.setText(label)
            strength_label.setStyleSheet(f"font-size:12px;color:{color}")
        self.p1.textChanged.connect(update_password_strength)
        self.lv = self.combo([("Standard: 5 wrong tries, then a lockout", 0), ("High: 4 wrong tries, lockouts up to 24 hours", 1), ("Maximum: 3 wrong tries, 10-minute in-app wipe", 2)])
        self.dm = self.combo([("Deadman switch: off", 0), ("Wipe if not opened for 7 days", 7), ("Wipe if not opened for 30 days", 30)])
        self.pt = QCheckBox("Portable: keep everything next to the app (USB friendly)")
        managed_profile = HOME.parent.resolve() == (Path.home() / ".unknwn-profiles").resolve()
        self.pt.setEnabled(not managed_profile)
        self.pt.setChecked(PORT.exists() and not managed_profile)
        self.tos_agree = QCheckBox("I agree to the UNKNWN TOS & Responsible Use Policy")
        self.tos_link = btn("Legal Notice, Responsible Use & Acceptable Use Policy", "flat")
        self.tos_link.setStyleSheet(f"color:{TH['acc']};text-decoration:underline;background:transparent;border:0")
        self.tos_link.clicked.connect(self.show_terms)
        self.msg = lbl(f"The ONLY way back in is {NW} recovery words you will write on paper next.", 13, "#ffb347"); self.btn = btn("Create vault", "go")
        self.btn.clicked.connect(self.create_vault); self.p2.returnPressed.connect(self.create_vault); self.p1.returnPressed.connect(self.p2.setFocus)
        password_visibility_checkbox: QCheckBox = QCheckBox("Show passwords")
        self.sp = password_visibility_checkbox
        def toggle_password_visibility(visible: bool) -> None:
            echo_mode = QLineEdit.EchoMode.Normal if visible else QLineEdit.EchoMode.Password
            self.p1.setEchoMode(echo_mode)
            self.p2.setEchoMode(echo_mode)
        password_visibility_checkbox.toggled.connect(toggle_password_visibility)
        self.show_w(self.panel(self.logo(), lbl("A private archive for what only you should know.", 13, MUT, center=True), self.p1, self.st, self.p2, self.sp, self.lv, self.dm, self.pt, self.tos_link, self.tos_agree, self.msg, self.btn), "setup")
    def show_terms(self) -> None:
        dialog = QDialog(self); dialog.setWindowTitle("UNKNWN :: Terms of Service")
        screen = self.screen()
        available = screen.availableGeometry() if screen is not None else QRect(0, 0, 900, 700)
        max_width = min(760, max(240, available.width() - 24))
        max_height = min(700, max(240, available.height() - 24))
        dialog.setMinimumSize(min(420, max_width), min(320, max_height))
        dialog.setMaximumSize(max_width, max_height)
        dialog.resize(max_width, max_height)
        layout = QVBoxLayout(dialog); layout.setContentsMargins(12, 12, 12, 12); layout.setSpacing(10)
        frame = QFrame(); frame.setObjectName("term"); inside = QVBoxLayout(frame)
        inside.setContentsMargins(12, 12, 12, 12); inside.setSpacing(8)
        inside.addWidget(tlbl("root@unknwn:~$ terms --view", 13, "#ff8a65"))
        inside.addWidget(tlbl("LEGAL NOTICE // RESPONSIBLE USE", 20, TH["acc"], True))
        policy = QTextBrowser()
        policy.setOpenLinks(False)
        policy.setOpenExternalLinks(False)
        policy.setStyleSheet(
            f"QTextBrowser {{ background:{TH['bg0']}; color:{TH['fg']}; border:1px solid {TH['line']}; "
            f"padding:10px; selection-background-color:{TH['acc']}; }}"
        )
        document = policy.document()
        if document is not None:
            document.setDefaultStyleSheet(
                f"body {{ color:{TH['fg']}; font-family:'Segoe UI'; font-size:10pt; }}"
                f"h1,h2,h3 {{ color:{TH['acc']}; }}"
                f"hr {{ color:{TH['line']}; }}"
            )
        policy.setMarkdown(TERMS_OF_SERVICE)
        inside.addWidget(policy, 1)
        layout.addWidget(frame, 1)
        close = btn("CLOSE"); close.clicked.connect(dialog.accept); layout.addWidget(close)
        dialog.exec_()
    def create_vault(self) -> None:
        try: self._create()
        except Exception as ex:
            try: self.btn.setEnabled(True); self.btn.setText("Create vault"); self.msg.setText(support_message(f"Could not create the vault ({type(ex).__name__}). Close other apps and try again."))
            except RuntimeError: pass
    def _create(self) -> None:
        if not self.tos_agree.isChecked():
            return self.msg.setText("Read the Terms of Service and Responsible Use Policy and agree before creating a vault.")
        if not self.sec_ok(): return
        a = self.p1.text(); ok, why = check_pw(a)
        if not ok: return self.msg.setText(why)
        if a != self.p2.text(): return self.msg.setText("The passwords do not match.")
        risks: list[str] = []
        if self.lv.currentData() == 2: risks.append("Maximum Security starts a 10-minute countdown after three failed attempts and destroys the vault if UNKNWN remains open until it expires. Closing the app cancels that process-only countdown.")
        if self.dm.currentData(): risks.append(f"The deadman switch permanently destroys vault data if you do not open the app for {self.dm.currentData()} days.")
        if risks and QMessageBox.question(self, "Review irreversible vault settings", "\n\n".join(risks) + "\n\nKeep offline backups and your recovery words somewhere safe. Create the vault with these settings?") != QMessageBox.StandardButton.Yes: return
        self.btn.setEnabled(False); self.btn.setText("Forging keys..."); QApplication.processEvents()
        if self.pt.isChecked():
            if active_profile_id:
                _update_profile_path(active_profile_id, PORT)
            set_home(PORT)
        dek = os.urandom(32); phrase = " ".join(random.SystemRandom().sample(WORDS, NW)); s1, s2 = os.urandom(16), os.urandom(16)
        cfg.clear(); cfg.update(n=17, s1=b64e(s1), s2=b64e(s2), wp=b64e(seal(kdf(a, s1), dek)), wr=b64e(seal(kdf(phrase, s2), dek)), f=0, lock=0, last=time.time(), fails=[],
                                set=dict(DEF, lv=self.lv.currentData(), dead=self.dm.currentData()))
        cfg["sc"] = IG.snap_make(dek, secset()); jsave(CFG, cfg); self.root = dek; self.ro = False
        idx.clear(); save_idx(dek, idx)
        self.signin("password"); self.apply_hk(); self.recovery_screen(phrase, self.unlock_fx)
    def recovery_screen(self, phrase: str, then: Callable[[], object]) -> None:
        ws = phrase.split(); k = random.randrange(NW); g = QWidget(); gl = QGridLayout(g); cols = 3 if self.width() >= 760 else 2
        for i, wd in enumerate(ws):
            c = QFrame(); c.setObjectName("card"); c.setMinimumHeight(64); l = QHBoxLayout(c); l.addWidget(lbl(str(i + 1), 12, MUT)); wl = lbl(wd, 20, bold=True, center=True); wl.setWordWrap(False); l.addWidget(wl, 1); gl.addWidget(c, i // cols, i % cols)
        self.vk = QLineEdit(); self.vk.setPlaceholderText(f"Type word #{k + 1} to prove you copied them"); cb = QCheckBox("I wrote these words on PAPER."); go = btn("Continue", "go"); go.setEnabled(False)
        def update_recovery_confirmation(*_args: object) -> None:
            go.setEnabled(cb.isChecked() and self.vk.text().strip().lower() == ws[k])
        cb.toggled.connect(update_recovery_confirmation); self.vk.textChanged.connect(update_recovery_confirmation); go.clicked.connect(_noarg_slot(then))
        bits = NW * math.log2(len(WORDS))
        self.show_w(self.panel(lbl("Your recovery words", 28, bold=True, center=True),
            lbl("If you forget your password, these words are the ONLY way back in. No reset, no email, no support. Lose both and the vault is gone forever.", 13, "#ffb347", center=True), g,
            lbl("Write them on paper and keep it somewhere physically safe. Do NOT store them online: no cloud notes, screenshots, email, chats or password managers. "
                f"Anyone who has these words can open your vault. (There is deliberately no copy button. {NW} random words = about {bits:.0f} bits, slowed by a 128 MB key stretch.)", 12, MUT, center=True),
            self.vk, cb, go, w=640), "recovery")
    def recover_screen(self) -> None:
        self.rw = QLineEdit(); self.rw.setPlaceholderText(f"your {NW} recovery words"); self.p1 = QLineEdit(); self.p2 = QLineEdit()
        for e, t in ((self.p1, "New master password (12+ characters)"), (self.p2, "Confirm new password")): e.setEchoMode(QLineEdit.EchoMode.Password); e.setPlaceholderText(t)
        self.msg = lbl("Wrong words count as failed attempts.", 12, MUT, center=True); self.btn = btn("Recover vault", "go"); bk = btn("Back"); self.btn.clicked.connect(_clicked_slot(self.do_recover)); bk.clicked.connect(self.login_screen)
        self.show_w(self.panel(self.logo(), lbl("Recovery", 30, bold=True, center=True), self.rw, self.p1, self.p2, self.msg, self.btn, bk), "recover")
    def do_recover(self) -> Optional[int]:
        if not self.sec_ok(): return
        a = self.p1.text(); ok, why = check_pw(a)
        if not ok: return self.msg.setText(why)
        if a != self.p2.text(): return self.msg.setText("The passwords do not match.")
        self.btn.setEnabled(False); self.btn.setText("Checking..."); QApplication.processEvents()
        try: dek = unseal(kdf(" ".join(self.rw.text().lower().split()), b64d(cfg["s2"])), b64d(cfg["wr"]))
        except InvalidTag: return self.fail()
        try:
            resolve_data_move_before_signin(dek)
        except Exception as exc:
            self.btn.setEnabled(True); self.btn.setText("Recover vault")
            return QMessageBox.warning(self, "Data-move recovery required",
                                       f"The interrupted data move could not be safely resolved ({type(exc).__name__}). No sign-in changes were made; preserve the source, staging data, and move journal.")
        try:
            self.show_storage_recovery_preview(storage_recovery_preview(dek))
            recovered = recover_storage_transaction(dek)
            if recovered: log_security_event("storage_transaction_recovered", operation=recovered["operation"])
            orphan_stage = recover_orphan_seal_stage(dek)
            if orphan_stage: log_security_event("seal_stage_recovered", removed=orphan_stage["removed"])
        except Exception as exc:
            self.btn.setEnabled(True); self.btn.setText("Recover vault")
            return QMessageBox.warning(self, "Storage recovery required",
                                       f"The interrupted storage operation could not be verified ({type(exc).__name__}). No further vault changes were made; preserve the data folder and try again.")
        if not self.load_vault_index(dek):
            self.btn.setEnabled(True); self.btn.setText("Recover vault")
            return QMessageBox.warning(self, "Vault index unavailable",
                                      "The encrypted vault index could not be authenticated or its files do not match the index. "
                                      "No index changes were made; preserve the vault data and restore from a trusted backup if needed.")
        if not self.prepare_settings_snapshot(dek):
            self.btn.setEnabled(True); self.btn.setText("Recover vault")
            self.msg.setText("Recovery was stopped. The password and vault settings were not changed.")
            return
        candidate = copy.deepcopy(cfg)
        s1 = os.urandom(16); candidate.update(s1=b64e(s1), wp=b64e(seal(kdf(a, s1), dek)))
        try:
            commit_config_transaction(candidate)
        except (OSError, TypeError, ValueError) as exc:
            self.btn.setEnabled(True); self.btn.setText("Recover vault")
            return QMessageBox.warning(
                self, "Recovery could not be saved",
                f"The new master password could not be saved ({type(exc).__name__}). "
                "The existing password remains active; no vault session was opened.")
        self.root = dek; self.ro = False
        if self.signin("recovery"): self.enter_vault()
        else: self.root = None; self.login_screen()

    def show_storage_recovery_preview(self, preview: _StorageRecoveryPreview) -> None:
        details = ["Read-only storage check completed after authentication."]
        if preview["pending_transaction"] is not None:
            details.append(
                f"An interrupted {preview['pending_transaction']} operation is pending; "
                "its journal and files will be verified before recovery continues.")
        if preview["pending_seal_stage"]:
            details.append("An authenticated interrupted-seal record is present.")
        if preview["missing_objects"]:
            details.append(f"Indexed items with missing or unsafe files: {preview['missing_objects']}.")
        if preview["orphan_objects"]:
            details.append(f"Unindexed encrypted files preserved for diagnosis: {preview['orphan_objects']}.")
        if preview["staged_objects"]:
            details.append(f"Staged encrypted files found: {preview['staged_objects']}.")
        if preview["unsafe_objects"]:
            details.append(f"Unsafe storage entries found: {preview['unsafe_objects']}; they will not be followed.")
        if len(details) == 1:
            return
        details.append("Verified recovery will continue automatically. No file names or decrypted contents are shown.")
        QMessageBox.information(self, "Storage recovery preview", "\n\n".join(details))

    def login_screen(self, shake: bool = False) -> None:
        if not self.integ_ok(): return
        pending_deadline = pending_self_destruct_deadline()
        now = time.time()
        if pending_deadline and now >= pending_deadline:
            self.panic(False)
            return
        pending = bool(pending_deadline)
        self.pending_password_ack = False
        if pending:
            left = max(0, int(pending_deadline - now))
            self.lk = lbl(f"Maximum Security countdown active: {cdt(left)} remaining before the vault is destroyed. Remembering your password will not stop the countdown.", 14, "#ff8a65", center=True)
            info = self.lk
        else:
            lock_limits: tuple[int, int, int] = (5, 4, 3)
            policy_index = max(0, min(2, int(S("lv"))))
            left = cfg["lock"] - now; L: int = lock_limits[policy_index] - int(cfg["f"]); self.lk = None
            if left > 0: self.lk = lbl("", 14, "#ff8a65", center=True); info = self.lk
            else:
                t = ("Wrong password. " + (f"{L} attempt(s) left before a lockout." if L > 0 else "Every further failure doubles the lockout.") + (" At the limit, everything burns." if S("lv") == 2 else "")) if cfg["f"] else "Enter your master password."
                info = lbl(t, 13, MUT, center=True)
        self.pw = QLineEdit(); self.pw.setEchoMode(QLineEdit.EchoMode.Password); self.pw.setPlaceholderText("password:"); self.ub = btn("> unlock", "go"); self.rob = QCheckBox("Open read-only (nothing can be changed)")
        self.pw.setEnabled(left <= 0 and not pending); self.ub.setEnabled(left <= 0 and not pending); self.pw.returnPressed.connect(_clicked_slot(self.try_login)); self.ub.clicked.connect(_clicked_slot(self.try_login))
        fg = btn("Forgot password? Use recovery words", "flat"); fg.clicked.connect(self.recover_screen); kp = btn("\u2328  On-screen keyboard"); kp.clicked.connect(self.keypad); kp.setEnabled(left <= 0 and not pending); self.kp = kp; sp = QCheckBox("Show password")
        def toggle_login_password(visible: bool) -> None:
            self.pw.setEchoMode(QLineEdit.EchoMode.Normal if visible else QLineEdit.EchoMode.Password)
        sp.toggled.connect(toggle_login_password)
        remember = btn("I REMEMBER THE PASSWORD", "go") if pending else None
        if remember: remember.clicked.connect(self.acknowledge_pending_password)
        back_to_profiles = btn("< Back to profiles", "flat") if active_profile_id else None
        if back_to_profiles:
            back_to_profiles.setAccessibleName("Back to vault profile selection")
            back_to_profiles.setToolTip("Return to profile selection. The vault remains locked and will still require its password.")
            back_to_profiles.clicked.connect(_noarg_slot(self.profile_chooser))
        tb = QFrame(); tb.setObjectName("term")
        login_bg = _normalize_theme_color(S("lbg"), TH["bg0"])
        login_fg = _normalize_theme_color(S("lfg"), TH["fg"])
        login_accent = _normalize_theme_color(S("lac"), TH["acc"])
        tb.setStyleSheet(
            f"QFrame#term{{background:{login_bg};color:{login_fg};border:1px solid {login_accent};"
            f"border-radius:8px;}}"
            f"QFrame#term QLabel{{color:{login_fg};}}")
        tl = QVBoxLayout(tb); tl.setContentsMargins(18, 16, 18, 16); tl.setSpacing(10)
        welcome = self.login_greeting()
        clock = self.clock_label(); clock.setAlignment(
            cast(Any, Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter))
        login_header = QHBoxLayout(); login_header.addWidget(welcome, 1); login_header.addWidget(clock)
        login_header.insertWidget(0, self.avatar_label(44))
        recovery_notice = lbl("An interrupted storage change is pending; it will be verified and resumed after authentication.", 12, "#ffb347", center=True) if storage_txn_path().exists() else None
        config_notice = lbl(
            "The primary configuration was unavailable; a valid local backup was loaded. "
            "Review the vault settings after sign-in.",
            12, "#ffb347", center=True) if startup_config_state == "recovered_backup" else None
        tl.addLayout(login_header)
        for x in (tlbl("UNKNWN :: secure shell v1.0\n---------------------------\nroot@unknwn:~$ unlock --vault", 13), info,
                  *([recovery_notice] if recovery_notice else []), *([config_notice] if config_notice else []),
                  *([remember] if remember else []), self.pw, sp,
                  *([kp] if S("keypad") else []), self.rob, self.ub, fg,
                  *([back_to_profiles] if back_to_profiles else [])): tl.addWidget(x)
        self.show_w(self.panel(tb, w=470), "login")
        if left <= 0 and not pending: self.pw.setFocus()
        else: self.tick()
        if shake: self.shake()
    def acknowledge_pending_password(self) -> None:
        deadline = pending_self_destruct_deadline()
        if not deadline or time.time() >= deadline:
            self.panic(False)
            return
        self.pending_password_ack = True
        self.pw.setEnabled(True); self.ub.setEnabled(True)
        if S("keypad"): self.kp.setEnabled(True)
        login_notice = self.lk
        if login_notice is not None:
            login_notice.setText(f"Password entry enabled. {cdt(deadline - time.time())} remains; the countdown will continue even if the password is correct.")
        self.pw.setFocus()
    def try_login(self) -> Optional[int]:
        pw = self.pw.text()
        pending_deadline = pending_self_destruct_deadline()
        now = time.time()
        if pending_deadline and now >= pending_deadline:
            self.panic(False)
            return
        pending_ack = bool(getattr(self, "pending_password_ack", False) and pending_deadline)
        if not pw or (cfg["lock"] > now and not pending_ack) or not self.sec_ok(): return
        if S("bind") and cfg.get("fp") and not _device_binding_matches(cfg["fp"]):
            return QMessageBox.warning(self, "Wrong device", "This vault is bound to another computer and will not open here.")
        if S("remote") and remote_session(): return QMessageBox.warning(self, "Remote session", "Sign-in is blocked while this PC is controlled over Remote Desktop.")
        self.pw.setEnabled(False); self.ub.setEnabled(False); self.ub.setText("Unlocking..."); QApplication.processEvents(); self.ro = self.rob.isChecked() or S("ro_always")
        try:
            salt_blob = cfg["s1"]; wrapped_key = cfg["wp"]
        except KeyError as ex:
            field = str(ex.args[0]) if ex.args else "unknown"
            log_security_event("unlock_configuration_incomplete", field=field)
            self.root = None; self.ro = False; self.login_screen()
            return QMessageBox.warning(self, "Vault configuration incomplete",
                                       f"A required key-wrapper field is missing ({field}). No vault data was changed. Restore config.json or config.json.bak from a trusted backup.")
        try: dek = unseal(kdf(pw, b64d(salt_blob)), b64d(wrapped_key))
        except InvalidTag: return self.fail()
        except MemoryError as ex:
            log_security_event("unlock_resource_exhausted", error=type(ex).__name__)
            self.root = None; self.ro = False; self.login_screen()
            return QMessageBox.warning(self, "Not enough memory to unlock",
                                       "This device could not allocate the memory needed for the strong 128 MiB password KDF. Close other applications and try again. The vault was not changed.")
        except Exception as ex:
            log_security_event("unlock_key_derivation_failed", error=type(ex).__name__)
            self.root = None; self.ro = False; self.login_screen()
            return QMessageBox.warning(self, "Cannot unlock",
                                       f"Key derivation failed ({type(ex).__name__}). The vault was not changed. Restore config.json from a trusted backup or contact support if the problem continues.")
        self.root = dek
        try:
            resolve_data_move_before_signin(dek)
        except Exception as exc:
            self.root = None; self.ro = False; self.login_screen()
            return QMessageBox.warning(self, "Data-move recovery required",
                                       f"The interrupted data move could not be safely resolved ({type(exc).__name__}). No sign-in changes were made; preserve the source, staging data, and move journal.")
        try:
            self.show_storage_recovery_preview(storage_recovery_preview(dek))
            recovered = recover_storage_transaction(dek)
            if recovered: log_security_event("storage_transaction_recovered", operation=recovered["operation"])
            orphan_stage = recover_orphan_seal_stage(dek)
            if orphan_stage: log_security_event("seal_stage_recovered", removed=orphan_stage["removed"])
        except Exception as exc:
            self.root = None; self.ro = False; self.login_screen()
            return QMessageBox.warning(self, "Storage recovery required",
                                       f"The interrupted storage operation could not be verified ({type(exc).__name__}). No further vault changes were made; preserve the data folder and try again.")
        if not self.load_vault_index(dek):
            self.root = None; self.ro = False; self.login_screen()
            return QMessageBox.warning(self, "Vault index unavailable",
                                      "The encrypted vault index could not be authenticated or its files do not match the index. "
                                      "No index changes were made; preserve the vault data and restore from a trusted backup if needed.")
        if self.signin("password"): self.enter_vault()
        else: self.root = None; self.ro = False; self.login_screen()
    def fail(self) -> Optional[int]:
        cfg["f"] += 1; cfg["fails"] = (cfg.get("fails", []) + [time.time()])[-50:]; lv = S("lv")
        cfg["tf"] = cfg.get("tf", 0) + 1
        now = time.time()
        pending_deadline = pending_self_destruct_deadline()
        if pending_deadline and now >= pending_deadline:
            return self.panic(False)
        if pending_deadline:
            cfg["lock"] = pending_deadline
            log_security_event("max_security_pending_attempt_failed", attempt=cfg["f"])
            return self.login_screen(True)
        if S("maxtf") and cfg["tf"] >= S("maxtf"): return self.panic(False)
        if lv == 2 and cfg["f"] >= 3:
            deadline = now + 10 * 60
            cfg["sd"] = _signed_self_destruct_state(SELF_DESTRUCT_RUNTIME_KEY, "pending", deadline)
            cfg["lock"] = deadline
            cfg["fails"] = [now]
            log_security_event("max_security_pending", deadline=deadline, attempt=cfg["f"], mode="maximum")
            return self.login_screen(True)
        n, b = [(5, 30), (4, 900), (99, 0)][lv]
        if cfg["f"] >= n: cfg["lock"] = now + min(b * 2 ** (cfg["f"] - n), 86400)
        jsave(CFG, cfg); self.login_screen(True)
    def prepare_settings_snapshot(self, dek: bytes) -> bool:
        st, good, changed = IG.snap_check(dek, cfg.get("sc"), secset())
        settings = cfg.setdefault("set", {})
        if st in ("bad", "new"):
            if not terminal_confirm(self, "Protected settings // integrity lost", "settings --reset-protected",
                    ["The authenticated security-settings snapshot is missing or cannot be verified.",
                     "UNKNWN cannot know which protected settings were changed. Continuing resets all protected settings to the built-in defaults.",
                     "The master password, recovery words, sealed files, and non-security appearance settings are not changed.",
                     "Cancel to stop sign-in and restore config.json from a trusted backup."]):
                self.fixed = []
                log_security_event("settings_snapshot_repair_declined", status=st)
                return False
            settings.update({key: DEF[key] for key in SECKEYS})
            self.fixed = ["protected settings reset to defaults"]
            log_security_event("settings_snapshot_reset", status=st)
        else:
            if st == "changed":
                settings.update({key: good[key] for key in changed})
                self.fixed = list(changed)
            else:
                self.fixed = []
            missing = SECKEYS - good.keys()
            if missing:
                settings.update({key: DEF[key] for key in missing})
                if "vmode" in missing:
                    log_security_event("playback_mode_migrated", mode="memory")
                log_security_event("settings_snapshot_migrated", count=len(missing))
        cfg["sc"] = IG.snap_make(dek, secset())
        return True
    def signin(self, how: str) -> bool:
        root = self.root
        if root is None:
            return False
        try:
            move = resolve_data_move_before_signin(root)
        except Exception as exc:
            QMessageBox.warning(self, "Data-move recovery required",
                f"The interrupted data move could not be safely resolved ({type(exc).__name__}). "
                "No sign-in changes were made; preserve the source, staging data, and move journal.")
            return False
        if not App.prepare_settings_snapshot(self, root): return False
        try:
            burn_exhausted_view_items(root)
        except Exception as exc:
            QMessageBox.warning(self, "Consumed item removal needs recovery",
                f"A file whose last view was already consumed could not be removed ({type(exc).__name__}). "
                "No new vault session was opened. Preserve the data folder and try recovery again.")
            return False
        self.move_recovery_notice = ""
        if move:
            self.move_recovery_notice = (
                f"Data-folder recovery verified the active copy. The original remains at {move['source']}."
            )
        if S("intro") > 1: cfg.setdefault("set", {})["intro"] = 1
        now = time.time(); L = self.logs()
        signins = [entry for entry in L if entry.get("type") != "session"]
        previous_signin = next((e.get("t") for e in reversed(signins)
                                if e.get("ok") is True and isinstance(e.get("t"), (int, float))), None)
        self.prev = float(previous_signin) if isinstance(previous_signin, (int, float)) else None
        fl = cfg.get("fails", []); self.nf = len(fl)
        if not getattr(self, "relocked", False) or getattr(self, "session_started", None) is None:
            self.session_activity = []; self.session_stored_names = []; self.session_stored_count = 0
            self.session_setting_changes = 0; self.session_activity_omitted = 0; self.session_started = now
            self.session_id = uuid.uuid4().hex
        elif not isinstance(self.session_id, str) or len(self.session_id) != 32:
            self.session_id = uuid.uuid4().hex
        if S("log") and not S("ghost"):
            history_error = self.__dict__.get("session_history_error")
            if history_error:
                log_security_event("sign_in_history_write_skipped", error=history_error)
            else:
                signins += [{"t": t, "ok": False, "attempt": i + 1} for i, t in enumerate(fl)]
                signins.append({"t": now, "ok": True, "how": how, "ro": self.ro})
                sessions = [entry for entry in L if entry.get("type") == "session"][-MAX_SESSION_HISTORY:]
                try:
                    HOME.mkdir(parents=True, exist_ok=True)
                    atomic_write_bytes(LOG, seal(file_key(root, b"unknwn-log"),
                                                 json.dumps(signins[-MAX_SIGNIN_HISTORY:] + sessions,
                                                            separators=(",", ":"), ensure_ascii=False).encode("utf-8")))
                except (OSError, TypeError, ValueError) as exc:
                    self.session_history_error = type(exc).__name__
                    log_security_event("sign_in_history_write_failed", error=self.session_history_error)
        cfg.update(f=0, lock=0, last=now, fails=[]); jsave(CFG, cfg)
        App.record_session_event(self, "vault_unlocked", method=how)
        return True
    def load_vault_index(self, root: bytes) -> bool:
        if not IDX.exists() and not IDX.with_name(IDX.name + ".bak").exists():
            if VAULT.is_dir() and any(VAULT.glob("*.cdr")):
                log_security_event("vault_index_missing_with_sealed_files")
                return False
        try:
            loaded, legacy = load_idx(root, with_legacy=True)
        except (InvalidTag, OSError, ValueError, TypeError) as exc:
            log_security_event("vault_index_authentication_failed", error=type(exc).__name__)
            return False
        vault_info: Optional[os.stat_result] = None
        try:
            vault_info = VAULT.lstat()
        except FileNotFoundError:
            pass
        except OSError as exc:
            log_security_event("vault_storage_directory_unavailable", error=type(exc).__name__)
            return False
        if vault_info is not None:
            if (stat.S_ISLNK(vault_info.st_mode)
                    or getattr(vault_info, "st_file_attributes", 0)
                    & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
                    or not stat.S_ISDIR(vault_info.st_mode)):
                log_security_event("vault_storage_directory_unsafe")
                return False

        missing_or_unsafe: list[str] = []
        for rid in loaded:
            item_path = _storage_file_path(rid)
            try:
                info = item_path.lstat()
            except FileNotFoundError:
                missing_or_unsafe.append(rid)
                continue
            except OSError as exc:
                log_security_event("vault_storage_object_unavailable", error=type(exc).__name__)
                return False
            if (stat.S_ISLNK(info.st_mode)
                    or getattr(info, "st_file_attributes", 0)
                    & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
                    or not stat.S_ISREG(info.st_mode)
                    or getattr(info, "st_nlink", 1) != 1):
                missing_or_unsafe.append(rid)
        if missing_or_unsafe:
            log_security_event(
                "vault_index_storage_mismatch", affected_items=len(missing_or_unsafe))
            return False

        for p in (VAULT.glob("*.cdr") if vault_info is not None else ()):
            if p.stem not in loaded:
                try: p.rename(p.with_suffix(".orphan"))
                except OSError as exc: log_security_event("orphan_vault_file_preserved", error=type(exc).__name__)
        idx.clear(); idx.update(loaded)
        if legacy or not IDX.exists():
            save_idx(root, idx)
            if legacy: log_security_event("vault_index_migrated", entries=len(idx))
        return True
    def unlock_fx(self) -> None:
        self.t0 = time.time()
        def introduce_warden() -> None:
            self.show_w(Warden(self.vault_screen, self), "unlock")
        self.show_w(Unlock(introduce_warden, self), "unlock")
    def enter_vault(self) -> None:
        if self.relocked:
            self.relocked = False; self.t0 = time.time()
            self.show_w(Warden(self.vault_screen, self), "unlock")
        else: self.unlock_fx()

    def vault_screen(self) -> None:
        try:
            self._prepare_vault_file_states()
        except FileStateError as exc:
            QMessageBox.warning(
                self, "Vault state requires recovery",
                f"The vault contains an item that is not available for use ({type(exc).__name__}). "
                "No item actions were enabled.")
            self.root = None
            self.login_screen()
            return
        w = QWidget(); v = QVBoxLayout(w); v.setContentsMargins(26, 18, 26, 14); self.cards = {}; self.cds = {}; self.lk = None
        self.reset_vault_group_widgets()
        self.selected_items: set[str] = set()
        self._syncing_selection = False
        top = QHBoxLayout(); self.count = lbl("", 13, MUT); self.sd_timer = lbl("", 13, "#ff8a65")
        commands = btn("Commands", "flat")
        commands.setToolTip("Search locally available items and actions (Ctrl+K).")
        commands.setAccessibleName("Open local search and command palette")
        commands.clicked.connect(_noarg_slot(self.open_command_palette))
        lk = btn("Lock"); switch = btn("Switch profile"); pn = btn("Panic wipe", "danger")
        switch.setToolTip("Lock this vault and choose another profile. Each profile keeps its own password and files.")
        switch.setAccessibleName("Switch vault profile")
        pending_deadline = pending_self_destruct_deadline()
        if pending_deadline:
            self.sd_timer.setText(f"SELF-DESTRUCT IN {cdt(pending_deadline - time.time())}")
        top.addWidget(self.logo()); top.addStretch(); top.addWidget(self.count); top.addWidget(self.sd_timer)
        top.addWidget(commands); top.addWidget(lk); top.addWidget(switch); top.addWidget(pn); v.addLayout(top)
        if getattr(self, "move_recovery_notice", ""):
            recovery_note = lbl(self.move_recovery_notice, 12, "#ffb347")
            recovery_note.setWordWrap(True); v.addWidget(recovery_note)
        note = ("Last sign-in: " + tfmt(self.prev)) if self.prev else "First sign-in on this vault."
        if self.nf: note += f"     \u26A0 {self.nf} failed attempt(s) since then (see Activity)."
        sign_in_row = QHBoxLayout()
        sign_in_row.addWidget(lbl(note, 12, "#ffb347" if self.nf else MUT))
        sign_in_row.addWidget(self.clock_label())
        sign_in_row.addStretch()
        v.addLayout(sign_in_row)
        if getattr(self, "fixed", None):
            v.addWidget(lbl("\u26A0 Security settings were changed outside UNKNWN" + (" and have been restored: " + ", ".join(self.fixed) if self.fixed != ["?"] else " and could not be verified. Please review them."), 12, "#ff8a65")); self.fixed = []
        tb = QHBoxLayout(); self.tabs = []
        for i, t in enumerate(("Vault", "Settings", "Activity", "Overview")):
            b = btn(t, "tab"); b.setCheckable(True); b.clicked.connect(_clicked_slot(self.tab, i)); self.tabs.append(b); tb.addWidget(b)
        tb.addStretch(); v.addLayout(tb); self.stack = QStackedWidget(); v.addWidget(self.stack, 1)
        p0 = QWidget(); q = QVBoxLayout(p0); q.setContentsMargins(0, 10, 0, 0)
        if self.ro: q.addWidget(lbl(f"{LOCK_ICON} READ-ONLY SESSION: nothing can be added, removed or changed, and timers and view counters are frozen.", 13, "#22d3ee", True))
        self.ex = self.combo([("Never", 0), ("1 minute", 60), ("1 hour", 3600), ("24 hours", 86400), ("7 days", 604800)])
        self.vw = self.combo([("Unlimited", 0), ("1 view", 1), ("3 views", 3), ("5 views", 5)]); self.rm = QCheckBox("Shred the original after sealing")
        self.rm.setToolTip("Permanently deletes the source file after its encrypted copy has been sealed. Keep another backup if needed.")
        add = btn("Seal files...", "go"); add_folder = btn("Seal a folder...")
        notes_button = btn("Vault notes...")
        notes_button.clicked.connect(self.open_vault_notes)
        row = QHBoxLayout(); row.addWidget(add); row.addWidget(add_folder); row.addWidget(notes_button)
        for t, c in (("Burn after", self.ex), ("Burn after views", self.vw)): row.addWidget(lbl(t, 13, MUT)); row.addWidget(c)
        for x in (add, add_folder, self.ex, self.vw, self.rm): x.setEnabled(not self.ro)
        q.addLayout(row); q.addWidget(self.rm)
        q.addWidget(lbl("Expiry and view limits permanently burn sealed files. Shredding the original deletes your source file; keep a separate backup if you may need it.", 11, "#ffb347"))
        sc = QScrollArea(); sc.setWidgetResizable(True); inner = QWidget(); self.rows = QVBoxLayout(inner); self.rows.setAlignment(Qt.AlignmentFlag.AlignTop); sc.setWidget(inner)
        self.search_edit = QLineEdit(); self.search_edit.setPlaceholderText("Search visible names, file types, sizes, or item IDs…")
        self.search_edit.setAccessibleName("Search vault items")
        self.search_edit.textEdited.connect(self.handle_vault_search_command)
        self.sort_order = self.combo([("Stored order", "stored"), ("File type", "type"), ("Largest first", "largest"), ("Smallest first", "smallest")])
        self.sort_order.setAccessibleName("Sort vault items")
        search_row = QHBoxLayout(); search_row.addWidget(self.search_edit, 1); search_row.addWidget(lbl("Sort", 12, MUT)); search_row.addWidget(self.sort_order)
        q.addLayout(search_row)
        self.select_visible = QCheckBox("Select visible")
        self.select_visible.toggled.connect(self.select_visible_items)
        q.addWidget(self.select_visible)
        self.selection_toolbar = QWidget()
        selection_layout = QHBoxLayout(self.selection_toolbar)
        selection_layout.setContentsMargins(8, 4, 8, 4)
        self.selection_label = lbl("0 selected", 12, TH["acc"], True)
        selection_layout.addWidget(self.selection_label)
        selection_layout.addStretch()
        self.bulk_buttons: dict[str, QPushButton] = {}
        for label, key, callback in (
            ("View selected", "view", self.view_selected_items),
            ("Group", "group", self.group_selected_items),
            ("Rename", "rename", self.rename_selected_item),
            ("Edit config", "config", self.configure_selected_items),
            ("Clear selection", "clear", self.clear_item_selection),
            ("Delete", "delete", self.delete_selected_items),
        ):
            action = btn(label, "danger" if key == "delete" else "flat")
            action.clicked.connect(_noarg_slot(callback))
            selection_layout.addWidget(action)
            self.bulk_buttons[key] = action
        self.selection_toolbar.hide()
        q.addWidget(self.selection_toolbar)
        self.empty = lbl("The vault is empty. Seal a file to get started.", 14, MUT, center=True)
        self.no_results = lbl("No vault items match this search.", 14, MUT, center=True)
        self.rows.addWidget(self.empty); self.rows.addWidget(self.no_results); q.addWidget(sc, 1)
        self.search_edit.textChanged.connect(self.apply_vault_filter)
        self.sort_order.currentIndexChanged.connect(_index_changed_slot(self.apply_vault_sort))
        self.sp: QScrollArea = QScrollArea(); self.sp.setWidgetResizable(True); self.ap: QScrollArea = QScrollArea(); self.ap.setWidgetResizable(True)
        self.changes = QScrollArea(); self.changes.setWidgetResizable(True)
        for x in (p0, self.sp, self.ap, self.changes): self.stack.addWidget(x)
        v.addWidget(lbl("AES-256-GCM, a unique key per file, scrypt 128 MB. Nothing leaves this computer. Overwrite-and-delete cannot beat SSD wear-levelling, so use full-disk encryption too.", 11, DIM))
        lk.clicked.connect(_clicked_slot(self.lock, True)); switch.clicked.connect(_clicked_slot(self.switch_profile))
        pn.clicked.connect(_clicked_slot(self.panic, True)); add.clicked.connect(_clicked_slot(self.add_files)); add_folder.clicked.connect(_clicked_slot(self.add_folder))
        self.show_w(w, "vault"); self.tabs[0].setChecked(True)
        for n, rid in enumerate(list(idx)): self.add_card(rid, n * 70)
        self.apply_vault_sort()
        self.sync()
    def reset_vault_group_widgets(self) -> None:
        self._group_headers: list[QFrame] = []
        self._group_headers_by_key: dict[str, QFrame] = {}
        self._group_header_members: dict[str, tuple[str, ...]] = {}
        self._group_header_checks: dict[str, QCheckBox] = {}
        self._group_collapse_buttons: dict[str, QPushButton] = {}
        empty_collapsed_groups: set[str] = set()
        self._collapsed_groups = cast(
            set[str], getattr(self, "_collapsed_groups", empty_collapsed_groups))
    def tab(self, i: int) -> None:
        previous = self.stack.currentIndex()
        for j, b in enumerate(self.tabs): b.setChecked(j == i)
        if i == 1: cast(Any, self.sp).setWidget(self.build_settings())
        if i == 2: self.ap.setWidget(self.build_log())
        if i == 3: self.changes.setWidget(self.build_changes())
        self.stack.setCurrentIndex(i)
        if previous != i: self.animate_tab()

    # ---------- settings & activity ----------
    def build_settings(self) -> QWidget:
        w = QWidget(); v = QVBoxLayout(w); v.setAlignment(Qt.AlignmentFlag.AlignTop); v.setSpacing(14); secs: list[tuple[QFrame, str, bool]] = []
        if self.ro: v.addWidget(lbl(f"{LOCK_ICON} Read-only session: settings are locked. Lock and sign in normally to change them.", 13, "#22d3ee", True))
        self.lock_ui(v)
        search = QLineEdit()
        search.setPlaceholderText("Search settings (for example: auto lock, clipboard, panic shortcut)")
        search.setAccessibleName("Search settings")
        search.setObjectName("settingsSearch")
        v.addWidget(search)
        search_status = lbl("No settings match your search.", 11, MUT)
        search_status.hide()
        v.addWidget(search_status)
        if self.ro and S("ro_always"):   # escape hatch: this switch must stay reachable from a read-only session
            c = QFrame(); c.setObjectName("card"); l = QVBoxLayout(c); l.addWidget(lbl("Always open read-only is ON", 15, bold=True)); l.addWidget(lbl("Every sign-in is view-only. Your master password is needed to turn this off.", 12, MUT))
            b = btn("Turn off 'Always open read-only'..."); b.clicked.connect(_clicked_slot(self.ro_off)); l.addWidget(b); v.addWidget(c)
        nw = QWidget(); nv = QVBoxLayout(nw); nv.setContentsMargins(0, 0, 0, 0); nv.setSpacing(14); nw.setEnabled(not self.ro)
        def sec(title: str, hint: str = "", host: QVBoxLayout = nv) -> QVBoxLayout:
            c = QFrame(); c.setObjectName("card"); l = QVBoxLayout(c); l.setSpacing(9); l.addWidget(lbl(title, 16, ACC, True))
            if hint: l.addWidget(lbl(hint, 12, MUT))
            secs.append((c, title, title in PROTSEC)); host.addWidget(c); return l
        def warn(text: str) -> bool:
            return QMessageBox.question(self, "Before you change this setting", text) == QMessageBox.StandardButton.Yes
        def reset_row(
            l: QVBoxLayout,
            key: str,
            control: QWidget,
            apply_default: Callable[[object], None],
        ) -> Callable[[], None]:
            status = lbl("Customized", 10, TH["acc"], True)
            reset = btn("Reset")
            reset.setToolTip("Restore this setting to its built-in default.")
            row = QHBoxLayout(); row.addWidget(control, 1); row.addWidget(status); row.addWidget(reset)
            l.addLayout(row)

            def refresh() -> None:
                customized = S(key) != DEF[key]
                status.setVisible(customized)
                reset.setVisible(customized)

            def reset_setting() -> None:
                default = DEF[key]
                if S(key) == default:
                    refresh()
                    return
                if key in PROTKEYS and not terminal_confirm(
                    self,
                    "Reset protected setting",
                    f"settings --reset {key}",
                    [f"Restore {key.replace('_', ' ')} to its built-in default.",
                     "This may reduce or change the current security policy. The vault's files and credentials are not deleted."],
                ):
                    return
                self.put(key, default)
                previous_block = control.blockSignals(True)
                try:
                    apply_default(S(key))
                finally:
                    control.blockSignals(previous_block)
                refresh()

            reset.clicked.connect(_clicked_slot(reset_setting))
            refresh()
            return refresh

        def search_settings(text: str) -> None:
            query = re.sub(r"[\W_]+", " ", text.casefold()).strip()
            aliases: dict[str, tuple[str, ...]] = {
                "idle timeout": ("auto lock when idle",),
                "session timeout": ("auto lock when idle", "maximum session length"),
                "panic shortcut": ("shortcut manager",),
            }
            terms: tuple[str, ...] = aliases.get(query, (query,))
            matches: list[QFrame] = []
            for section, title, _protected in secs:
                if not query:
                    section.setVisible(True)
                    continue
                values = [title]
                values.extend(item.text() for item in section.findChildren(QLabel))
                values.extend(item.text() for item in section.findChildren(QCheckBox))
                values.extend(item.text() for item in section.findChildren(QPushButton))
                for combo in section.findChildren(QComboBox):
                    values.extend(combo.itemText(index) for index in range(combo.count()))
                searchable = re.sub(r"[\W_]+", " ", " ".join(values).casefold())
                matched = any(term in searchable for term in terms)
                section.setVisible(matched)
                if matched:
                    matches.append(section)
            search_status.setVisible(bool(query) and not matches)
            if query and matches:
                parent = matches[0].parentWidget()
                while parent is not None and not isinstance(parent, QScrollArea):
                    parent = parent.parentWidget()
                if isinstance(parent, QScrollArea):
                    cast(QScrollArea, parent).ensureWidgetVisible(matches[0])

        search.textChanged.connect(search_settings)
        def chk(
            l: QVBoxLayout,
            k: str,
            t: str,
            h: str = "",
            warning: Optional[Union[str, tuple[bool, str], dict[bool, str]]] = None,
        ) -> None:
            c = QCheckBox(t); c.setChecked(bool(S(k)))
            def changed(value: bool) -> None:
                if isinstance(warning, dict): message = warning.get(bool(value))
                elif isinstance(warning, tuple): message = warning[1] if bool(value) == warning[0] else None
                else: message = warning if value else None
                if message and not warn(message):
                    c.blockSignals(True); c.setChecked(bool(S(k))); c.blockSignals(False); return
                self.put(k, value)
                if bool(S(k)) != c.isChecked():
                    c.blockSignals(True); c.setChecked(bool(S(k))); c.blockSignals(False)
                refresh()
            c.toggled.connect(changed)
            refresh = reset_row(l, k, c, lambda value: c.setChecked(bool(value)))
            if h: l.addWidget(lbl(h, 11, DIM))
        def drop(
            l: QVBoxLayout,
            k: str,
            t: str,
            items: Iterable[tuple[str, object]],
            warnings: Optional[Mapping[object, str]] = None,
        ) -> None:
            r = QHBoxLayout(); r.addWidget(lbl(t, 13)); c = self.combo(items); c.setCurrentIndex(max(0, c.findData(S(k)))); selected = [S(k)]
            def changed(_: int) -> None:
                value = c.currentData(); message = (warnings or {}).get(value)
                if message and not warn(message):
                    c.blockSignals(True); c.setCurrentIndex(c.findData(selected[0])); c.blockSignals(False); return
                self.put(k, value)
                selected[0] = S(k)
                accepted_index = c.findData(selected[0])
                if accepted_index >= 0 and accepted_index != c.currentIndex():
                    c.blockSignals(True); c.setCurrentIndex(accepted_index); c.blockSignals(False)
                refresh()
            c.currentIndexChanged.connect(changed)
            r.addWidget(c)
            row = QHBoxLayout(); row.addLayout(r)
            status = lbl("Customized", 10, TH["acc"], True); reset = btn("Reset")
            reset.setToolTip("Restore this setting to its built-in default.")
            row.addWidget(status); row.addWidget(reset); l.addLayout(row)

            def refresh() -> None:
                customized = S(k) != DEF[k]
                status.setVisible(customized); reset.setVisible(customized)

            def reset_setting() -> None:
                default = DEF[k]
                if S(k) == default:
                    refresh()
                    return
                if k in PROTKEYS and not terminal_confirm(
                    self,
                    "Reset protected setting",
                    f"settings --reset {k}",
                    [f"Restore {k.replace('_', ' ')} to its built-in default.",
                     "This may reduce or change the current security policy. The vault's files and credentials are not deleted."],
                ):
                    return
                index = c.findData(default)
                if index < 0:
                    QMessageBox.warning(
                        self, "Setting cannot be reset",
                        "The built-in default is not available in this control.")
                    return
                self.put(k, default)
                actual = S(k)
                actual_index = c.findData(actual)
                if actual_index >= 0:
                    c.blockSignals(True); c.setCurrentIndex(actual_index); c.blockSignals(False)
                selected[0] = actual
                refresh()

            reset.clicked.connect(_clicked_slot(reset_setting))
            refresh()
        reset_section = sec("Settings controls")
        reset_section.addWidget(lbl(
            "Settings are saved and applied as you change them. Reset restores recognized preferences to built-in defaults.",
            12, MUT))
        history_row = QHBoxLayout()
        self.settings_undo_button = btn("Undo setting")
        self.settings_redo_button = btn("Redo setting")
        self.settings_undo_button.clicked.connect(self.undo_setting)
        self.settings_redo_button.clicked.connect(self.redo_setting)
        history_row.addWidget(self.settings_undo_button); history_row.addWidget(self.settings_redo_button)
        reset_section.addLayout(history_row)
        reset_section.addWidget(lbl(
            "Undo/redo applies only to this session's reversible preferences. It does not reverse vault operations or protected security settings.",
            11, DIM))
        self.refresh_settings_history_controls()
        reset_button = btn("Reset all settings to defaults…", "danger")
        reset_button.clicked.connect(_clicked_slot(self.reset_settings))
        reset_section.addWidget(reset_button)
        dashboard = sec("Overview dashboard", "Choose which non-sensitive summary cards appear on Overview.")
        chk(dashboard, "dash_session", "Show active vault session summary")
        chk(dashboard, "dash_look", "Show current appearance summary")
        chk(dashboard, "dash_privacy", "Show privacy and history summary")
        l = sec("Security & self-destruct", "Rules that protect the vault, even while it is locked.")
        drop(l, "lv", "Wrong-password policy", [("Standard: 5 tries, then lockout", 0), ("High: 4 tries, lockouts up to 24h", 1), ("Maximum: 3 tries, 10-minute in-app wipe", 2)],
             {1: "High policy applies increasingly long lockouts, up to 24 hours, after failed attempts. This can delay legitimate access if you mistype or forget the password. Enable it?",
              2: "Maximum Security starts a 10-minute process-only countdown after three failed attempts and destroys the vault if UNKNWN remains open until it expires. Correctly entering the password does not cancel it; closing the app cancels it. This avoids trusting a forgeable wipe instruction in config.json. Keep your recovery words and backups safe. Enable this?"})
        drop(l, "dead", "Deadman switch (wipe if not opened)", [("Off", 0), ("After 3 days", 3), ("After 7 days", 7), ("After 14 days", 14), ("After 30 days", 30)],
             {3: "If the vault is not opened for this period, its data is permanently destroyed. Are you sure you want a 3-day deadline?",
              7: "If the vault is not opened for this period, its data is permanently destroyed. Are you sure you want a 7-day deadline?",
              14: "If the vault is not opened for this period, its data is permanently destroyed. Are you sure you want a 14-day deadline?",
              30: "If the vault is not opened for this period, its data is permanently destroyed. Are you sure you want a 30-day deadline?"})
        drop(l, "idle", "Auto-lock when idle", [("Never", 0), ("1 minute", 1), ("5 minutes", 5), ("15 minutes", 15)])
        l.addWidget(lbl("Never leaves an unlocked vault open until you lock it yourself.", 11, DIM))
        drop(l, "shred", "Secure-erase strength", [("1 pass (fast)", 1), ("3 passes", 3), ("7 passes (slow)", 7)],
             {3: "Additional overwrite passes can make burn operations take longer. They cannot guarantee physical erasure on SSDs or flash storage. Continue with 3 passes?",
              7: "Seven overwrite passes can make burn operations substantially slower. They cannot guarantee physical erasure on SSDs or flash storage. Continue?"})
        chk(l, "blur", "Lock instantly when the window loses focus"); chk(l, "ro_always", "Always open read-only", "Every sign-in becomes a safe, view-only session.", "Always-open read-only prevents all changes until you disable it with the master password.")
        l = sec("Privacy")
        privacy_layout = l
        chk(l, "nocap", "Block screenshots & screen recording (Windows)", "UNKNWN windows appear black to capture tools."); chk(l, "mask", "Mask file names in the list", "Names show as hidden until you open the file.")
        chk(l, "hideuser", "Use a generic greeting instead of the Windows account name", "Keeps the account-folder name out of the application header.")
        chk(l, "clip", "Clear the clipboard on lock and exit", warning={
            True: "The app will clear the clipboard when you lock or exit. This can interrupt copy/paste work in other applications. Enable it?",
            False: "With automatic clearing disabled, copied decrypted content may remain in the clipboard after lock or exit. Disable this protection?"})
        chk(l, "export", "Allow saving decrypted copies", "Turn off so files can only ever be viewed.",
            (False, "Disabling exports prevents you from saving decrypted copies from the viewer. You can re-enable it later, but first make sure you do not rely on exporting files. Continue?"))
        chk(l, "log", "Record encrypted activity history", "Stores bounded per-session action logs and sign-in history under this vault's key. Passwords, recovery words, and file contents are never recorded.",
            (False, "Disabling this stops recording session and sign-in history. Continue?"))
        chk(l, "nocopy", "Disable copying in the viewer", "Text files open without selection or a right-click menu.",
            "Disabling copying makes it harder to move text from the viewer into other apps. You can re-enable copying later.")
        chk(l, "minlock", "Lock when the window is minimized", warning="Minimizing the app will immediately lock the vault, so you may need to unlock again when returning. Enable this?")
        chk(l, "logwipe", "Erase activity history when UNKNWN closes", warning="This permanently removes encrypted session and sign-in history each time the app closes. Enable it?")
        chk(l, "hidecnt", "Hide the number of sealed files")
        drop(l, "vmode", "Video/audio playback (disk mode uses less RAM but stores temporary plaintext)", [("Disk (default): stream to a temporary plaintext file; lower RAM use", "file"), ("Memory: no app-created media file; may use substantial RAM", "mem"), ("Off: show file info only", "off")],
             {"file": "Disk playback streams authenticated decryption directly to a temporary plaintext file. A crash or power loss may leave it behind; overwrite-and-delete cannot guarantee physical erasure, especially on SSDs. Ghost mode always overrides this and uses memory. Enable disk playback?",
              "mem": "Memory playback avoids an app-created plaintext file but keeps the media in RAM and may use substantial memory. OS paging may still write memory to disk. Use memory playback?"})
        l.addWidget(lbl("Disk is the default to reduce RAM use. Decrypted media is temporarily stored under UNKNWN data; switching modes asks for confirmation. Ghost mode forces memory playback.", 11, DIM))
        drop(l, "vclose", "Auto-close the viewer", [("Never", 0), ("After 15 seconds", 15), ("After 30 seconds", 30), ("After 1 minute", 60), ("After 5 minutes", 300)],
             {15: "The viewer will close automatically after 15 seconds. For a file with a one-view limit, closing it also burns it. Continue?",
              30: "The viewer will close automatically after 30 seconds. For a file with a one-view limit, closing it also burns it. Continue?",
              60: "The viewer will close automatically after one minute. For a file with a one-view limit, closing it also burns it. Continue?",
              300: "The viewer will close automatically after five minutes. For a file with a one-view limit, closing it also burns it. Continue?"})
        drop(l, "title", "Window title (disguise)", [("UNKNWN", "UNKNWN"), ("Notepad", "Notepad"), ("Calculator", "Calculator"), ("Settings", "Settings")],
             {"Notepad": "Using a misleading title can make the app harder to identify and troubleshoot. Continue?",
              "Calculator": "Using a misleading title can make the app harder to identify and troubleshoot. Continue?",
              "Settings": "Using a misleading title can make the app harder to identify and troubleshoot. Continue?"})
        l = sec("Ghost mode", "Leaves as little trace as possible. Nothing can promise safety from malware that already runs on this PC.")
        chk(l, "ghost", "Ghost mode: no sign-in log, hidden from screen capture, taskbar and Alt-Tab, disguised title, locks on minimize or focus loss, no intro, no crash log",
            "Ghost mode combines several settings, hides the app, suppresses diagnostic logs and may make it harder to recover or troubleshoot the session. It does not protect against malware already running on the PC. Enable it?")
        chk(l, "keypad", "On-screen keyboard button on the login screen", "This may avoid some physical keystroke capture, but does not defeat screen capture, accessibility hooks, or malware.")
        chk(l, "dimidle", "Fade the window to almost invisible when idle")
        chk(l, "exitclean", "Delete crash logs and cache when UNKNWN closes", "This removes local troubleshooting logs and Python cache files on exit. You may lose evidence needed to diagnose a problem.")
        drop(l, "cliptime", "Clear the clipboard automatically", [("Never", 0), ("After 10 seconds", 10), ("After 30 seconds", 30), ("After 1 minute", 60)],
             {10: "Clipboard contents will be cleared after 10 seconds, which may interrupt a copy/paste operation. Continue?",
              30: "Clipboard contents will be cleared after 30 seconds, which may interrupt a copy/paste operation. Continue?",
              60: "Clipboard contents will be cleared after one minute, which may interrupt a copy/paste operation. Continue?"})
        privacy_layout.addWidget(lbl("ADVANCED PRIVACY", 13, ACC, True))
        advanced_privacy = QWidget()
        advanced_privacy_layout = QVBoxLayout(advanced_privacy)
        advanced_privacy_layout.setContentsMargins(0, 0, 0, 0)
        advanced_privacy_layout.setSpacing(9)
        advanced_privacy_locked = lock_on() and not self.owner
        advanced_privacy.setEnabled(not advanced_privacy_locked)
        if advanced_privacy_locked:
            privacy_layout.addWidget(lbl("Unlock protected settings above to change these options.", 11, MUT))
        privacy_layout.addWidget(advanced_privacy)
        l = advanced_privacy_layout
        chk(l, "reauth", "Ask for the password again before opening any file"); chk(l, "boss", "Boss key: press Esc twice to lock and minimize instantly")
        chk(l, "remote", "Block sign-in during Remote Desktop sessions (Windows)", "You will not be able to unlock the vault through Remote Desktop, even when you are its legitimate user.",
            "This blocks all vault sign-ins through Remote Desktop, including your own legitimate sessions. Enable it?")
        chk(l, "dbg", "Lock if a debugger is attached", "Developer tools and some diagnostics may trigger a lock. Disable this only if you understand the debugging risk.",
            "Debuggers and some diagnostic tools can trigger a lock and interrupt your session. Enable this?")
        chk(l, "hidename", "Hide file names in viewer titles")
        drop(l, "sess", "Maximum session length", [("Unlimited", 0), ("15 minutes", 15), ("30 minutes", 30), ("1 hour", 60), ("4 hours", 240)],
             {15: "The vault will lock after 15 minutes, including during a long task. Unsaved work outside the vault is not affected, but you may need to unlock again. Continue?",
              30: "The vault will lock after 30 minutes, including during a long task. Continue?",
              60: "The vault will lock after one hour, including during a long task. Continue?",
              240: "The vault will lock after four hours, including during a long task. Continue?"})
        l.addWidget(lbl("Unlimited leaves the session open until manually locked or closed.", 11, DIM))
        drop(l, "maxtf", "Wipe after this many failed sign-ins in total (never resets)", [("Off", 0), ("10", 10), ("25", 25), ("50", 50)],
             {10: "After 10 failed sign-ins over the vault's lifetime, the entire vault is permanently destroyed. The counter never resets. Enable this?",
              25: "After 25 failed sign-ins over the vault's lifetime, the entire vault is permanently destroyed. The counter never resets. Enable this?",
              50: "After 50 failed sign-ins over the vault's lifetime, the entire vault is permanently destroyed. The counter never resets. Enable this?"})
        chk(l, "bind", "Bind the vault to this PC: refuse to open on any other computer",
            "Hardware fingerprints can change after system repairs or hardware changes. Binding also prevents normal portable use.",
            "The vault may refuse to open after hardware or system changes and will not work as a portable vault. Keep a backup and recovery words accessible. Bind this vault?")
        l = sec("Appearance", "Pick a look or build your own. Changes apply right away.")
        sb = btn("Open Look studio: themes, backgrounds, effects...", "go"); sb.clicked.connect(self.look_studio); l.addWidget(sb)
        l.addWidget(lbl(
            "Login colors follow the active theme unless you set a per-profile override below.",
            11, MUT))
        login_color_row = QHBoxLayout()
        for key, label in (("lbg", "Login background"), ("lfg", "Login text"),
                           ("lac", "Login accent")):
            color_button = btn(label)
            color_button.clicked.connect(
                _clicked_slot(self.pick_login_color, key))
            login_color_row.addWidget(color_button)
        l.addLayout(login_color_row)
        reset_login_colors = btn("Reset login colors to active theme", "flat")
        def reset_login_palette() -> None:
            for key in ("lbg", "lfg", "lac"):
                self.put(key, "")
            if self.mode == "login":
                self.login_screen()
        reset_login_colors.clicked.connect(reset_login_palette)
        l.addWidget(reset_login_colors)
        avatar_row = QHBoxLayout()
        avatar_row.addWidget(self.avatar_label(44))
        avatar_row.addWidget(lbl(
            "Vault profile photo. Stored locally as an appearance asset, not encrypted Vault content.",
            11, MUT), 1)
        choose_avatar = btn("Choose profile photo...")
        remove_avatar = btn("Remove photo", "flat")
        choose_avatar.clicked.connect(self.pick_vault_avatar)
        remove_avatar.clicked.connect(self.remove_vault_avatar)
        avatar_row.addWidget(choose_avatar)
        avatar_row.addWidget(remove_avatar)
        l.addLayout(avatar_row)
        avatar_crop = self.combo([
            ("Center", "center"),
            ("Top", "top"),
            ("Top left", "top-left"),
            ("Top right", "top-right"),
            ("Left", "left"),
            ("Right", "right"),
            ("Bottom", "bottom"),
            ("Bottom left", "bottom-left"),
            ("Bottom right", "bottom-right"),
        ])
        avatar_crop.setCurrentIndex(avatar_crop.findData(S("avatar_crop")))
        def set_avatar_crop() -> None:
            self.put("avatar_crop", avatar_crop.currentData())
            self._refresh_profile_photo()
        avatar_crop.currentIndexChanged.connect(_index_changed_slot(set_avatar_crop))
        avatar_crop.setAccessibleName("Vault profile photo framing")
        avatar_crop.setToolTip("Choose which part of the photo stays in the circular profile crop.")
        l.addWidget(lbl("Profile photo framing", 12, MUT))
        l.addWidget(avatar_crop)
        chk(l, "reduce_motion", "Reduce decorative motion",
            "Pauses animated backgrounds and removes hover, ripple, screen-fade, and tab-transition effects. Login and security workflows remain unchanged.")
        drop(l, "intro", "Terminal intro with a quote at start", [("Off", 0), ("On", 1)])
        drop(l, "perf", "Performance", [("Auto (detect weak device)", "auto"), ("Full", "full"), ("Lite: fewer effects", "lite"), ("Minimal: no animated background", "min")])
        l.addWidget(lbl("Full effects can increase CPU/GPU use and battery drain; Auto is recommended for older devices.", 11, DIM))
        drop(l, "winop", "Window opacity", [("100%", 100), ("90%", 90), ("80%", 80), ("65%", 65), ("50%", 50)])
        l.addWidget(lbl("Lower opacity can make the interface difficult to read against some backgrounds.", 11, DIM))
        drop(l, "wipefx", "Panic and self-destruct animation", [("Full inferno", "full"), ("Short", "short"), ("Almost instant", "none")],
             {"none": "This only shortens the visual effect; it does not cancel, delay, or undo a wipe. Continue?"})
        l = sec("Shortcut manager", "Configure the panic shortcut and its action. Unsafe, reserved, or conflicting key combinations are rejected.")
        ke = QKeySequenceEdit(QKeySequence(S("hk"))); self.hk_edit = ke
        ke.keySequenceChanged.connect(self.set_hk); r = QHBoxLayout(); r.addWidget(lbl("Shortcut (click, then press keys)", 13), 1); r.addWidget(ke); l.addLayout(r)
        ac = self.combo([("Lock the vault", "lock"), ("Wipe vault data (burn all files)", "wipe"), ("FULL SELF-DESTRUCT + restart PC", "destruct")]); ac.setCurrentIndex(ac.findData(S("hk_act")))
        ac.currentIndexChanged.connect(_index_changed_slot(lambda: self.set_act(ac))); r = QHBoxLayout(); r.addWidget(lbl("When pressed", 13), 1); r.addWidget(ac); l.addLayout(r)
        l.addWidget(lbl("Warning: this shortcut directly runs the selected action without an execution confirmation. Choose it carefully; avoid keys you use elsewhere.", 11, "#ffb347"))
        self.shortcut_status_label = lbl("", 11, MUT)
        l.addWidget(self.shortcut_status_label); self.refresh_shortcut_status()
        chk(l, "hk_glob", "Global: also works when UNKNWN is not focused (Windows)", "It captures that shortcut in other apps while UNKNWN runs. This can interfere with normal work; avoid common shortcuts.",
            "The selected shortcut will be captured system-wide while UNKNWN runs, even when another app is active. It may interfere with normal work. Enable global capture?")
        chk(l, "hk_notice", "Show a notice when the panic shortcut is used",
            "Informational only; it does not add, remove, or bypass action confirmations.")
        l = sec("Account & portability")
        p = btn("Change password..."); p.clicked.connect(self.chpw); n = btn(f"Generate {NW} new recovery words..."); n.clicked.connect(self.newrec); l.addWidget(p); l.addWidget(n)
        rk = btn("Rotate vault key (re-encrypt everything)..."); rk.clicked.connect(_clicked_slot(self.rotate)); l.addWidget(rk)
        profiles = sec("Vault profiles / Import & Export",
                      f"Active profile: {active_profile_name or 'Default'}. Every profile has separate encrypted files and its own master password.")
        if active_profile_id:
            rename_profile = btn("Rename this profile...")
            rename_profile.clicked.connect(self.rename_profile_dialog)
            profiles.addWidget(rename_profile)
            preferred = btn("Make this the preferred profile in the chooser")
            preferred.clicked.connect(self.set_default_profile)
            profiles.addWidget(preferred)
        export_button = profile_action_button("Export this vault profile...", self.export_profile_dialog, "go")
        export_button.setEnabled(bool(self.root) and not self.ro)
        import_button = profile_action_button("Import another vault as a new profile...", self.import_profile_dialog)
        chooser_button = btn("Close app to choose another vault profile on next run")
        chooser_button.clicked.connect(lambda: _close_widget(self))
        profiles.addWidget(export_button); profiles.addWidget(import_button); profiles.addWidget(chooser_button)
        if active_profile_id:
            try:
                pending_exports = _pending_profile_exports(active_profile_id)
            except Exception as exc:
                pending_exports = []
                profiles.addWidget(lbl(
                    support_message(f"Interrupted export recovery is unavailable ({type(exc).__name__}). No pending export was resumed."),
                    11, "#ffb347"))
            for record in pending_exports:
                resume_export = btn("Resume interrupted export...")
                resume_export.clicked.connect(_clicked_slot(self.export_profile_dialog, record))
                profiles.addWidget(resume_export)
        l.addWidget(lbl(f"Data folder: {HOME}" + ("   (portable)" if HOME == PORT else ""), 12, MUT))
        m = btn("Move data back to this PC" if HOME == PORT else "Make portable: move data next to the app")
        m.clicked.connect(_clicked_slot(self.move_data))
        supported_move_home = HOME.resolve() in {PORT.resolve(), (Path.home() / ".unknwn").resolve()}
        m.setEnabled(supported_move_home and (self.owner or not lock_on()))
        l.addWidget(m)
        v.addWidget(nw); l = sec("Danger zone", "These work even in a read-only session.", v)
        a = btn("Wipe vault data now", "danger"); a.clicked.connect(_clicked_slot(self.panic, True)); b = btn("FULL SELF-DESTRUCT: erase everything, delete UNKNWN, restart PC", "danger"); b.clicked.connect(_clicked_slot(self.destruct, True)); l.addWidget(a); l.addWidget(b)
        for i, (section, _title, protected) in enumerate(secs):
            section.setEnabled(not (protected and lock_on() and not self.owner)); self.pop(section, i * 110)
        return w
    def lock_ui(self, v: QVBoxLayout) -> None:
        c = QFrame(); c.setObjectName("card"); l = QVBoxLayout(c); on = lock_on(); root = self.root
        bad = on and (root is None or not lock_bound(root))
        l.addWidget(lbl("Settings password", 15, bold=True))
        l.addWidget(lbl("The lock record was changed outside UNKNWN, so protected settings stay locked." if bad else "Locks the security, advanced privacy and panic settings behind a password only you choose. It is stored as a salted hash, never in the code.", 12, MUT)); r = QHBoxLayout()
        if not on: b = btn("Set a settings password...", "go"); b.clicked.connect(_clicked_slot(self.lock_set)); r.addWidget(b)
        elif not bad and not self.owner: b = btn("Unlock protected settings..."); b.clicked.connect(self.lock_unlock); r.addWidget(b)
        elif not bad:
            for t, f in (("Lock now", self.lock_now), ("Change password...", self.lock_set), ("Remove password...", self.lock_drop)): b = btn(t); b.clicked.connect(_clicked_slot(f)); r.addWidget(b)
        l.addLayout(r); v.addWidget(c)
    def lock_set(self) -> Optional[int]:
        root = self.root
        if root is None:
            return QMessageBox.warning(self, "Vault locked", "Unlock the vault before changing its settings password.")
        a, ok = QInputDialog.getText(self, "Settings password", "New settings password (at least 10 characters):", QLineEdit.EchoMode.Password)
        if not ok: return
        if len(a) < 10: return QMessageBox.warning(self, "Too short", "Use at least 10 characters.")
        b, ok = QInputDialog.getText(self, "Settings password", "Type it again:", QLineEdit.EchoMode.Password)
        if not ok or a != b: return QMessageBox.warning(self, "Settings password", "The two passwords did not match.")
        salt = os.urandom(16); h = slk_hash(a, salt)
        candidate = copy.deepcopy(cfg)
        candidate["slk"] = {"s": b64e(salt), "h": b64e(h)}
        candidate["slc"] = b64e(seal(root, b"slk:" + h))
        try:
            commit_config_transaction(candidate)
        except (OSError, TypeError, ValueError) as exc:
            return QMessageBox.warning(
                self, "Settings password not saved",
                f"The settings password could not be saved ({type(exc).__name__}). "
                "No settings-lock change was applied.")
        self.owner = True; self.tab(1)
    def lock_unlock(self) -> None:
        pw, ok = QInputDialog.getText(self, "Settings password", "Settings password:", QLineEdit.EchoMode.Password)
        if not ok: return
        if lock_ok(pw): self.owner = True; self.tab(1)
        else: QMessageBox.warning(self, "Settings password", "That password is not correct.")
    def lock_now(self) -> None: self.owner = False; self.tab(1)
    def lock_drop(self) -> None:
        if QMessageBox.question(self, "Remove settings password", "This removes the extra password protecting high-impact security settings. The vault master password is still required to sign in. Remove this protection?") != QMessageBox.StandardButton.Yes: return
        candidate = copy.deepcopy(cfg)
        candidate.pop("slk", None); candidate.pop("slc", None)
        try:
            commit_config_transaction(candidate)
        except (OSError, TypeError, ValueError) as exc:
            QMessageBox.warning(
                self, "Settings password not removed",
                f"The settings password could not be removed ({type(exc).__name__}). "
                "The existing settings lock remains active.")
            return
        self.owner = False; self.tab(1)
    def clipchg(self) -> None:
        if S("cliptime"): QTimer.singleShot(S("cliptime") * 1000, clear_clipboard)
    def keypad(self) -> None: d = Keypad(self, self.pw.text()); d.exec_(); self.pw.setText(d.v); self.pw.setFocus()
    def ghost_apply(self) -> None:
        g = bool(S("ghost")); nocap(self, g or S("nocap")); self.setWindowTitle(random.choice(["Notepad", "Calculator", "Settings"]) if g else S("title"))
        if sys.platform == "win32":
            try:
                h = int(self.winId()); u = ctypes.windll.user32; st = u.GetWindowLongW(h, -20); ns = ((st | 0x80) & ~0x40000) if g else ((st & ~0x80) | 0x40000)
                if ns != st:
                    u.SetWindowLongW(h, -20, ns)
                    u.SetWindowPos(h, 0, 0, 0, 0, 0, WINDOW_FRAME_REFRESH_FLAGS)
            except Exception: pass
    def integ_fail(self, category: Optional[IG.GateError] = None) -> None:
        """Fail closed: no login, no vault, nothing deleted."""
        global integ_error
        if category is not None:
            integ_error = category
        elif not integ_error:
            integ_error = "release_integrity"
        INTEG[0] = "fail"; self.root = None; self.ro = False; self.cards.clear(); self.cds.clear()
        cfg.clear(); idx.clear()
        for dialog in (
            getattr(self, "move_dialog", None),
            getattr(self, "seal_dialog", None),
            getattr(self, "vault_analysis_dialog", None),
            getattr(self, "package_dialog", None),
        ):
            if isinstance(dialog, (MoveProgressDialog, _SealProgressDialog, VaultAnalysisDialog, PackageProgressDialog)):
                if dialog.is_running:
                    dialog.request_cancel()
        if self.dlg: self.dlg.reject()
        if release_integrity_state == "ok":
            cleanup_temp_files()
        if not S("ghost") and not getattr(self, "il", 0):
            self.il = 1
            try: HOME.mkdir(parents=True, exist_ok=True); open(HOME / "integrity.log", "a").write(tfmt(time.time()) + "  integrity check failed\n")
            except Exception: pass
        self._integrity_exit_started = False
        self.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        self.setFocus()
        b = btn("Quit"); b.clicked.connect(self.acknowledge_integrity_failure)
        message = (
            "A required startup security check or state validation failed.\n\n"
            f"Diagnostic category: {integ_error}\n\n"
            "For your protection, secure operations have been disabled.\n\n"
            "Please reinstall UNKNWN from a trusted release.\n\n"
            "Press any key to exit, or choose Quit."
        )
        self.integrity_message = lbl(support_message(message), 14, MUT, center=True)
        self.failure_indicator = SecurityFailurePulse(self)
        self.show_w(self.panel(self.logo(), lbl("UNKNWN Security Check Failed", 26, bold=True, center=True),
                         self.failure_indicator, self.integrity_message, b), "blocked")
    def acknowledge_integrity_failure(self) -> None:
        if self.mode != "blocked" or getattr(self, "_integrity_exit_started", False):
            return
        self._integrity_exit_started = True
        if self.working():
            message = getattr(self, "integrity_message", None)
            if message is not None:
                message.setText(
                    "Stopping an in-progress operation safely. The application will exit when it finishes."
                )
            QTimer.singleShot(50, _noarg_slot(self._complete_integrity_exit))
            return
        _close_widget(self)
    def _complete_integrity_exit(self) -> None:
        if self.mode != "blocked" or not getattr(self, "_integrity_exit_started", False):
            return
        if self.working():
            QTimer.singleShot(50, _noarg_slot(self._complete_integrity_exit))
            return
        _close_widget(self)
    def keyPressEvent(self, a0: Any) -> None:
        if (self.mode == "blocked"
                and not a0.isAutoRepeat()
                and a0.key() != Qt.Key.Key_unknown):
            self.acknowledge_integrity_failure()
            return
        super().keyPressEvent(a0)
    def integ_ok(self) -> bool:
        if INTEG[0] == "fail": self.integ_fail(); return False
        if INTEG[0] == "ok" and not IG.spot(2):
            self.integ_fail("package_integrity_changed")
            return False
        return True
    def working(self) -> bool:
        return App.other_working(self) or App.sealing_in_background(self)
    def other_working(self) -> bool:
        move_dialog = getattr(self, "move_dialog", None)
        analysis_dialog = getattr(self, "vault_analysis_dialog", None)
        package_dialog = getattr(self, "package_dialog", None)
        return (any(w.isVisible() for w in self.findChildren(Upload)) or
                bool(isinstance(move_dialog, MoveProgressDialog) and move_dialog.is_running) or
                bool(isinstance(analysis_dialog, VaultAnalysisDialog) and analysis_dialog.is_running) or
                bool(isinstance(package_dialog, PackageProgressDialog) and package_dialog.is_running))
    def sealing_in_background(self) -> bool:
        dialog = getattr(self, "seal_dialog", None)
        queue = App._seal_queue_jobs(self)
        return (getattr(self, "_seal_queue_active", False) is True
                or bool(queue)
                or isinstance(dialog, _SealProgressDialog) and dialog.is_running)
    def _seal_queue_jobs(self) -> list[_SealQueueJob]:
        queue_value: object = getattr(self, "_seal_queue", None)
        if isinstance(queue_value, list):
            return cast(list[_SealQueueJob], queue_value)
        return list[_SealQueueJob]()
    def _update_seal_queue_status(self) -> None:
        dialog = getattr(self, "seal_dialog", None)
        if isinstance(dialog, _SealProgressDialog):
            dialog.set_queued_count(len(App._seal_queue_jobs(self)))
    def _discard_queued_seal_jobs(self) -> int:
        queue = App._seal_queue_jobs(self)
        discarded = list(queue)
        queue.clear()
        for _label, _root, _factory, _finished, cleanup in discarded:
            if cleanup is not None:
                cleanup()
        self._update_seal_queue_status()
        return len(discarded)
    def cancel_queued_seal_jobs(self) -> None:
        queue = App._seal_queue_jobs(self)
        if not queue:
            return
        names = "\n".join(f"• {sanitize_text(job[0], 100)}" for job in queue[:12])
        if len(queue) > 12:
            names += f"\n…and {len(queue) - 12} more job(s)."
        if QMessageBox.question(
                self, "Cancel queued encryption jobs",
                "These jobs have not started and their source files will remain unchanged. "
                "Only the queued jobs below will be removed from the queue:\n\n"
                + names + "\n\nContinue?",
                cast(Any, QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No),
                QMessageBox.StandardButton.No) != QMessageBox.StandardButton.Yes:
            return
        count = self._discard_queued_seal_jobs()
        if count:
            QMessageBox.information(
                self, "Queued jobs cancelled",
                f"{count} queued encryption job(s) were cancelled before starting. "
                "Their source files were not changed.")
    def _queue_seal_job(
        self,
        label: str,
        expected_root: bytes,
        factory: Callable[[], Union[_SealWorker, _FolderSealWorker]],
        on_finished: Callable[[Mapping[str, Any]], None],
        cleanup: Optional[Callable[[], None]] = None,
    ) -> None:
        queue_value = getattr(self, "_seal_queue", None)
        if not isinstance(queue_value, list):
            queue: list[_SealQueueJob] = []
            self._seal_queue = queue
        else:
            queue = cast(list[_SealQueueJob], queue_value)
        queue.append((label, expected_root, factory, on_finished, cleanup))
        self._update_seal_queue_status()
        if getattr(self, "_seal_queue_active", False) is not True:
            self._start_next_seal_job()
    def _start_next_seal_job(self) -> None:
        if getattr(self, "_seal_queue_active", False) is True:
            return
        queue = App._seal_queue_jobs(self)
        if not queue:
            self._update_seal_queue_status()
            if getattr(self, "_pending_seal_action", None) is not None:
                self.run_pending_seal_action()
            return
        if getattr(self, "_pending_seal_action", None) is not None:
            self._discard_queued_seal_jobs()
            self.run_pending_seal_action()
            return
        label, expected_root, factory, on_finished, cleanup = queue.pop(0)
        self._update_seal_queue_status()
        if self.root is None or self.root != expected_root or self.ro or self.mode != "vault":
            if cleanup is not None:
                cleanup()
            QMessageBox.warning(
                self, "Queued encryption unavailable",
                f"{sanitize_text(label, 100)} was not started because the original Vault session is no longer active. "
                "Its source files were not changed.")
            QTimer.singleShot(0, _noarg_slot(self._start_next_seal_job))
            return
        try:
            worker = factory()
        except Exception as exc:
            if cleanup is not None:
                cleanup()
            log_security_event("queued_seal_worker_creation_failed", error=type(exc).__name__)
            QMessageBox.warning(
                self, "Could not start queued encryption",
                f"{sanitize_text(label, 100)} was not started ({type(exc).__name__}). "
                "Its source files were not changed.")
            QTimer.singleShot(0, _noarg_slot(self._start_next_seal_job))
            return
        self._seal_queue_active = True
        self._seal_active_cleanup = cleanup
        dialog = _SealProgressDialog(
            self, worker, on_finished, title=label,
            cancel_queued=self.cancel_queued_seal_jobs)
        self.seal_dialog = dialog
        dialog.set_queued_count(len(queue))
        self.refresh_vault_item_actions()
        dialog.show()
        try:
            _start_qrunnable(worker)
        except Exception as exc:
            if worker.operation.snapshot.state not in {
                OperationState.COMPLETED, OperationState.FAILED,
                OperationState.CANCELED, OperationState.RECOVERY_FAILED,
            }:
                worker.operation.fail(type(exc).__name__)
            dialog.finish({
                "status": "failed",
                "records": [],
                "failures": [{"name": "", "detail": f"Background worker could not start ({type(exc).__name__})."}],
                "completed": 0,
                "total": 0,
            })
    def _seal_queue_job_finished(self) -> None:
        cleanup = getattr(self, "_seal_active_cleanup", None)
        self._seal_active_cleanup = None
        self._seal_queue_active = False
        self.seal_dialog = None
        if cleanup is not None:
            cleanup()
        self.refresh_vault_item_actions()
        if getattr(self, "_pending_seal_action", None) is not None:
            QTimer.singleShot(0, _noarg_slot(self.run_pending_seal_action))
        elif App._seal_queue_jobs(self):
            QTimer.singleShot(0, _noarg_slot(self._start_next_seal_job))
    def refresh_vault_item_actions(self) -> None:
        sealing = App.sealing_in_background(self)
        for card in self.cards.values():
            for action in card.findChildren(QPushButton):
                if action.text() not in {"View", "Burn"}:
                    continue
                enabled = not sealing and (action.text() != "Burn" or not self.ro)
                action.setEnabled(enabled)
                action.setToolTip(
                    "Unavailable while encryption is using the vault." if sealing else "")
    def defer_seal_action(self, action: str, argument: bool) -> bool:
        dialog = getattr(self, "seal_dialog", None)
        self._discard_queued_seal_jobs()
        if dialog is None or not dialog.is_running:
            return False
        if getattr(self, "_pending_seal_action", None) is None:
            self._pending_seal_action = (action, argument)
        dialog.request_cancel()
        dialog.status.setText(
            "A security action is queued. The active seal will cancel at a safe checkpoint; "
            "queued jobs were discarded before they could start.")
        return True
    def run_pending_seal_action(self) -> None:
        pending = getattr(self, "_pending_seal_action", None)
        if pending is None:
            return
        self._pending_seal_action = None
        action, argument = pending
        if action == "lock":
            QTimer.singleShot(0, _noarg_slot(lambda: self.lock(argument)))
        elif action == "panic":
            QTimer.singleShot(0, _noarg_slot(lambda: self.panic(argument)))
        elif action == "destruct":
            QTimer.singleShot(0, _noarg_slot(lambda: self.destruct(argument)))
    def look_studio(self) -> None:
        old = getattr(self, "studio", None)
        if old is not None: old.close()
        d = QDialog(self); self.studio = d; d.setWindowTitle("Look studio"); screen = self.screen(); area = screen.availableGeometry() if screen is not None else QRect(0, 0, 900, 700)
        d.resize(min(800, max(320, area.width() - 24)), min(720, max(320, area.height() - 48))); v = QVBoxLayout(d); v.setContentsMargins(0, 0, 0, 0); v.setSpacing(0)
        preview = Preview(); v.addWidget(preview); d.finished.connect(preview.stop_animation); self.pop(preview, 90)
        sa = QScrollArea(); sa.setWidgetResizable(True); sa.setFrameShape(QFrame.Shape.NoFrame); body = QWidget(); bl = QVBoxLayout(body); bl.setContentsMargins(22, 16, 22, 16); bl.setSpacing(10); sa.setWidget(body); v.addWidget(sa, 1)
        bl.addWidget(tlbl("> look --studio", 18, TH["acc"])); bl.addWidget(lbl("Themes and backgrounds in one place. Everything applies live; the strip above is the real renderer.", 12, MUT))
        def reopen() -> None: d.close(); QTimer.singleShot(80, self.look_studio)
        def pick_theme(k: str) -> None:
            if k == "tired":
                self.put("bg", "tiredfield")
            self.set_th(k)
            reopen()
        bl.addWidget(lbl("THEME", 13, ACC, True)); gr = QGridLayout(); gr.setSpacing(8); theme_cols = max(2, min(5, (d.width() - 64) // 134))
        for i, (nm, k) in enumerate(THEMES):
            swatch = Swatch(k, nm, pick_theme, S("th") == k); gr.addWidget(swatch, i // theme_cols, i % theme_cols); self.pop(swatch, i * 28)
        bl.addLayout(gr); r = QHBoxLayout()
        for k, t in (("tbg", "background"), ("tfg", "text"), ("tac", "accent")):
            b = btn(f"Custom {t}  {S(k)}")
            def pick_custom_color(_checked: bool = False, key: str = k) -> None:
                self.pick(key)
                reopen()
            b.clicked.connect(pick_custom_color); r.addWidget(b)
        bl.addLayout(r); bl.addWidget(lbl("BACKGROUND", 13, ACC, True)); bl.addWidget(lbl(
            f"Choose from {sum(key in ANIM for _, key in BGS)} animated and "
            f"{sum(key in STILL for _, key in BGS)} still scenes. Static scenes stop the background timer; "
            "Minimal performance mode pauses animation.", 11, MUT))
        gb = QGridLayout(); gb.setSpacing(8); bt: dict[str, QPushButton] = {}; names: dict[str, str] = {k: n for n, k in BGS}
        def mark() -> None:
            for kk, b in bt.items(): b.setText(("[x] " if S("bg") == kk else "[ ] ") + names[kk])
        def setbg(k: str) -> None:
            if k == "photo" and not (HOME / "bg.img").exists(): self.pick_photo()
            else: self.put("bg", k)
            mark()
        for i, (nm, k) in enumerate(BGS):
            b = btn(""); b.setToolTip(nm); b.clicked.connect(_clicked_slot(setbg, k)); bt[k] = b; gb.addWidget(b, i // 3, i % 3); self.pop(b, 120 + i * 22)
        mark(); bl.addLayout(gb); bl.addWidget(lbl("TUNING", 13, ACC, True))
        def slider(k: str, t: str, lo: int, hi: int) -> None:
            r = QHBoxLayout(); lab = lbl(f"{t}: {S(k)}%", 13); sl = QSlider(Qt.Orientation.Horizontal); sl.setRange(lo, hi); sl.setValue(int(S(k)))
            def ch(x: int) -> None:
                lab.setText(f"{t}: {x}%")
                if sl.isSliderDown(): cfg.setdefault("set", {})[k] = x   # live while dragging, saved on release
                else: self.put(k, x)
            sl.valueChanged.connect(ch); sl.sliderReleased.connect(lambda: self.put(k, sl.value())); r.addWidget(lab, 1); r.addWidget(sl, 2); bl.addLayout(r)
        slider("bgspd", "Animation speed", 25, 250); slider("bgden", "Density / intensity", 20, 250)
        bl.addWidget(lbl("Higher speed and density increase visual intensity and rendering work.", 11, MUT))
        for k, t in (("tstyle", "Terminal style: monospace font and square corners"),
                     ("crt", "CRT scanlines and brief glitch on animated backgrounds"),
                     ("bgfocus", "Pause animated backgrounds when UNKNWN is minimized or not focused")):
            c = QCheckBox(t); c.setChecked(bool(S(k)))
            def update_setting(enabled: bool, key: str = k) -> None:
                self.put(key, enabled)
            c.toggled.connect(update_setting); bl.addWidget(c)
        r = QHBoxLayout(); b1 = btn("Choose photo..."); b2 = btn("Remove photo")
        def choose_photo() -> None:
            self.pick_photo()
            mark()
        def remove_photo() -> None:
            self.drop_photo()
            mark()
        b1.clicked.connect(_clicked_slot(choose_photo)); b2.clicked.connect(_clicked_slot(remove_photo)); r.addWidget(b1); r.addWidget(b2); bl.addLayout(r)
        def reset() -> None:
            for k, x in dict(bg="termlog", bgspd=100, bgden=100, tstyle=True, crt=True).items(): self.put(k, x)
            self.set_th("matrix"); reopen()
        rb = btn("Reset look to default"); rb.clicked.connect(reset); cb = btn("Close", "go"); cb.clicked.connect(lambda: _close_widget(d)); bl.addWidget(rb); bl.addWidget(cb); d.show(); self.pop(d)
    def rotate(self) -> Optional[int]:
        if self.ro or self.working(): return
        root = self.root
        if root is None: return
        if QMessageBox.question(self, "Rotate vault key", "This creates a brand-new vault key and re-encrypts EVERY file with it. An old copy of your data folder (and the old password and recovery words) will still open what it already contained, but nothing in your live vault from now on.\n\nBig vaults take a while and you must not close the app meanwhile. A crash is safe: the app finishes the job on the next start.\n\nYou will get NEW recovery words. Continue?") != QMessageBox.StandardButton.Yes: return
        pw, ok = QInputDialog.getText(self, "Confirm it is you", "Master password:", QLineEdit.EchoMode.Password)
        if not ok: return
        try:
            if unseal(kdf(pw, b64d(cfg["s1"])), b64d(cfg["wp"])) != root: raise InvalidTag()
        except InvalidTag: return QMessageBox.warning(self, "Wrong password", "That is not the master password.")
        u = Upload(self); u.show()
        avatar_data = self._vault_avatar_data()
        try: new, phrase = rotate_vault(root, pw, lambda f, t: u.pump(f, t))
        except Exception as e: u.close(); return QMessageBox.warning(self, "Rotation failed", f"Nothing was changed.\n\n{e}")
        self.root = new
        if avatar_data is not None:
            try:
                self._write_vault_avatar(avatar_data)
            except (OSError, ValueError, RuntimeError) as exc:
                log_security_event("vault_avatar_rekey_failed", error=type(exc).__name__)
                QMessageBox.warning(
                    self, "Profile photo needs to be chosen again",
                    "Vault key rotation succeeded, but the encrypted profile photo could not be updated. "
                    "Choose the photo again in Appearance.")
        u.finish("Vault key rotated."); u.close(); self.recovery_screen(phrase, self.vault_screen)
    def sec_ok(self, capability: VaultCapability = "sensitive_action") -> bool:
        """Apply the release-trust gate and, when requested, an authenticated-session capability gate."""
        if not self.integ_ok(): return False
        if COMPILED:
            runtime = IG.runtime_trust()
            if runtime != "clear":
                self.integ_fail(
                    "runtime_debugger_detected" if runtime == "debugger"
                    else "runtime_check_unavailable"
                )
                return False
        if S("dbg") and dbg_now(): QMessageBox.warning(self, "Security", "A debugger or tracer was detected, so this action is blocked."); return False
        if capability != "sensitive_action":
            reason = capability_block_reason(
                capability,
                authenticated=getattr(self, "root", None) is not None,
                read_only=bool(getattr(self, "ro", False)),
                recovery_pending=storage_txn_path().exists() or (HOME / "rotate.json").exists(),
            )
            if reason is not None:
                QMessageBox.warning(self, "Capability unavailable", reason)
                return False
        return True
    def ro_off(self) -> Optional[int]:
        if lock_on() and not self.owner: return QMessageBox.warning(self, "Settings password", "Unlock protected settings first (Settings password card above).")
        if not self.ask_pw(): return
        self.put("ro_always", False); self.tab(1); QMessageBox.information(self, "Done", "Turned off. Lock and sign in again for a normal session.")
    def ask_pw(self) -> bool:
        pw, ok = QInputDialog.getText(self, "Confirm it is you", "Master password:", QLineEdit.EchoMode.Password)
        if not ok: return False
        try: unseal(kdf(pw, b64d(cfg["s1"])), b64d(cfg["wp"])); return True
        except InvalidTag: QMessageBox.warning(self, "Wrong password", "That is not the master password."); return False
    def pick_photo(self) -> None:
        p, _ = QFileDialog.getOpenFileName(self, "Choose a background photo", "", "Images (*.png *.jpg *.jpeg *.bmp *.webp)"); pm = QPixmap(p) if p else QPixmap()
        if pm.isNull(): return
        HOME.mkdir(parents=True, exist_ok=True); pm.scaled(1920, 1080, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation).save(str(HOME / "bg.img"), "JPG", 85); self.px = None; self.put("bg", "photo"); self.tab(1)
    def drop_photo(self) -> None:
        try: (HOME / "bg.img").unlink()
        except OSError: pass
        self.px = None
        if S("bg") == "photo": self.put("bg", "gradient")
        self.tab(1)
    def set_th(self, n: str) -> None:
        self.put("th", n); _refresh_theme(); self.vault_screen(); self.tab(1)
    def pick(self, k: str) -> None:
        c = QColorDialog.getColor(_QC(S(k)), self, "Pick a color")
        if c.isValid(): self.put(k, c.name()); self.set_th("custom")
    def pick_login_color(self, key: str) -> None:
        fallback = {"lbg": TH["bg0"], "lfg": TH["fg"], "lac": TH["acc"]}[key]
        current = _normalize_theme_color(S(key), fallback)
        color = QColorDialog.getColor(_QC(current), self, "Pick a login color")
        if not color.isValid():
            return
        self.put(key, color.name())
        if self.mode == "login":
            self.login_screen()
    def set_hk(self, ks: QKeySequence) -> None:
        sequence = QKeySequence(ks)
        problem = self.shortcut_problem(sequence)
        if problem:
            QMessageBox.warning(self, "Shortcut rejected", problem)
            if self.hk_edit is not None:
                self.hk_edit.blockSignals(True)
                self.hk_edit.setKeySequence(QKeySequence(S("hk")))
                self.hk_edit.blockSignals(False)
            return
        previous = S("hk")
        portable_text_format: Any = getattr(QKeySequence, "PortableText")
        selected = sequence.toString(portable_text_format)
        if selected == previous: return
        self.put("hk", selected)
        if S("hk") != selected:
            QMessageBox.warning(self, "Shortcut unchanged", "Unlock protected settings before changing the panic shortcut.")
            return
        error = self.apply_hk()
        if error:
            self.put("hk", previous)
            self.apply_hk()
            if self.hk_edit is not None:
                self.hk_edit.blockSignals(True)
                self.hk_edit.setKeySequence(QKeySequence(previous))
                self.hk_edit.blockSignals(False)
            QMessageBox.warning(self, "Shortcut rejected", error)
    def set_act(self, c: QComboBox) -> None:
        self.put("hk_act", c.currentData())
    def open_command_palette(self) -> None:
        if self.mode != "vault":
            return
        entries: list[tuple[str, str, Callable[[], object]]] = []
        entries.extend([
            ("Open Vault", "vault", lambda: self.tab(0)),
            ("Search vault items", "visible names groups types", self.focus_vault_search),
            ("Open Settings", "settings appearance privacy", lambda: self.tab(1)),
            ("Open Activity Center", "activity history sessions", lambda: self.tab(2)),
            ("Open Overview", "dashboard profile", lambda: self.tab(3)),
            ("Switch profile", "profiles", self.switch_profile),
            ("Lock Vault", "lock", self.lock),
            ("Open Diagnostics Center", "diagnostics", self.open_diagnostics_center),
            ("Open Operation Center", "operations progress cancellation", self.open_operation_center),
            ("Open Vault Health / Security Self-Test", "integrity authenticated checks", self.open_health_center),
            ("Open Vault Statistics & Duplicates", "duplicate analysis", self.open_vault_analysis),
            ("Open Look Studio", "themes backgrounds", self.look_studio),
        ])
        for rid, card in self.cards.items():
            visible_name = (
                f"Hidden item {rid[:4]}" if S("mask")
                else sanitize_text(card.name, 160))
            search_data = card.filter_text
            query = rid if S("mask") else card.name
            entries.append((
                f"Vault item: {visible_name}",
                search_data,
                lambda value=query: self.focus_vault_search(value),
            ))
            entries.append((
                f"Inspect item: {visible_name}",
                search_data,
                lambda item_id=rid: self.inspect_vault_item(item_id),
            ))
        if not S("mask"):
            groups: dict[str, str] = {}
            for card in self.cards.values():
                value = cast(dict[str, object], card.meta).get("group")
                if isinstance(value, str) and value.strip():
                    groups.setdefault(value.casefold(), value)
            for group_name in groups.values():
                entries.append((
                    f"Vault group: {sanitize_text(group_name, 64)}",
                    group_name,
                    lambda value=group_name: self.focus_vault_search(value),
                ))
            try:
                profiles = _read_profiles()
            except Exception as exc:
                QMessageBox.warning(
                    self, "Profile search unavailable",
                    f"The local profile list could not be verified ({type(exc).__name__}). "
                    "No profile data was changed.")
            else:
                for profile in profiles:
                    name = sanitize_text(profile["name"], 80)
                    entries.append((
                        f"Profile: {name} — open the profile switcher",
                        name,
                        self.switch_profile,
                    ))
        active_operations = OPERATION_MANAGER.snapshots()
        for snapshot in active_operations:
            operation_name = (
                "Operation name hidden" if S("mask")
                else sanitize_text(snapshot.name, 100))
            entries.append((
                f"Operation: {operation_name} — {snapshot.state.value}",
                snapshot.state.value,
                self.open_operation_center,
            ))
        old = getattr(self, "command_palette", None)
        if old is not None:
            old.close()
        self.command_palette = CommandPaletteDialog(self, entries)
        self.command_palette.show()
        self.command_palette.search.setFocus()
    def focus_vault_search(self, query: str = "") -> None:
        self.tab(0)
        self.search_edit.setText(query)
        self.search_edit.setFocus()
    def open_health_center(self) -> None:
        if getattr(self, "health_dialog", None) is not None:
            self.health_dialog.close()
        self.health_dialog = HealthCenterDialog(self)
        self.health_dialog.show()
    def open_diagnostics_center(self) -> None:
        if getattr(self, "diagnostics_dialog", None) is not None:
            self.diagnostics_dialog.close()
        self.diagnostics_dialog = DiagnosticsCenterDialog(self)
        self.diagnostics_dialog.show()
    def open_operation_center(self) -> None:
        if getattr(self, "operation_dialog", None) is not None:
            self.operation_dialog.close()
        self.operation_dialog = OperationCenterDialog(self)
        self.operation_dialog.show()
    def open_vault_analysis(self) -> Optional[int]:
        if self.ro or not self.sec_ok("vault_read"):
            return
        old = getattr(self, "vault_analysis_dialog", None)
        if old is not None and old.is_running:
            old.raise_()
            old.activateWindow()
            return
        if self.working():
            return QMessageBox.warning(self, "Vault operation in progress",
                                       "Finish or cancel the current vault operation before starting analysis.")
        if old is not None:
            old.close()
        self.vault_analysis_dialog = VaultAnalysisDialog(self)
        self.vault_analysis_dialog.show()
    def build_log(self) -> QWidget:
        w = QWidget(); v = QVBoxLayout(w); v.setAlignment(Qt.AlignmentFlag.AlignTop); L: list[dict[str, object]] = self.logs(); h = QHBoxLayout()
        mode = getattr(self, "log_filter", "all")
        recent_filter = self.combo([("All events", "all"), ("Successful", "success"), ("Failed", "failed")])
        recent_filter.setCurrentIndex(max(0, recent_filter.findData(mode)))
        recent_filter.currentIndexChanged.connect(_index_changed_slot(lambda: self.set_log_filter(recent_filter.currentData())))
        signins = [e for e in L if e.get("type") != "session"]
        session_records = sorted((e for e in L if e.get("type") == "session"),
                                 key=event_time, reverse=True)
        filtered = [e for e in signins if (mode == "all") or (mode == "success" and e.get("ok") is True) or (mode == "failed" and e.get("ok") is False)]
        ok_count = sum(1 for e in signins if e.get("ok") is True)
        fail_count = sum(1 for e in signins if e.get("ok") is False)
        latest = max((e for e in signins if isinstance(e.get("t"), (int, float))), key=event_time, default=None)
        v.addWidget(lbl("ACTIVITY CENTER", 17, ACC, True))
        v.addWidget(lbl("Activity history is encrypted with this vault's key. It keeps up to 50 session logs and 300 sign-in records; session event detail is bounded. Passwords, recovery words, and file contents are never recorded.", 12, MUT))
        history_error = self.__dict__.get("session_history_error")
        if history_error:
            v.addWidget(lbl(f"Encrypted activity history could not be read or updated ({history_error}). Existing data was preserved; check storage permissions or restore a trusted log.bin backup.", 12, "#ffb347"))
        elif not S("log") or S("ghost"):
            v.addWidget(lbl("Persistent activity history is disabled by the current privacy settings. The active session timeline is only held in memory.", 12, "#ffb347"))
        center_card = QFrame(); center_card.setObjectName("card"); center_box = QVBoxLayout(center_card)
        center_box.addWidget(lbl("VAULT HEALTH & DIAGNOSTICS", 14, ACC, True))
        center_box.addWidget(lbl("Run read-only encrypted-storage checks or inspect bounded, sanitized local logs. Existing session timeline and sign-in history remain below.", 11, MUT))
        center_buttons = QHBoxLayout()
        health_button = btn("Vault Health Center", "go"); diagnostics_button = btn("Diagnostics Center")
        health_button.clicked.connect(self.open_health_center); diagnostics_button.clicked.connect(self.open_diagnostics_center)
        center_buttons.addWidget(health_button); center_buttons.addWidget(diagnostics_button); center_buttons.addStretch()
        center_box.addLayout(center_buttons); v.addWidget(center_card); self.pop(center_card)
        activity_value: object = getattr(self, "session_activity", [])
        session_events: list[dict[str, object]] = []
        if isinstance(activity_value, list):
            for event_value in cast(list[object], activity_value):
                if isinstance(event_value, dict):
                    session_events.append(cast(dict[str, object], event_value))
        stored_names_value: object = getattr(self, "session_stored_names", [])
        session_stored_names: list[str] = (
            [name for name in cast(list[object], stored_names_value) if isinstance(name, str)]
            if isinstance(stored_names_value, list) else []
        )
        session_stored_count = int(getattr(self, "session_stored_count", 0))
        session_setting_count = int(getattr(self, "session_setting_changes", 0))
        theme_names = {key: title for title, key in THEMES}
        background_names = {key: title for title, key in BGS}
        background_names.update({"sweep": "Sweep lamp (retired)", "pulse": "Signal pulse (retired)"})
        setting_names = {"lv": "Wrong-password policy", "dead": "Deadman switch", "idle": "Auto-lock when idle",
                         "shred": "Secure-erase strength", "blur": "Lock on focus loss", "ro_always": "Always open read-only",
                         "nocap": "Screen-capture blocking", "mask": "Mask file names", "hideuser": "Generic greeting",
                         "clip": "Clear clipboard on lock/exit", "export": "Allow decrypted exports", "log": "Record sign-in log",
                         "nocopy": "Disable viewer copying", "minlock": "Lock on minimize", "logwipe": "Erase sign-in log on exit",
                         "hidecnt": "Hide vault item count", "vmode": "Playback mode", "vclose": "Viewer auto-close",
                         "title": "Window title", "ghost": "Ghost mode", "keypad": "On-screen keyboard",
                         "dimidle": "Dim when idle", "exitclean": "Clean local logs on exit", "cliptime": "Clipboard auto-clear",
                         "reauth": "Re-authenticate before opening files", "boss": "Boss key",
                         "remote": "Block Remote Desktop sign-in", "dbg": "Lock when debugger is detected",
                         "hidename": "Hide names in viewer titles", "sess": "Maximum session length",
                         "maxtf": "Lifetime failure wipe limit", "bind": "Bind vault to this device",
                         "th": "Theme", "bg": "Background", "intro": "Terminal intro", "perf": "Performance mode",
                         "winop": "Window opacity", "wipefx": "Destructive-action animation",
                         "hk": "Panic shortcut", "hk_act": "Panic shortcut action", "hk_glob": "Global panic shortcut",
                         "bgspd": "Background animation speed", "bgden": "Background density",
                         "tstyle": "Terminal typography", "crt": "CRT effects",
                         "reduce_motion": "Reduce decorative motion"}
        def setting_value(key: str, value: Any) -> str:
            if isinstance(value, bool): return "On" if value else "Off"
            if key == "th": return theme_names.get(value, str(value))
            if key == "bg": return background_names.get(value, str(value))
            if isinstance(value, str) and len(value) > 100: return value[:97] + "..."
            return str(value)
        session_card = QFrame(); session_card.setObjectName("card"); session_box = QVBoxLayout(session_card)
        session_box.addWidget(lbl("THIS SESSION", 14, ACC, True))
        started = getattr(self, "session_started", None)
        elapsed = max(0, int(time.time() - started)) if isinstance(started, (int, float)) else None
        elapsed_text = f"Started {time.strftime('%H:%M:%S', time.localtime(started))}  /  elapsed {elapsed // 3600:02d}:{elapsed % 3600 // 60:02d}:{elapsed % 60:02d}" if elapsed is not None else "No active sign-in session."
        session_box.addWidget(lbl(elapsed_text, 11, MUT))
        if S("hidecnt"):
            session_box.addWidget(lbl("Stored item count is hidden by the current privacy setting.", 12, MUT))
        else:
            session_box.addWidget(lbl(f"Vault items stored this session: {session_stored_count}", 12, ACC, True))
        if S("mask") and session_stored_names:
            names_label = lbl("File names are masked by the current privacy setting.", 11, MUT)
        else:
            names_label = lbl("\n".join(str(name) for name in session_stored_names) or "No items stored this session.", 11, MUT)
            names_label.setTextFormat(Qt.TextFormat.PlainText); names_label.setWordWrap(True)
        session_box.addWidget(names_label)
        session_box.addWidget(lbl(f"Settings changed this session: {session_setting_count}", 12, ACC, True))
        changes = [event for event in session_events if event.get("kind") == "setting_changed"]
        if changes:
            change_lines: list[str] = []
            for event in changes[-30:]:
                key_value = event.get("key")
                key = key_value if isinstance(key_value, str) else "setting"
                label = setting_names.get(key, key.replace("_", " ").title())
                change_lines.append(
                    f"{label}: {setting_value(key, event.get('before'))} -> "
                    f"{setting_value(key, event.get('after'))}")
            changes_label = lbl("\n".join(change_lines), 11, MUT); changes_label.setTextFormat(Qt.TextFormat.PlainText); changes_label.setWordWrap(True)
            session_box.addWidget(changes_label)
            if session_setting_count > len(change_lines):
                session_box.addWidget(lbl(f"Showing the latest {len(change_lines)} changes.", 10, DIM))
        if getattr(self, "session_activity_omitted", 0):
            session_box.addWidget(lbl("Older timeline entries were omitted to keep the session responsive; stored-item and setting-change totals remain complete.", 10, DIM))
        v.addWidget(session_card); self.pop(session_card)
        v.addWidget(lbl("SESSION TIMELINE", 14, ACC, True))
        if not session_events:
            v.addWidget(lbl("No session actions recorded yet.", 12, MUT))
        for i, event in enumerate(reversed(session_events[-100:])):
            kind = event.get("kind"); detail = ""; color = ACC
            if kind == "vault_unlocked":
                title = "Vault unlocked"; detail = "Sign-in: " + str(event.get("method", "unknown"))
            elif kind == "vault_locked":
                title = "Vault locked"; color = "#ffb347"
            elif kind == "profile_switch":
                title = "Profile switch requested"; detail = "Current vault locked; profile chooser opened."; color = "#22d3ee"
            elif kind == "files_stored":
                names_value = event.get("names", [])
                names = [str(name) for name in cast(list[object], names_value)] if isinstance(names_value, list) else []
                count_value = event.get("count", len(names))
                count = count_value if isinstance(count_value, int) else len(names)
                title = "Stored vault items" if S("hidecnt") else f"Stored {count} vault item(s)"
                detail = "Names masked by the current privacy setting." if S("mask") else "\n".join(names)
            elif kind == "file_opened":
                title = "Opened a file viewer"; detail = "Hidden file" if S("mask") else str(event.get("name", ""))
            elif kind == "file_burned":
                title = "Burned a vault item"; detail = "Hidden file" if S("mask") else str(event.get("name", ""))
                color = "#ff8a65"
            elif kind == "setting_changed":
                key_value = event.get("key")
                key = key_value if isinstance(key_value, str) else "setting"
                title = "Setting changed: " + setting_names.get(key, key.replace("_", " ").title())
                detail = setting_value(key, event.get("before")) + " -> " + setting_value(key, event.get("after"))
            else:
                title = str(kind or "Session event")
            card = QFrame(); card.setObjectName("card"); row = QHBoxLayout(card)
            row.addWidget(lbl("\u25CF", 12, color, True))
            body = QVBoxLayout(); body.addWidget(lbl(title, 12, color, True))
            if detail:
                text = lbl(detail, 11, MUT); text.setTextFormat(Qt.TextFormat.PlainText); text.setWordWrap(True); body.addWidget(text)
            row.addLayout(body, 1)
            timestamp = event.get("t")
            if isinstance(timestamp, (int, float)):
                row.addWidget(lbl(time.strftime("%H:%M:%S", time.localtime(timestamp)), 10, DIM))
            v.addWidget(card); self.pop(card, min(i * 25, 350))
        v.addWidget(lbl("PAST SESSION LOGS", 14, ACC, True))
        if not session_records:
            v.addWidget(lbl("No session logs are available yet.", 12, MUT))
        for i, record in enumerate(session_records[:MAX_SESSION_HISTORY]):
            session_card = QFrame(); session_card.setObjectName("card"); row = QHBoxLayout(session_card)
            start = record.get("t")
            when = time.strftime("%d %b %Y  /  %H:%M:%S", time.localtime(start)) if isinstance(start, (int, float)) else "Unknown start time"
            events_value = record.get("events", [])
            count = len(cast(list[object], events_value)) if isinstance(events_value, list) else 0
            summary_label = lbl(f"Session  /  {when}\n{count} recorded event(s)", 11, MUT); summary_label.setWordWrap(True)
            row.addWidget(summary_label, 1)
            history_button = btn("View session log")
            history_button.clicked.connect(_clicked_slot(self.show_session_log, record))
            row.addWidget(history_button); v.addWidget(session_card); self.pop(session_card, min(i * 20, 300))
        v.addWidget(lbl("ENCRYPTED SIGN-IN HISTORY", 14, ACC, True))
        summary = QHBoxLayout()
        for i, (title, value, color) in enumerate((("Successful sign-ins", ok_count, "#4ade80"), ("Failed attempts", fail_count, "#ff8a65"),
                                                   ("Most recent", tfmt(event_time(latest)) if latest else "No activity", MUT))):
            tile = QFrame(); tile.setObjectName("card"); box = QVBoxLayout(tile); box.addWidget(lbl(str(value), 15, color, True)); box.addWidget(lbl(title, 11, MUT)); summary.addWidget(tile)
            self.pop(tile, i * 45)
        v.addLayout(summary)
        h = QHBoxLayout(); h.addWidget(lbl(f"Showing {len(filtered)} of {len(signins)} sign-in event(s) kept (up to {MAX_SIGNIN_HISTORY}), newest first; log data is encrypted.", 12, MUT), 1)
        h.addWidget(recent_filter)
        cl = btn("Clear activity history"); cl.setEnabled(not self.ro and bool(L)); h.addWidget(cl); v.addLayout(h)
        def clear() -> None:
            root = self.root
            if root is None:
                QMessageBox.warning(self, "Vault locked", "Unlock the vault before changing its activity history.")
                return
            try:
                atomic_write_bytes(LOG, seal(file_key(root, b"unknwn-log"), b"[]"))
            except (OSError, TypeError, ValueError) as exc:
                self.session_history_error = type(exc).__name__
                QMessageBox.warning(self, "Could not clear activity history",
                                    f"Encrypted activity history was not cleared ({type(exc).__name__}). Check storage permissions and try again.")
                return
            self.session_history_error = None; self.ap.setWidget(self.build_log())
        cl.clicked.connect(clear)
        if not signins: v.addWidget(lbl("Nothing recorded yet.", 14, MUT, center=True))
        elif not filtered: v.addWidget(lbl("No events match this filter.", 14, MUT, center=True))
        recent = sorted((e for e in filtered if isinstance(e.get("t"), (int, float))), key=event_time, reverse=True)[:100]
        for i, e in enumerate(recent):
            ok = e.get("ok") is True; c = QFrame(); c.setObjectName("card"); row = QHBoxLayout(c)
            row.addWidget(lbl("\u2713" if ok else "\u2717", 18, "#4ade80" if ok else "#ff6b61", True))
            details = QVBoxLayout(); details.addWidget(lbl("Authentication succeeded" if ok else "Authentication failed", 14, "#ece8ff" if ok else "#ffb3c0", True))
            if ok:
                method = "Recovery words" if e.get("how") == "recovery" else "Master password"
                access = "Read-only session" if e.get("ro") else "Full session"
                details.addWidget(lbl(f"Method: {method}    /    Access: {access}", 11, MUT))
            else:
                details.addWidget(lbl(f"Failed attempt {e.get('attempt', '—')} in the recorded sequence", 11, MUT))
            timestamp = e.get("t")
            if isinstance(timestamp, (int, float)):
                row.addLayout(details, 1); row.addWidget(lbl(time.strftime("%d %b %Y\n%H:%M:%S", time.localtime(timestamp)), 11, MUT)); v.addWidget(c); self.pop(c, i * 20)
        return w
    def show_session_log(self, record: Mapping[str, Any]) -> None:
        dialog = QDialog(self); dialog.setWindowTitle("Vault session log")
        screen = self.screen(); available = screen.availableGeometry() if screen is not None else QRect(0, 0, 900, 700)
        dialog.resize(min(720, max(320, available.width() - 32)), min(560, max(300, available.height() - 48)))
        layout = QVBoxLayout(dialog); layout.addWidget(lbl("SESSION LOG", 17, ACC, True))
        started = record.get("t")
        if isinstance(started, (int, float)):
            layout.addWidget(lbl("Started " + time.strftime("%d %b %Y  /  %H:%M:%S", time.localtime(started)), 11, MUT))
        editor = QPlainTextEdit(); editor.setReadOnly(True); editor.setLineWrapMode(QPlainTextEdit.LineWrapMode.WidgetWidth)
        lines: list[str] = []
        events_value = record.get("events", [])
        events_list = cast(list[object], events_value) if isinstance(events_value, list) else []
        for event_value in events_list:
            if not isinstance(event_value, dict): continue
            event = cast(dict[str, object], event_value)
            kind = event.get("kind")
            when = event.get("t")
            timestamp = time.strftime("%H:%M:%S", time.localtime(when)) if isinstance(when, (int, float)) else "--:--:--"
            if kind == "vault_unlocked": detail = "Vault unlocked (" + str(event.get("method", "unknown")) + ")"
            elif kind == "vault_locked": detail = "Vault locked"
            elif kind == "profile_switch": detail = "Profile switch requested"
            elif kind == "session_ended": detail = "Session ended"
            elif kind == "files_stored":
                count_value = event.get("count", 0)
                count = count_value if isinstance(count_value, int) else 0
                detail = "Vault items stored" if S("hidecnt") else f"Stored {count} vault item(s)"
                if S("mask"): detail += "  /  file names masked"
                else:
                    names_value = event.get("names")
                    if isinstance(names_value, list) and names_value:
                        detail += "  /  " + ", ".join(str(name) for name in cast(list[object], names_value))
            elif kind in ("file_opened", "file_burned"):
                action = "Opened" if kind == "file_opened" else "Burned"
                detail = action + " vault item: " + ("Hidden file" if S("mask") else str(event.get("name", "")))
            elif kind == "setting_changed":
                key = str(event.get("key", "setting")).replace("_", " ").title()
                detail = f"Setting changed: {key} ({event.get('before')} -> {event.get('after')})"
            else:
                continue
            lines.append(f"{timestamp}  {detail}")
        editor.setPlainText("\n".join(lines) or "No recorded events.")
        layout.addWidget(editor, 1)
        close = btn("CLOSE"); close.clicked.connect(dialog.accept); layout.addWidget(close)
        dialog.exec_()
    def set_log_filter(self, value: str) -> None:
        self.log_filter = value
        self.ap.setWidget(self.build_log())
    def build_changes(self) -> QWidget:
        w = QWidget(); v = QVBoxLayout(w); v.setAlignment(Qt.AlignmentFlag.AlignTop); v.setSpacing(12)
        names = {key: title for title, key in BGS}; themes = {key: title for title, key in THEMES}
        v.addWidget(lbl("SYSTEM OVERVIEW", 17, ACC, True))
        v.addWidget(lbl("A live, local snapshot of this vault session and its configuration. These indicators are not a complete security assessment.", 12, MUT))

        integrity = {"ok": "Release manifest verified",
                     "fail": "Verification failed — secure operations are disabled",
                     "dev": "Development/source build — release verification is not enforced"}
        try:
            busy = bool(self.working())
        except (AttributeError, RuntimeError):
            busy = False
        session = "Read-only" if getattr(self, "ro", False) else "Standard access"
        activity_count = len(getattr(self, "session_activity", []))
        profile_name = active_profile_name or "Unregistered vault"

        if S("dash_session"):
            card = QFrame(); card.setObjectName("card"); box = QVBoxLayout(card)
            box.addWidget(lbl("ACTIVE VAULT SESSION", 14, ACC, True))
            box.addWidget(lbl(f"Profile: {profile_name}    /    Session: {session}", 12))
            box.addWidget(lbl("Switch profile locks this vault and returns to the chooser; each profile keeps its own password and files.", 11, MUT))
            box.addWidget(lbl(f"Current session events: {activity_count}    /    Vault operations: {'In progress' if busy else 'Idle'}", 11, MUT))
            box.addWidget(lbl("Installation status: " + integrity.get(INTEG[0], "Not verified"), 11, MUT))
            v.addWidget(card); self.pop(card)

        if S("dash_look"):
            look = QFrame(); look.setObjectName("card"); box = QVBoxLayout(look)
            box.addWidget(lbl("CURRENT LOOK", 14, ACC, True))
            box.addWidget(lbl(f"Theme: {themes.get(S('th'), 'Custom')}    /    Background: {names.get(S('bg'), 'Gradient (still)')}", 12))
            box.addWidget(lbl(f"Performance: {S('perf').upper()}    /    Animation speed: {S('bgspd')}%    /    Density: {S('bgden')}%", 11, MUT))
            v.addWidget(look); self.pop(look)

        if S("dash_privacy"):
            privacy = QFrame(); privacy.setObjectName("card"); box = QVBoxLayout(privacy)
            box.addWidget(lbl("PRIVACY & HISTORY", 14, ACC, True))
            box.addWidget(lbl(f"File names: {'masked' if S('mask') else 'visible'}    /    Item counts: {'hidden' if S('hidecnt') else 'visible'}", 12))
            history = "disabled" if not S("log") or S("ghost") else "encrypted history enabled"
            box.addWidget(lbl(f"Persistent activity history: {history}", 11, MUT))
            box.addWidget(lbl(f"Clock: {'24-hour' if S('clock24') else '12-hour'} format. Click the clock to switch; hold it for a hint.", 11, MUT))
            v.addWidget(privacy); self.pop(privacy)

        nothing = nothing_egg_button(self.show_nothing_easter_egg)
        v.addWidget(nothing, 0, Qt.AlignmentFlag.AlignRight)

        actions = QHBoxLayout()
        for title, callback in (("Vault Health Center", self.open_health_center),
                               ("Diagnostics Center", self.open_diagnostics_center),
                               ("Operation Center", self.open_operation_center),
                               ("Vault Statistics & Duplicates", self.open_vault_analysis),
                               ("Look Studio", self.look_studio),
                               ("Switch profile", self.switch_profile),
                               ("Settings", lambda: self.tab(1))):
            action = btn(title, "go" if title == "Vault Health Center" else "flat")
            if title == "Switch profile":
                action.setToolTip("Lock this vault and choose another profile, each with its own password and files.")
            action.clicked.connect(_clicked_slot(callback)); actions.addWidget(action)
        v.addLayout(actions)
        return w
    def chpw(self) -> None:
        d = QDialog(self); d.setWindowTitle("Change password"); v = QVBoxLayout(d); es: list[QLineEdit] = []
        for t in ("Current password", "New password (12+ characters)", "Confirm new password"):
            e = QLineEdit(); e.setEchoMode(QLineEdit.EchoMode.Password); e.setPlaceholderText(t); v.addWidget(e); es.append(e)
        m = lbl("", 12, "#ff8a65"); v.addWidget(m); ok = btn("Change", "go"); v.addWidget(ok)
        def go() -> None:
            try: dek = unseal(kdf(str(es[0].text()), b64d(cfg["s1"])), b64d(cfg["wp"]))
            except InvalidTag: return m.setText("Current password is wrong.")
            a: str = str(es[1].text()); good, why = check_pw(a)
            if not good: return m.setText(why)
            if a != str(es[2].text()): return m.setText("Passwords do not match.")
            candidate = copy.deepcopy(cfg)
            s1 = os.urandom(16); candidate.update(s1=b64e(s1), wp=b64e(seal(kdf(a, s1), dek)))
            try:
                commit_config_transaction(candidate)
            except (OSError, TypeError, ValueError) as exc:
                return m.setText(f"The new password could not be saved ({type(exc).__name__}); the current password remains active.")
            d.accept()
        ok.clicked.connect(go); d.exec_()
    def newrec(self) -> None:
        root = self.root
        if root is None: return
        if QMessageBox.question(self, "New recovery words", "The OLD words stop working on THIS copy of the vault. Older backups of config.json will still accept them. Write the new ones on paper. Continue?") != QMessageBox.StandardButton.Yes: return
        phrase = " ".join(random.SystemRandom().sample(WORDS, NW)); s2 = os.urandom(16)
        candidate = copy.deepcopy(cfg)
        candidate.update(s2=b64e(s2), wr=b64e(seal(kdf(phrase, s2), root)))
        try:
            commit_config_transaction(candidate)
        except (OSError, TypeError, ValueError) as exc:
            QMessageBox.warning(
                self, "Recovery words not changed",
                f"The new recovery words could not be saved ({type(exc).__name__}). "
                "The existing recovery words remain active.")
            return
        self.recovery_screen(phrase, self.vault_screen)
    def move_data(self) -> Optional[int]:
        root = self.root
        if self.ro or root is None or not self.sec_ok("vault_write"):
            return
        if self.working():
            return QMessageBox.warning(self, "Vault operation in progress",
                                       "Finish or cancel the current vault operation before moving data.")
        to = _move_target_for(HOME)
        if to.exists() or to.is_symlink():
            return QMessageBox.warning(self, "Destination already exists",
                f"UNKNWN will not merge with or overwrite an existing data folder:\n{to}\n"
                "Choose a new destination by moving or backing up that folder first.")
        if not terminal_confirm(self, "Move vault data", "vault --move-data",
                [f"Copy all UNKNWN data to: {to}",
                 "The source stays intact unless the staged copy is independently verified. No encrypted vault item is decrypted.",
                 "The original folder is retained as a backup after the verified copy becomes active.",
                 "Available space is estimated before copying and checked again before activation."]):
            return
        worker = _MoveWorker(HOME, to, root)
        dialog = MoveProgressDialog(self, worker, self.finish_move_data)
        self.move_dialog = dialog
        self.hold += 1
        dialog.show()
        try:
            _start_qrunnable(worker)
        except Exception as exc:
            worker.operation.fail(type(exc).__name__)
            dialog.finish({"status": "failed", "error": type(exc).__name__,
                           "detail": "The background worker could not be started; the source remains intact.",
                           "source": str(HOME), "target": str(to),
                           "journal": str(_move_journal_path(HOME))})

    def finish_move_data(self, result: Mapping[str, Any]) -> None:
        self.hold = max(0, self.hold - 1)
        self.move_dialog = None
        if result["status"] in {"completed", "recovery_required"}:
            set_home(Path(result["target"]))
            if active_profile_id:
                _update_profile_path(active_profile_id, HOME)
            cast(Any, self.sp).setWidget(self.build_settings())
            if result["status"] == "completed":
                QMessageBox.information(self, "Data copy verified",
                    f"The verified copy is now active at:\n{result['target']}\n\n"
                    f"The original data remains intact at:\n{result['source']}")
            else:
                QMessageBox.warning(self, "Data copy active; recovery needed",
                    f"The destination was verified and is active at:\n{result['target']}\n\n"
                    f"The original remains intact at:\n{result['source']}\n\n"
                    f"Preserve the recovery journal at:\n{result['journal']}")
                self.lock()
            return
        detail = result.get("detail", "The source was not removed.")
        state = ("The operation was cancelled." if result.get("error") == "MoveDataCancelled"
                 else "The destination was not activated.")
        recovery = result.get("recovery_state")
        recovery_detail = ""
        if recovery:
            recovery_detail = (
                f"\n\nRecovery state: {recovery['phase']}."
                + (f"\nPreserved staging folder:\n{recovery['stage']}" if recovery.get("stage") else "")
            )
        QMessageBox.warning(self, "Data move did not complete",
            f"{state}\n\nThe original source remains intact at:\n{result['source']}\n\n"
            f"{detail}{recovery_detail}\n\n"
            f"Preserve the move journal if present at:\n{result['journal']}")

    # ---------- vault logic ----------
    def _vault_file_state_key(self, rid: str) -> str:
        vault_token = hashlib.sha256(os.fsencode(VAULT.resolve())).hexdigest()[:16]
        return f"{vault_token}:{rid}"

    def _prepare_vault_file_states(self) -> None:
        for rid in idx:
            key = self._vault_file_state_key(rid)
            try:
                state = FILE_STATE_MANAGER.snapshot(key)
            except FileStateError:
                FILE_STATE_MANAGER.register(key)
                continue
            if state.state == FileState.LOCKED:
                FILE_STATE_MANAGER.unlock_verified(key, state.revision)
            elif state.state == FileState.RECOVERY_REQUIRED:
                self._recover_vault_file_state(rid, key, state.revision)
            elif state.state != FileState.AVAILABLE:
                raise FileStateError(
                    f"Vault item state requires attention ({state.state.value}).")

    def _recover_vault_file_state(self, rid: str, key: str, revision: int) -> None:
        root = self.root
        if root is None or rid not in idx:
            raise FileStateError("The file cannot be recovered without an authenticated index entry.")
        operation = OPERATION_MANAGER.create(
            "Recover file state", resource_keys=(f"vault-file:{key}",),
            require_report=True)
        try:
            operation.start()
        except OperationBlocked as exc:
            operation.fail(type(exc).__name__)
            raise FileStateError("Another operation owns this file.") from exc
        try:
            processing = FILE_STATE_MANAGER.transition(
                key, FileState.PROCESSING, expected_revision=revision,
                operation_id=operation.operation_id, recovery=True)
            _verify_sealed_object(root, VAULT / f"{rid}.cdr", idx[rid])
            pending = FILE_STATE_MANAGER.transition(
                key, FileState.PENDING_VERIFICATION, expected_revision=processing.revision,
                operation_id=operation.operation_id)
            available = FILE_STATE_MANAGER.transition(
                key, FileState.AVAILABLE, expected_revision=pending.revision,
                operation_id=operation.operation_id, recovery=True, verified=True)
            card = getattr(self, "cards", {}).get(rid)
            if card is not None:
                card._file_state_revision = available.revision
            operation.complete()
        except (OSError, ValueError, TypeError, InvalidTag, FileStateError,
                InvalidOperationTransition, KeyError) as exc:
            try:
                current = FILE_STATE_MANAGER.snapshot(key)
                if current.state == FileState.PROCESSING:
                    FILE_STATE_MANAGER.transition(
                        key, FileState.RECOVERY_REQUIRED,
                        expected_revision=current.revision,
                        operation_id=operation.operation_id)
                operation.recovering("file_state_verification_failed")
                operation.fail(
                    type(exc).__name__, recovery_state="file_state_verification_failed")
            except (FileStateError, InvalidOperationTransition, KeyError):
                log_security_event("file_state_recovery_transition_failed",
                                   error=type(exc).__name__)
            raise FileStateError("Authenticated file verification did not permit recovery.") from exc
        operation.report_result(
            "recover_file_state", affected_items=(rid,), succeeded_items=(rid,),
            verified_items=(rid,), committed_items=(rid,), recovered_items=(rid,))

    def _begin_vault_file_operation(
        self, rid: str, action: str, simulation: SimulationPlan,
    ) -> tuple[Operation, int]:
        card = self.cards.get(rid)
        if card is None:
            raise FileStateError("The item is no longer present in the current view.")
        key = self._vault_file_state_key(rid)
        revision = getattr(card, "_file_state_revision", None)
        if type(revision) is not int:
            raise FileStateError("The item has no current state revision.")
        FILE_STATE_MANAGER.require_available(key, revision)
        current_simulation = self._simulate_vault_action(
            (rid,), action, destructive=simulation.destructive)
        OPERATION_MANAGER.require_current_simulation(simulation, current_simulation)
        operation = OPERATION_MANAGER.create(
            action, resource_keys=(f"vault-file:{key}",), require_report=True)
        try:
            operation.start()
            processing = FILE_STATE_MANAGER.transition(
                key, FileState.PROCESSING, expected_revision=revision,
                operation_id=operation.operation_id)
        except (FileStateError, OperationBlocked, InvalidOperationTransition, KeyError) as exc:
            snapshot = operation.snapshot
            if snapshot.state not in {
                OperationState.COMPLETED, OperationState.FAILED, OperationState.CANCELED,
                OperationState.RECOVERY_FAILED,
            }:
                operation.fail(type(exc).__name__)
            raise
        card._file_state_revision = processing.revision
        return operation, processing.revision

    def _simulate_vault_action(
        self, rid_values: Iterable[str], action: str, *, destructive: bool = False,
    ) -> SimulationPlan:
        rids = tuple(dict.fromkeys(rid_values))
        conflicts: list[str] = []
        resources: list[str] = []
        revisions: dict[str, int] = {}
        for rid in rids:
            key = self._vault_file_state_key(rid)
            resources.append(f"vault-file:{key}")
            if action in {"view_file", "burn_file"} and rid not in idx:
                conflicts.append("vault_index_entry_missing")
            try:
                state = FILE_STATE_MANAGER.snapshot(key)
            except FileStateError:
                conflicts.append("file_state_missing")
                continue
            revisions[key] = state.revision
            if state.state != FileState.AVAILABLE:
                conflicts.append(f"file_state_{state.state.value}")
        return OPERATION_MANAGER.simulate(
            action, affected_items=rids, resource_keys=resources,
            preflight_conflicts=tuple(dict.fromkeys(conflicts)),
            destructive=destructive,
            state_revisions=revisions,
            expected_changes=("ciphertext_removed", "index_updated")
            if destructive else ("authenticated_decryption",),
            verification_requirements=("authenticated_readback",),
            recovery_implications=("storage_journal_may_require_recovery",)
            if destructive else (),
        )

    def _finish_vault_file_operation(
        self,
        rid: str,
        operation: Operation,
        revision: int,
        *,
        verified: bool,
        recovery_required: bool = False,
        safe_cleanup: bool = False,
        unavailable: bool = False,
        failed: bool = False,
    ) -> None:
        key = self._vault_file_state_key(rid)
        card = self.cards.get(rid)
        try:
            current = FILE_STATE_MANAGER.snapshot(key)
            if current.revision != revision:
                raise StaleFileState("The item state changed before the operation finished.")
            if current.state == FileState.PROCESSING and not recovery_required and safe_cleanup:
                final = FILE_STATE_MANAGER.transition(
                    key, FileState.AVAILABLE, expected_revision=revision,
                    operation_id=operation.operation_id, safe_cleanup=True)
            else:
                pending = FILE_STATE_MANAGER.transition(
                    key, FileState.PENDING_VERIFICATION, expected_revision=revision,
                    operation_id=operation.operation_id)
                target = FileState.RECOVERY_REQUIRED if recovery_required else (
                    FileState.UNAVAILABLE if unavailable else FileState.AVAILABLE)
                final = FILE_STATE_MANAGER.transition(
                    key, target, expected_revision=pending.revision,
                    operation_id=operation.operation_id,
                    verified=verified and not recovery_required,
                )
            if card is not None:
                card._file_state_revision = final.revision
            if recovery_required:
                operation.recovering("file_state_recovery_required")
                operation.fail("File state requires recovery.", recovery_state="file_state_recovery_required")
            elif failed:
                operation.fail("The requested file action did not complete.")
            else:
                operation.complete()
        except (FileStateError, InvalidOperationTransition, KeyError) as exc:
            if operation.snapshot.state not in {
                OperationState.COMPLETED, OperationState.FAILED, OperationState.CANCELED,
                OperationState.RECOVERY_FAILED,
            }:
                operation.fail(type(exc).__name__, recovery_state="file_state_transition_failed")
            raise

    def sync(self) -> None:
        total = sum(meta["size"] for meta in idx.values())
        self.count.setText("" if S("hidecnt") else f"{len(self.cards)} sealed  /  {fmt(total)}")
        query = getattr(getattr(self, "search_edit", None), "text", lambda: "")().strip()
        visible = sum(1 for card in self.cards.values() if not card.isHidden())
        self.empty.setVisible(not self.cards)
        if hasattr(self, "no_results"): self.no_results.setVisible(bool(self.cards) and bool(query) and visible == 0)
        if hasattr(self, "selection_toolbar"): self.update_selection_toolbar()
    def apply_vault_filter(self, query: Optional[str] = None) -> None:
        if not hasattr(self, "cards"): return
        if query is None: query = getattr(getattr(self, "search_edit", None), "text", lambda: "")()
        needle = str(query).strip().casefold()
        matches: dict[str, bool] = {}
        for card in self.cards.values():
            card.filter_text = vault_search_text(card.rid, card.name, self.card_details(card.meta, card.name), S("mask"))
            matches[card.rid] = not needle or needle in card.filter_text.casefold()
        grouped_items: dict[str, str] = {}
        for key, members in getattr(self, "_group_header_members", {}).items():
            for rid in members:
                grouped_items[rid] = key
        empty_collapsed_groups: set[str] = set()
        collapsed_groups = cast(
            set[str], getattr(self, "_collapsed_groups", empty_collapsed_groups))
        for rid, card in self.cards.items():
            group_key = grouped_items.get(rid)
            card.setVisible(
                matches[rid] and (group_key is None or group_key not in collapsed_groups))
        for key, header in getattr(self, "_group_headers_by_key", {}).items():
            members = getattr(self, "_group_header_members", {}).get(key, ())
            header.setVisible(any(matches.get(rid, False) for rid in members))
        self.empty.setVisible(not self.cards)
        if hasattr(self, "no_results"):
            no_matches = bool(self.cards) and bool(needle) and not any(
                not card.isHidden() for card in self.cards.values())
            previous_empty_query = getattr(self, "_empty_search_message_query", None)
            if no_matches and needle != previous_empty_query:
                self.no_results.setText(EASTER_EGGS.message("empty_search"))
                self._empty_search_message_query = needle
            elif not no_matches:
                self._empty_search_message_query = None
            self.no_results.setVisible(no_matches)
        if hasattr(self, "selection_toolbar"):
            self.update_selection_toolbar()
    def apply_vault_sort(self) -> None:
        if not hasattr(self, "rows") or not hasattr(self, "cards"): return
        mode = getattr(getattr(self, "sort_order", None), "currentData", lambda: "stored")()
        def sort_cards(cards: list[tuple[str, Card]]) -> None:
            if mode == "type":
                cards.sort(key=lambda pair: (Path(pair[1].name).suffix.casefold(), pair[0]))
            elif mode == "largest":
                cards.sort(key=lambda pair: (-pair[1].meta["size"], pair[0]))
            elif mode == "smallest":
                cards.sort(key=lambda pair: (pair[1].meta["size"], pair[0]))
            else:
                cards.sort(key=lambda pair: pair[0])

        cards = list(self.cards.items())
        grouped: dict[str, list[tuple[str, Card]]] = {}
        ungrouped: list[tuple[str, Card]] = []
        group_names: dict[str, str] = {}
        for rid, card in cards:
            group_value = cast(dict[str, object], card.meta).get("group")
            if not isinstance(group_value, str) or not group_value.strip():
                ungrouped.append((rid, card))
                continue
            key = group_value.casefold()
            grouped.setdefault(key, []).append((rid, card))
            group_names[key] = group_value
        sort_cards(ungrouped)
        for group_cards in grouped.values():
            sort_cards(group_cards)

        for _rid, card in cards:
            self.rows.removeWidget(card)
        old_headers = getattr(self, "_group_headers", [])
        for header in old_headers:
            self.rows.removeWidget(header)
            header.setParent(None)
            header.deleteLater()
        self._group_headers: list[QFrame] = []
        self._group_headers_by_key: dict[str, QFrame] = {}
        self._group_header_members: dict[str, tuple[str, ...]] = {}
        self._group_header_checks: dict[str, QCheckBox] = {}
        self._group_collapse_buttons: dict[str, QPushButton] = {}
        self._collapsed_groups = cast(
            set[str], getattr(self, "_collapsed_groups", set[str]()))
        self._collapsed_groups.intersection_update(grouped)
        for _rid, card in ungrouped:
            self.rows.addWidget(card)
        search_query = str(getattr(
            getattr(self, "search_edit", None), "text", lambda: "")()).strip().casefold()
        for key in sorted(grouped):
            group_cards = grouped[key]
            heading = QFrame()
            heading.setObjectName("folderHeader")
            heading_layout = QHBoxLayout(heading)
            heading_layout.setContentsMargins(12, 7, 12, 7)
            visible_count = sum(
                not search_query
                or search_query in card.filter_text.casefold()
                for _rid, card in group_cards)
            folder_name = "Folder (name hidden)" if S("mask") else sanitize_text(group_names[key], 64)
            select_folder = QCheckBox("Select folder")
            select_folder.setAccessibleName(
                "Select all items in folder " + ("hidden" if S("mask") else folder_name))
            def select_folder_items(checked: bool, group_key: str = key) -> None:
                self.set_group_items_selected(group_key, checked)
            select_folder.toggled.connect(select_folder_items)
            heading_layout.addWidget(select_folder)
            self._group_header_checks[key] = select_folder
            heading_layout.addWidget(lbl(
                f"\U0001F4C1  {folder_name}  /  {len(group_cards)} item(s)",
                12, TH["fg"], True), 1)
            collapsed = key in self._collapsed_groups
            collapse_button = btn("Expand" if collapsed else "Minimize", "flat")
            collapse_button.setAccessibleName(
                ("Expand" if collapsed else "Minimize") + " folder " +
                ("hidden" if S("mask") else folder_name))
            collapse_button.clicked.connect(
                _clicked_slot(self.toggle_group_collapsed, key))
            heading_layout.addWidget(collapse_button)
            self._group_collapse_buttons[key] = collapse_button
            heading.setVisible(visible_count > 0)
            self._group_headers.append(heading)
            self._group_headers_by_key[key] = heading
            self._group_header_members[key] = tuple(rid for rid, _card in group_cards)
            self.rows.addWidget(heading)
            for _rid, card in group_cards:
                self.rows.addWidget(card)
        self.apply_vault_filter()
    def card_details(self, meta: _VaultMetadata, name: str) -> str:
        kind = Path(name).suffix.lower().lstrip(".").upper() or "FILE"
        details = f"{kind}   /   {fmt(meta['size'])}   /   {vtxt(meta)}"
        group = cast(dict[str, object], meta).get("group")
        if S("mask"):
            return details + ("   /   GROUPED" if isinstance(group, str) and group else "")
        return details + (f"   /   GROUP: {sanitize_text(group, 64)}" if isinstance(group, str) and group else "")
    def add_card(self, rid: str, delay: int = 0) -> None:
        root = self.root
        if root is None: return
        m = idx[rid]
        try: name = unseal(file_key(root, b64d(m["s"])), b64d(m["nm"])).decode()
        except Exception: return
        c = Card(); c.setObjectName("card"); c.name = name; c.rid = rid; c.meta = cast(_VaultMetadata, dict(m))
        file_state = FILE_STATE_MANAGER.register(self._vault_file_state_key(rid))
        c._file_state_revision = file_state.revision
        details = self.card_details(m, name)
        c.filter_text = vault_search_text(rid, name, details, S("mask"))
        c.setAccessibleName("Vault item " + (f"{rid[:4]}" if S("mask") else name))
        h = QHBoxLayout(c); h.setContentsMargins(16, 12, 16, 12); v = QVBoxLayout()
        select = QCheckBox()
        select.setAccessibleName("Select vault item " + (f"{rid[:4]}" if S("mask") else name))
        empty_selection: set[str] = set()
        selected_ids = cast(set[str], getattr(self, "selected_items", empty_selection))
        select.setChecked(rid in selected_ids)
        def update_selection(checked: bool, item_id: str = rid) -> None:
            self.set_item_selected(item_id, checked)
        select.toggled.connect(update_selection)
        h.addWidget(select)
        n = lbl(f"Hidden file  \u00B7  {rid[:4]}" if S("mask") else name, 15, bold=True); n.setTextFormat(Qt.TextFormat.PlainText); detail_label: QLabel = lbl(self.card_details(m, name), 12, MUT); setattr(c, "vl", detail_label); v.addWidget(n); v.addWidget(detail_label); h.addLayout(v, 1)
        cd = lbl("No timer" if not m["exp"] else "...", 13, MUT); h.addWidget(cd); self.cds[rid] = cd
        inspect_button = btn("Inspect", "flat")
        inspect_button.clicked.connect(_clicked_slot(self.inspect_vault_item, rid))
        vb = btn("View"); bb = btn("Burn", "danger"); bb.setEnabled(not self.ro); vb.clicked.connect(_clicked_slot(self.view, rid)); bb.clicked.connect(_clicked_slot(self.burn, rid)); h.addWidget(inspect_button); h.addWidget(vb); h.addWidget(bb)
        self.cards[rid] = c; self.rows.addWidget(c); self.pop(c, delay); self.apply_vault_filter(); self.sync()
    def set_item_selected(self, rid: str, selected: bool) -> None:
        if self._syncing_selection:
            return
        if rid not in self.cards:
            return
        if selected:
            self.selected_items.add(rid)
        else:
            self.selected_items.discard(rid)
        self.update_selection_toolbar()
    def select_visible_items(self, selected: bool) -> None:
        if self._syncing_selection:
            return
        self._syncing_selection = True
        target_ids = {
            rid for rid, card in self.cards.items()
            if selected and not card.isHidden()
        }
        if selected:
            self.selected_items.update(target_ids)
        else:
            self.selected_items.difference_update(
                rid for rid, card in self.cards.items() if not card.isHidden()
            )
        for rid, card in self.cards.items():
            check = cast(Optional[QCheckBox], card.findChild(QCheckBox))
            if check is not None:
                check.setChecked(rid in self.selected_items)
        self._syncing_selection = False
        self.update_selection_toolbar()
    def set_group_items_selected(self, group_key: str, selected: bool) -> None:
        members = getattr(self, "_group_header_members", {}).get(group_key, ())
        self._syncing_selection = True
        for rid in members:
            if rid not in self.cards:
                continue
            if selected:
                self.selected_items.add(rid)
            else:
                self.selected_items.discard(rid)
            check = cast(Optional[QCheckBox], self.cards[rid].findChild(QCheckBox))
            if check is not None:
                check.setChecked(selected)
        self._syncing_selection = False
        self.update_selection_toolbar()
    def set_group_collapsed(self, group_key: str, collapsed: bool) -> None:
        if collapsed:
            self._collapsed_groups.add(group_key)
        else:
            self._collapsed_groups.discard(group_key)
        collapse_button = getattr(self, "_group_collapse_buttons", {}).get(group_key)
        if collapse_button is not None:
            collapse_button.setText("Expand" if collapsed else "Minimize")
            accessible_name = collapse_button.accessibleName()
            folder_description = accessible_name.partition(" folder ")[2] or "group"
            collapse_button.setAccessibleName(
                ("Expand" if collapsed else "Minimize")
                + " folder " + folder_description)
        self.apply_vault_filter()
    def toggle_group_collapsed(self, group_key: str) -> None:
        self.set_group_collapsed(
            group_key, group_key not in self._collapsed_groups)
    def update_selection_toolbar(self) -> None:
        if not hasattr(self, "selection_toolbar"):
            return
        self.selected_items.intersection_update(self.cards)
        count = len(self.selected_items)
        self.selection_toolbar.setVisible(count > 0)
        self.selection_label.setText(f"{count} selected")
        mutation_available = not self.ro and not self.working()
        self.bulk_buttons["rename"].setEnabled(count == 1 and mutation_available)
        for key in ("group", "config", "delete"):
            self.bulk_buttons[key].setEnabled(count > 0 and mutation_available)
        self.bulk_buttons["view"].setEnabled(count > 0)
        self.bulk_buttons["clear"].setEnabled(count > 0)
        if not self._syncing_selection and hasattr(self, "select_visible"):
            visible = {rid for rid, card in self.cards.items() if not card.isHidden()}
            checked_count = len(visible & self.selected_items)
            self._syncing_selection = True
            self.select_visible.setChecked(bool(visible) and checked_count == len(visible))
            self._syncing_selection = False
        if not self._syncing_selection:
            for key, check in getattr(self, "_group_header_checks", {}).items():
                members = getattr(self, "_group_header_members", {}).get(key, ())
                self._syncing_selection = True
                check.setChecked(bool(members) and all(
                    rid in self.selected_items for rid in members))
                self._syncing_selection = False
    def clear_item_selection(self) -> None:
        self._syncing_selection = True
        self.selected_items.clear()
        for card in self.cards.values():
            check = cast(Optional[QCheckBox], card.findChild(QCheckBox))
            if check is not None:
                check.setChecked(False)
        self._syncing_selection = False
        self.update_selection_toolbar()
    def inspect_vault_item(self, rid: str) -> None:
        if self.mode != "vault" or self.root is None:
            QMessageBox.information(
                self, "File Inspector unavailable",
                "Unlock the Vault to inspect authenticated item metadata.")
            return
        if not self.sec_ok():
            return
        metadata = idx.get(rid)
        card = self.cards.get(rid)
        if metadata is None or card is None:
            QMessageBox.warning(
                self, "File Inspector unavailable",
                "This item is no longer present in the active authenticated index.")
            return
        revision = getattr(card, "_file_state_revision", None)
        if type(revision) is not int:
            QMessageBox.warning(
                self, "File Inspector unavailable",
                "This item has no current authoritative state. Refresh the Vault before inspecting it.")
            return
        try:
            FILE_STATE_MANAGER.require_available(
                self._vault_file_state_key(rid), revision)
        except (FileStateError, KeyError) as exc:
            QMessageBox.warning(
                self, "File Inspector unavailable",
                f"This item is not currently available ({type(exc).__name__}). Refresh the Vault and retry.")
            return
        try:
            key = file_key(self.root, b64d(metadata["s"]))
            authenticated_name = unseal(key, b64d(metadata["nm"])).decode("utf-8")
        except (InvalidTag, UnicodeDecodeError, ValueError, TypeError) as exc:
            QMessageBox.warning(
                self, "Metadata authentication failed",
                f"The item name could not be authenticated ({type(exc).__name__}).")
            return
        visible_name = "Hidden file" if S("mask") else sanitize_text(authenticated_name, 255)
        item_path = _storage_file_path(rid)
        try:
            info = item_path.lstat()
            is_reparse = bool(
                getattr(info, "st_file_attributes", 0)
                & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
            if stat.S_ISLNK(info.st_mode) or is_reparse or not stat.S_ISREG(info.st_mode):
                ciphertext_state = "Unavailable: storage path is not a regular file."
                modified = "Unavailable"
            else:
                ciphertext_state = f"Present ({info.st_size:,} ciphertext bytes)"
                modified = tfmt(info.st_mtime)
        except OSError:
            ciphertext_state = "Unavailable: ciphertext file is missing or unreadable."
            modified = "Unavailable"
        group_value = cast(dict[str, object], metadata).get("group")
        group = (
            "Hidden" if S("mask") and isinstance(group_value, str) and group_value
            else sanitize_text(group_value, 64) if isinstance(group_value, str) and group_value
            else "None")
        details = [
            f"Name: {visible_name}",
            f"Type: {Path(authenticated_name).suffix.lower().lstrip('.') or 'unknown'}",
            f"Plaintext size (authenticated index): {fmt(metadata['size'])}",
            f"Burn policy: {vtxt(metadata)}",
            f"Group: {group}",
            f"Ciphertext storage: {ciphertext_state}",
            f"Ciphertext modified: {modified}",
            "Payload integrity: not rechecked by this view. Run Vault Health Center to stream-verify it.",
        ]
        QMessageBox.information(
            self, "UNKNWN / Vault / File Inspector",
            "\n".join(details))
    def _selected_item_names(self) -> list[str]:
        return [
            ("Hidden file " + rid[:4]) if S("mask") else sanitize_text(self.cards[rid].name, 255)
            for rid in sorted(self.selected_items) if rid in self.cards
        ]
    def _persist_selected_metadata(self, candidate: dict[str, _VaultMetadata]) -> bool:
        root = self.root
        if root is None or self.ro or not self.sec_ok():
            return False
        try:
            for rid in sorted(self.selected_items):
                card = self.cards.get(rid)
                revision = getattr(card, "_file_state_revision", None) if card is not None else None
                if type(revision) is not int:
                    raise FileStateError("A selected item is no longer present in the current view.")
                FILE_STATE_MANAGER.require_available(self._vault_file_state_key(rid), revision)
        except (FileStateError, KeyError) as exc:
            QMessageBox.warning(
                self, "Vault change unavailable",
                f"A selected item changed state; refresh the vault and retry ({type(exc).__name__}).")
            return False
        if self.working():
            QMessageBox.information(
                self, "Vault change unavailable",
                "Vault items cannot be changed while another vault operation is active.")
            return False
        try:
            save_idx(root, candidate)
        except (OSError, TypeError, ValueError, InvalidTag) as exc:
            QMessageBox.warning(
                self, "Vault settings not saved",
                f"The authenticated vault index could not be updated ({type(exc).__name__}).")
            return False
        idx.clear(); idx.update(candidate)
        for rid in self.selected_items:
            card = self.cards.get(rid)
            metadata = idx.get(rid)
            if card is None or metadata is None:
                continue
            card.meta = cast(_VaultMetadata, dict(metadata))
            detail_label = getattr(card, "vl", None)
            if isinstance(detail_label, QLabel):
                detail_label.setText(self.card_details(metadata, card.name))
        self.apply_vault_filter()
        self.apply_vault_sort()
        self.sync()
        return True
    def view_selected_items(self) -> None:
        for rid in sorted(self.selected_items):
            if rid in idx and self.root is not None:
                self.view(rid)
    def delete_selected_items(self) -> None:
        selected = [rid for rid in sorted(self.selected_items) if rid in idx and rid not in self.dying]
        if not selected or self.ro or self.root is None:
            return
        if self.working():
            QMessageBox.information(
                self, "Vault change unavailable",
                "Items cannot be removed while another vault operation is active.")
            return
        names: list[str] = []
        for rid in selected:
            card = self.cards.get(rid)
            name = f"Hidden file {rid[:4]}" if S("mask") else (sanitize_text(card.name, 255) if card else rid)
            names.append(name)
        if not terminal_confirm(
                self, "Delete selected vault items", "vault --burn-selected",
                ["The following selected items will be removed through the authenticated, journaled secure deletion path:",
                 *names,
                 "This cannot be undone. Physical erasure cannot be guaranteed on SSDs, flash storage, snapshots, or backups."]):
            return
        for rid in selected:
            self.burn(rid, ask=False)
    def group_selected_items(self) -> None:
        selected = [rid for rid in self.selected_items if rid in idx]
        if not selected or self.ro or self.root is None:
            return
        group, accepted = QInputDialog.getText(self, "Group vault items", "Virtual folder name (leave blank to remove from group):")
        if not accepted:
            return
        group = str(group).strip()
        if len(group) > 64 or any(ord(char) < 32 for char in group):
            QMessageBox.warning(self, "Invalid group name", "Use a group name of at most 64 printable characters.")
            return
        current_groups = {
            cast(dict[str, object], idx[rid]).get("group", "") for rid in selected
        }
        if len(current_groups) > 1 and QMessageBox.question(
                self, "Replace existing groups",
                "The selected items have different group settings. Assigning "
                f"{group or 'no group'} will overwrite them for all selected items:\n\n"
                + "\n".join(self._selected_item_names())
                + "\n\nContinue?",
                cast(Any, QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No),
                QMessageBox.StandardButton.No) != QMessageBox.StandardButton.Yes:
            return
        candidate = {rid: cast(_VaultMetadata, dict(metadata)) for rid, metadata in idx.items()}
        for rid in selected:
            if group:
                cast(dict[str, object], candidate[rid])["group"] = group
            else:
                cast(dict[str, object], candidate[rid]).pop("group", None)
        self._persist_selected_metadata(candidate)
    def rename_selected_item(self) -> None:
        selected = [rid for rid in self.selected_items if rid in idx]
        if len(selected) != 1 or self.ro or self.root is None:
            return
        rid = selected[0]
        card = self.cards.get(rid)
        if card is None:
            return
        name, accepted = QInputDialog.getText(
            self, "Rename vault item", "New encrypted display name:",
            QLineEdit.EchoMode.Normal, card.name)
        if not accepted:
            return
        name = str(name).strip()
        if not name or len(name) > 255 or any(ord(char) < 32 for char in name):
            QMessageBox.warning(self, "Invalid item name", "Use a printable name between 1 and 255 characters.")
            return
        try:
            key = file_key(self.root, b64d(idx[rid]["s"]))
            encrypted_name = b64e(seal(key, name.encode("utf-8")))
        except (ValueError, TypeError, InvalidTag) as exc:
            QMessageBox.warning(
                self, "Item name not changed",
                f"The selected item's authenticated metadata could not be updated ({type(exc).__name__}).")
            return
        candidate = {item_id: cast(_VaultMetadata, dict(metadata)) for item_id, metadata in idx.items()}
        candidate[rid]["nm"] = encrypted_name
        if not self._persist_selected_metadata(candidate):
            return
        card.name = name
        labels = card.findChildren(QLabel)
        if labels:
            labels[0].setText(f"Hidden file  ·  {rid[:4]}" if S("mask") else name)
        detail_label = getattr(card, "vl", None)
        if isinstance(detail_label, QLabel):
            detail_label.setText(self.card_details(card.meta, name))
        self.apply_vault_filter()
    def configure_selected_items(self) -> None:
        selected = [rid for rid in sorted(self.selected_items) if rid in idx]
        if not selected or self.ro or self.root is None:
            return
        expiry_options = [("Never", 0), ("1 minute", 60), ("1 hour", 3600),
                          ("24 hours", 86400), ("7 days", 604800)]
        view_options = [("Unlimited", 0), ("1 view", 1), ("3 views", 3), ("5 views", 5)]
        expiry_label, accepted = QInputDialog.getItem(
            self, "Bulk expiry", "Set expiry for every selected item:", [label for label, _ in expiry_options], 0, False)
        if not accepted:
            return
        views_label, accepted = QInputDialog.getItem(
            self, "Bulk view limit", "Set remaining views for every selected item:", [label for label, _ in view_options], 0, False)
        if not accepted:
            return
        expiry = next(value for label, value in expiry_options if label == expiry_label)
        views = next(value for label, value in view_options if label == views_label)
        old_settings = {(idx[rid]["exp"], idx[rid]["views"]) for rid in selected}
        if len(old_settings) > 1 and QMessageBox.question(
                self, "Overwrite different item settings",
                "The selected items have different expiry or view-limit settings. This bulk edit will overwrite those settings for every listed item:\n\n"
                + "\n".join(self._selected_item_names())
                + "\n\nContinue?",
                cast(Any, QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No),
                QMessageBox.StandardButton.No) != QMessageBox.StandardButton.Yes:
            return
        candidate = {rid: cast(_VaultMetadata, dict(metadata)) for rid, metadata in idx.items()}
        deadline = time.time() + expiry if expiry else None
        for rid in selected:
            candidate[rid]["exp"] = deadline
            candidate[rid]["views"] = views or None
        self._persist_selected_metadata(candidate)
    def _drop_enabled(self) -> bool:
        return (self.mode == "vault" and not self.ro and not self.busy
                and self.root is not None and not self.working())
    def _valid_drop_mime(self, mime: Any) -> bool:
        if not mime.hasUrls():
            return False
        for url in mime.urls():
            if not url.isLocalFile():
                continue
            raw_path = url.toLocalFile()
            if not raw_path:
                continue
            try:
                info = Path(raw_path).lstat()
                attributes = getattr(info, "st_file_attributes", 0)
                reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
                if (stat.S_ISLNK(info.st_mode) or attributes & reparse):
                    continue
                if stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode):
                    return True
            except OSError:
                continue
        return False
    def _pulse_drop_feedback(self) -> None:
        self._drop_feedback_phase = not self._drop_feedback_phase
        color = TH["acc"] if self._drop_feedback_phase else TH["acc2"]
        c = _QC(color)
        alpha = 42 if self._drop_feedback_phase else 24
        self._drop_overlay.setStyleSheet(
            f"QFrame#dropOverlay{{background:rgba({c.red()},{c.green()},{c.blue()},"
            f"{alpha});border:2px dashed {color};}}"
        )
        self._drop_overlay.update()
    def _show_drop_feedback(self) -> None:
        fade = self._drop_fade
        if fade is not None:
            fade.stop()
            fade.deleteLater()
            self._drop_fade = None
        self._drop_opacity.setOpacity(1.0)
        if not self._drop_overlay.isVisible():
            self._drop_overlay.setGeometry(self.rect())
            self._drop_overlay.show()
            self._drop_overlay.raise_()
            self._drop_feedback_timer.start()
            self._pulse_drop_feedback()
    def _hide_drop_feedback(self) -> None:
        self._drop_feedback_timer.stop()
        if not self._drop_overlay.isVisible():
            return
        if self._drop_fade is not None:
            return
        fade = QPropertyAnimation(self._drop_opacity, b"opacity", self._drop_overlay)
        fade.setDuration(140)
        fade.setStartValue(self._drop_opacity.opacity())
        fade.setEndValue(0.0)
        fade.finished.connect(self._finish_drop_fade)
        self._drop_fade = fade
        fade.start()
    def _finish_drop_fade(self) -> None:
        self._drop_overlay.hide()
        self._drop_overlay.clear_trace()
        fade = self._drop_fade
        self._drop_fade = None
        if fade is not None:
            fade.deleteLater()
    def _restore_drop_title(self) -> None:
        self._hide_drop_feedback()
        previous = self._drop_previous_title
        self._drop_previous_title = None
        if previous is not None:
            self.setWindowTitle(previous)
    def dragEnterEvent(self, a0: Any) -> None:
        mime = a0.mimeData()
        if self._drop_enabled() and self._valid_drop_mime(mime):
            if self._drop_previous_title is None:
                self._drop_previous_title = self.windowTitle()
            self.setWindowTitle("Drop items to validate and seal")
            self._show_drop_feedback()
            self._drop_overlay.track_position(QPointF(a0.pos()))
            a0.acceptProposedAction()
            return
        self._restore_drop_title()
        a0.ignore()
    def dragMoveEvent(self, a0: Any) -> None:
        if self._drop_enabled() and self._valid_drop_mime(a0.mimeData()):
            self._show_drop_feedback()
            self._drop_overlay.track_position(QPointF(a0.pos()))
            a0.acceptProposedAction()
            return
        self._restore_drop_title()
        a0.ignore()
    def dragLeaveEvent(self, a0: Any) -> None:
        self._restore_drop_title()
        a0.accept()
    def dropEvent(self, a0: Any) -> None:
        self._restore_drop_title()
        if not self._drop_enabled():
            a0.ignore()
            return
        files: list[Path] = []
        folders: list[Path] = []
        rejected: list[str] = []
        seen: set[str] = set()
        for url in a0.mimeData().urls():
            if not url.isLocalFile():
                rejected.append("Non-local items are not supported.")
                continue
            raw_path = url.toLocalFile()
            if not raw_path:
                rejected.append("An item did not contain a local filesystem path.")
                continue
            path = Path(raw_path)
            try:
                info = path.lstat()
                attributes = getattr(info, "st_file_attributes", 0)
                reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
                if (stat.S_ISLNK(info.st_mode) or attributes & reparse):
                    raise ValueError("Symbolic links and reparse points are not accepted.")
                identity = str(path.resolve(strict=True)).casefold()
                if identity in seen:
                    continue
                if stat.S_ISREG(info.st_mode):
                    files.append(path)
                elif stat.S_ISDIR(info.st_mode):
                    folders.append(path)
                else:
                    raise ValueError("Only regular files and folders can be sealed.")
                seen.add(identity)
            except (OSError, ValueError) as exc:
                rejected.append(
                    f"{sanitize_text(path.name or str(path), 120)}: {sanitize_text(str(exc), 240)}")
        a0.acceptProposedAction()
        if not files and not folders:
            QMessageBox.warning(
                self, "Nothing to seal",
                "No supported local files or folders were accepted.\n\n"
                + "\n".join(rejected[:8]))
            return
        if files:
            self.add_files(files)
        for folder in folders:
            if self.ro or self.root is None or self.busy:
                rejected.append(f"{sanitize_text(folder.name, 120)}: further work was stopped because the vault is no longer available.")
                break
            self.add_folder(folder)
        if rejected:
            QMessageBox.warning(
                self, "Some dropped items were rejected",
                "Supported items were sent through the normal review and sealing workflow. "
                "Rejected items were not changed.\n\n"
                + "\n".join(rejected[:8])
                + (f"\n…and {len(rejected) - 8} more." if len(rejected) > 8 else ""))
    def add_files(
        self,
        source_paths: Optional[Iterable[Union[os.PathLike[str], str]]] = None,
    ) -> Optional[int]:
        vault_root = self.root
        if self.ro or vault_root is None or not self.sec_ok("vault_write"): return
        if App.other_working(self) or self.dying:
            return QMessageBox.warning(self, "Vault operation in progress",
                                       "Finish or cancel the other active vault operation before adding an encryption job.")
        if source_paths is None:
            self.hold += 1
            try:
                ps, _ = QFileDialog.getOpenFileNames(self, "Choose files to seal")
            finally:
                self.hold -= 1
        else:
            ps = [os.fspath(path) for path in source_paths]
        if not ps: return
        sources: list[tuple[Path, int, int, int, int]] = []; seen: set[str] = set()
        try:
            for raw_path in ps:
                path = Path(raw_path)
                info = path.lstat()
                if (stat.S_ISLNK(info.st_mode)
                        or getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
                        or not stat.S_ISREG(info.st_mode)):
                    raise OSError(f"{path.name}: links and non-regular files are not sealed as ordinary files.")
                identity = str(path.resolve(strict=True)).casefold()
                if identity in seen: continue
                seen.add(identity)
                sources.append((path, info.st_size, info.st_mtime_ns, info.st_dev, info.st_ino))
        except OSError as exc:
            return QMessageBox.warning(self, "Could not review selected files", str(exc))
        if not sources: return
        total_plain = sum(entry[1] for entry in sources)
        estimated_output = sum(estimate_ciphertext_size(entry[1]) for entry in sources)
        forecast = storage_preflight(VAULT, estimated_output)
        if forecast["status"] == "unsafe":
            return QMessageBox.warning(self, "Unsafe vault storage path", "The vault storage path is a symbolic link or is not a directory. No files were sealed.")
        if forecast["status"] == "insufficient":
            return QMessageBox.warning(self, "Not enough storage",
                f"The encrypted files are estimated to need about {fmt(estimated_output)} plus a safety margin. "
                f"Available space is {fmt_storage_size(forecast['free'])}. Choose a different storage location or free space before sealing.")
        if forecast["status"] == "unavailable" and QMessageBox.question(
                self, "Storage estimate unavailable",
                "UNKNWN could not read available disk space. The operation may fail if storage runs out. Continue?") != QMessageBox.StandardButton.Yes:
            return
        ttl, vw = self.ex.currentData(), self.vw.currentData()
        risks: list[str] = []
        if ttl: risks.append(f"These files will be permanently burned after {self.ex.currentText()}.")
        if vw: risks.append(f"These files will be permanently burned after {self.vw.currentText()}.")
        if self.rm.isChecked(): risks.append("The selected originals will be removed after sealing; overwrite attempts cannot guarantee physical erasure on SSDs or flash storage.")
        review: list[str] = [f"{len(sources)} selected file(s), {fmt(total_plain)} of source data.",
                  f"Estimated encrypted output: about {fmt(estimated_output)}; the estimate includes chunk-authentication overhead but is not a guarantee."]
        review.extend(f"• {sanitize_text(entry[0].name, 160)} — {fmt(entry[1])}" for entry in sources[:8])
        if len(sources) > 8: review.append(f"…and {len(sources) - 8} more file(s).")
        if forecast["status"] == "pass":
            review.append(f"Available storage now: {fmt_storage_size(forecast['free'])}; a safety margin is included in the check.")
        review.extend(risks)
        if not terminal_confirm(self, "Review files before sealing", "vault --seal --preview",
                review + ["Only encrypted data will be committed. Selected originals remain unless source shredding was enabled."]):
            return
        remove_originals = self.rm.isChecked()
        shred_passes = S("shred")
        mask_names = bool(S("mask"))
        def create_worker() -> _SealWorker:
            if self.root != vault_root:
                raise RuntimeError("The originating Vault session is no longer active.")
            return _SealWorker(
                sources, vault_root, dict(idx), ttl, vw,
                remove_originals, shred_passes, mask_names)
        self._queue_seal_job(
            f"Seal {len(sources)} file(s)", vault_root, create_worker,
            self.finish_seal_operation)
    def finish_seal_operation(self, result: Mapping[str, Any]) -> None:
        self._seal_queue_job_finished()
        records = result.get("records", [])
        for record in records:
            idx[record["rid"]] = record["metadata"]
        for offset, record in enumerate(records):
            self.add_card(record["rid"], offset * 120)
        self.apply_vault_sort()
        names = [record["name"] for record in records]
        if names:
            self.record_session_event("files_stored", count=len(names), names=names)
        if result.get("status") == "recovery_required":
            self._discard_queued_seal_jobs()
            QMessageBox.warning(
                self, "Storage recovery required",
                "The encrypted stage or storage journal could not be finalized safely. Preserve the vault data and sign in again to run authenticated recovery. The original source files were not removed unless a completed item had explicitly requested source removal.")
            self.lock()
            self.run_pending_seal_action()
            return
        failures_value: object = result.get("failures", [])
        failures = (
            [cast(dict[str, object], failure) for failure in cast(list[object], failures_value) if isinstance(failure, dict)]
            if isinstance(failures_value, list) else []
        )
        if result.get("status") == "cancelled":
            QMessageBox.information(
                self, "Sealing cancelled",
                f"Cancellation completed at a safe boundary. {len(records)} file(s) were already committed; any uncommitted staging output was removed. Uncommitted source files remain unchanged.")
        elif failures:
            details: list[str] = []
            for failure in failures[:8]:
                name = "Hidden file" if S("mask") else sanitize_text(failure.get("name", "File"), 120)
                details.append(f"{name}: {sanitize_text(failure.get('detail', 'Failed'), 300)}")
            if len(failures) > 8:
                details.append(f"…and {len(failures) - 8} more failure(s).")
            QMessageBox.warning(
                self, "Some files could not be sealed",
                f"{len(records)} of {result.get('total', 0)} file(s) were sealed; {len(failures)} failed.\n\n"
                + "\n".join(details))
        self.run_pending_seal_action()
    def add_folder(
        self,
        source_path: Optional[Union[os.PathLike[str], str]] = None,
    ) -> Optional[int]:
        vault_root = self.root
        if self.ro or vault_root is None or not self.sec_ok(): return
        if App.other_working(self) or self.dying:
            return QMessageBox.warning(self, "Vault operation in progress",
                                       "Finish or cancel the other active vault operation before adding an encryption job.")
        if source_path is None:
            self.hold += 1
            try: selected = QFileDialog.getExistingDirectory(self, "Choose a folder to seal")
            finally: self.hold -= 1
        else:
            selected = os.fspath(source_path)
        if not selected: return
        try:
            root, entries = folder_entries(selected)
            file_entries = [entry for entry in entries if not entry[2]]
            directory_count = sum(1 for entry in entries if entry[2])
            total_bytes = sum(snapshot[2] for _, _, _is_dir, snapshot in file_entries)
            type_bytes: dict[str, int] = {}
            for path, _relative, _is_dir, snapshot in file_entries:
                category = _analysis_category(path.name)
                type_bytes[category] = type_bytes.get(category, 0) + snapshot[2]
        except (OSError, ValueError) as exc:
            return QMessageBox.warning(self, "Could not read folder", f"{type(exc).__name__}: {exc}")
        if not entries and not root.is_dir():
            return QMessageBox.warning(self, "Could not read folder", "The selected folder no longer exists.")
        archive_estimate = total_bytes + max(1 << 20, total_bytes // 100) + sum(len(relative.encode("utf-8")) + 256 for _, relative, _, _ in entries)
        estimated_output = estimate_ciphertext_size(archive_estimate)
        forecast = storage_preflight(VAULT, estimated_output)
        if forecast["status"] == "unsafe":
            return QMessageBox.warning(self, "Unsafe vault storage path", "The vault storage path is a symbolic link or is not a directory. The folder was not sealed.")
        if forecast["status"] == "insufficient":
            return QMessageBox.warning(self, "Not enough storage",
                f"The encrypted folder is estimated to need about {fmt(estimated_output)} plus a safety margin. "
                f"Available space is {fmt_storage_size(forecast['free'])}. Free space before sealing this folder.")
        if forecast["status"] == "unavailable" and QMessageBox.question(
                self, "Storage estimate unavailable",
                "UNKNWN could not read available disk space. The encrypted folder operation may fail if storage runs out. Continue?") != QMessageBox.StandardButton.Yes:
            return
        ttl, views = self.ex.currentData(), self.vw.currentData()
        archive_display_name = "Hidden folder archive" if S("mask") else root.name + ".zip"
        file_label = "file" if len(file_entries) == 1 else "files"
        directory_label = "folder" if directory_count == 1 else "folders"
        risks = [
            f"Folder inventory: {len(file_entries):,} {file_label}, {directory_count:,} {directory_label}, "
            f"{fmt(total_bytes)} total file data; sealed as {archive_display_name}.",
        ]
        if type_bytes:
            risks.append("File-type totals: " + ", ".join(
                f"{category} {fmt(size)}" for category, size in sorted(type_bytes.items())) + ".")
        risks.append(
            f"Estimated encrypted output: about {fmt(estimated_output)}; ZIP compression and filesystem overhead make this an estimate.")
        risks.append(
            "Already-compressed file formats are stored without a second compression pass; other files use ZIP deflate.")
        if ttl: risks.append(f"The sealed folder archive will be permanently burned after {self.ex.currentText()}.")
        if views: risks.append(f"The sealed folder archive will be permanently burned after {self.vw.currentText()}.")
        if self.rm.isChecked():
            risks.append("After a successful seal, source files included in the archive will be removed. Empty directories will be removed where possible; skipped symlinks and other files will remain.")
            risks.append("Overwrite attempts cannot guarantee physical erasure on SSDs or flash storage.")
        if not terminal_confirm(self, "Seal folder", "vault --seal-folder",
                risks + ["The folder is stored as a compressed ZIP inside the encrypted vault. Archive contents are not extracted to disk."]):
            return
        remove_originals = self.rm.isChecked()
        shred_passes = S("shred")
        mask_names = bool(S("mask"))
        def create_worker() -> _FolderSealWorker:
            if self.root != vault_root:
                raise RuntimeError("The originating Vault session is no longer active.")
            return _FolderSealWorker(
                root, entries, vault_root, dict(idx), ttl, views,
                remove_originals, shred_passes, mask_names)
        self._queue_seal_job(
            f"Seal folder: {sanitize_text(root.name, 80)}",
            vault_root, create_worker, self.finish_folder_seal_operation)
    def finish_folder_seal_operation(self, result: Mapping[str, Any]) -> None:
        self._seal_queue_job_finished()
        records = result.get("records", [])
        for record in records:
            idx[record["rid"]] = record["metadata"]
            self.add_card(record["rid"])
        if records:
            self.apply_vault_sort()
            self.record_session_event(
                "files_stored", count=1, names=[records[0]["name"]])
        if result.get("status") == "recovery_required":
            self._discard_queued_seal_jobs()
            QMessageBox.warning(
                self, "Storage recovery required",
                "The encrypted folder stage or storage journal could not be finalized safely. Preserve the vault data and sign in again to run authenticated recovery. The source folder was not removed unless the encrypted item was fully committed.")
            self.lock()
            self.run_pending_seal_action()
            return
        failures = result.get("failures", [])
        if result.get("status") == "cancelled":
            QMessageBox.information(
                self, "Folder sealing cancelled",
                "Cancellation completed at a safe boundary. Any uncommitted encrypted stage was removed; the source folder remains unchanged.")
        elif failures:
            details = "\n".join(
                f"{sanitize_text(failure.get('name', 'Folder'), 120)}: "
                f"{sanitize_text(failure.get('detail', 'Failed'), 300)}"
                for failure in failures[:8])
            QMessageBox.warning(
                self, "Could not seal folder",
                "The folder was not fully sealed. Source files were not intentionally removed.\n\n" + details)
        elif records and result.get("cleanup_warning"):
            QMessageBox.warning(
                self, "Folder sealed; source cleanup incomplete",
                "The encrypted folder is in the vault, but some source entries may remain. Check the original folder.")
        self.run_pending_seal_action()
    def open_vault_notes(self) -> None:
        dialog = QDialog(self)
        dialog.setWindowTitle("UNKNWN // VAULT NOTES")
        dialog.setMinimumSize(420, 360)
        layout = QVBoxLayout(dialog)
        layout.addWidget(lbl("VAULT NOTES", 17, ACC, True))
        note_list = QListWidget(dialog)
        note_ids: list[str] = []
        for rid, card in self.cards.items():
            if card.name.startswith("Note - ") and rid in idx:
                note_ids.append(rid)
                label = "Hidden note" if S("mask") else card.name
                item = QListWidgetItem(label)
                item.setData(Qt.ItemDataRole.UserRole, rid)
                note_list.addItem(item)
        if not note_ids:
            note_list.addItem("No notes yet. Notes are encrypted and stored in this Vault.")
            note_list.setEnabled(False)
        layout.addWidget(note_list, 1)
        actions = QHBoxLayout()
        create = btn("New note", "go")
        open_note = btn("Open selected")
        close = btn("Close", "flat")
        def create_note() -> None:
            dialog.accept()
            self.create_vault_note()
        create.clicked.connect(create_note)
        def open_selected_note() -> None:
            item = note_list.currentItem()
            rid_value = item.data(Qt.ItemDataRole.UserRole) if item is not None else None
            if isinstance(rid_value, str) and rid_value in self.cards:
                dialog.accept()
                self.view(rid_value)
        open_note.clicked.connect(open_selected_note)
        close.clicked.connect(dialog.accept)
        actions.addWidget(create)
        actions.addWidget(open_note)
        actions.addStretch()
        actions.addWidget(close)
        layout.addLayout(actions)
        dialog.exec_()
    def create_vault_note(self) -> None:
        if self.ro or self.root is None or not self.sec_ok():
            return
        if App.other_working(self):
            QMessageBox.warning(self, "Vault operation in progress",
                                "Wait for the other active Vault operation before creating a note.")
            return
        dialog = QDialog(self)
        dialog.setWindowTitle("UNKNWN // NEW VAULT NOTE")
        dialog.setMinimumSize(480, 420)
        layout = QVBoxLayout(dialog)
        layout.addWidget(lbl("NEW ENCRYPTED NOTE", 16, ACC, True))
        title = QLineEdit()
        title.setPlaceholderText("Note title")
        content = QPlainTextEdit()
        content.setPlaceholderText("Write a note. It will be encrypted as a normal Vault item.")
        content.setMaximumBlockCount(5000)
        layout.addWidget(title)
        layout.addWidget(content, 1)
        expiry = self.combo([("Never", 0), ("1 minute", 60), ("1 hour", 3600),
                             ("24 hours", 86400), ("7 days", 604800)])
        views = self.combo([("Unlimited", 0), ("1 view", 1), ("3 views", 3), ("5 views", 5)])
        limits = QHBoxLayout()
        limits.addWidget(lbl("Burn after", 12, MUT))
        limits.addWidget(expiry, 1)
        limits.addWidget(lbl("Burn after views", 12, MUT))
        limits.addWidget(views, 1)
        layout.addLayout(limits)
        buttons = QHBoxLayout()
        cancel = btn("Cancel", "flat")
        save = btn("Encrypt note", "go")
        cancel.clicked.connect(dialog.reject)
        save.clicked.connect(dialog.accept)
        buttons.addStretch()
        buttons.addWidget(cancel)
        buttons.addWidget(save)
        layout.addLayout(buttons)
        if dialog.exec_() != QDialog.DialogCode.Accepted:
            return
        note_title = re.sub(r'[\\x00-\\x1f<>:"/\\\\|?*]+', "-", title.text()).strip(" .-")[:80]
        note_text = content.toPlainText()
        if not note_title or not note_text.strip():
            QMessageBox.warning(self, "Note not saved",
                                "Enter a title and some note text before encrypting.")
            return
        note_name = f"Note - {note_title}.txt"
        payload = note_text.encode("utf-8")
        if len(payload) > 1 << 20:
            QMessageBox.warning(self, "Note is too large",
                                "Vault notes are limited to 1 MiB each.")
            return
        ttl = cast(int, expiry.currentData())
        view_limit = cast(int, views.currentData())
        output_estimate = estimate_ciphertext_size(len(payload))
        forecast = storage_preflight(VAULT, output_estimate)
        if forecast["status"] in ("unsafe", "insufficient"):
            QMessageBox.warning(
                self, "Cannot encrypt note",
                "Vault storage is unsafe or does not have enough available space. The note was not written.")
            return
        if not terminal_confirm(
                self, "Review encrypted note", "notes --seal --preview",
                [f"Encrypt {note_name} as a Vault item.",
                 f"Note size: {fmt(len(payload))}.",
                 f"Expiry: {expiry.currentText()}; view limit: {views.currentText()}.",
                 "The note is staged in the app's private temporary directory and cleaned up after the queued operation."]):
            return
        note_path: Optional[Path] = None
        try:
            note_path = tmp_media(note_name, payload)
            info = note_path.lstat()
            source = (note_path, info.st_size, info.st_mtime_ns, info.st_dev, info.st_ino)
            vault_root = cast(Optional[bytes], self.root)
            if vault_root is None:
                tmp_wipe(note_path)
                return
            def create_worker() -> _SealWorker:
                if self.root != vault_root:
                    raise RuntimeError("The originating Vault session is no longer active.")
                return _SealWorker(
                    [source], vault_root, dict(idx), ttl, view_limit, True,
                    S("shred"), bool(S("mask")), {str(note_path): note_name})
            self._queue_seal_job(
                f"Encrypt note: {note_name}", vault_root, create_worker,
                self.finish_seal_operation,
                cleanup=lambda path=note_path: tmp_wipe(path))
        except Exception as exc:
            if note_path is not None:
                tmp_wipe(note_path)
            log_security_event("vault_note_staging_failed", error=type(exc).__name__)
            QMessageBox.warning(self, "Could not stage note",
                                f"The note was not queued ({type(exc).__name__}).")
    def view(self, rid: str) -> Optional[int]:
        if App.sealing_in_background(self):
            return QMessageBox.information(
                self, "Vault item unavailable",
                "Viewing items is paused while encryption updates the vault. Try again when sealing finishes.")
        root = self.root
        if root is None or not self.sec_ok("vault_read"): return
        if S("reauth") and not self.ask_pw(): return
        m = idx.get(rid)
        c = self.cards.get(rid)
        if m is None or c is None:
            return QMessageBox.information(
                self, "Vault item unavailable",
                "The selected item is no longer present in the authenticated vault index.")
        simulation = self._simulate_vault_action((rid,), "view_file")
        if not simulation.valid:
            return QMessageBox.warning(
                self, "Vault item unavailable",
                "Preflight blocked viewing: " + ", ".join(simulation.conflicts))
        try:
            operation, file_revision = self._begin_vault_file_operation(
                rid, "view_file", simulation)
        except (FileStateError, StaleSimulationPlan, OperationBlocked,
                InvalidOperationTransition, KeyError) as exc:
            return QMessageBox.warning(
                self, "Vault item unavailable",
                f"The item state does not allow viewing ({type(exc).__name__}). Refresh the vault and try again.")
        limited_access = m["exp"] is not None or m["views"] is not None
        u = Upload(self) if m["size"] >= BIG else None; label = ("Hidden file " + rid[:4]) if S("mask") else c.name
        data: Optional[bytes] = None; media_path: Optional[Path] = None; media_digest: Optional[str] = None; ok = False
        if u: u.show()
        try:
            key = file_key(root, b64d(m["s"]))
            progress: Optional[Callable[[int, int], None]] = None
            if u is not None:
                upload = u
                def report_decrypt_progress(done: int, total: int) -> None:
                    upload.pump(done / total, "Decrypting " + label)
                progress = report_decrypt_progress
            disk_media = (S("vmode") == "file" and not S("ghost")
                          and Path(c.name).suffix.lower() in MD.VID_EXT | MD.AUD_EXT)
            if disk_media:
                media_path, plain_size, media_digest = dec_file_to_temp(
                    VAULT / f"{rid}.cdr", key, c.name, progress, with_digest=True)
                with open(media_path, "rb") as source: preview = source.read(8192)
                media_kind = MD.kind(c.name, preview)
                if plain_size == m["size"] and media_kind in ("video", "audio"):
                    ok = True
                else:
                    tmp_wipe(media_path); media_path = None; media_digest = None
            if not ok:
                data = dec_file(VAULT / f"{rid}.cdr", key, progress)
                ok = len(data) == m["size"]
        except Exception:
            if media_path is not None: tmp_wipe(media_path); media_path = None
            ok = False
        if u:
            if ok: u.finish("Decrypted. Opening viewer...")
            u.close()
        if not ok:
            if media_path is not None: tmp_wipe(media_path)
            try:
                self._finish_vault_file_operation(
                    rid, operation, file_revision, verified=False, recovery_required=True)
                operation.report_result(
                    "view_file", affected_items=(rid,), failed_items=(rid,),
                    recovery_items=(rid,), failure_codes=("file_verification_failed",))
            except (FileStateError, InvalidOperationTransition, KeyError):
                log_security_event("file_state_view_finalization_failed",
                                   error="FileStateError")
            return QMessageBox.warning(self, "Cannot open", "This file could not be decrypted. It may have been altered.")
        if m["views"] is not None and not self.ro:
            remaining_views = m["views"]
            assert remaining_views is not None
            candidate: dict[str, _VaultMetadata] = dict(idx)
            updated: _VaultMetadata = {**m, "views": remaining_views - 1}
            candidate[rid] = updated
            try:
                commit_storage_transaction(root, "index", rid, candidate, expected_index=idx)
            except Exception as exc:
                detail = "Details hidden by file-name masking." if S("mask") else sanitize_text(str(exc), 300)
                if media_path is not None: tmp_wipe(media_path)
                if storage_txn_path().exists():
                    try:
                        self._finish_vault_file_operation(
                            rid, operation, file_revision, verified=False, recovery_required=True)
                        operation.report_result(
                            "view_file", affected_items=(rid,), failed_items=(rid,),
                            recovery_items=(rid,), failure_codes=("storage_recovery_required",))
                    except (FileStateError, InvalidOperationTransition, KeyError):
                        log_security_event("file_state_view_finalization_failed",
                                           error="FileStateError")
                    QMessageBox.warning(self, "Storage recovery required",
                                        f"The view-count update will be verified after authentication ({type(exc).__name__}: {detail}); the file was not opened.")
                    self.lock()
                else:
                    try:
                        self._finish_vault_file_operation(
                            rid, operation, file_revision, verified=True,
                            safe_cleanup=True, failed=True)
                        operation.report_result(
                            "view_file", affected_items=(rid,), failed_items=(rid,),
                            failure_codes=("view_count_commit_failed",))
                    except (FileStateError, InvalidOperationTransition, KeyError):
                        log_security_event("file_state_view_finalization_failed",
                                           error="FileStateError")
                    QMessageBox.warning(self, "Could not update vault",
                                        f"The view-count update did not commit ({type(exc).__name__}: {detail}); the file was not opened.")
                return
            idx.clear(); idx.update(candidate); m = idx[rid]
            detail_label = getattr(c, "vl", None)
            if isinstance(detail_label, QLabel): detail_label.setText(self.card_details(m, c.name))
        try:
            self._finish_vault_file_operation(
                rid, operation, file_revision, verified=True)
            operation.report_result(
                "view_file", affected_items=(rid,), succeeded_items=(rid,),
                verified_items=(rid,))
        except (FileStateError, InvalidOperationTransition, KeyError) as exc:
            if data is not None:
                data = None
            if media_path is not None:
                tmp_wipe(media_path)
            return QMessageBox.warning(
                self, "Vault item unavailable",
                f"The file state could not be finalized ({type(exc).__name__}); the item was not opened.")
        self.record_session_event("file_opened", name=c.name)
        self.viewing = rid; self.hold += 1
        try:
            try:
                self.dlg = Viewer(c.name, data, m["views"] == 0 and not self.ro, self,
                               media_path=media_path, media_digest=media_digest,
                               limited_access=limited_access)
            except TypeError as exc:
                if "limited_access" in str(exc):
                    try:
                        self.dlg = Viewer(
                            c.name, data, m["views"] == 0 and not self.ro, self,
                            media_path=media_path, media_digest=media_digest)
                    except TypeError as legacy_exc:
                        if "media_digest" not in str(legacy_exc):
                            raise
                        self.dlg = Viewer(
                            c.name, data, m["views"] == 0 and not self.ro, self,
                            media_path=media_path)
                elif "media_digest" in str(exc):
                    self.dlg = Viewer(
                        c.name, data, m["views"] == 0 and not self.ro, self,
                        media_path=media_path)
                else:
                    raise
            if media_path is not None and self.dlg.tmp == Path(media_path): media_path = None
            self.dlg.exec_()
        finally:
            self.dlg = None; self.hold -= 1; self.viewing = None
            if media_path is not None: tmp_wipe(media_path)
        self.tick()
    def burn(self, rid: str, ask: bool = True) -> None:
        if App.sealing_in_background(self):
            if ask:
                QMessageBox.information(
                    self, "Vault item unavailable",
                    "Removing items is paused while encryption updates the vault. Try again when sealing finishes.")
            return
        if rid in self.dying or self.root is None or not self.sec_ok("destructive"): return
        c = self.cards.get(rid)
        if c is None or rid not in idx or self.mode != "vault":
            return
        simulation = self._simulate_vault_action((rid,), "burn_file", destructive=True)
        if not simulation.valid:
            if ask:
                QMessageBox.warning(
                    self, "Removal unavailable",
                    "Preflight blocked removal: " + ", ".join(simulation.conflicts))
            return
        if ask and not terminal_confirm(self, "Burn sealed file", "vault --burn " + rid[:8],
                [f"Simulation predicts {simulation.affected_count} affected item(s); no changes have been made yet.",
                 "Delete this sealed file. It cannot be restored with the password or recovery words.",
                 "Overwrite attempts are best-effort and cannot guarantee physical erasure on SSDs, flash storage, snapshots, or backups."]): return
        try:
            operation, revision = self._begin_vault_file_operation(
                rid, "burn_file", simulation)
        except (FileStateError, StaleSimulationPlan, OperationBlocked,
                InvalidOperationTransition, KeyError) as exc:
            QMessageBox.warning(
                self, "Vault item unavailable",
                f"The item state does not allow removal ({type(exc).__name__}). Refresh the vault and try again.")
            return
        c._file_operation = operation
        c._file_state_revision = revision
        self.dying.add(rid)
        a = QPropertyAnimation(c, b"burn"); a.setDuration(1300); a.setStartValue(0.0); a.setEndValue(1.0); a.setEasingCurve(QEasingCurve.Type.InQuad)
        a.finished.connect(lambda: self.finish(rid)); c.anim = a; a.start()
    def finish(self, rid: str) -> None:
        root = self.root
        if root is None:
            self.dying.discard(rid)
            return
        fp_ = VAULT / f"{rid}.cdr"; c0 = self.cards.get(rid); u = None
        operation = getattr(c0, "_file_operation", None) if c0 is not None else None
        revision = getattr(c0, "_file_state_revision", None) if c0 is not None else None
        if not isinstance(operation, Operation) or type(revision) is not int:
            self.dying.discard(rid)
            return
        if fp_.exists() and fp_.stat().st_size >= BIG and not self.busy:
            u = Upload(self)
            u.show_after()
        lab = ("Hidden file " + rid[:4]) if (S("mask") or not c0) else c0.name
        candidate = dict(idx); candidate.pop(rid, None)
        try:
            commit_storage_transaction(root, "burn", rid, candidate, passes=S("shred"),
                                      cb=(lambda done, total: u.pump(done / total, "Removing " + lab)) if u else None,
                                      expected_index=idx)
        except Exception as exc:
            detail = "Details hidden by file-name masking." if S("mask") else sanitize_text(str(exc), 300)
            self.dying.discard(rid)
            try:
                self._finish_vault_file_operation(
                    rid, operation, revision, verified=False, recovery_required=True)
                OPERATION_MANAGER.record_result(
                    operation.operation_id, "burn_file", affected_items=(rid,),
                    failed_items=(rid,), recovery_items=(rid,),
                    failure_codes=(type(exc).__name__,))
            except (FileStateError, InvalidOperationTransition, KeyError, ValueError):
                pass
            if u: u.finish("Removal paused for recovery."); u.close()
            if storage_txn_path().exists():
                QMessageBox.warning(self, "Storage recovery required",
                                    f"The selected removal will resume after authentication ({type(exc).__name__}: {detail}).")
                self.lock()
            else:
                QMessageBox.warning(self, "Could not remove vault item",
                                    f"The item was not removed ({type(exc).__name__}: {detail}); it remains in the vault.")
            return
        idx.clear(); idx.update(candidate)
        try:
            self._finish_vault_file_operation(
                rid, operation, revision, verified=True, unavailable=True)
            OPERATION_MANAGER.record_result(
                operation.operation_id, "burn_file", affected_items=(rid,),
                succeeded_items=(rid,), verified_items=(rid,), committed_items=(rid,))
        except (FileStateError, InvalidOperationTransition, KeyError, ValueError) as exc:
            log_security_event("file_state_commit_failed", error=type(exc).__name__)
            QMessageBox.warning(
                self, "Removal requires recovery",
                "The vault removal committed, but its in-memory file state could not be finalized. "
                "Lock the vault and resolve recovery before continuing.")
            self.lock()
            return
        if u: u.finish("Removed from vault."); u.close()
        if c0: self.record_session_event("file_burned", name=c0.name)
        self.dying.discard(rid); self.cds.pop(rid, None)
        self.selected_items.discard(rid)
        c = self.cards.pop(rid, None)
        if c: c.setParent(None); c.deleteLater()
        if self.mode == "vault":
            self.apply_vault_sort()
            self.sync()
    def lock(self, anim: bool = False) -> None:
        self.restore_secret_theme()
        if self.defer_seal_action("lock", anim):
            return
        if self.mode == "vault": self.record_session_event("vault_locked")
        self.relocked = self.relocked or self.mode == "vault"
        fx = LockSequence(self) if anim and self.mode == "vault" and not self.busy and S("wipefx") != "none" and perf() != "min" else None
        for r in list(self.dying): self.finish(r)
        for rid in tuple(getattr(self, "cards", {})):
            key = self._vault_file_state_key(rid)
            try:
                state = FILE_STATE_MANAGER.snapshot(key)
                if state.state == FileState.AVAILABLE:
                    FILE_STATE_MANAGER.lock_available(key, state.revision)
            except (FileStateError, StaleFileState) as exc:
                log_security_event("file_state_lock_deferred", error=type(exc).__name__)
        if self.dlg: self.dlg.reject()
        st_ = getattr(self, "studio", None)
        if st_ is not None: st_.close()
        if S("clip") or S("ghost"): clear_clipboard()
        self.root = None; self.ro = False; self.cards.clear(); self.cds.clear(); self.login_screen()
        if fx: fx.raise_()
    def switch_profile(self) -> Optional[int]:
        if self.mode not in ("vault", "login"):
            return
        if not self.sec_ok():
            return
        if pending_self_destruct_deadline():
            return QMessageBox.warning(
                self, "Profile switch unavailable",
                "A Maximum Security countdown is active for this vault. Switching profiles is blocked so the countdown cannot be bypassed."
            )
        if self.busy or self.working() or self.hold:
            return QMessageBox.warning(
                self, "Vault operation in progress",
                "Finish or close the active vault operation or viewer before switching profiles. The current vault remains open."
            )
        try:
            profiles = _read_profiles()
        except Exception as exc:
            log_security_event("profile_switch_registry_check_failed", error=type(exc).__name__)
            return QMessageBox.warning(
                self, "Profile switch unavailable",
                f"The profile registry could not be verified ({type(exc).__name__}). "
                "The current profile remains open.")
        if self.mode == "vault":
            self.record_session_event("profile_switch")
            self.lock(False)
        self.relocked = False
        self.session_id = None; self.session_started = None; self.session_activity = []
        self.session_stored_names = []; self.session_stored_count = 0
        self.session_setting_changes = 0; self.session_activity_omitted = 0
        self.session_history_error = None
        self.profile_switch = ProfileSwitchSequence(
            self, self.profile_chooser, len(profiles))
    def tick(self) -> Optional[int]:
        if self.mode == "blocked" or INTEG[0] == "fail": return
        self.tc = getattr(self, "tc", 0) + 1
        if COMPILED and self.tc % 45 == 0:
            runtime = IG.runtime_trust()
            if runtime != "clear":
                self.integ_fail(
                    "runtime_debugger_detected" if runtime == "debugger"
                    else "runtime_check_unavailable"
                )
                return
        sealing = App.sealing_in_background(self)
        if self.busy or (self.working() and not sealing): return
        now = time.time()
        if INTEG[0] == "ok" and self.tc % 45 == 0 and not self.integ_ok(): return
        pending_deadline = pending_self_destruct_deadline()
        if pending_deadline and now >= pending_deadline:
            return self.panic(False)
        if self.mode == "vault" and getattr(self, "sd_timer", None) is not None:
            self.sd_timer.setText(f"SELF-DESTRUCT IN {cdt(pending_deadline - now)}" if pending_deadline else "")
        login_label = getattr(self, "lk", None)
        if self.mode == "login" and login_label is not None:
            if pending_deadline:
                msg = f"Maximum Security countdown active: {cdt(pending_deadline - now)} remains before the vault is destroyed."
                if getattr(self, "pending_password_ack", False): msg += " Password entry is enabled; the countdown continues."
                login_label.setText(msg)
            else:
                r = cfg["lock"] - now
                if r > 0: login_label.setText(f"Too many wrong tries. say goodbye to your files in {cdt(r)}.")
                else: self.lk = None; self.login_screen()
        if S("idle") and self.mode == "vault" and not self.hold and now - self.act > S("idle") * 60: return self.lock()
        if S("sess") and self.mode == "vault" and not self.hold and now - getattr(self, "t0", now) > S("sess") * 60: return self.lock()
        if S("dimidle") and self.mode == "vault": self.setWindowOpacity(.15 if now - self.act > 15 else S("winop") / 100)
        if S("dbg") and self.mode == "vault" and dbg_now(): return self.lock()
        if sealing: return
        if not (self.ro and self.root):   # time bombs + view limits keep running while locked, but freeze in a read-only session
            for rid, m in list(idx.items()):
                if (m["exp"] and m["exp"] <= now) or (m["views"] == 0 and rid != self.viewing): self.burn(rid, ask=False)
        for rid, l in list(self.cds.items()):
            m = idx.get(rid)
            if m and m["exp"]: l.setText(FIRE_ICON + " " + cdt(m["exp"] - now)); l.setStyleSheet("color:#ff3b5c" if m["exp"] - now < 60 else "color:#22d3ee")

    # ---------- wipe & self-destruct ----------
    def confirm_panic(self) -> bool:
        return terminal_confirm(self, "Terminal // vault wipe", "wipe --vault --all",
                ["Delete every stored sealed file and reset UNKNWN. This cannot be undone from this installation.",
                 "Overwrite attempts, when enabled, are best-effort; SSDs, flash storage, snapshots, and backups may retain copies.",
                 "This confirmation does not display file names or contents."])
    def panic(self, ask: bool = True) -> Optional[int]:
        if self.busy: return
        if self.defer_seal_action("panic", ask): return
        if ask and not self.confirm_panic(): return
        try:
            begin_destructive_cleanup("panic-wipe")
        except Exception as exc:
            return QMessageBox.warning(self, "Wipe could not start",
                                       support_message(f"The cleanup journal could not be created ({type(exc).__name__}); no wipe began."))
        self.busy = True; self.root = None
        if self.dlg: self.dlg.reject()
        self.fl = PanicSequence(self, self.wipe_all, S("wipefx"))
    def wipe_all(self) -> None:
        global active_profile_id, active_profile_name
        restore_state = self.windowState() & ~Qt.WindowState.WindowMinimized
        self.showMinimized(); QApplication.processEvents(); error = None
        try:
            try:
                record = read_destruct_journal()
            except Exception:
                raise
            if record is None:
                record = begin_destructive_cleanup("panic-wipe")
            if record["operation"] != "panic-wipe":
                raise ValueError("A different UNKNWN cleanup operation is pending.")
            record = resume_destructive_cleanup(HOME, S("shred"))
            clear_destruct_journal()
            active_profile_id = None
            active_profile_name = None
        except Exception as exc:
            error = exc
        cfg.clear(); idx.clear(); self.root = None; self.cards.clear(); self.cds.clear(); self.dying.clear()
        self.fl.deleteLater(); self.busy = False; self.ro = False
        if error is not None:
            return self.destructive_recovery_screen(error)
        self.profile_chooser()
        QTimer.singleShot(0, lambda: self.restore_wipe_window(restore_state))
    def restore_wipe_window(self, state: Any) -> None:
        self.setWindowState(state & ~Qt.WindowState.WindowMinimized)
        self.show(); self.raise_()
    def targets(self) -> list[Path]:
        if not PACKAGED: return []
        app_dir = APP.parent
        executable_name = "UNKNWN.exe" if sys.platform == "win32" else "UNKNWN"
        app_path = APP.resolve()
        if (app_path.name.casefold() != executable_name.casefold()
                or app_path.parent != app_dir.resolve()):
            raise ValueError("The running executable is not at a dedicated UNKNWN package root.")
        return [_validate_packaged_install_target(app_dir)]
    def confirm_destruct(self) -> bool:
        try:
            targets = self.targets()
        except (OSError, ValueError) as exc:
            QMessageBox.warning(
                self, "Full self-destruct is unavailable",
                support_message(f"The signed UNKNWN installation could not be validated ({type(exc).__name__}); no cleanup began."))
            return False
        if sys.platform != "win32":
            QMessageBox.warning(
                self, "Full self-destruct is unavailable",
                "Staged Full Self-Destruct is supported only by the verified Windows package; no cleanup began.")
            return False
        if not targets:
            QMessageBox.warning(
                self, "Full self-destruct is unavailable",
                "Full Self-Destruct is available only from a verified packaged installation. "
                "This source/development run is protected; use the vault-only wipe if you intend to clear its data.")
            return False
        app_removal = "Remove the verified UNKNWN application: " + ", ".join(map(str, targets))
        restart_notice = ("After the verified application and data cleanup, create and verify "
                         "%USERPROFILE%\\Downloads\\meow.txt with exact contents `meow`, then request a normal "
                         "Windows restart countdown of 10 seconds; other apps may delay or block the restart.")
        details = [f"Delete supported vault/profile data: {HOME}, {PORT}, {Path.home() / '.unknwn'}, and {Path.home() / '.unknwn-profiles'}",
                   f"Delete the profile registry file: {PROFILE_REGISTRY}. For a validated Windows package, a temporary recovery value is created only at HKCU\\{DESTRUCT_RUNONCE_KEY}\\{DESTRUCT_RUNONCE_VALUE} and removed after successful cleanup; no other UNKNWN Registry entries are targeted.",
                   app_removal,
                   restart_notice,
                   "An existing Downloads\\meow.txt is never overwritten; if it is not already the exact verification marker, finalization stops and remains recoverable.",
                   "Save your work first; other apps will not be force-closed.",
                   "Overwrite attempts are best-effort. SSDs, flash storage, snapshots, and backups may retain copies."]
        if not terminal_confirm(self, "FULL SELF-DESTRUCT", "system --self-destruct --restart", details, acknowledge=True): return False
        return terminal_confirm(self, "Final confirmation // restart", "confirm --delete-and-restart",
                   ["The deletion and restart will begin immediately. Save and close other work first."])
    def destruct(self, ask: bool = True) -> Optional[Union[bool, int]]:
        if self.busy: return
        if self.defer_seal_action("destruct", ask): return
        if self.working() or self.hold:
            return QMessageBox.warning(
                self, "Vault operation in progress",
                "Finish or close the active operation or viewer before self-destruct. No data was changed.")
        if ask and not self.confirm_destruct(): return
        dry = bool(os.environ.get("UNKNWN_DRYRUN"))
        try:
            targets = self.targets()
        except (OSError, ValueError) as exc:
            return QMessageBox.warning(
                self, "Self-destruct could not start",
                support_message(f"The signed installation could not be revalidated ({type(exc).__name__}); no data was changed."))
        if not dry and sys.platform != "win32":
            return QMessageBox.warning(
                self, "Full self-destruct is unavailable",
                "Staged Full Self-Destruct is supported only by the verified Windows package. No vault data was changed.")
        if not targets and not dry:
            return QMessageBox.warning(
                self, "Full self-destruct is unavailable",
                "A verified packaged UNKNWN installation is required. No vault data was changed.")
        if not dry and len(targets) != 1:
            return QMessageBox.warning(
                self, "Self-destruct could not start",
                "The validated installation root is ambiguous; no data was changed.")
        self.busy = True; self.root = None
        if not dry:
            try:
                target = targets[0]
                begin_destructive_cleanup("self-destruct", target)
            except Exception as exc:
                self.busy = False
                return QMessageBox.warning(self, "Self-destruct could not start",
                                           support_message(f"The cleanup journal could not be created ({type(exc).__name__}); no wipe began."))
            if sys.platform == "win32":
                try:
                    register_destruct_runonce(target, None, destruct_journal_path())
                except Exception as exc:
                    log_security_event("self_destruct_recovery_registration_failed",
                                       error=type(exc).__name__)
                    try:
                        clear_destruct_journal()
                    except Exception as journal_exc:
                        self.busy = False
                        return self.destructive_recovery_screen(journal_exc)
                    self.busy = False
                    return QMessageBox.warning(
                        self, "Self-destruct recovery could not be prepared",
                        support_message(f"The restart-safe recovery helper could not be registered ({type(exc).__name__}); no wipe began."))
        self._destruct_wipe_complete = dry
        self._destruct_wipe_error = None
        if self.dlg: self.dlg.reject()
        wipe_effect = cast(str, S("wipefx"))
        wipe_effects: dict[str, float] = {"full": 1.0, "short": .55, "none": .06}
        k: float = wipe_effects.get(wipe_effect, 1.0); f = Inferno(self, int(8000 * k), "GO FUCK YOURSELF BITCH.", .22, True); self.fl = f; m = QLabel("", f); m.setAlignment(cast(Any, Qt.AlignmentFlag.AlignHCenter | Qt.AlignmentFlag.AlignBottom)); m.setGeometry(f.rect()); m.setStyleSheet("font:15px Consolas,monospace;color:#d9a678;background:transparent;padding-bottom:40px"); m.show(); QTimer.singleShot(int(7200 * k), m.hide)
        application_status = ("> application ............. removal pending verification"
                              if targets else "> source files ............ retained")
        for t, x in ((int(2000 * k), "> vault files ............ cleanup starting"), (int(3300 * k), "> UNKNWN data ............. cleanup running"), (int(4800 * k), application_status), (int(6400 * k), "> restart countdown ....... begins after cleanup succeeds")):
            def update_status(message: str = x) -> None:
                m.setText(message)
            QTimer.singleShot(t, update_status)
        def erase() -> None:
            if dry: return
            try:
                record = read_destruct_journal()
                if record is None or record["operation"] != "self-destruct":
                    raise ValueError("No authorized self-destruct operation is pending.")
                record = resume_destructive_cleanup(HOME, S("shred"))
                if record["operation"] != "self-destruct":
                    raise ValueError("A different UNKNWN cleanup operation is pending.")
                cfg.clear(); idx.clear()
                self._destruct_wipe_complete = True
            except Exception as exc:
                self._destruct_wipe_error = exc
        QTimer.singleShot(int(2200 * k), erase); QTimer.singleShot(int(8100 * k), _noarg_slot(lambda: self.finish_destruct(dry)))
    def finish_destruct(self, dry: bool) -> None:
        if dry:
            t = self.targets()
            QMessageBox.information(self, "Dry run", "Nothing was deleted or restarted.\n\nVault data: " + str(HOME) +
                                    "\nInstallation directory: " + (str(t[0]) if t else "not a validated packaged UNKNWN directory"))
            self.fl.deleteLater(); self.busy = False; self.root = None; return self.login_screen()
        try:
            record = read_destruct_journal()
        except Exception as exc:
            self.fl.deleteLater(); self.busy = False; self.root = None
            return self.destructive_recovery_screen(exc)
        if record is None or record["operation"] != "self-destruct" or record["phase"] != "data-cleared":
            error = getattr(self, "_destruct_wipe_error", None)
            self.fl.deleteLater(); self.busy = False; self.root = None; cfg.clear(); idx.clear()
            return self.destructive_recovery_screen(error or OSError("cleanup is not complete"))
        self.fl.deleteLater(); self.busy = False; self.root = None; cfg.clear(); idx.clear()
        return self.finalize_destructive_cleanup(record)
    def finalize_destructive_cleanup(self, record: _DestructJournal) -> None:
        global active_profile_id, active_profile_name
        self.root = None; self.ro = False; cfg.clear(); idx.clear()
        active_profile_id = None
        active_profile_name = None
        if record["operation"] == "panic-wipe":
            try:
                clear_destruct_journal()
            except Exception as exc:
                return self.destructive_recovery_screen(exc)
            self.profile_chooser()
            return
        if record.get("phase") != "data-cleared":
            return self.destructive_recovery_screen(
                ValueError("The application installation cannot be removed before data cleanup completes."))
        target = record.get("install_target")
        if not isinstance(target, str):
            return self.destructive_recovery_screen(
                ValueError("Full Self-Destruct requires a validated signed installation root."))
        try:
            target_path = _validate_packaged_install_target(
                Path(target), require_exists=False, allow_partial=True)
        except Exception as exc:
            return self.destructive_recovery_screen(exc)
        try:
            if sys.platform != "win32":
                raise OSError("Staged Full Self-Destruct is supported only by the verified Windows package.")
            if target_path.exists():
                register_destruct_runonce(target, None, destruct_journal_path())
            elif not _safe_recovery_script(Path.home() / DESTRUCT_RECOVERY_SCRIPT):
                raise FileNotFoundError(
                    "The staged recovery helper is missing and the signed installation is already absent.")
            cmd = destruct_runonce_command(os.getpid())
            subprocess.Popen(cmd, creationflags=0x08000008, cwd=tempfile.gettempdir(), close_fds=True)
        except Exception as exc:
            journal = read_destruct_journal()
            if journal is not None:
                journal["failures"] = (journal["failures"] + [type(exc).__name__])[-16:]
                write_destruct_journal(journal)
            return self.destructive_recovery_screen(exc)
        os._exit(0)

if __name__ == "__main__":
    def log_error(
        t: type[BaseException],
        v: BaseException,
        tb: Optional[TracebackType],
    ) -> None:  # crashes go to error.log in the data folder instead of vanishing
        if cfg.get("set", {}).get("ghost"): return
        saved = False
        try:
            write_error_log(HOME, t, tb)
            saved = True
        except Exception: pass
        app = QApplication.instance()
        if app is not None and not getattr(app, "_unknwn_error_notice", False):
            setattr(app, "_unknwn_error_notice", True)
            detail = "Error details were saved locally." if saved else "UNKNWN could not save the local error details."
            message = support_message(f"UNKNWN encountered an unexpected serious error ({getattr(v, '__class__', type(v)).__name__}). {detail}")
            QTimer.singleShot(0, _noarg_slot(lambda: QMessageBox.critical(None, "UNKNWN // serious error", message)))
    sys.excepthook = log_error
    os.environ.setdefault("QT_MULTIMEDIA_PREFERRED_PLUGINS", "windowsmediafoundation")   # Windows Media Foundation handles video far more reliably than DirectShow
    QApplication.setAttribute(Qt.ApplicationAttribute.AA_EnableHighDpiScaling, True); QApplication.setAttribute(Qt.ApplicationAttribute.AA_UseHighDpiPixmaps, True)
    if hasattr(Qt, "HighDpiScaleFactorRoundingPolicy"): QApplication.setHighDpiScaleFactorRoundingPolicy(Qt.HighDpiScaleFactorRoundingPolicy.PassThrough)
    ap = QApplication([a for a in sys.argv if a != "--portable"]); ap.setStyleSheet(qss()); w = App(); w.show(); sys.exit(ap.exec_())

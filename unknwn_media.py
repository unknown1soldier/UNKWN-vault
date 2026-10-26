"""File-type detection and text/hex helpers for the UNKNWN viewer. Pure Python: no Qt, no disk access, no network.
Everything works on bytes already decrypted in memory."""
import os, codecs, hashlib, struct, io, stat, zipfile, xml.etree.ElementTree as ET
from typing import Protocol, TypedDict, cast
try: import py7zr
except ImportError: py7zr = None
try: import rarfile  # type: ignore[reportMissingTypeStubs]
except ImportError: rarfile = None

Data = bytes | bytearray | memoryview


class ZipEntry(TypedDict):
    name: str
    is_dir: bool
    size: int
    compressed_size: int
    member_index: int | None
    path: str


class ZipStatistics(TypedDict):
    files: int
    directories: int
    logical_bytes: int
    compressed_bytes: int
    type_bytes: dict[str, int]


class _SevenZipEntry(Protocol):
    filename: str
    uncompressed: int | None


class _RarEntry(Protocol):
    filename: str
    file_size: int

IMG_EXT = {".png", ".jpg", ".jpeg", ".jpe", ".jfif", ".gif", ".webp", ".bmp", ".dib", ".tif", ".tiff", ".ico", ".cur", ".ppm", ".pgm", ".pbm", ".xpm", ".xbm", ".svgz"}
VID_EXT = {".mp4", ".m4v", ".mov", ".mkv", ".webm", ".avi", ".wmv", ".asf", ".flv", ".mpg", ".mpeg", ".mpe", ".ts", ".m2ts", ".mts", ".3gp", ".3g2", ".ogv", ".ogm", ".vob", ".f4v"}
AUD_EXT = {".mp3", ".m4a", ".m4b", ".aac", ".wav", ".wma", ".flac", ".ogg", ".oga", ".opus", ".mka", ".aif", ".aiff", ".amr", ".weba", ".mp2"}
FRIENDLY = {".pdf": "PDF document", ".zip": "ZIP archive", ".7z": "7-Zip archive", ".rar": "RAR archive", ".docx": "Word document", ".xlsx": "Excel workbook",
            ".pptx": "PowerPoint presentation", ".exe": "Windows program", ".dll": "Windows library", ".iso": "Disk image", ".epub": "E-book", ".mid": "MIDI music"}
MAXTEXT = 400_000   # characters shown; bigger files are cut (and the viewer says so)
MAX_ARCHIVE_ENTRIES = 2_000
MAX_ARCHIVE_MEMBER = 8 << 20
MAX_ARCHIVE_LIST = 500
MAX_ARCHIVE_VIEW_MEMBER = 128 << 20
MAX_DOCUMENT_ROWS = 2_000
OFFICE_EXT = {".docx", ".xlsx", ".pptx"}


def kind(name: str | None, data: Data) -> str:
    """Identify previewable media and document containers; unsupported formats stay on the safe info/hex path."""
    h = bytes(data[:16]); ext = os.path.splitext(name or "")[1].lower()
    riff = h[:4] == b"RIFF" and len(data) >= 12
    if h[:6] in (b"GIF87a", b"GIF89a"): return "gif"
    if h[:8] == b"\x89PNG\r\n\x1a\n" or h[:3] == b"\xff\xd8\xff" or (riff and h[8:12] == b"WEBP") or h[:4] in (b"II*\x00", b"MM\x00*"): return "image"
    if h[:4] == b"\x00\x00\x01\x00" and ext in (".ico", ".cur"): return "image"
    if h[:2] == b"BM" and ext in (".bmp", ".dib"): return "image"
    if h[:5] == b"%PDF-": return "pdf"
    if h[:4] in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"):
        if ext in OFFICE_EXT: return "office"
        if ext in (".epub",): return "epub"
        return "archive"
    if h[:6] == b"7z\xbc\xaf'\x1c": return "archive"
    if h[:6] == b"Rar!\x1a\x07": return "archive"
    if h[:4] == b"MThd": return "midi"
    if h[:2] == b"MZ": return "program"
    if len(data) >= 17 * 2048 and bytes(data[16 * 2048 + 1:16 * 2048 + 6]) == b"CD001": return "disk"
    if h[4:8] == b"ftyp":
        b = h[8:12]
        if b in (b"heic", b"heix", b"heim", b"heis", b"mif1", b"msf1", b"avif", b"avis"): return "image"   # HEIC / AVIF photos are pictures, not videos
        return "audio" if b in (b"M4A ", b"M4B ", b"F4A ") else "video"
    if h[:4] == b"\x1a\x45\xdf\xa3": return "audio" if ext in (".mka", ".weba") else "video"
    if riff and h[8:12] == b"AVI ": return "video"
    if riff and h[8:12] == b"WAVE": return "audio"
    if h[:3] == b"FLV": return "video"
    if h[:4] == b"fLaC": return "audio"
    if h[:4] == b"OggS": return "video" if ext in (".ogv", ".ogm", ".ogx") else "audio"
    if h[:16] == bytes.fromhex("3026b2758e66cf11a6d900aa0062ce6c"): return "audio" if ext == ".wma" else "video"
    if h[:4] == b"\x00\x00\x01\xba": return "video"
    if h[:3] == b"ID3": return "audio"
    if ext == ".svg" or b"<svg" in bytes(data[:2048]).lower(): return "svg" if decode_text(data[:2048]) else "other"
    if ext in IMG_EXT: return "image"
    if ext in VID_EXT:
        if ext == ".ts" and not (len(data) > 188 and data[0] == 0x47 and data[188] == 0x47): return "text" if decode_text(data[:8192]) is not None else "other"   # TypeScript, not MPEG-TS
        return "video"
    if ext in AUD_EXT: return "audio"
    if ext in OFFICE_EXT: return "office"
    if ext == ".epub": return "epub"
    if ext in (".zip", ".7z", ".rar"): return "archive"
    if ext in (".mid", ".midi"): return "midi"
    if ext in (".exe", ".dll"): return "program"
    if ext == ".iso": return "disk"
    return "text" if decode_text(data[:8192]) is not None else "other"


def _xml_member(archive: zipfile.ZipFile, name: str) -> bytes | None:
    """Read a bounded ZIP/XML member; never extracts archive paths to disk."""
    try:
        info = archive.getinfo(name)
        if info.file_size > MAX_ARCHIVE_MEMBER: return None
        with archive.open(info) as stream:
            content = stream.read(MAX_ARCHIVE_MEMBER + 1)
        return content if len(content) <= MAX_ARCHIVE_MEMBER else None
    except (KeyError, OSError, RuntimeError, zipfile.BadZipFile):
        return None


def _open_zip(data: Data) -> tuple[zipfile.ZipFile, list[zipfile.ZipInfo]]:
    archive = zipfile.ZipFile(io.BytesIO(data))
    entries = archive.infolist()
    if len(entries) > MAX_ARCHIVE_ENTRIES:
        archive.close()
        raise ValueError("Archive has too many entries for the in-app preview.")
    return archive, entries


def _xml_root(archive: zipfile.ZipFile, name: str) -> ET.Element | None:
    content = _xml_member(archive, name)
    if content is not None:
        ascii_xml = content.upper().replace(b"\0", b"")
        if b"<!DOCTYPE" in ascii_xml or b"<!ENTITY" in ascii_xml: return None
    return ET.fromstring(content) if content is not None else None


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]

def _bounded_preview(text: str) -> str:
    if len(text) <= MAXTEXT: return text
    return text[:MAXTEXT] + f"\n\n... preview truncated at {MAXTEXT:,} characters."


def _archive_preview(data: Data) -> str:
    if data[:6] == b"7z\xbc\xaf'\x1c":
        if py7zr is None: return "7-Zip archive recognized, but its in-app reader is unavailable in this build."
        try:
            with py7zr.SevenZipFile(io.BytesIO(data), mode="r") as archive:
                entries = cast(list[_SevenZipEntry], archive.list())
            if len(entries) > MAX_ARCHIVE_ENTRIES:
                return "7-Zip archive has too many entries for the in-app preview."
            lines = [f"7-Zip archive · {len(entries):,} entries", "Paths are listed only; nothing is extracted."]
            for item in entries[:MAX_ARCHIVE_LIST]:
                name = _safe_archive_name(item.filename)
                lines.append(f"{max(0, item.uncompressed or 0):>12,} B  {name[:240]}")
            if len(entries) > MAX_ARCHIVE_LIST: lines.append(f"... {len(entries) - MAX_ARCHIVE_LIST:,} more entries")
            return _bounded_preview("\n".join(lines))
        except Exception as exc:
            return f"7-Zip preview unavailable ({type(exc).__name__}). The archive was not extracted."
    if data[:6] == b"Rar!\x1a\x07":
        if rarfile is None: return "RAR archive recognized, but its in-app reader is unavailable in this build."
        try:
            with rarfile.RarFile(io.BytesIO(data), errors="strict", crc_check=False) as archive:
                entries = cast(list[_RarEntry], archive.infolist())
            if len(entries) > MAX_ARCHIVE_ENTRIES:
                return "RAR archive has too many entries for the in-app preview."
            lines = [f"RAR archive · {len(entries):,} entries", "Paths are listed only; nothing is extracted."]
            for item in entries[:MAX_ARCHIVE_LIST]:
                name = _safe_archive_name(item.filename)
                lines.append(f"{max(0, item.file_size):>12,} B  {name[:240]}")
            if len(entries) > MAX_ARCHIVE_LIST: lines.append(f"... {len(entries) - MAX_ARCHIVE_LIST:,} more entries")
            return _bounded_preview("\n".join(lines))
        except Exception as exc:
            return f"RAR preview unavailable ({type(exc).__name__}). The archive was not extracted."
    try:
        archive, entries = _open_zip(data)
    except (OSError, ValueError, zipfile.BadZipFile) as exc:
        return f"Archive preview unavailable: {exc}"
    try:
        lines = [f"ZIP archive · {len(entries):,} entries", "Paths are listed only; nothing is extracted."]
        for item in entries[:MAX_ARCHIVE_LIST]:
            name = _safe_archive_name(item.filename)
            lines.append(f"{item.file_size:>12,} B  {name[:240]}")
        if len(entries) > MAX_ARCHIVE_LIST: lines.append(f"... {len(entries) - MAX_ARCHIVE_LIST:,} more entries")
        return _bounded_preview("\n".join(lines))
    finally:
        archive.close()

def _safe_archive_name(name: str) -> str:
    name = str(name).replace("\\", "/")
    return "[unsafe path omitted]" if name.startswith("/") or any(part == ".." for part in name.split("/")) else name


def _archive_parts(name: str) -> list[str] | None:
    name = str(name).replace("\\", "/")
    parts = name.split("/")
    if name.startswith("/") or "\0" in name or any(part == ".." for part in parts):
        return None
    parts = [part for part in parts if part not in ("", ".")]
    if not parts or ":" in parts[0]:
        return None
    return parts


def is_zip_data(data: Data) -> bool:
    return bytes(data[:4]) in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")


def zip_directory_entries(data: Data, directory: str = "") -> list[ZipEntry]:
    """Return safe direct children of a ZIP path, without extracting members."""
    prefix = _archive_parts(directory) if directory else []
    if prefix is None:
        raise ValueError("Invalid archive directory.")
    archive, entries = _open_zip(data)
    try:
        children: dict[str, ZipEntry] = {}
        prefix_len = len(prefix)
        for index, info in enumerate(entries):
            parts = _archive_parts(info.filename)
            if parts is None or parts[:prefix_len] != prefix or len(parts) <= prefix_len:
                continue
            mode = info.external_attr >> 16
            if stat.S_ISLNK(mode):
                continue
            is_dir = info.is_dir() or info.filename.endswith(("/", "\\"))
            child = parts[prefix_len]
            if len(parts) > prefix_len + 1 or is_dir:
                path = "/".join(prefix + [child])
                children.setdefault(path, {"name": child, "is_dir": True, "size": 0,
                                           "compressed_size": 0, "member_index": None, "path": path})
            else:
                path = "/".join(parts)
                children[path] = {"name": child, "is_dir": False, "size": info.file_size,
                                  "compressed_size": info.compress_size,
                                  "member_index": index, "path": path}
        return sorted(children.values(), key=lambda entry: (not entry["is_dir"], entry["name"].casefold()))
    finally:
        archive.close()


def zip_archive_statistics(data: Data) -> ZipStatistics:
    """Summarize safe ZIP members from central-directory metadata only."""
    archive, entries = _open_zip(data)
    try:
        statistics: ZipStatistics = {
            "files": 0,
            "directories": 0,
            "logical_bytes": 0,
            "compressed_bytes": 0,
            "type_bytes": {},
        }
        for info in entries:
            parts = _archive_parts(info.filename)
            mode = info.external_attr >> 16
            if parts is None or stat.S_ISLNK(mode):
                continue
            if info.is_dir() or info.filename.endswith(("/", "\\")):
                statistics["directories"] += 1
                continue
            statistics["files"] += 1
            statistics["logical_bytes"] += info.file_size
            statistics["compressed_bytes"] += info.compress_size
            extension = os.path.splitext(parts[-1])[1].casefold() or "Other"
            by_type = statistics["type_bytes"]
            by_type[extension] = by_type.get(extension, 0) + info.file_size
        return statistics
    finally:
        archive.close()


def filter_sort_zip_entries(entries: list[ZipEntry], query: str = "", sort_by: str = "name") -> list[ZipEntry]:
    """Filter and sort a ZIP directory listing without changing its member references."""
    needle = str(query).strip().casefold()
    visible: list[ZipEntry] = [entry for entry in entries if needle in entry["name"].casefold()]

    def name_key(entry: ZipEntry) -> tuple[bool, str]:
        return not entry["is_dir"], entry["name"].casefold()

    if sort_by == "size":
        return sorted(visible, key=lambda entry: (not entry["is_dir"], -entry["size"], entry["name"].casefold()))
    elif sort_by == "type":
        def type_key(entry: ZipEntry) -> tuple[bool, str, str]:
            return (
                not entry["is_dir"],
                os.path.splitext(entry["name"])[1].casefold(),
                entry["name"].casefold(),
            )

        return sorted(visible, key=type_key)
    return sorted(visible, key=name_key)


def zip_member_data(data: Data, member_index: int) -> bytes:
    """Read one bounded ZIP member into memory; paths are never written to disk."""
    archive, entries = _open_zip(data)
    try:
        if not 0 <= member_index < len(entries):
            raise ValueError("Archive member is no longer available.")
        info = entries[member_index]
        if _archive_parts(info.filename) is None or info.is_dir():
            raise ValueError("This archive entry cannot be opened.")
        mode = info.external_attr >> 16
        if stat.S_ISLNK(mode):
            raise ValueError("Symbolic links inside archives cannot be opened.")
        if info.flag_bits & 1:
            raise ValueError("Password-protected ZIP members are not supported.")
        if info.file_size > MAX_ARCHIVE_VIEW_MEMBER:
            raise ValueError(f"This member exceeds the {MAX_ARCHIVE_VIEW_MEMBER // (1 << 20)} MiB in-app viewing limit.")
        chunks: list[bytes] = []
        total = 0
        with archive.open(info) as stream:
            while True:
                chunk = stream.read(min(1 << 20, MAX_ARCHIVE_VIEW_MEMBER + 1 - total))
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
                if total > MAX_ARCHIVE_VIEW_MEMBER:
                    raise ValueError(f"This member exceeds the {MAX_ARCHIVE_VIEW_MEMBER // (1 << 20)} MiB in-app viewing limit.")
        return b"".join(chunks)
    finally:
        archive.close()


def _office_preview(data: Data, ext: str) -> str:
    try:
        archive, _ = _open_zip(data)
    except (OSError, ValueError, zipfile.BadZipFile) as exc:
        return f"Office preview unavailable: {exc}"
    try:
        if ext == ".docx":
            root = _xml_root(archive, "word/document.xml")
            if root is None: return "Word document has no readable document.xml."
            lines: list[str] = []
            for para in (node for node in root.iter() if _local(node.tag) == "p"):
                paragraph_parts = [node.text or "" for node in para.iter() if _local(node.tag) == "t"]
                paragraph_text = "".join(paragraph_parts)
                if paragraph_text.strip(): lines.append(paragraph_text)
            return _bounded_preview("WORD DOCUMENT TEXT PREVIEW\n\n" + ("\n".join(lines) or "(No readable paragraph text.)"))
        if ext == ".pptx":
            slides: list[tuple[str, list[str]]] = []
            for item in archive.namelist():
                if item.startswith("ppt/slides/slide") and item.endswith(".xml"):
                    root = _xml_root(archive, item)
                    if root is not None:
                        text: list[str] = [node.text or "" for node in root.iter() if _local(node.tag) == "t"]
                        slides.append((item, text))
            slides.sort(key=lambda entry: int("".join(c for c in entry[0].rsplit("slide", 1)[-1] if c.isdigit()) or 0))
            lines = ["POWERPOINT TEXT PREVIEW"]
            for index, (_, texts) in enumerate(slides[:MAX_DOCUMENT_ROWS], 1):
                lines.extend((f"\n--- SLIDE {index} ---", "\n".join(texts)))
            return _bounded_preview("\n".join(lines)) if slides else "Presentation contains no readable slides."
        shared_root = _xml_root(archive, "xl/sharedStrings.xml")
        strings: list[str] = []
        if shared_root is not None:
            strings = ["".join(node.text or "" for node in item.iter() if _local(node.tag) == "t")
                       for item in shared_root if _local(item.tag) == "si"]
        workbook = _xml_root(archive, "xl/workbook.xml")
        relationships = _xml_root(archive, "xl/_rels/workbook.xml.rels")
        targets: dict[str, str] = {}
        if relationships is not None:
            for rel in relationships:
                if rel.attrib.get("Id") and rel.attrib.get("Target"):
                    targets[rel.attrib["Id"]] = rel.attrib["Target"].lstrip("/")
        if workbook is None: return "Workbook has no readable workbook.xml."
        lines = ["EXCEL WORKBOOK TEXT PREVIEW"]
        rows_seen = 0
        for sheet in (node for node in workbook.iter() if _local(node.tag) == "sheet"):
            rel_id = next((value for key, value in sheet.attrib.items() if _local(key) == "id"), "")
            target = targets.get(rel_id, "")
            if not target: continue
            path = target if target.startswith("xl/") else "xl/" + target
            root = _xml_root(archive, path)
            if root is None: continue
            lines.append(f"\n--- SHEET: {sheet.attrib.get('name', 'Sheet')} ---")
            for row in (node for node in root.iter() if _local(node.tag) == "row"):
                cells: list[str] = []
                for cell in row:
                    if _local(cell.tag) != "c": continue
                    ref, kind, value = cell.attrib.get("r", "?"), cell.attrib.get("t", ""), ""
                    for child in cell:
                        if _local(child.tag) == "v": value = child.text or ""
                        elif _local(child.tag) == "is":
                            value = "".join(n.text or "" for n in child.iter() if _local(n.tag) == "t")
                    if kind == "s":
                        try: value = strings[int(value)]
                        except (ValueError, IndexError): value = "[invalid shared string]"
                    if value: cells.append(f"{ref}={value}")
                if cells: lines.append(" | ".join(cells))
                rows_seen += 1
                if rows_seen >= MAX_DOCUMENT_ROWS: break
            if rows_seen >= MAX_DOCUMENT_ROWS: break
        return _bounded_preview("\n".join(lines)) if len(lines) > 1 else "Workbook has no readable cell values."
    except (ET.ParseError, OSError, RuntimeError, zipfile.BadZipFile, ValueError) as exc:
        return f"Office preview unavailable: {exc}"
    finally:
        archive.close()


def _epub_preview(data: Data) -> str:
    try:
        archive, _ = _open_zip(data)
    except (OSError, ValueError, zipfile.BadZipFile) as exc:
        return f"E-book preview unavailable: {exc}"
    try:
        container = _xml_root(archive, "META-INF/container.xml")
        rootfile = next((node.attrib.get("full-path") for node in container.iter()
                 if _local(node.tag) == "rootfile"), None) if container is not None else None
        if not rootfile: return "E-book package metadata could not be read."
        package = _xml_root(archive, rootfile)
        if package is None: return "E-book package metadata could not be read."
        base = os.path.dirname(rootfile).replace("\\", "/")
        manifest: dict[str, str] = {}
        spine: list[str] = []
        for node in package.iter():
            tag = _local(node.tag)
            if tag == "item" and node.attrib.get("id") and node.attrib.get("href"):
                manifest[node.attrib["id"]] = node.attrib["href"]
            elif tag == "itemref" and node.attrib.get("idref"):
                spine.append(node.attrib["idref"])
        lines = ["E-BOOK TEXT PREVIEW"]
        for index, ident in enumerate(spine[:MAX_DOCUMENT_ROWS], 1):
            href = manifest.get(ident)
            if not href: continue
            member = os.path.normpath(os.path.join(base, href)).replace("\\", "/")
            if member.startswith("../") or member.startswith("/"): continue
            root = _xml_root(archive, member)
            if root is None: continue
            text = " ".join(str(piece).strip() for piece in root.itertext() if piece and str(piece).strip())
            if text: lines.extend((f"\n--- SECTION {index} ---", text))
        return _bounded_preview("\n".join(lines)) if len(lines) > 1 else "E-book package contains no readable text sections."
    except (ET.ParseError, OSError, RuntimeError, zipfile.BadZipFile, ValueError) as exc:
        return f"E-book preview unavailable: {exc}"
    finally:
        archive.close()


def _midi_preview(data: Data) -> str:
    if len(data) < 14 or data[:4] != b"MThd": return "MIDI file header is missing or incomplete."
    header_length, = struct.unpack(">I", data[4:8])
    if header_length < 6 or 8 + header_length > len(data): return "MIDI file header is invalid."
    fmt, track_count, division = struct.unpack(">HHH", data[8:14])
    if fmt > 2 or track_count > MAX_ARCHIVE_ENTRIES or division == 0: return "MIDI header values are invalid."
    pos = 8 + header_length; lines = [f"MIDI sequence · format {fmt} · {track_count} track(s)",
                                      f"Timing division: {division} ticks per quarter note" if not division & 0x8000 else f"Timing division: SMPTE {((division >> 8) & 0xff) - 256} fps, {division & 0xff} ticks/frame"]
    for track_number in range(1, track_count + 1):
        if pos + 8 > len(data) or data[pos:pos + 4] != b"MTrk": return "MIDI track chunk is missing or truncated."
        length, = struct.unpack(">I", data[pos + 4:pos + 8]); start, end = pos + 8, pos + 8 + length
        if end > len(data): return "MIDI track data is truncated."
        cursor = start; running = None; notes = 0; events = 0; track_name = ""
        try:
            while cursor < end:
                delta = 0
                for _ in range(4):
                    byte = data[cursor]; cursor += 1; delta = (delta << 7) | (byte & 0x7f)
                    if not byte & 0x80: break
                else: return "MIDI contains an invalid variable-length value."
                if cursor >= end: break
                status = data[cursor]
                if status & 0x80: cursor += 1; running = status
                elif running is not None: status = running
                else: return "MIDI contains an invalid running-status event."
                if status == 0xff:
                    if cursor >= end: return "MIDI meta event is truncated."
                    meta = data[cursor]; cursor += 1; size, cursor = _midi_vlq(data, cursor, end)
                    if cursor + size > end: return "MIDI meta event is truncated."
                    payload = bytes(data[cursor:cursor + size]); cursor += size
                    if meta == 0x03: track_name = payload.decode("utf-8", "replace")[:120]
                    if meta == 0x2f: break
                elif status in (0xf0, 0xf7):
                    size, cursor = _midi_vlq(data, cursor, end); cursor += size
                    if cursor > end: return "MIDI system-exclusive event is truncated."
                elif 0x80 <= status <= 0xef:
                    size = 1 if status >> 4 in (0xc, 0xd) else 2
                    if cursor + size > end: return "MIDI channel event is truncated."
                    cursor += size
                    if status >> 4 == 0x9 and size == 2 and data[cursor - 1] > 0: notes += 1
                    events += 1
                else: return "MIDI contains an unsupported system event."
            lines.append(f"Track {track_number}: {track_name or 'Untitled'} · {events:,} channel events · {notes:,} note-ons")
        except (IndexError, ValueError):
            return "MIDI track data is malformed."
        pos = end
    return _bounded_preview("\n".join(lines))


def _midi_vlq(data: Data, cursor: int, end: int) -> tuple[int, int]:
    value = 0
    for _ in range(4):
        if cursor >= end: raise ValueError("truncated MIDI variable-length value")
        byte = data[cursor]; cursor += 1; value = (value << 7) | (byte & 0x7f)
        if not byte & 0x80: return value, cursor
    raise ValueError("invalid MIDI variable-length value")


def _program_preview(data: Data) -> str:
    if len(data) < 64 or data[:2] != b"MZ": return "Program header is missing or incomplete."
    pe_offset, = struct.unpack_from("<I", data, 0x3c)
    if pe_offset > len(data) - 24 or data[pe_offset:pe_offset + 4] != b"PE\0\0":
        return "Windows PE metadata could not be read."
    machine, sections, _, _, _, optional_size, characteristics = struct.unpack_from("<HHIIIHH", data, pe_offset + 4)
    arch = {0x14c: "x86", 0x8664: "x64", 0xaa64: "ARM64"}.get(machine, f"Unknown (0x{machine:04x})")
    lines = [f"Windows PE file · {arch}", f"Sections: {sections}", f"Characteristics: 0x{characteristics:04x}"]
    opt = pe_offset + 24
    if optional_size >= 20 and opt + optional_size <= len(data):
        magic, = struct.unpack_from("<H", data, opt)
        if magic in (0x10b, 0x20b):
            entry, = struct.unpack_from("<I", data, opt + 16)
            lines.append(f"Entry point RVA: 0x{entry:08x}")
    lines.append("This is metadata only; the program is never executed.")
    return _bounded_preview("\n".join(lines))


def _iso_preview(data: Data) -> str:
    block = 2048; pvd = 16 * block
    if len(data) < 17 * block or data[pvd] != 1 or data[pvd + 1:pvd + 6] != b"CD001":
        return "ISO-9660 primary volume descriptor was not found."
    volume = bytes(data[pvd + 40:pvd + 72]).decode("ascii", "replace").strip()
    root_record = data[pvd + 156:pvd + 190]
    if len(root_record) < 34 or root_record[0] < 34: return "ISO-9660 root directory record is invalid."
    extent = int.from_bytes(root_record[2:6], "little"); size = int.from_bytes(root_record[10:14], "little")
    if extent * block + size > len(data): return "ISO-9660 root directory points outside the image."
    lines = [f"ISO-9660 disk image · {volume or 'Untitled volume'}", "Directory listing only; image files are not extracted."]
    queue: list[tuple[str, int, int]] = [("", extent, size)]; visited: set[int] = set()
    while queue and len(visited) < MAX_ARCHIVE_ENTRIES:
        parent, sector, length = queue.pop(0); start = sector * block; end = min(len(data), start + length); cursor = start
        if sector in visited: continue
        visited.add(sector)
        while cursor < end and len(visited) < MAX_ARCHIVE_ENTRIES:
            record_length = data[cursor]
            if record_length == 0: cursor = ((cursor // block) + 1) * block; continue
            record_end = cursor + record_length
            if record_end > end or record_length < 34: break
            name_length = data[cursor + 32]
            if 33 + name_length > record_length: break
            identifier = bytes(data[cursor + 33:cursor + 33 + name_length])
            is_dir = bool(data[cursor + 25] & 2); record_extent = int.from_bytes(data[cursor + 2:cursor + 6], "little")
            record_size = int.from_bytes(data[cursor + 10:cursor + 14], "little")
            if identifier not in (b"\0", b"\1"):
                name = identifier.decode("ascii", "replace").split(";", 1)[0].rstrip(".")
                path = f"{parent}/{name}".lstrip("/")
                lines.append(f"{'[DIR] ' if is_dir else f'{record_size:>12,} B  '}{path[:240]}")
                if is_dir and record_extent not in visited and record_extent * block + record_size <= len(data):
                    queue.append((path, record_extent, record_size))
            cursor = record_end
    if queue: lines.append("... directory listing limit reached")
    return _bounded_preview("\n".join(lines))


def preview_content(name: str | None, data: Data, file_kind: str | None = None) -> str | None:
    """Return bounded, read-only in-app text for formats with a safe parser, else None."""
    ext = os.path.splitext(name or "")[1].lower()
    file_kind = file_kind or kind(name, data)
    try:
        if file_kind == "archive": return _bounded_preview(_archive_preview(data))
        if file_kind == "office": return _bounded_preview(_office_preview(data, ext))
        if file_kind == "epub": return _bounded_preview(_epub_preview(data))
        if file_kind == "midi": return _bounded_preview(_midi_preview(data))
        if file_kind == "program": return _bounded_preview(_program_preview(data))
        if file_kind == "disk": return _bounded_preview(_iso_preview(data))
    except (OSError, ValueError, IndexError, struct.error, zipfile.BadZipFile, ET.ParseError) as exc:
        return f"Preview unavailable: {exc}"
    if file_kind == "other":
        return None
    return None


def decode_text(data: Data) -> tuple[str, str, bool] | None:
    """-> (text, encoding, truncated) or None if the bytes do not look like text."""
    if not len(data): return "", "utf-8", False
    d = bytes(data[:MAXTEXT * 4 + 4]); cut = len(data) > len(d) or None
    for bom, enc in ((codecs.BOM_UTF8, "utf-8-sig"), (codecs.BOM_UTF32_LE, "utf-32"), (codecs.BOM_UTF32_BE, "utf-32"), (codecs.BOM_UTF16_LE, "utf-16"), (codecs.BOM_UTF16_BE, "utf-16")):
        if d.startswith(bom):
            try:
                n = len(d) - (len(d) % (4 if "32" in enc else 2 if "16" in enc else 1)); t = d[:n].decode(enc)
                return t[:MAXTEXT], enc, len(t) > MAXTEXT or bool(cut)
            except UnicodeDecodeError: return None
    s = d[:8192]
    if b"\x00" in s: return None
    ctl = sum(1 for b in s if b < 9 or 13 < b < 32 and b != 27 or b == 127)
    if ctl > len(s) * 0.03: return None
    t = None
    try: t = d.decode("utf-8")
    except UnicodeDecodeError as e:
        if cut and e.reason == "unexpected end of data" and e.start >= len(d) - 3:      # only a character cut by our own size limit is forgiven
            try: t = d[:e.start].decode("utf-8")
            except UnicodeDecodeError: t = None
    enc = "utf-8"
    if t is None: t, enc = d.decode("cp1252", errors="replace"), "windows-1252"
    return t[:MAXTEXT], enc, len(t) > MAXTEXT or bool(cut)


def hexdump(data: Data, limit: int = 2048) -> str:
    out: list[str] = []
    for i in range(0, min(len(data), limit), 16):
        row = bytes(data[i:i + 16]); out.append(f"{i:08x}  {row.hex(' '):<47}  |{''.join(chr(b) if 32 <= b < 127 else '.' for b in row)}|")
    if len(data) > limit: out.append(f"... {len(data) - limit:,} more bytes not shown")
    return "\n".join(out)


def describe(name: str | None, data: Data, k: str) -> tuple[str, str]:
    ext = os.path.splitext(name or "")[1].lower()
    what = {"pdf": "PDF document", "video": "Video", "audio": "Audio", "image": "Image", "gif": "Animated image", "svg": "Vector image",
            "text": "Text", "archive": "Archive", "office": "Office document", "epub": "E-book", "midi": "MIDI sequence",
            "program": "Windows program/library", "disk": "Disk image"}.get(k) or FRIENDLY.get(ext) or (ext[1:].upper() + " file" if ext else "Binary file")
    return what, hashlib.sha256(data).hexdigest()


ORIENT = {2: (0, -1, 1), 3: (180, 1, 1), 4: (0, 1, -1), 5: (90, -1, 1), 6: (90, 1, 1), 7: (270, -1, 1), 8: (270, 1, 1)}   # EXIF orientation -> (rotate degrees, scale x, scale y)


def exif_orientation(data: Data) -> int:
    """EXIF orientation (1-8) of a JPEG, 1 when there is none or the data is odd. Phone photos are often stored sideways with this flag set."""
    try:
        d = bytes(data[:70000])
        if d[:2] != b"\xff\xd8": return 1
        i = 2
        while i + 4 <= len(d) and d[i] == 0xFF:
            mk = d[i + 1]; ln = struct.unpack(">H", d[i + 2:i + 4])[0]
            if mk == 0xDA: break
            if mk == 0xE1 and d[i + 4:i + 10] == b"Exif\0\0":
                t = d[i + 10:i + 2 + ln]; e = "<" if t[:2] == b"II" else ">" if t[:2] == b"MM" else None
                if e is None: return 1
                p = struct.unpack(e + "I", t[4:8])[0]; n = struct.unpack(e + "H", t[p:p + 2])[0]
                for k in range(n):
                    q = p + 2 + k * 12
                    if struct.unpack(e + "H", t[q:q + 2])[0] == 0x0112:
                        o = struct.unpack(e + "H", t[q + 8:q + 10])[0]; return o if 1 <= o <= 8 else 1
                return 1
            i += 2 + ln
    except Exception: pass
    return 1

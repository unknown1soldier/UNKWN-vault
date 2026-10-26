"""Run: python -m unittest tests.test_media -v"""
# pyright: reportConstantRedefinition=false, reportUnknownParameterType=false, reportMissingParameterType=false
# pyright: reportUnknownArgumentType=false, reportUnknownMemberType=false, reportUnknownVariableType=false
# pyright: reportSelfClsParameterName=false, reportPrivateUsage=false, reportUnknownLambdaType=false
# pyright: reportCallIssue=false, reportArgumentType=false, reportIndexIssue=false, reportAssignmentType=false
# pyright: reportUnusedVariable=false, reportOptionalSubscript=false, reportAttributeAccessIssue=false, reportOptionalCall=false
# pyright: reportOptionalMemberAccess=false
import sys, random, unittest, hashlib, io, zipfile, struct, binascii
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import unknwn_media as M

def rnd(n, seed=1): return random.Random(seed).randbytes(n)

class Kinds(unittest.TestCase):
    def k(s, name, data): return M.kind(name, data)
    def test_images(s):
        s.assertEqual(s.k("a", b"\x89PNG\r\n\x1a\n" + rnd(50)), "image"); s.assertEqual(s.k("a.bin", b"\xff\xd8\xff\xe0" + rnd(50)), "image")
        s.assertEqual(s.k("a", b"RIFF\x10\0\0\0WEBPVP8 " + rnd(20)), "image"); s.assertEqual(s.k("a", b"II*\x00" + rnd(20)), "image")
        s.assertEqual(s.k("a.bmp", b"BM" + rnd(40)), "image"); s.assertEqual(s.k("a", b"GIF89a" + rnd(40)), "gif")
    def test_bmp_magic_alone_is_not_enough(s): s.assertEqual(s.k("notes.txt", b"BMW service history\nOil change done"), "text")
    def test_video_and_audio_by_content_not_name(s):
        s.assertEqual(s.k("x.dat", b"\0\0\0\x18ftypisom" + rnd(40)), "video"); s.assertEqual(s.k("x.dat", b"\0\0\0\x18ftypM4A " + rnd(40)), "audio")
        s.assertEqual(s.k("x", b"\x1a\x45\xdf\xa3" + rnd(40)), "video"); s.assertEqual(s.k("x", b"RIFF\x10\0\0\0AVI LIST" + rnd(20)), "video")
        s.assertEqual(s.k("x", b"RIFF\x10\0\0\0WAVEfmt " + rnd(20)), "audio"); s.assertEqual(s.k("x", b"ID3\x03" + rnd(40)), "audio")
        s.assertEqual(s.k("x", b"fLaC" + rnd(40)), "audio"); s.assertEqual(s.k("x.ogg", b"OggS" + rnd(40)), "audio"); s.assertEqual(s.k("x.ogv", b"OggS" + rnd(40)), "video")
        s.assertEqual(s.k("x.wma", bytes.fromhex("3026b2758e66cf11a6d900aa0062ce6c") + rnd(20)), "audio")
    def test_extension_fallback_for_formats_without_simple_magic(s):
        s.assertEqual(s.k("clip.MKV", rnd(300)), "video"); s.assertEqual(s.k("song.mp3", rnd(300)), "audio"); s.assertEqual(s.k("pic.ico", rnd(300)), "image")
    def test_pdf_svg(s):
        s.assertEqual(s.k("a", b"%PDF-1.7\n" + rnd(30)), "pdf"); s.assertEqual(s.k("a.svg", b'<svg xmlns="http://www.w3.org/2000/svg"/>'), "svg"); s.assertEqual(s.k("noext", b'<?xml version="1"?><svg></svg>'), "svg")
    def test_text_variants(s):
        s.assertEqual(s.k("a", "hello\nw\u00F6rld \u20AC".encode()), "text"); s.assertEqual(s.k("a", "hello w\u00F6rld".encode("utf-16")), "text"); s.assertEqual(s.k("a", b"caf\xe9 au lait"), "text")
        s.assertEqual(s.k("a", b""), "text"); s.assertEqual(s.k("a", "\u65E5\u672C\u8A9E\u306E\u30C6\u30AD\u30B9\u30C8".encode("utf-8-sig")), "text")
    def test_binary_is_other(s):
        s.assertEqual(s.k("a.zip", b"PK\x03\x04" + rnd(500)), "archive"); s.assertEqual(s.k("a.exe", b"MZ\x90\x00" + rnd(500)), "program"); s.assertEqual(s.k("a", rnd(5000)), "other"); s.assertEqual(s.k("a", b"abc\0def"), "other")

class Text(unittest.TestCase):
    def test_encodings_decoded(s):
        s.assertEqual(M.decode_text("h\u00E9llo".encode("utf-16"))[:2], ("h\u00E9llo", "utf-16")); s.assertEqual(M.decode_text(b"caf\xe9")[:2], ("caf\u00E9", "windows-1252"))
        s.assertEqual(M.decode_text("x".encode("utf-8-sig"))[0], "x"); s.assertEqual(M.decode_text("\u65E5\u672C".encode("utf-32"))[0], "\u65E5\u672C")
    def test_big_file_truncated_without_splitting_characters(s):
        for ch in ("\u00E9", "\u20AC", "\u1F600"):
            r = M.decode_text((ch * 900_000).encode()); s.assertIsNotNone(r); s.assertEqual((len(r[0]), r[1], r[2]), (M.MAXTEXT, "utf-8", True), ch)
    def test_small_file_not_flagged_truncated(s): s.assertFalse(M.decode_text(b"hello")[2])
    def test_hexdump_and_describe(s):
        h = M.hexdump(b"Hello, world!\x00\x01\x02" * 3, 32).splitlines(); s.assertTrue(h[0].startswith("00000000  48 65 6c 6c")); s.assertIn("|Hello, world!...|", h[0]); s.assertIn("more bytes", h[-1])
        w, d = M.describe("report.docx", b"abc", "other"); s.assertEqual((w, d), ("Word document", hashlib.sha256(b"abc").hexdigest())); s.assertEqual(M.describe("x.qqq", b"", "other")[0], "QQQ file")

def jpeg_exif(o, be=False):
    e = "big" if be else "little"; p = lambda n: n.to_bytes(2, e); q = lambda n: n.to_bytes(4, e)
    tiff = (b"MM" if be else b"II") + p(42) + q(8) + p(1) + p(0x0112) + p(3) + q(1) + p(o) + b"\0\0" + q(0)
    seg = b"Exif\0\0" + tiff; return b"\xff\xd8\xff\xe1" + (len(seg) + 2).to_bytes(2, "big") + seg + b"\xff\xd9"

class MoreTypes(unittest.TestCase):
    def test_heic_and_avif_are_images_not_video(s):
        for b in (b"heic", b"mif1", b"avif"): s.assertEqual(M.kind("x", b"\0\0\0\x18ftyp" + b + rnd(40)), "image", b)
    def test_typescript_is_text_but_mpeg_ts_is_video(s):
        s.assertEqual(M.kind("app.ts", b"export const a: number = 1;\n"), "text")
        ts = bytearray(rnd(600)); ts[0] = 0x47; ts[188] = 0x47; s.assertEqual(M.kind("clip.ts", bytes(ts)), "video")
    def test_exif_orientation_both_byte_orders(s):
        for o in range(1, 9):
            s.assertEqual(M.exif_orientation(jpeg_exif(o)), o); s.assertEqual(M.exif_orientation(jpeg_exif(o, True)), o)
    def test_exif_orientation_defaults_to_1(s):
        s.assertEqual(M.exif_orientation(b"\xff\xd8\xff\xe0" + rnd(100)), 1); s.assertEqual(M.exif_orientation(rnd(200)), 1); s.assertEqual(M.exif_orientation(b""), 1)
        s.assertEqual(M.exif_orientation(jpeg_exif(9)), 1); s.assertEqual(M.exif_orientation(jpeg_exif(6)[:30]), 1)

def zipped(files):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, content in files.items(): archive.writestr(name, content)
    return stream.getvalue()

class FormatPreviews(unittest.TestCase):
    def test_detects_common_document_archive_program_and_midi_signatures(s):
        for name, data, kind in (
            ("a.docx", b"PK\x03\x04" + rnd(50), "office"),
            ("a.xlsx", b"PK\x03\x04" + rnd(50), "office"),
            ("a.pptx", b"PK\x03\x04" + rnd(50), "office"),
            ("a.epub", b"PK\x03\x04" + rnd(50), "epub"),
            ("a.zip", b"PK\x03\x04" + rnd(50), "archive"),
            ("a.7z", b"7z\xbc\xaf'\x1c" + rnd(50), "archive"),
            ("a.rar", b"Rar!\x1a\x07\x00" + rnd(50), "archive"),
            ("a.mid", b"MThd" + rnd(50), "midi"),
            ("a.exe", b"MZ" + rnd(50), "program"),
        ): s.assertEqual(M.kind(name, data), kind, name)
    def test_zip_archive_preview_lists_members_without_extracting(s):
        data = zipped({"docs/readme.txt": b"hello", "../escape.txt": b"unsafe"})
        preview = M.preview_content("bundle.zip", data)
        s.assertIn("docs/readme.txt", preview); s.assertIn("[unsafe path omitted]", preview); s.assertNotIn("escape.txt", preview)
    def test_archive_entry_limit_prevents_unbounded_listing(s):
        data = zipped({"one.txt": b"1", "two.txt": b"2"})
        from unittest.mock import patch
        with patch.object(M, "MAX_ARCHIVE_ENTRIES", 1):
            s.assertIn("too many entries", M.preview_content("bundle.zip", data))
    def test_zip_browser_lists_directories_and_files_without_unsafe_paths(s):
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as archive:
            archive.writestr("docs/readme.txt", b"hello")
            archive.writestr("docs/nested/data.bin", b"nested")
            archive.writestr("../escape.txt", b"unsafe")
            archive.writestr("C:/drive.txt", b"unsafe")
        root = M.zip_directory_entries(stream.getvalue())
        s.assertEqual([(entry["name"], entry["is_dir"]) for entry in root], [("docs", True)])
        docs = M.zip_directory_entries(stream.getvalue(), "docs")
        s.assertEqual([(entry["name"], entry["is_dir"]) for entry in docs],
                      [("nested", True), ("readme.txt", False)])
        readme = docs[1]
        s.assertEqual(M.zip_member_data(stream.getvalue(), readme["member_index"]), b"hello")
    def test_zip_browser_skips_symbolic_links(s):
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as archive:
            link = zipfile.ZipInfo("link.txt"); link.create_system = 3; link.external_attr = 0o120777 << 16
            archive.writestr(link, b"target")
            archive.writestr("safe.txt", b"safe")
        entries = M.zip_directory_entries(stream.getvalue())
        s.assertEqual([entry["name"] for entry in entries], ["safe.txt"])
    def test_zip_browser_filter_and_sort_keep_only_safe_directory_entries(s):
        data = zipped({"folder/large.txt": b"12345", "folder/small.bin": b"1", "folder/photo.jpg": b"123"})
        entries = M.zip_directory_entries(data, "folder")
        s.assertEqual([entry["name"] for entry in M.filter_sort_zip_entries(entries, "PHOTO")], ["photo.jpg"])
        s.assertEqual([entry["name"] for entry in M.filter_sort_zip_entries(entries, sort_by="size")],
                      ["large.txt", "photo.jpg", "small.bin"])
        s.assertEqual([entry["name"] for entry in M.filter_sort_zip_entries(entries, sort_by="type")],
                      ["small.bin", "photo.jpg", "large.txt"])
        s.assertEqual(entries[0]["compressed_size"], 7)
    def test_zip_archive_statistics_use_metadata_and_skip_unsafe_entries(s):
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as archive:
            archive.writestr("docs/readme.txt", b"hello")
            archive.writestr("docs/", b"")
            archive.writestr("../escape.bin", b"unsafe")
            link = zipfile.ZipInfo("link.txt"); link.create_system = 3; link.external_attr = 0o120777 << 16
            archive.writestr(link, b"target")
        statistics = M.zip_archive_statistics(stream.getvalue())
        s.assertEqual((statistics["files"], statistics["directories"]), (1, 1))
        s.assertEqual(statistics["logical_bytes"], 5)
        s.assertEqual(statistics["type_bytes"], {".txt": 5})
    def test_zip_member_read_is_bounded(s):
        data = zipped({"large.bin": b"12345"})
        from unittest.mock import patch
        entry = M.zip_directory_entries(data)[0]
        with patch.object(M, "MAX_ARCHIVE_VIEW_MEMBER", 4):
            with s.assertRaisesRegex(ValueError, "viewing limit"):
                M.zip_member_data(data, entry["member_index"])
    def test_docx_text_is_previewed_in_memory(s):
        data = zipped({"word/document.xml": b'<w:document xmlns:w="urn:w"><w:body><w:p><w:r><w:t>Secret text</w:t></w:r></w:p></w:body></w:document>'})
        preview = M.preview_content("report.docx", data)
        s.assertIn("Secret text", preview)
    def test_office_xml_entity_declarations_are_not_processed(s):
        data = zipped({"word/document.xml": b'<!DOCTYPE x [<!ENTITY secret "expanded">]><document>&secret;</document>'})
        preview = M.preview_content("report.docx", data)
        s.assertIn("no readable", preview.lower())
    def test_xlsx_shared_string_cell_is_previewed(s):
        data = zipped({
            "xl/workbook.xml": b'<workbook xmlns:r="urn:r"><sheets><sheet name="Budget" r:id="rId1"/></sheets></workbook>',
            "xl/_rels/workbook.xml.rels": b'<Relationships><Relationship Id="rId1" Target="worksheets/sheet1.xml"/></Relationships>',
            "xl/sharedStrings.xml": b'<sst><si><t>Quarter one</t></si></sst>',
            "xl/worksheets/sheet1.xml": b'<worksheet><sheetData><row r="1"><c r="A1" t="s"><v>0</v></c></row></sheetData></worksheet>',
        })
        preview = M.preview_content("budget.xlsx", data)
        s.assertIn("Budget", preview); s.assertIn("A1=Quarter one", preview)
    def test_pptx_slide_text_is_previewed(s):
        data = zipped({"ppt/slides/slide1.xml": b'<p:sld xmlns:p="urn:p" xmlns:a="urn:a"><a:t>Opening slide</a:t></p:sld>'})
        s.assertIn("Opening slide", M.preview_content("deck.pptx", data))
    def test_epub_spine_text_is_previewed(s):
        data = zipped({
            "META-INF/container.xml": b'<container><rootfiles><rootfile full-path="OEBPS/book.opf"/></rootfiles></container>',
            "OEBPS/book.opf": b'<package><manifest><item id="chapter" href="chapter.xhtml"/></manifest><spine><itemref idref="chapter"/></spine></package>',
            "OEBPS/chapter.xhtml": b'<html><body><h1>Chapter title</h1><p>Readable chapter</p></body></html>',
        })
        preview = M.preview_content("book.epub", data)
        s.assertIn("Chapter title", preview); s.assertIn("Readable chapter", preview)
    def test_midi_track_and_note_metadata(s):
        track = b"\x00\xff\x03\x04Lead\x00\x90\x3c\x64\x60\x80\x3c\x00\x00\xff\x2f\x00"
        data = b"MThd" + struct.pack(">IHHH", 6, 0, 1, 480) + b"MTrk" + struct.pack(">I", len(track)) + track
        preview = M.preview_content("song.mid", data)
        s.assertIn("Lead", preview); s.assertIn("1 note-ons", preview)
    def test_pe_header_metadata_without_execution(s):
        data = bytearray(512); data[:2] = b"MZ"; struct.pack_into("<I", data, 0x3c, 0x80); data[0x80:0x84] = b"PE\0\0"
        struct.pack_into("<HHIIIHH", data, 0x84, 0x8664, 2, 0, 0, 0, 0xf0, 0x22)
        struct.pack_into("<H", data, 0x98, 0x20b); struct.pack_into("<I", data, 0xa8, 0x1234)
        preview = M.preview_content("app.exe", bytes(data))
        s.assertIn("x64", preview); s.assertIn("0x00001234", preview); s.assertIn("never executed", preview)
    def test_iso9660_directory_listing(s):
        block = 2048; data = bytearray(19 * block); pvd = 16 * block
        data[pvd:pvd + 7] = b"\x01CD001\x01"; data[pvd + 40:pvd + 48] = b"TESTDISC"
        def record(extent, size, ident, directory=False):
            extra = b"\0" if len(ident) % 2 == 0 else b""
            length = 33 + len(ident) + len(extra); out = bytearray(length); out[0] = length
            out[2:6] = extent.to_bytes(4, "little"); out[6:10] = extent.to_bytes(4, "big")
            out[10:14] = size.to_bytes(4, "little"); out[14:18] = size.to_bytes(4, "big")
            out[25] = 2 if directory else 0; out[28:30] = (1).to_bytes(2, "little"); out[30:32] = (1).to_bytes(2, "big")
            out[32] = len(ident); out[33:33 + len(ident)] = ident; return bytes(out)
        root = record(18, block, b"\0", True); data[pvd + 156:pvd + 156 + len(root)] = root
        directory = record(18, block, b"\0", True) + record(18, block, b"\1", True) + record(18, 42, b"HELLO.TXT;1")
        data[18 * block:18 * block + len(directory)] = directory
        preview = M.preview_content("disc.iso", bytes(data))
        s.assertIn("TESTDISC", preview); s.assertIn("HELLO.TXT", preview)
    def test_malformed_structured_files_fail_closed_to_explanatory_preview(s):
        s.assertIn("header", M.preview_content("bad.mid", b"MThd"))
        s.assertIn("missing or incomplete", M.preview_content("bad.exe", b"MZ" + b"\0" * 60))
        s.assertIn("preview unavailable", M.preview_content("bad.docx", b"PK\x03\x04broken").lower())
    def test_7z_rar_are_identified_without_launching_external_tools(s):
        import py7zr
        stream = io.BytesIO()
        with py7zr.SevenZipFile(stream, "w") as archive: archive.writestr("hello", "folder/readme.txt")
        preview = M.preview_content("a.7z", stream.getvalue())
        s.assertIn("7-Zip archive", preview); s.assertIn("folder/readme.txt", preview)
        def rar_block(kind, flags, extra):
            body = struct.pack("<BHH", kind, flags, 7 + len(extra)) + extra
            return struct.pack("<H", binascii.crc32(body) & 0xffff) + body
        name = b"archive-note.txt"
        main = rar_block(0x73, 0, b"\0" * 6)
        file_header = struct.pack("<LLBLLBBHL", 0, 0, 0, 0, 0, 20, 0x30, len(name), 0) + name
        rar_data = b"Rar!\x1a\x07\0" + main + rar_block(0x74, 0x8000, file_header) + rar_block(0x7b, 0, b"")
        rar_preview = M.preview_content("valid.rar", rar_data)
        s.assertIn("RAR archive", rar_preview); s.assertIn("archive-note.txt", rar_preview)
        rar_preview = M.preview_content("a.rar", b"Rar!\x1a\x07\x00" + rnd(40))
        s.assertIn("RAR preview unavailable", rar_preview)
        s.assertIn("not extracted", rar_preview)

if __name__ == "__main__": unittest.main()

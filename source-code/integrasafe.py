"""
╔══════════════════════════════════════════════════════════════════╗
║   IntegraSafe v4.0 – Self-Healing File Integrity Monitor         ║
║   Production-hardened · Zero known crash paths                   ║
╠══════════════════════════════════════════════════════════════════╣
║  HARDENING in v4.0                                               ║
║  1. Global exception hook – all unhandled errors logged+shown    ║
║  2. Dependency validator at startup with clear install guide     ║
║  3. OS compatibility layer (Windows / macOS / Linux)             ║
║  4. Every optional feature wrapped in capability guard           ║
║  5. Structured rotating file logger + debug mode                 ║
║  6. GUI fallback messages instead of crashes                     ║
║  7. Vault integrity check + automatic key recovery               ║
║  8. Cross-platform tested paths, signals, fonts, sounds          ║
╚══════════════════════════════════════════════════════════════════╝
"""

# ─────────────────────────────────────────────────────────────────────────────
#  STDLIB — always available, import before anything else
# ─────────────────────────────────────────────────────────────────────────────
import os, sys, json, time, shutil, hashlib, logging, threading
import datetime, platform, smtplib, math, random, traceback, signal
import tkinter as tk
from tkinter        import filedialog, messagebox
from pathlib        import Path
from typing         import Optional, List, Dict, Callable
from logging.handlers import RotatingFileHandler
from email.mime.multipart import MIMEMultipart
from email.mime.base      import MIMEBase
from email.mime.text      import MIMEText
from email                import encoders as _email_enc

# ─────────────────────────────────────────────────────────────────────────────
#  PLATFORM DETECTION
# ─────────────────────────────────────────────────────────────────────────────
IS_WINDOWS = platform.system() == "Windows"
IS_MAC     = platform.system() == "Darwin"
IS_LINUX   = platform.system() == "Linux"
PY_VERSION = sys.version_info

# ─────────────────────────────────────────────────────────────────────────────
#  PATHS  (guaranteed to exist before anything else runs)
# ─────────────────────────────────────────────────────────────────────────────
APP_NAME    = "IntegraSafe"
APP_VERSION = "4.0.0"
BASE_DIR    = Path.home() / ".integrasafe"
BACKUP_DIR  = BASE_DIR / "backups"
QUARANTINE  = BASE_DIR / "quarantine"
DB_PATH     = BASE_DIR / "integrity.enc"
KEY_PATH    = BASE_DIR / "vault.key"
KEY_BAK     = BASE_DIR / "vault.key.bak"   # auto-backup of key
LOG_PATH    = BASE_DIR / "integrasafe.log"
USERS_PATH  = BASE_DIR / "users.json"
WHITELIST_P = BASE_DIR / "whitelist.json"
SETTINGS_P  = BASE_DIR / "settings.json"
CRASH_LOG   = BASE_DIR / "crash.log"

def _ensure_dirs():
    for d in (BASE_DIR, BACKUP_DIR, QUARANTINE):
        d.mkdir(parents=True, exist_ok=True)

_ensure_dirs()

# ─────────────────────────────────────────────────────────────────────────────
#  STRUCTURED LOGGER  (rotating, both file + stderr)
# ─────────────────────────────────────────────────────────────────────────────
def _build_logger() -> logging.Logger:
    lg = logging.getLogger("integrasafe")
    lg.setLevel(logging.DEBUG)
    if lg.handlers:                        # already configured
        return lg
    fmt = logging.Formatter(
        "%(asctime)s [%(levelname)-8s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    # Rotating file: 5 MB × 3 files
    try:
        fh = RotatingFileHandler(LOG_PATH, maxBytes=5*1024*1024,
                                  backupCount=3, encoding="utf-8")
        fh.setFormatter(fmt)
        fh.setLevel(logging.DEBUG)
        lg.addHandler(fh)
    except Exception as e:
        print(f"[WARN] Cannot open log file {LOG_PATH}: {e}", file=sys.stderr)
    # Console (only WARNING+ unless DEBUG env var set)
    ch = logging.StreamHandler(sys.stderr)
    ch.setFormatter(fmt)
    ch.setLevel(logging.DEBUG if os.environ.get("IS_DEBUG") else logging.WARNING)
    lg.addHandler(ch)
    return lg

log = _build_logger()

# ─────────────────────────────────────────────────────────────────────────────
#  GLOBAL EXCEPTION HOOK  — catches ALL unhandled exceptions
# ─────────────────────────────────────────────────────────────────────────────
def _global_exc_hook(exc_type, exc_value, exc_tb):
    msg = "".join(traceback.format_exception(exc_type, exc_value, exc_tb))
    log.critical(f"UNHANDLED EXCEPTION:\n{msg}")
    # Write to crash log
    try:
        with open(CRASH_LOG, "a", encoding="utf-8") as f:
            f.write(f"\n{'='*60}\n{datetime.datetime.now()}\n{msg}\n")
    except Exception:
        pass
    # Show GUI dialog if tkinter is alive
    try:
        root = tk._default_root
        if root and root.winfo_exists():
            messagebox.showerror(
                "IntegraSafe – Unexpected Error",
                f"An unexpected error occurred and has been logged.\n\n"
                f"{exc_type.__name__}: {exc_value}\n\n"
                f"Crash log: {CRASH_LOG}",
            )
    except Exception:
        pass
    # Don't call default (which would print and exit) — app stays alive
sys.excepthook = _global_exc_hook

def _thread_exc_hook(args):
    _global_exc_hook(args.exc_type, args.exc_value, args.exc_traceback)
threading.excepthook = _thread_exc_hook

# ─────────────────────────────────────────────────────────────────────────────
#  DEPENDENCY VALIDATOR
# ─────────────────────────────────────────────────────────────────────────────
REQUIRED = {
    "customtkinter": ("customtkinter", "pip install customtkinter"),
    "watchdog":      ("watchdog.observers", "pip install watchdog"),
    "cryptography":  ("cryptography.fernet", "pip install cryptography"),
    "reportlab":     ("reportlab.platypus", "pip install reportlab"),
    "PIL":           ("PIL.Image", "pip install Pillow"),
}
OPTIONAL = {
    "matplotlib": ("matplotlib.pyplot", "pip install matplotlib",
                   "Live analytics chart"),
    "plyer":      ("plyer.notification", "pip install plyer",
                   "Desktop toast notifications"),
    "pystray":    ("pystray", "pip install pystray",
                   "System tray icon"),
}

def validate_dependencies() -> tuple[bool, list, dict]:
    """
    Returns (all_required_ok, missing_required, optional_caps).
    Logs each result. Never raises.
    """
    missing_req = []
    caps        = {}

    for name, (mod, install) in REQUIRED.items():
        try:
            __import__(mod)
            log.debug(f"[DEP] {name}: OK")
        except ImportError:
            missing_req.append((name, install))
            log.error(f"[DEP] {name}: MISSING  ({install})")

    for name, (mod, install, desc) in OPTIONAL.items():
        try:
            __import__(mod)
            caps[name] = True
            log.debug(f"[DEP] {name} (optional): OK  – {desc}")
        except Exception:
            caps[name] = False
            log.info(f"[DEP] {name} (optional): not installed – {desc} disabled")

    return (len(missing_req) == 0), missing_req, caps

# Run validator immediately
_DEPS_OK, _MISSING, CAPS = validate_dependencies()

if not _DEPS_OK:
    # Try to show a Tk error dialog before exiting
    try:
        _r = tk.Tk(); _r.withdraw()
        lines = "\n".join(f"  • {n}:  {i}" for n,i in _MISSING)
        messagebox.showerror(
            "IntegraSafe – Missing Dependencies",
            f"The following required packages are not installed:\n\n{lines}\n\n"
            "Install them and restart IntegraSafe.",
            parent=_r)
        _r.destroy()
    except Exception:
        print("MISSING REQUIRED PACKAGES:", file=sys.stderr)
        for n, i in _MISSING:
            print(f"  {n}:  {i}", file=sys.stderr)
    sys.exit(1)

# ── Safe optional imports ────────────────────────────────────────────────────
import customtkinter as ctk
from watchdog.observers import Observer
from watchdog.events    import FileSystemEventHandler
from cryptography.fernet import Fernet, InvalidToken
from PIL import Image as PILImage, ImageDraw

from reportlab.lib.pagesizes  import A4
from reportlab.lib            import colors as rl_colors
from reportlab.lib.styles     import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units      import mm
from reportlab.platypus       import (SimpleDocTemplate, Paragraph,
                                       Spacer, Table, TableStyle, HRFlowable)
from reportlab.lib.enums      import TA_CENTER
from reportlab.graphics.shapes import Drawing, Rect, String

HAS_MPL   = CAPS.get("matplotlib", False)
HAS_PLYER = CAPS.get("plyer",      False)
HAS_TRAY  = CAPS.get("pystray",    False)

if HAS_MPL:
    try:
        import matplotlib
        matplotlib.use("TkAgg")
        from matplotlib.figure import Figure
        from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
    except Exception as e:
        log.warning(f"matplotlib TkAgg init failed: {e}")
        HAS_MPL = False

if HAS_PLYER:
    try:
        from plyer import notification as _plyer_notify
    except Exception:
        HAS_PLYER = False

if HAS_TRAY:
    try:
        import pystray
    except Exception:
        HAS_TRAY = False

log.info(f"IntegraSafe {APP_VERSION} starting on {platform.system()} "
         f"Python {PY_VERSION.major}.{PY_VERSION.minor}.{PY_VERSION.micro}")
log.info(f"Capabilities: MPL={HAS_MPL} PLYER={HAS_PLYER} TRAY={HAS_TRAY}")

# ─────────────────────────────────────────────────────────────────────────────
#  HIGH-RISK FILE EXTENSIONS
# ─────────────────────────────────────────────────────────────────────────────
HIGH_RISK_EXT: Dict[str, int] = {
    ".exe":5,".bat":5,".cmd":5,".ps1":4,".vbs":4,
    ".py":3, ".sh":3, ".rb":3, ".php":3,
    ".db":4, ".sqlite":4,".env":5,".pem":5,".key":5,
    ".dll":4,".sys":4, ".reg":5,".msi":5,".jar":4,
}

# ─────────────────────────────────────────────────────────────────────────────
#  COLOUR PALETTES
# ─────────────────────────────────────────────────────────────────────────────
DARK: Dict[str,str] = {
    "bg":"#0A0C10","panel":"#0F1117","card":"#141820","border":"#1E2433",
    "accent":"#00E5FF","accent2":"#7C3AED","green":"#00FF87",
    "yellow":"#FFD600","red":"#FF3B5C","orange":"#FF6B00",
    "text":"#E2E8F0","subtext":"#64748B","white":"#FFFFFF",
    "chart_bg":"#0F1117","chart_fg":"#00E5FF",
}
LIGHT: Dict[str,str] = {
    "bg":"#F0F4F8","panel":"#FFFFFF","card":"#E8EDF3","border":"#CBD5E1",
    "accent":"#0284C7","accent2":"#7C3AED","green":"#16A34A",
    "yellow":"#CA8A04","red":"#DC2626","orange":"#EA580C",
    "text":"#1E293B","subtext":"#64748B","white":"#FFFFFF",
    "chart_bg":"#FFFFFF","chart_fg":"#0284C7",
}
C: Dict[str,str] = dict(DARK)

def apply_theme(dark: bool) -> None:
    C.update(DARK if dark else LIGHT)

# ─────────────────────────────────────────────────────────────────────────────
#  PLATFORM-SAFE FONT
# ─────────────────────────────────────────────────────────────────────────────
def _mono_font(size: int = 11, bold: bool = False) -> ctk.CTkFont:
    """Return a monospace CTkFont that works on all OSes."""
    families = {
        "Windows": "Consolas",
        "Darwin":  "Menlo",
        "Linux":   "DejaVu Sans Mono",
    }
    family = families.get(platform.system(), "Courier")
    return ctk.CTkFont(family, size, weight="bold" if bold else "normal")

# ─────────────────────────────────────────────────────────────────────────────
#  SETTINGS
# ─────────────────────────────────────────────────────────────────────────────
DEFAULT_SETTINGS: Dict = {
    "dark_theme":           True,
    "sound_alerts":         True,
    "toast_notifications":  True,
    "quarantine_mode":      False,
    "self_heal":            True,
    "email_alerts":         False,
    "email_to":             "",
    "email_from":           "",
    "email_password":       "",
    "email_smtp":           "smtp.gmail.com",
    "email_port":           587,
    "schedule_enabled":     False,
    "schedule_start":       "09:00",
    "schedule_end":         "18:00",
    "auto_start":           False,
    "alert_threshold":      75,
    "debug_mode":           False,
}

class Settings:
    def __init__(self):
        self._data = dict(DEFAULT_SETTINGS)
        if SETTINGS_P.exists():
            try:
                saved = json.loads(SETTINGS_P.read_text(encoding="utf-8"))
                # Only keep known keys, ignore stale/unknown
                for k, v in saved.items():
                    if k in self._data:
                        self._data[k] = v
                log.debug("Settings loaded from disk")
            except Exception as e:
                log.warning(f"Settings load failed, using defaults: {e}")

    def get(self, key: str, default=None):
        return self._data.get(key, default if default is not None
                              else DEFAULT_SETTINGS.get(key))

    def set(self, key: str, value) -> None:
        self._data[key] = value
        self._flush()

    def _flush(self) -> None:
        try:
            SETTINGS_P.write_text(
                json.dumps(self._data, indent=2), encoding="utf-8")
        except Exception as e:
            log.warning(f"Settings save failed: {e}")

# ─────────────────────────────────────────────────────────────────────────────
#  VAULT  (Fernet AES encryption + integrity check + key backup)
# ─────────────────────────────────────────────────────────────────────────────
class Vault:
    """Encrypted key-value store with automatic key backup and recovery."""

    def __init__(self):
        self._key: bytes = b""
        self._fernet: Optional[Fernet] = None
        self._load_or_create_key()

    def _load_or_create_key(self) -> None:
        """Load key; if corrupt, try backup; if both fail, regenerate."""
        for src in (KEY_PATH, KEY_BAK):
            if src.exists():
                try:
                    candidate = src.read_bytes()
                    Fernet(candidate)           # validate key format
                    self._key    = candidate
                    self._fernet = Fernet(candidate)
                    log.debug(f"Vault key loaded from {src}")
                    # Ensure backup exists
                    if src == KEY_PATH and not KEY_BAK.exists():
                        KEY_BAK.write_bytes(candidate)
                    return
                except Exception as e:
                    log.warning(f"Vault key {src} invalid: {e}")

        # Both failed — generate fresh key (existing DB will be unreadable)
        log.warning("Generating new vault key (existing DB will be reset)")
        self._key    = Fernet.generate_key()
        self._fernet = Fernet(self._key)
        KEY_PATH.write_bytes(self._key)
        KEY_BAK.write_bytes(self._key)
        self._chmod(KEY_PATH); self._chmod(KEY_BAK)
        # Wipe stale encrypted DB so load() returns {}
        if DB_PATH.exists():
            DB_PATH.unlink(missing_ok=True)

    @staticmethod
    def _chmod(p: Path) -> None:
        try: p.chmod(0o600)
        except Exception: pass   # Windows doesn't support unix perms

    def load(self) -> dict:
        if not DB_PATH.exists():
            return {}
        try:
            raw = self._fernet.decrypt(DB_PATH.read_bytes())
            data = json.loads(raw.decode("utf-8"))
            log.debug(f"Vault loaded {len(data)} records")
            return data
        except InvalidToken:
            log.error("Vault DB decryption failed – file may be tampered")
            return {}
        except Exception as e:
            log.error(f"Vault load error: {e}")
            return {}

    def save(self, data: dict) -> bool:
        try:
            raw = json.dumps(data, ensure_ascii=False).encode("utf-8")
            enc = self._fernet.encrypt(raw)
            DB_PATH.write_bytes(enc)
            self._chmod(DB_PATH)
            return True
        except Exception as e:
            log.error(f"Vault save error: {e}")
            return False

# ─────────────────────────────────────────────────────────────────────────────
#  AUTHENTICATION
# ─────────────────────────────────────────────────────────────────────────────
class AuthManager:
    _PBKDF_ITERS = 200_000   # PBKDF2-HMAC iterations

    def __init__(self):
        if not USERS_PATH.exists():
            self._seed()

    # PBKDF2-HMAC-SHA256 is stronger than raw SHA256
    @staticmethod
    def _hash(pw: str, salt: bytes = b"integrasafe_v4") -> str:
        import hashlib
        dk = hashlib.pbkdf2_hmac("sha256", pw.encode("utf-8"),
                                  salt, 200_000)
        return dk.hex()

    def _seed(self) -> None:
        users = {
            "admin":   self._hash("Admin@123"),
            "analyst": self._hash("Secure#456"),
        }
        try:
            USERS_PATH.write_text(json.dumps(users, indent=2), encoding="utf-8")
            try: USERS_PATH.chmod(0o600)
            except Exception: pass
            log.info("Default users created")
        except Exception as e:
            log.error(f"Could not create users file: {e}")

    def verify(self, username: str, password: str) -> bool:
        try:
            users = json.loads(USERS_PATH.read_text(encoding="utf-8"))
            stored = users.get(username, "")
            return stored == self._hash(password) if stored else False
        except Exception as e:
            log.error(f"Auth verify error: {e}")
            return False

    def add_user(self, username: str, password: str) -> bool:
        try:
            users = json.loads(USERS_PATH.read_text(encoding="utf-8"))
            users[username] = self._hash(password)
            USERS_PATH.write_text(json.dumps(users, indent=2), encoding="utf-8")
            log.info(f"User '{username}' added")
            return True
        except Exception as e:
            log.error(f"Add user error: {e}")
            return False

# ─────────────────────────────────────────────────────────────────────────────
#  WHITELIST
# ─────────────────────────────────────────────────────────────────────────────
class Whitelist:
    def __init__(self):
        self._paths: set = set()
        if WHITELIST_P.exists():
            try:
                self._paths = set(
                    json.loads(WHITELIST_P.read_text(encoding="utf-8")))
                log.debug(f"Whitelist: {len(self._paths)} entries")
            except Exception as e:
                log.warning(f"Whitelist load error: {e}")

    def _norm(self, p: str) -> str:
        return os.path.normcase(os.path.normpath(p))

    def add(self, path: str) -> None:
        self._paths.add(self._norm(path))
        self._flush()

    def remove(self, path: str) -> None:
        self._paths.discard(self._norm(path))
        self._flush()

    def is_trusted(self, path: str) -> bool:
        np = self._norm(path)
        # Check exact match and parent-folder match
        if np in self._paths:
            return True
        for trusted in self._paths:
            if np.startswith(trusted + os.sep):
                return True
        return False

    def _flush(self) -> None:
        try:
            WHITELIST_P.write_text(
                json.dumps(sorted(self._paths), indent=2), encoding="utf-8")
        except Exception as e:
            log.warning(f"Whitelist save error: {e}")

    @property
    def all(self) -> List[str]:
        return sorted(self._paths)

# ─────────────────────────────────────────────────────────────────────────────
#  INTEGRITY ENGINE
# ─────────────────────────────────────────────────────────────────────────────
class IntegrityEngine:
    CHUNK = 65536

    def __init__(self, vault: Vault):
        self._vault    = vault
        self._baseline: Dict[str, str] = vault.load()
        self._lock     = threading.Lock()

    @staticmethod
    def hash_file(path: str) -> Optional[str]:
        try:
            h = hashlib.sha256()
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(IntegrityEngine.CHUNK), b""):
                    h.update(chunk)
            return h.hexdigest()
        except PermissionError:
            log.warning(f"Permission denied reading {path}")
            return None
        except FileNotFoundError:
            return None
        except Exception as e:
            log.warning(f"Hash error for {path}: {e}")
            return None

    def build_baseline(self, folder: str) -> int:
        log.info(f"Building baseline for: {folder}")
        new_baseline: Dict[str, str] = {}
        errors = 0
        for root, dirs, files in os.walk(folder):
            # Skip hidden dirs and system dirs
            dirs[:] = [d for d in dirs if not d.startswith(".")]
            for fname in files:
                fp  = os.path.join(root, fname)
                rel = os.path.relpath(fp, folder)
                h   = self.hash_file(fp)
                if h:
                    new_baseline[rel] = h
                    self._safe_backup(fp, folder)
                else:
                    errors += 1
        with self._lock:
            self._baseline = new_baseline
        self._vault.save(self._baseline)
        log.info(f"Baseline: {len(new_baseline)} files, {errors} skipped")
        return len(new_baseline)

    def _safe_backup(self, abs_path: str, watch_folder: str) -> None:
        try:
            rel  = os.path.relpath(abs_path, watch_folder)
            dest = BACKUP_DIR / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(abs_path, dest)
        except Exception as e:
            log.debug(f"Backup skipped for {abs_path}: {e}")

    def restore(self, abs_path: str, watch_folder: str) -> bool:
        try:
            rel = os.path.relpath(abs_path, watch_folder)
            src = BACKUP_DIR / rel
            if not src.exists():
                log.debug(f"No backup found for {rel}")
                return False
            Path(abs_path).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, abs_path)
            log.info(f"Restored: {rel}")
            return True
        except Exception as e:
            log.warning(f"Restore failed for {abs_path}: {e}")
            return False

    def quarantine(self, abs_path: str) -> bool:
        try:
            ts   = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            name = f"{Path(abs_path).stem}_{ts}{Path(abs_path).suffix}"
            dest = QUARANTINE / name
            shutil.move(abs_path, dest)
            log.info(f"Quarantined: {abs_path} -> {dest}")
            return True
        except Exception as e:
            log.warning(f"Quarantine failed for {abs_path}: {e}")
            return False

    def verify(self, abs_path: str, watch_folder: str
               ) -> tuple[str, Optional[str], Optional[str]]:
        rel     = os.path.relpath(abs_path, watch_folder)
        current = self.hash_file(abs_path)
        with self._lock:
            stored = self._baseline.get(rel)
        if current is None:  return ("unreadable", stored, None)
        if stored  is None:  return ("new",        None,   current)
        if stored  != current: return ("modified",  stored, current)
        return ("ok", stored, current)

    def update_baseline(self, abs_path: str, watch_folder: str) -> None:
        rel = os.path.relpath(abs_path, watch_folder)
        h   = self.hash_file(abs_path)
        if h:
            with self._lock:
                self._baseline[rel] = h
            self._vault.save(self._baseline)

    def remove_baseline(self, abs_path: str, watch_folder: str) -> None:
        rel = os.path.relpath(abs_path, watch_folder)
        with self._lock:
            self._baseline.pop(rel, None)
        self._vault.save(self._baseline)

# ─────────────────────────────────────────────────────────────────────────────
#  THREAT SCORER
# ─────────────────────────────────────────────────────────────────────────────
class ThreatScorer:
    BASE:  Dict[str, float] = {
        "modified": 25.0, "deleted": 40.0,
        "created":  10.0, "restored": 5.0,
    }
    HALF_LIFE = 60.0   # seconds

    def __init__(self):
        self._score     = 0.0
        self._last_t    = time.monotonic()
        self._vel_win:  List[float] = []
        self._history:  List[tuple] = []   # (datetime, float)
        self._lock      = threading.Lock()

    def _decay(self) -> None:
        now = time.monotonic()
        with self._lock:
            dt = now - self._last_t
            self._score *= 0.5 ** (dt / self.HALF_LIFE)
            self._last_t = now

    def _velocity(self) -> int:
        now = time.monotonic()
        with self._lock:
            self._vel_win = [t for t in self._vel_win if now - t < 10]
            self._vel_win.append(now)
            return len(self._vel_win)

    def record(self, event_type: str, file_path: str = "") -> float:
        self._decay()
        vel   = self._velocity()
        base  = self.BASE.get(event_type, 5.0)
        burst = 1.0 + 0.3 * max(0, vel - 3)
        ext   = Path(file_path).suffix.lower() if file_path else ""
        risk  = HIGH_RISK_EXT.get(ext, 1)
        delta = base * burst * (1.0 + 0.15 * (risk - 1))
        with self._lock:
            self._score = min(100.0, self._score + delta)
            s = round(self._score, 1)
        self._history.append((datetime.datetime.now(), s))
        if len(self._history) > 1000:
            self._history = self._history[-500:]
        log.debug(f"Score +{delta:.1f} ({event_type}) → {s}")
        return s

    @property
    def score(self) -> float:
        self._decay()
        with self._lock:
            return round(self._score, 1)

    @property
    def level(self) -> tuple[str, str]:
        s = self.score
        if s < 20: return ("LOW",      C["green"])
        if s < 50: return ("MEDIUM",   C["yellow"])
        if s < 75: return ("HIGH",     C["orange"])
        return            ("CRITICAL", C["red"])

    def history_by_hour(self) -> Dict[str, int]:
        now     = datetime.datetime.now()
        buckets = {}
        for i in range(11, -1, -1):
            h = (now - datetime.timedelta(hours=i)).strftime("%H:00")
            buckets[h] = 0
        for ts, _ in self._history:
            k = ts.strftime("%H:00")
            if k in buckets:
                buckets[k] += 1
        return buckets

# ─────────────────────────────────────────────────────────────────────────────
#  EVENT LOGGER
# ─────────────────────────────────────────────────────────────────────────────
class EventLogger:
    def __init__(self):
        self._records: List[Dict] = []
        self._lock = threading.Lock()

    def log(self, event_type: str, file_path: str,
            score: float, detail: str = "") -> Dict:
        ts  = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        rec = dict(timestamp=ts, event_type=event_type,
                   file_path=str(file_path),
                   threat_score=score, detail=detail)
        with self._lock:
            self._records.append(rec)
        log.info(f"EVENT {event_type.upper():10s} score={score:6.1f} "
                 f"file={os.path.basename(file_path)}")
        return rec

    @property
    def records(self) -> List[Dict]:
        with self._lock:
            return list(self._records)

    def filtered(self, query: str = "", event_type: str = "ALL") -> List[Dict]:
        q = query.strip().lower()
        with self._lock:
            recs = list(self._records)
        return [
            r for r in recs
            if (event_type == "ALL" or
                r["event_type"].lower() == event_type.lower())
            and (not q or q in r["file_path"].lower()
                 or q in r.get("detail","").lower())
        ]

# ─────────────────────────────────────────────────────────────────────────────
#  OS-SAFE SOUND ALERT
# ─────────────────────────────────────────────────────────────────────────────
def play_alert() -> None:
    try:
        if IS_WINDOWS:
            import winsound
            winsound.MessageBeep(winsound.MB_ICONEXCLAMATION)
        elif IS_MAC:
            os.system("afplay /System/Library/Sounds/Funk.aiff 2>/dev/null &")
        elif IS_LINUX:
            # Try paplay, then aplay, then bell
            if os.system("which paplay >/dev/null 2>&1") == 0:
                os.system("paplay /usr/share/sounds/freedesktop/stereo/"
                          "alarm-clock-elapsed.oga 2>/dev/null &")
            elif os.system("which aplay >/dev/null 2>&1") == 0:
                os.system("aplay /usr/share/sounds/freedesktop/stereo/"
                          "bell.oga 2>/dev/null &")
            else:
                print("\a", end="", flush=True)   # terminal bell fallback
    except Exception as e:
        log.debug(f"Sound alert failed: {e}")

# ─────────────────────────────────────────────────────────────────────────────
#  TOAST NOTIFICATIONS  (OS-safe)
# ─────────────────────────────────────────────────────────────────────────────
def send_toast(title: str, message: str) -> None:
    if not HAS_PLYER:
        log.debug("Toast skipped (plyer not installed)")
        return
    try:
        _plyer_notify.notify(title=title[:50], message=message[:200],
                             app_name=APP_NAME, timeout=6)
        log.debug(f"Toast sent: {title}")
    except Exception as e:
        log.debug(f"Toast failed: {e}")

# ─────────────────────────────────────────────────────────────────────────────
#  AUTO-START  (Windows only, graceful on others)
# ─────────────────────────────────────────────────────────────────────────────
def set_autostart(enable: bool) -> bool:
    if not IS_WINDOWS:
        log.info("Auto-start only supported on Windows")
        return False
    try:
        import winreg
        RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY,
                             0, winreg.KEY_SET_VALUE)
        if enable:
            script = os.path.abspath(__file__)
            cmd    = f'"{sys.executable}" "{script}"'
            winreg.SetValueEx(key, APP_NAME, 0, winreg.REG_SZ, cmd)
            log.info(f"Auto-start enabled: {cmd}")
        else:
            try:
                winreg.DeleteValue(key, APP_NAME)
                log.info("Auto-start disabled")
            except FileNotFoundError:
                pass
        winreg.CloseKey(key)
        return True
    except Exception as e:
        log.warning(f"Auto-start failed: {e}")
        return False

# ─────────────────────────────────────────────────────────────────────────────
#  EMAIL REPORTER
# ─────────────────────────────────────────────────────────────────────────────
class EmailReporter:
    def send(self, settings: Settings, pdf_path: str,
             subject: str = "IntegraSafe Security Report") -> tuple[bool, str]:
        """Returns (success, error_message)."""
        frm  = settings.get("email_from", "")
        to   = settings.get("email_to",   "")
        pw   = settings.get("email_password", "")
        smtp = settings.get("email_smtp", "smtp.gmail.com")
        port = int(settings.get("email_port", 587))

        if not all([frm, to, pw]):
            return False, "Email credentials incomplete"
        if not Path(pdf_path).exists():
            return False, "PDF file not found"

        try:
            msg            = MIMEMultipart()
            msg["From"]    = frm
            msg["To"]      = to
            msg["Subject"] = subject
            msg.attach(MIMEText(
                "Please find the attached IntegraSafe security report.\n\n"
                f"Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
                f"Application: {APP_NAME} v{APP_VERSION}",
                "plain"))
            with open(pdf_path, "rb") as f:
                part = MIMEBase("application", "octet-stream")
                part.set_payload(f.read())
            _email_enc.encode_base64(part)
            part.add_header("Content-Disposition",
                            f"attachment; filename={Path(pdf_path).name}")
            msg.attach(part)

            with smtplib.SMTP(smtp, port, timeout=15) as server:
                server.ehlo()
                server.starttls()
                server.login(frm, pw)
                server.sendmail(frm, to, msg.as_string())
            log.info(f"Email report sent to {to}")
            return True, ""
        except smtplib.SMTPAuthenticationError:
            msg = "SMTP authentication failed – check email/password"
            log.warning(msg)
            return False, msg
        except smtplib.SMTPException as e:
            msg = f"SMTP error: {e}"
            log.warning(msg)
            return False, msg
        except Exception as e:
            msg = f"Email error: {e}"
            log.error(msg)
            return False, msg

# ─────────────────────────────────────────────────────────────────────────────
#  WATCHDOG HANDLER
# ─────────────────────────────────────────────────────────────────────────────
class FIMHandler(FileSystemEventHandler):
    def __init__(self, engine: IntegrityEngine, scorer: ThreatScorer,
                 event_log: EventLogger, whitelist: Whitelist,
                 watch_folder: str, settings: Settings,
                 callback: Callable):
        super().__init__()
        self._engine   = engine
        self._scorer   = scorer
        self._log      = event_log
        self._wl       = whitelist
        self._folder   = watch_folder
        self._cfg      = settings
        self._cb       = callback
        self._debounce: Dict[str, float] = {}
        self._deb_lock = threading.Lock()

    def _debounced(self, path: str, gap: float = 0.5) -> bool:
        """Return True if event should be processed (debounce rapid fires)."""
        now = time.monotonic()
        with self._deb_lock:
            last = self._debounce.get(path, 0)
            if now - last < gap:
                return False
            self._debounce[path] = now
            return True

    def _handle(self, etype: str, src: str, extra: str = "") -> None:
        try:
            if os.path.isdir(src):
                return
            if not self._debounced(src):
                return
            if self._wl.is_trusted(src):
                log.debug(f"Skipping trusted file: {src}")
                return

            score  = self._scorer.record(etype, src)
            detail = extra
            healed = False
            quar   = False

            if self._cfg.get("quarantine_mode") and etype == "created":
                ok     = self._engine.quarantine(src)
                detail = f"{extra} | {'QUARANTINED' if ok else 'Quarantine failed'}"
                quar   = ok

            elif self._cfg.get("self_heal", True) and etype in ("modified","deleted"):
                ok     = self._engine.restore(src, self._folder)
                detail = f"{extra} | {'Restored from backup' if ok else 'No backup found'}"
                healed = ok
                if ok:
                    self._scorer.record("restored", src)

            rec = self._log.log(etype, src, score, detail)
            # Marshal to main thread safely
            try:
                self._cb(rec, healed, quar, score)
            except Exception as e:
                log.warning(f"Event callback error: {e}")

        except Exception as e:
            log.error(f"FIMHandler._handle error: {e}\n{traceback.format_exc()}")

    def on_modified(self, event):
        if event.is_directory: return
        try:
            st, oh, nh = self._engine.verify(event.src_path, self._folder)
            if st == "modified":
                short_old = oh[:10] if oh else "?"
                short_new = nh[:10] if nh else "?"
                self._handle("modified", event.src_path,
                             f"Hash {short_old}...→{short_new}...")
        except Exception as e:
            log.error(f"on_modified error: {e}")

    def on_deleted(self, event):
        if event.is_directory: return
        try:
            self._engine.remove_baseline(event.src_path, self._folder)
            self._handle("deleted", event.src_path)
        except Exception as e:
            log.error(f"on_deleted error: {e}")

    def on_created(self, event):
        if event.is_directory: return
        try:
            self._engine.update_baseline(event.src_path, self._folder)
            self._handle("created", event.src_path, "New file detected")
        except Exception as e:
            log.error(f"on_created error: {e}")

# ─────────────────────────────────────────────────────────────────────────────
#  PDF REPORT BUILDER
# ─────────────────────────────────────────────────────────────────────────────
class ReportBuilder:
    def build(self, records: List[Dict], scorer: ThreatScorer,
              folders: List[str]) -> str:
        ts       = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        out_path = str(BASE_DIR / f"IntegraSafe_Report_{ts}.pdf")
        try:
            self._do_build(out_path, records, scorer, folders)
            log.info(f"PDF report generated: {out_path}")
        except Exception as e:
            log.error(f"PDF build error: {e}\n{traceback.format_exc()}")
            # Write minimal fallback PDF
            try:
                doc = SimpleDocTemplate(out_path, pagesize=A4)
                styles = getSampleStyleSheet()
                doc.build([
                    Paragraph("IntegraSafe Report", styles["Title"]),
                    Paragraph(f"Error generating full report: {e}",
                              styles["Normal"])
                ])
            except Exception:
                pass
        return out_path

    def _do_build(self, out_path: str, records: List[Dict],
                  scorer: ThreatScorer, folders: List[str]) -> None:
        doc    = SimpleDocTemplate(out_path, pagesize=A4,
                                   leftMargin=15*mm, rightMargin=15*mm,
                                   topMargin=20*mm,  bottomMargin=20*mm)
        styles = getSampleStyleSheet()
        story  = []

        T = ParagraphStyle("T", parent=styles["Title"], fontSize=22,
                           textColor=rl_colors.HexColor("#00E5FF"),
                           spaceAfter=2*mm, alignment=TA_CENTER)
        S = ParagraphStyle("S", parent=styles["Normal"], fontSize=9,
                           textColor=rl_colors.HexColor("#64748B"),
                           alignment=TA_CENTER, spaceAfter=6*mm)
        H = ParagraphStyle("H", parent=styles["Normal"], fontSize=11,
                           textColor=rl_colors.HexColor("#00E5FF"),
                           fontName="Helvetica-Bold", spaceAfter=2*mm)
        F = ParagraphStyle("F", parent=styles["Normal"], fontSize=7,
                           textColor=rl_colors.HexColor("#64748B"),
                           alignment=TA_CENTER, spaceBefore=2*mm)

        folder_str = ", ".join(folders) if folders else "N/A"
        story.append(Paragraph("IntegraSafe v4 Security Report", T))
        story.append(Paragraph(
            f"Generated: {datetime.datetime.now().strftime('%A, %d %B %Y  %H:%M:%S')} "
            f"| OS: {platform.system()} {platform.release()} "
            f"| Folders: {folder_str[:80]}", S))
        story.append(HRFlowable(width="100%", thickness=1,
                                color=rl_colors.HexColor("#1E2433")))
        story.append(Spacer(1, 4*mm))

        # Summary
        level, _ = scorer.level
        total = len(records)
        mods  = sum(1 for r in records if r["event_type"]=="modified")
        dels  = sum(1 for r in records if r["event_type"]=="deleted")
        news  = sum(1 for r in records if r["event_type"]=="created")

        sdata = [["Total","Modified","Deleted","New Files","Threat Level"],
                 [str(total), str(mods), str(dels), str(news), level]]
        t = Table(sdata, colWidths=[36*mm]*5)
        t.setStyle(TableStyle([
            ("BACKGROUND",(0,0),(-1,0),rl_colors.HexColor("#141820")),
            ("BACKGROUND",(0,1),(-1,1),rl_colors.HexColor("#0F1117")),
            ("TEXTCOLOR",(0,0),(-1,0),rl_colors.HexColor("#64748B")),
            ("TEXTCOLOR",(0,1),(-1,1),rl_colors.HexColor("#E2E8F0")),
            ("FONTSIZE",(0,0),(-1,-1),9),
            ("FONTNAME",(0,1),(-1,1),"Helvetica-Bold"),
            ("ALIGN",(0,0),(-1,-1),"CENTER"),
            ("VALIGN",(0,0),(-1,-1),"MIDDLE"),
            ("BOX",(0,0),(-1,-1),0.5,rl_colors.HexColor("#1E2433")),
            ("INNERGRID",(0,0),(-1,-1),0.3,rl_colors.HexColor("#1E2433")),
            ("TOPPADDING",(0,0),(-1,-1),5),
            ("BOTTOMPADDING",(0,0),(-1,-1),5),
        ]))
        story.append(t)
        story.append(Spacer(1, 5*mm))

        # Timeline chart
        story.append(Paragraph("Event Activity (last 12h)", H))
        hdata  = scorer.history_by_hour()
        labels = list(hdata.keys())
        vals   = list(hdata.values())
        maxv   = max(vals) if any(v > 0 for v in vals) else 1
        cw, ch = 540, 80
        d  = Drawing(cw, ch)
        bw = max(1, cw / max(len(labels), 1) - 4)
        for i, (lbl, v) in enumerate(zip(labels, vals)):
            bh  = max(2, int(v / maxv * (ch - 20)))
            clr = (rl_colors.HexColor("#FF3B5C") if v >= 3
                   else rl_colors.HexColor("#00E5FF"))
            d.add(Rect(i*(bw+4)+2, 0, bw, bh,
                       fillColor=clr, strokeColor=None))
            if i % 3 == 0:
                d.add(String(i*(bw+4)+2, -10, lbl, fontSize=5,
                             fillColor=rl_colors.HexColor("#64748B")))
        story.append(d)
        story.append(Spacer(1, 8*mm))

        # Event table
        story.append(Paragraph("Detailed Event Log", H))
        if records:
            ec   = {"modified":"#FFD600","deleted":"#FF3B5C",
                    "created":"#00E5FF","restored":"#00FF87"}
            rows = [["Timestamp","Event","File","Score","Detail"]]
            for r in records:
                rows.append([
                    r["timestamp"],
                    r["event_type"].upper(),
                    os.path.basename(r["file_path"])[:40],
                    str(r["threat_score"]),
                    r.get("detail","")[:55],
                ])
            et = Table(rows, colWidths=[38*mm,22*mm,55*mm,18*mm,47*mm],
                       repeatRows=1)
            rs = [
                ("BACKGROUND",(0,0),(-1,0),rl_colors.HexColor("#141820")),
                ("TEXTCOLOR",(0,0),(-1,0),rl_colors.HexColor("#00E5FF")),
                ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),
                ("FONTSIZE",(0,0),(-1,-1),7.5),
                ("ALIGN",(0,0),(-1,-1),"LEFT"),
                ("BOX",(0,0),(-1,-1),0.5,rl_colors.HexColor("#1E2433")),
                ("INNERGRID",(0,0),(-1,-1),0.3,rl_colors.HexColor("#1E2433")),
                ("TOPPADDING",(0,0),(-1,-1),3),
                ("BOTTOMPADDING",(0,0),(-1,-1),3),
            ]
            for i, rec in enumerate(records, 1):
                bg = "#0F1117" if i%2==0 else "#0A0C10"
                rs.append(("BACKGROUND",(0,i),(-1,i),rl_colors.HexColor(bg)))
                c2 = ec.get(rec["event_type"],"#E2E8F0")
                rs += [("TEXTCOLOR",(1,i),(1,i),rl_colors.HexColor(c2)),
                       ("FONTNAME",(1,i),(1,i),"Helvetica-Bold"),
                       ("TEXTCOLOR",(3,i),(3,i),rl_colors.HexColor(c2))]
            et.setStyle(TableStyle(rs))
            story.append(et)
        else:
            story.append(Paragraph("No events recorded.", styles["Normal"]))

        story.append(Spacer(1, 6*mm))
        story.append(HRFlowable(width="100%", thickness=0.5,
                                color=rl_colors.HexColor("#1E2433")))
        story.append(Paragraph(
            f"{APP_NAME} v{APP_VERSION}  |  Confidential  |  "
            f"Platform: {platform.system()}  |  Do not distribute", F))
        doc.build(story)

# ─────────────────────────────────────────────────────────────────────────────
#  SYSTEM TRAY
# ─────────────────────────────────────────────────────────────────────────────
class TrayManager:
    def __init__(self, app_ref):
        self._app  = app_ref
        self._icon = None

    def _make_img(self, color: str = "#00E5FF") -> "PILImage.Image":
        img  = PILImage.new("RGBA", (64, 64), (0, 0, 0, 0))
        draw = ImageDraw.Draw(img)
        r = int(color[1:3], 16)
        g = int(color[3:5], 16)
        b = int(color[5:7], 16)
        draw.ellipse([4, 4, 60, 60], fill=(r, g, b, 255))
        draw.polygon([(32,12),(44,44),(20,44)], fill=(0,0,0,200))
        return img

    def start(self) -> None:
        if not HAS_TRAY:
            log.info("System tray disabled (pystray not installed)")
            return
        try:
            menu = pystray.Menu(
                pystray.MenuItem(
                    "Show IntegraSafe",
                    lambda icon, item: self._app.after(0, self._show)),
                pystray.MenuItem(
                    "Exit",
                    lambda icon, item: self._app.after(0, self._app.destroy)),
            )
            self._icon = pystray.Icon(APP_NAME, self._make_img(),
                                      f"{APP_NAME} – Active", menu)
            threading.Thread(target=self._icon.run, daemon=True).start()
            log.info("System tray icon started")
        except Exception as e:
            log.warning(f"Tray start failed: {e}")

    def _show(self) -> None:
        try:
            self._app.deiconify()
            self._app.lift()
            self._app.focus_force()
        except Exception: pass

    def update_color(self, color: str) -> None:
        if not (self._icon and HAS_TRAY): return
        try:
            self._icon.icon = self._make_img(color)
        except Exception: pass

    def stop(self) -> None:
        if self._icon:
            try: self._icon.stop()
            except Exception: pass

# ─────────────────────────────────────────────────────────────────────────────
#  ANIMATED PARTICLE CANVAS
# ─────────────────────────────────────────────────────────────────────────────
class ParticleCanvas(tk.Canvas):
    N_PARTICLES = 55
    N_DROPS     = 28
    CHARS       = list("01アイウエオカキクケABCDEF<>{}[]")
    FPS         = 30

    def __init__(self, master, **kw):
        super().__init__(master, bg="#0A0C10", highlightthickness=0, **kw)
        self._particles: List = []
        self._drops:     List = []
        self._running         = True
        self._w, self._h      = 800, 600
        self.bind("<Configure>", self._on_resize)
        self.after(120, self._init)

    def _on_resize(self, e):
        self._w = max(e.width,  100)
        self._h = max(e.height, 100)

    def _init(self):
        try:
            self._w = max(self.winfo_width(),  100)
            self._h = max(self.winfo_height(), 100)
        except Exception:
            pass
        for _ in range(self.N_PARTICLES):
            x  = random.uniform(0, self._w)
            y  = random.uniform(0, self._h)
            r  = random.uniform(1.5, 4)
            vx = random.uniform(-0.5, 0.5)
            vy = random.uniform(-0.4, 0.4)
            a  = random.randint(35, 150)
            clr = self._blend(0, 229, 255, a)
            cid = self.create_oval(x-r, y-r, x+r, y+r,
                                   fill=clr, outline="")
            self._particles.append([cid, x, y, r, vx, vy])

        cols = max(1, self._w // 20)
        for _ in range(self.N_DROPS):
            x   = random.randint(0, cols-1) * 20
            y   = random.randint(-self._h, 0)
            sp  = random.uniform(2.5, 7)
            ch  = random.choice(self.CHARS)
            a   = random.randint(15, 70)
            clr = self._blend(0, 229, 255, a)
            cid = self.create_text(x, y, text=ch, fill=clr,
                                   font=("Courier", 10))
            self._drops.append([cid, x, y, sp])
        self._animate()

    @staticmethod
    def _blend(r, g, b, a):
        bg = (10, 12, 16)
        f  = a / 255
        return "#{:02x}{:02x}{:02x}".format(
            int(r*f + bg[0]*(1-f)),
            int(g*f + bg[1]*(1-f)),
            int(b*f + bg[2]*(1-f)),
        )

    def _animate(self):
        if not self._running:
            return
        try:
            w = self._w; h = self._h
            for p in self._particles:
                cid, x, y, r, vx, vy = p
                x = (x + vx) % w
                y = (y + vy) % h
                p[1] = x; p[2] = y
                self.coords(cid, x-r, y-r, x+r, y+r)
            for d in self._drops:
                cid, x, y, sp = d
                y += sp
                if y > h:
                    y = random.randint(-80, 0)
                    x = random.randint(0, max(1, w//20 - 1)) * 20
                    self.itemconfig(cid, text=random.choice(self.CHARS))
                d[2] = y
                self.coords(cid, x, y)
            self.after(1000 // self.FPS, self._animate)
        except Exception:
            pass  # widget destroyed – stop silently

    def stop(self):
        self._running = False

# ─────────────────────────────────────────────────────────────────────────────
#  CAPABILITY BADGE  (shown in GUI when optional feature is unavailable)
# ─────────────────────────────────────────────────────────────────────────────
def _unavailable_label(parent, feature: str, install: str) -> ctk.CTkLabel:
    return ctk.CTkLabel(
        parent,
        text=f"⚠  {feature} unavailable\n(pip install {install})",
        font=_mono_font(10),
        text_color=C["subtext"],
    )

# ─────────────────────────────────────────────────────────────────────────────
#  CHART WIDGET
# ─────────────────────────────────────────────────────────────────────────────
class ChartWidget(ctk.CTkFrame):
    def __init__(self, master, scorer: ThreatScorer):
        super().__init__(master, fg_color=C["card"], corner_radius=12,
                         border_width=1, border_color=C["border"])
        self._scorer = scorer
        if HAS_MPL:
            try:
                self._fig = Figure(figsize=(5, 2.2), dpi=80,
                                   facecolor=C["chart_bg"])
                self._ax  = self._fig.add_subplot(111,
                                                   facecolor=C["chart_bg"])
                self._cv  = FigureCanvasTkAgg(self._fig, master=self)
                self._cv.get_tk_widget().pack(fill="both", expand=True,
                                              padx=4, pady=4)
                self.update_chart()
                return
            except Exception as e:
                log.warning(f"Chart widget init failed: {e}")
        # Fallback label
        _unavailable_label(self, "Analytics chart", "matplotlib").pack(pady=20)

    def update_chart(self):
        if not HAS_MPL or not hasattr(self, "_ax"):
            return
        try:
            data   = self._scorer.history_by_hour()
            labels = list(data.keys())
            vals   = list(data.values())
            self._ax.clear()
            bar_colors = [C["red"] if v >= 3 else C["accent"] for v in vals]
            self._ax.bar(range(len(labels)), vals,
                         color=bar_colors, width=0.7, zorder=2)
            self._ax.set_xticks(range(len(labels)))
            self._ax.set_xticklabels(labels, rotation=45,
                                      fontsize=6, color=C["subtext"])
            self._ax.tick_params(colors=C["subtext"], labelsize=6)
            self._ax.set_facecolor(C["chart_bg"])
            for spine in self._ax.spines.values():
                spine.set_color(C["border"])
            self._ax.set_ylabel("Events", fontsize=7, color=C["subtext"])
            self._ax.set_title("Events / Hour  (last 12h)", fontsize=8,
                                color=C["accent"], pad=4)
            self._fig.tight_layout()
            self._cv.draw()
        except Exception as e:
            log.debug(f"Chart update error: {e}")

# ─────────────────────────────────────────────────────────────────────────────
#  LOGIN FRAME
# ─────────────────────────────────────────────────────────────────────────────
class LoginFrame(ctk.CTkFrame):
    def __init__(self, master, auth: AuthManager, on_success: Callable):
        super().__init__(master, fg_color=C["bg"])
        self._auth       = auth
        self._on_success = on_success
        self._canvas: Optional[ParticleCanvas] = None
        self._attempts   = 0
        self._build()

    def _build(self):
        self.place(relx=0, rely=0, relwidth=1, relheight=1)

        # Animated background
        try:
            self._canvas = ParticleCanvas(self)
            self._canvas.place(relx=0, rely=0, relwidth=1, relheight=1)
        except Exception as e:
            log.warning(f"Particle canvas failed: {e}")

        # Login card
        card = ctk.CTkFrame(self, fg_color=C["card"], corner_radius=20,
                            width=440, height=560,
                            border_width=1, border_color=C["border"])
        card.place(relx=0.5, rely=0.5, anchor="center")
        card.pack_propagate(False)

        _shield_font = ("Segoe UI Emoji", 52) if IS_WINDOWS else ("Arial", 52)
        ctk.CTkLabel(card, text="🛡", font=_shield_font,
                     text_color=C["accent"]).pack(pady=(34, 2))
        ctk.CTkLabel(card, text=APP_NAME,
                     font=_mono_font(28, bold=True),
                     text_color=C["white"]).pack()
        ctk.CTkLabel(card, text=f"v{APP_VERSION}  ·  Self-Healing FIM",
                     font=_mono_font(10),
                     text_color=C["subtext"]).pack(pady=(2, 26))

        # Username
        ctk.CTkLabel(card, text="USERNAME", font=_mono_font(9),
                     text_color=C["subtext"], anchor="w").pack(padx=40, fill="x")
        self._uv = ctk.StringVar(value="admin")
        ctk.CTkEntry(card, textvariable=self._uv, width=360, height=44,
                     font=_mono_font(13), fg_color=C["panel"],
                     border_color=C["border"], text_color=C["text"],
                     corner_radius=8).pack(padx=40, pady=(4, 14))

        # Password
        ctk.CTkLabel(card, text="PASSWORD", font=_mono_font(9),
                     text_color=C["subtext"], anchor="w").pack(padx=40, fill="x")
        self._pv = ctk.StringVar()
        self._pe = ctk.CTkEntry(card, textvariable=self._pv, show="●",
                                width=360, height=44,
                                font=_mono_font(13), fg_color=C["panel"],
                                border_color=C["border"], text_color=C["text"],
                                corner_radius=8)
        self._pe.pack(padx=40, pady=(4, 8))
        self._pe.bind("<Return>", lambda e: self._login())

        # Error label
        self._err = ctk.CTkLabel(card, text="", font=_mono_font(11),
                                  text_color=C["red"])
        self._err.pack(pady=(0, 10))

        # Login button
        self._btn = ctk.CTkButton(card, text="AUTHENTICATE  →",
                                   font=_mono_font(13, bold=True),
                                   fg_color=C["accent2"], hover_color="#6D28D9",
                                   text_color=C["white"], width=360, height=48,
                                   corner_radius=10, command=self._login)
        self._btn.pack(padx=40)

        # Dependency status row
        caps_text = "  ".join(
            f"{'✔' if v else '✘'} {k}"
            for k, v in [("chart", HAS_MPL),
                          ("toast", HAS_PLYER),
                          ("tray",  HAS_TRAY)]
        )
        ctk.CTkLabel(card, text=caps_text, font=_mono_font(8),
                     text_color=C["subtext"]).pack(pady=(14, 4))
        ctk.CTkLabel(card, text=f"v{APP_VERSION}  ·  Secure Admin Access",
                     font=_mono_font(9),
                     text_color=C["subtext"]).pack(pady=(0, 10))

    def _login(self):
        u = self._uv.get().strip()
        p = self._pv.get()
        if not u or not p:
            self._err.configure(text="⚠  All fields required")
            return
        self._btn.configure(state="disabled", text="Authenticating…")
        self.after(50, lambda: self._do_auth(u, p))

    def _do_auth(self, u: str, p: str):
        try:
            if self._auth.verify(u, p):
                log.info(f"Login: '{u}' authenticated")
                if self._canvas:
                    self._canvas.stop()
                self._on_success(u)
            else:
                self._attempts += 1
                log.warning(f"Login: failed attempt #{self._attempts} for '{u}'")
                self._err.configure(
                    text=f"✘  Invalid credentials  (attempt {self._attempts})")
                self._pv.set("")
                self._btn.configure(state="normal", text="AUTHENTICATE  →")
                if self._attempts >= 5:
                    self._btn.configure(state="disabled")
                    self._err.configure(
                        text="⛔  Too many attempts – restart app")
        except Exception as e:
            log.error(f"Auth exception: {e}")
            self._err.configure(text="⚠  Auth error – see log")
            self._btn.configure(state="normal", text="AUTHENTICATE  →")

# ─────────────────────────────────────────────────────────────────────────────
#  SETTINGS PANEL
# ─────────────────────────────────────────────────────────────────────────────
class SettingsPanel(ctk.CTkToplevel):
    def __init__(self, master, settings: Settings, on_save: Callable):
        super().__init__(master)
        self.title(f"{APP_NAME} – Settings")
        self.geometry("560x720")
        self.configure(fg_color=C["bg"])
        self.resizable(False, True)
        self._s  = settings
        self._cb = on_save
        self._build()
        self.grab_set()
        self.lift()

    def _section(self, parent, title: str):
        ctk.CTkLabel(parent, text=title, font=_mono_font(10, bold=True),
                     text_color=C["accent"]).pack(anchor="w", padx=24, pady=(14,3))
        ctk.CTkFrame(parent, height=1, fg_color=C["border"]).pack(fill="x", padx=24)

    def _row(self, parent, label: str, widget_fn: Callable):
        f = ctk.CTkFrame(parent, fg_color="transparent")
        f.pack(fill="x", padx=24, pady=4)
        ctk.CTkLabel(f, text=label, font=_mono_font(11),
                     text_color=C["text"], width=210, anchor="w").pack(side="left")
        w = widget_fn(f)
        if w: w.pack(side="right")
        return w

    def _sw(self, parent, var):
        return ctk.CTkSwitch(parent, text="", variable=var,
                             fg_color=C["border"], progress_color=C["accent"],
                             button_color=C["white"])

    def _en(self, parent, var, w=120, show=""):
        return ctk.CTkEntry(parent, textvariable=var, width=w, height=32,
                            show=show, font=_mono_font(10),
                            fg_color=C["card"], border_color=C["border"],
                            text_color=C["text"])

    def _build(self):
        ctk.CTkLabel(self, text="⚙  Settings",
                     font=_mono_font(17, bold=True),
                     text_color=C["white"]).pack(pady=(18, 6))

        scroll = ctk.CTkScrollableFrame(self, fg_color=C["panel"],
                                         corner_radius=12)
        scroll.pack(fill="both", expand=True, padx=14, pady=6)

        # Appearance
        self._dark  = ctk.BooleanVar(value=self._s.get("dark_theme", True))
        self._section(scroll, "APPEARANCE")
        self._row(scroll, "Dark Theme", lambda p: self._sw(p, self._dark))

        # Alerts
        self._sound  = ctk.BooleanVar(value=self._s.get("sound_alerts",  True))
        self._toast  = ctk.BooleanVar(value=self._s.get("toast_notifications", True))
        self._thresh = ctk.StringVar( value=str(self._s.get("alert_threshold", 75)))
        self._section(scroll, "ALERTS")
        self._row(scroll, f"Sound Alerts {'(winsound)' if IS_WINDOWS else ''}",
                  lambda p: self._sw(p, self._sound))
        if not HAS_PLYER:
            self._row(scroll, "Toast Notifications",
                      lambda p: ctk.CTkLabel(p,
                          text="Install plyer to enable",
                          font=_mono_font(9), text_color=C["subtext"]))
        else:
            self._row(scroll, "Toast Notifications",
                      lambda p: self._sw(p, self._toast))
        self._row(scroll, "Alert Threshold (0-100)",
                  lambda p: self._en(p, self._thresh, w=80))

        # Behaviour
        self._qmode = ctk.BooleanVar(value=self._s.get("quarantine_mode", False))
        self._heal  = ctk.BooleanVar(value=self._s.get("self_heal", True))
        self._section(scroll, "BEHAVIOUR")
        self._row(scroll, "Self-Heal (auto-restore)",
                  lambda p: self._sw(p, self._heal))
        self._row(scroll, "Quarantine New Files",
                  lambda p: self._sw(p, self._qmode))

        # Schedule
        self._sch_on = ctk.BooleanVar(value=self._s.get("schedule_enabled", False))
        self._sch_st = ctk.StringVar( value=self._s.get("schedule_start", "09:00"))
        self._sch_en = ctk.StringVar( value=self._s.get("schedule_end",   "18:00"))
        self._section(scroll, "MONITORING SCHEDULE")
        self._row(scroll, "Enable Schedule",
                  lambda p: self._sw(p, self._sch_on))
        self._row(scroll, "Start Time (HH:MM)",
                  lambda p: self._en(p, self._sch_st, w=100))
        self._row(scroll, "End Time (HH:MM)",
                  lambda p: self._en(p, self._sch_en, w=100))

        # Email
        self._em_on = ctk.BooleanVar(value=self._s.get("email_alerts",   False))
        self._em_to = ctk.StringVar( value=self._s.get("email_to",       ""))
        self._em_fr = ctk.StringVar( value=self._s.get("email_from",     ""))
        self._em_pw = ctk.StringVar( value=self._s.get("email_password", ""))
        self._em_sm = ctk.StringVar( value=self._s.get("email_smtp", "smtp.gmail.com"))
        self._section(scroll, "EMAIL REPORTS")
        self._row(scroll, "Enable Email Reports",
                  lambda p: self._sw(p, self._em_on))
        self._row(scroll, "Recipient Email",
                  lambda p: self._en(p, self._em_to, w=220))
        self._row(scroll, "Sender Email",
                  lambda p: self._en(p, self._em_fr, w=220))
        self._row(scroll, "App Password",
                  lambda p: self._en(p, self._em_pw, w=220, show="*"))
        self._row(scroll, "SMTP Server",
                  lambda p: self._en(p, self._em_sm, w=220))

        # System
        self._ast   = ctk.BooleanVar(value=self._s.get("auto_start", False))
        self._debug = ctk.BooleanVar(value=self._s.get("debug_mode", False))
        self._section(scroll, "SYSTEM")
        lbl_ast = ("Auto-Start on Boot (Windows only)"
                   if not IS_WINDOWS else "Auto-Start on Boot")
        self._row(scroll, lbl_ast,
                  lambda p: self._sw(p, self._ast))
        self._row(scroll, "Debug Mode (verbose log)",
                  lambda p: self._sw(p, self._debug))

        ctk.CTkButton(self, text="SAVE SETTINGS",
                      font=_mono_font(13, bold=True),
                      fg_color=C["accent2"], hover_color="#6D28D9",
                      text_color=C["white"], height=46, corner_radius=10,
                      command=self._save).pack(fill="x", padx=14, pady=12)

    def _save(self):
        try:
            thr = int(self._thresh.get())
            thr = max(0, min(100, thr))
        except ValueError:
            thr = 75

        self._s.set("dark_theme",           self._dark.get())
        self._s.set("sound_alerts",         self._sound.get())
        self._s.set("toast_notifications",  self._toast.get())
        self._s.set("quarantine_mode",      self._qmode.get())
        self._s.set("self_heal",            self._heal.get())
        self._s.set("schedule_enabled",     self._sch_on.get())
        self._s.set("schedule_start",       self._sch_st.get())
        self._s.set("schedule_end",         self._sch_en.get())
        self._s.set("email_alerts",         self._em_on.get())
        self._s.set("email_to",             self._em_to.get().strip())
        self._s.set("email_from",           self._em_fr.get().strip())
        self._s.set("email_password",       self._em_pw.get())
        self._s.set("email_smtp",           self._em_sm.get().strip())
        self._s.set("auto_start",           self._ast.get())
        self._s.set("debug_mode",           self._debug.get())
        self._s.set("alert_threshold",      thr)

        if self._ast.get():
            result = set_autostart(True)
            if not result and IS_WINDOWS:
                messagebox.showwarning("Auto-Start",
                    "Could not set auto-start.\n"
                    "Try running as Administrator.")
        else:
            set_autostart(False)

        if self._debug.get():
            log.setLevel(logging.DEBUG)
        else:
            log.setLevel(logging.INFO)

        log.info("Settings saved")
        self._cb()
        self.destroy()

# ─────────────────────────────────────────────────────────────────────────────
#  DASHBOARD
# ─────────────────────────────────────────────────────────────────────────────
class Dashboard(ctk.CTkFrame):
    MAX_ROWS = 300

    def __init__(self, master, username: str, settings: Settings):
        super().__init__(master, fg_color=C["bg"])
        self._username    = username
        self._settings    = settings
        self._vault       = Vault()
        self._engine      = IntegrityEngine(self._vault)
        self._scorer      = ThreatScorer()
        self._event_log   = EventLogger()
        self._reporter    = ReportBuilder()
        self._emailer     = EmailReporter()
        self._whitelist   = Whitelist()
        self._tray        = TrayManager(master)

        self._folders:    List[str]    = []
        self._observers:  List         = []
        self._running     = False
        self._heal_var    = ctk.BooleanVar(value=settings.get("self_heal", True))
        self._theme_var   = ctk.BooleanVar(value=settings.get("dark_theme", True))
        self._active_tab  = "dashboard"

        self._ev_count    = 0
        self._heal_count  = 0
        self._quar_count  = 0
        self._last_alert  = 0.0

        self._build()
        self._tick()
        self._tray.start()
        self._start_schedule_watcher()
        log.info(f"Dashboard initialized for user '{username}'")

    # ── LAYOUT ───────────────────────────────────────────────────────────────
    def _build(self):
        self.place(relx=0, rely=0, relwidth=1, relheight=1)
        self._build_sidebar()
        self._build_content()

    def _build_sidebar(self):
        sb = ctk.CTkFrame(self, fg_color=C["panel"],
                          corner_radius=0, width=244)
        sb.pack(side="left", fill="y")
        sb.pack_propagate(False)

        _shield_font2 = ("Segoe UI Emoji", 32) if IS_WINDOWS else ("Arial", 32)
        ctk.CTkLabel(sb, text="🛡", font=_shield_font2,
                     text_color=C["accent"]).pack(pady=(26, 2))
        ctk.CTkLabel(sb, text=APP_NAME, font=_mono_font(19, bold=True),
                     text_color=C["white"]).pack()
        ctk.CTkLabel(sb, text=f"v{APP_VERSION}  ·  FIM System",
                     font=_mono_font(9), text_color=C["subtext"]).pack(pady=(0, 18))
        ctk.CTkFrame(sb, height=1, fg_color=C["border"]).pack(fill="x", padx=16)

        nav = [
            ("dashboard", "📊  Dashboard"),
            ("events",    "📋  Event Log"),
            ("chart",     "📈  Analytics"),
            ("whitelist", "🔒  Whitelist"),
            ("settings",  "⚙   Settings"),
        ]
        for tab, label in nav:
            ctk.CTkButton(
                sb, text=label, font=_mono_font(12),
                fg_color="transparent", hover_color=C["card"],
                text_color=C["subtext"], anchor="w", height=40,
                corner_radius=8,
                command=lambda t=tab: self._switch(t),
            ).pack(fill="x", padx=12, pady=2)

        ctk.CTkFrame(sb, height=1, fg_color=C["border"]).pack(fill="x", padx=16, pady=12)

        # Self-heal toggle
        ctk.CTkLabel(sb, text="SELF-HEALING", font=_mono_font(9),
                     text_color=C["subtext"]).pack(padx=16, anchor="w")
        ctk.CTkSwitch(sb, text="Auto-Restore", font=_mono_font(11),
                      variable=self._heal_var,
                      fg_color=C["border"], progress_color=C["green"],
                      text_color=C["text"], button_color=C["white"],
                      command=self._on_heal_toggle,
                      ).pack(padx=20, pady=6, anchor="w")

        # Theme toggle
        ctk.CTkLabel(sb, text="THEME", font=_mono_font(9),
                     text_color=C["subtext"]).pack(padx=16, anchor="w")
        ctk.CTkSwitch(sb, text="Dark Mode", font=_mono_font(11),
                      variable=self._theme_var,
                      fg_color=C["border"], progress_color=C["accent2"],
                      text_color=C["text"], button_color=C["white"],
                      command=self._toggle_theme,
                      ).pack(padx=20, pady=4, anchor="w")

        # OS info
        ctk.CTkFrame(sb, height=1, fg_color=C["border"]).pack(fill="x", padx=16, pady=8)
        ctk.CTkLabel(sb, text=f"{platform.system()} {platform.release()}",
                     font=_mono_font(8), text_color=C["subtext"]).pack(padx=16)

        # User card
        uf = ctk.CTkFrame(sb, fg_color=C["card"], corner_radius=10)
        uf.pack(side="bottom", fill="x", padx=12, pady=14)
        ctk.CTkLabel(uf, text=f"●  {self._username}",
                     font=_mono_font(11), text_color=C["green"]).pack(pady=(10, 2))
        ctk.CTkLabel(uf, text="Administrator",
                     font=_mono_font(9), text_color=C["subtext"]).pack(pady=(0, 10))

    def _build_content(self):
        self._content = ctk.CTkFrame(self, fg_color=C["bg"])
        self._content.pack(side="right", fill="both", expand=True)

        # Top bar
        tb = ctk.CTkFrame(self._content, fg_color=C["panel"],
                          corner_radius=0, height=56)
        tb.pack(fill="x")
        tb.pack_propagate(False)
        self._title_lbl = ctk.CTkLabel(tb, text="Security Dashboard",
                                        font=_mono_font(15, bold=True),
                                        text_color=C["white"])
        self._title_lbl.pack(side="left", padx=20)
        self._clock_lbl = ctk.CTkLabel(tb, text="",
                                        font=_mono_font(11),
                                        text_color=C["subtext"])
        self._clock_lbl.pack(side="right", padx=20)

        self._tab_frame = ctk.CTkFrame(self._content, fg_color=C["bg"])
        self._tab_frame.pack(fill="both", expand=True)

        self._tabs: Dict[str, ctk.CTkFrame] = {}
        self._build_dashboard_tab()
        self._build_events_tab()
        self._build_chart_tab()
        self._build_whitelist_tab()
        self._build_settings_tab()
        self._switch("dashboard")

    def _switch(self, name: str):
        for t in self._tabs.values():
            t.pack_forget()
        if name in self._tabs:
            self._tabs[name].pack(fill="both", expand=True)
        self._active_tab = name
        titles = {
            "dashboard": "Security Dashboard",
            "events":    "Event Log",
            "chart":     "Analytics",
            "whitelist": "Trusted Files",
            "settings":  "Settings",
        }
        self._title_lbl.configure(text=titles.get(name, APP_NAME))
        if name == "chart" and hasattr(self, "_chart_w"):
            self._chart_w.update_chart()

    # ── DASHBOARD TAB ─────────────────────────────────────────────────────────
    def _build_dashboard_tab(self):
        tab = ctk.CTkFrame(self._tab_frame, fg_color=C["bg"])
        self._tabs["dashboard"] = tab
        cnt = ctk.CTkFrame(tab, fg_color=C["bg"])
        cnt.pack(fill="both", expand=True, padx=18, pady=14)

        # Stat cards
        r1 = ctk.CTkFrame(cnt, fg_color="transparent")
        r1.pack(fill="x", pady=(0, 10))
        stats = [
            ("THREAT SCORE", "0.0",  C["accent"],  "_score_lbl"),
            ("THREAT LEVEL", "LOW",  C["green"],   "_level_lbl"),
            ("EVENTS",       "0",    C["accent2"], "_ev_lbl"),
            ("HEALED",       "0",    C["green"],   "_heal_lbl"),
            ("QUARANTINED",  "0",    C["yellow"],  "_quar_lbl"),
        ]
        for i, (title, val, clr, attr) in enumerate(stats):
            card = ctk.CTkFrame(r1, fg_color=C["card"], corner_radius=12,
                                border_width=1, border_color=C["border"])
            card.grid(row=0, column=i, padx=4, sticky="ew")
            r1.grid_columnconfigure(i, weight=1)
            ctk.CTkLabel(card, text=title, font=_mono_font(8),
                         text_color=C["subtext"]).pack(pady=(12, 2))
            lbl = ctk.CTkLabel(card, text=val,
                               font=_mono_font(22, bold=True),
                               text_color=clr)
            lbl.pack(pady=(0, 12))
            setattr(self, attr, lbl)

        # Controls row
        r2 = ctk.CTkFrame(cnt, fg_color="transparent")
        r2.pack(fill="x", pady=(0, 10))

        ctrl = ctk.CTkFrame(r2, fg_color=C["card"], corner_radius=12,
                            border_width=1, border_color=C["border"])
        ctrl.pack(side="left", fill="both", expand=True, padx=(0, 8))

        ctk.CTkLabel(ctrl, text="MONITOR CONTROLS", font=_mono_font(10),
                     text_color=C["subtext"]).pack(anchor="w", padx=16, pady=(12, 5))
        self._folder_lbl = ctk.CTkLabel(ctrl, text="No folder selected",
                                         font=_mono_font(10),
                                         text_color=C["subtext"],
                                         wraplength=390, justify="left")
        self._folder_lbl.pack(anchor="w", padx=16, pady=(0, 8))

        br = ctk.CTkFrame(ctrl, fg_color="transparent")
        br.pack(padx=16, pady=(0, 8), anchor="w")

        ctk.CTkButton(br, text="📂 Add Folder",
                      font=_mono_font(11), fg_color=C["border"],
                      hover_color="#2A3040", text_color=C["text"],
                      width=138, height=38, corner_radius=8,
                      command=self._add_folder).pack(side="left", padx=(0, 6))

        self._mon_btn = ctk.CTkButton(br, text="▶  START",
                                       font=_mono_font(11, bold=True),
                                       fg_color=C["accent2"],
                                       hover_color="#6D28D9",
                                       text_color=C["white"],
                                       width=120, height=38, corner_radius=8,
                                       command=self._toggle_monitor)
        self._mon_btn.pack(side="left", padx=(0, 6))

        ctk.CTkButton(br, text="📄 PDF",
                      font=_mono_font(11), fg_color=C["accent"],
                      hover_color="#00B8CC", text_color=C["bg"],
                      width=90, height=38, corner_radius=8,
                      command=self._export_pdf).pack(side="left", padx=(0, 6))

        ctk.CTkButton(br, text="📧 Email",
                      font=_mono_font(11), fg_color=C["border"],
                      hover_color="#2A3040", text_color=C["text"],
                      width=90, height=38, corner_radius=8,
                      command=self._email_report).pack(side="left")

        self._status = ctk.CTkLabel(ctrl, text="⬤  Idle – add a folder to begin",
                                     font=_mono_font(10),
                                     text_color=C["subtext"])
        self._status.pack(anchor="w", padx=16, pady=(0, 12))

        # Threat gauge
        gauge = ctk.CTkFrame(r2, fg_color=C["card"], corner_radius=12,
                             border_width=1, border_color=C["border"],
                             width=230)
        gauge.pack(side="right", fill="both")
        gauge.pack_propagate(False)
        ctk.CTkLabel(gauge, text="THREAT GAUGE", font=_mono_font(10),
                     text_color=C["subtext"]).pack(pady=(14, 6))
        self._gauge_bar = ctk.CTkProgressBar(gauge, width=190, height=22,
                                              corner_radius=10,
                                              fg_color=C["border"],
                                              progress_color=C["green"])
        self._gauge_bar.set(0)
        self._gauge_bar.pack(padx=20)
        self._gauge_lbl = ctk.CTkLabel(gauge, text="0.0 / 100",
                                        font=_mono_font(10),
                                        text_color=C["subtext"])
        self._gauge_lbl.pack(pady=4)
        ctk.CTkLabel(gauge, text="LOW ←──────→ CRITICAL",
                     font=_mono_font(8), text_color=C["subtext"]).pack()
        self._gauge_lvl = ctk.CTkLabel(gauge, text="LOW",
                                        font=_mono_font(20, bold=True),
                                        text_color=C["green"])
        self._gauge_lvl.pack(pady=(6, 14))

        # Live feed
        ff = ctk.CTkFrame(cnt, fg_color=C["card"], corner_radius=12,
                          border_width=1, border_color=C["border"])
        ff.pack(fill="both", expand=True)

        hdr = ctk.CTkFrame(ff, fg_color="transparent")
        hdr.pack(fill="x", padx=16, pady=(10, 4))
        ctk.CTkLabel(hdr, text="LIVE EVENT FEED", font=_mono_font(10),
                     text_color=C["subtext"]).pack(side="left")
        ctk.CTkButton(hdr, text="Clear", font=_mono_font(10),
                      fg_color="transparent", hover_color=C["border"],
                      text_color=C["subtext"], width=60, height=24,
                      corner_radius=6,
                      command=self._clear_feed).pack(side="right")

        ch_frame = ctk.CTkFrame(ff, fg_color=C["panel"], corner_radius=0)
        ch_frame.pack(fill="x")
        for col, w in [("TIMESTAMP",150),("EVENT",82),("FILE",270),
                       ("SCORE",60),("RISK",68),("DETAIL",0)]:
            ctk.CTkLabel(ch_frame, text=col, font=_mono_font(9),
                         text_color=C["subtext"], width=w, anchor="w"
                         ).pack(side="left",
                                padx=(12 if col=="TIMESTAMP" else 4, 4),
                                pady=4)

        self._feed = ctk.CTkScrollableFrame(ff, fg_color="transparent",
                                             corner_radius=0)
        self._feed.pack(fill="both", expand=True)

    # ── EVENTS TAB ────────────────────────────────────────────────────────────
    def _build_events_tab(self):
        tab = ctk.CTkFrame(self._tab_frame, fg_color=C["bg"])
        self._tabs["events"] = tab

        self._fq = ctk.StringVar()
        self._ft = ctk.StringVar(value="ALL")

        bar = ctk.CTkFrame(tab, fg_color=C["panel"],
                           corner_radius=0, height=56)
        bar.pack(fill="x")
        bar.pack_propagate(False)

        ctk.CTkLabel(bar, text="Search:", font=_mono_font(11),
                     text_color=C["subtext"]).pack(side="left", padx=(18, 6), pady=14)
        ctk.CTkEntry(bar, textvariable=self._fq, width=240, height=32,
                     font=_mono_font(11), fg_color=C["card"],
                     border_color=C["border"], text_color=C["text"],
                     corner_radius=8,
                     placeholder_text="filename or detail…"
                     ).pack(side="left", padx=(0, 10))

        ctk.CTkLabel(bar, text="Type:", font=_mono_font(11),
                     text_color=C["subtext"]).pack(side="left", padx=(0, 6))
        ctk.CTkOptionMenu(bar, variable=self._ft,
                          values=["ALL","modified","deleted",
                                  "created","restored"],
                          font=_mono_font(11), fg_color=C["card"],
                          button_color=C["border"],
                          button_hover_color=C["accent2"],
                          text_color=C["text"], width=130,
                          command=lambda _: self._refresh_events()
                          ).pack(side="left")
        ctk.CTkButton(bar, text="🔍 Search", font=_mono_font(11),
                      fg_color=C["accent2"], width=100, height=32,
                      corner_radius=8,
                      command=self._refresh_events).pack(side="left", padx=10)
        ctk.CTkButton(bar, text="Export PDF", font=_mono_font(11),
                      fg_color=C["accent"], hover_color="#00B8CC",
                      text_color=C["bg"], width=110, height=32,
                      corner_radius=8,
                      command=self._export_pdf).pack(side="right", padx=18)

        ch_frame = ctk.CTkFrame(tab, fg_color=C["panel"], corner_radius=0)
        ch_frame.pack(fill="x")
        for col, w in [("TIMESTAMP",155),("EVENT",90),("FILE",300),
                       ("SCORE",65),("DETAIL",0)]:
            ctk.CTkLabel(ch_frame, text=col, font=_mono_font(9),
                         text_color=C["subtext"], width=w, anchor="w"
                         ).pack(side="left",
                                padx=(12 if col=="TIMESTAMP" else 4, 4),
                                pady=5)

        self._ev_feed = ctk.CTkScrollableFrame(tab, fg_color=C["bg"],
                                                corner_radius=0)
        self._ev_feed.pack(fill="both", expand=True)

    def _refresh_events(self):
        self._clear_frame(self._ev_feed)

        ec = {"modified":C["yellow"],"deleted":C["red"],
              "created":C["accent"],"restored":C["green"]}
        recs = self._event_log.filtered(self._fq.get(), self._ft.get())
        for i, r in enumerate(reversed(recs)):
            clr = ec.get(r["event_type"], C["text"])
            row = ctk.CTkFrame(self._ev_feed,
                               fg_color=C["panel"] if i%2==0 else C["card"],
                               corner_radius=4)
            row.pack(fill="x", padx=4, pady=1)
            row.bind("<Button-3>",
                     lambda e, fp=r["file_path"]: self._ctx_trust(fp))
            for val, w, tc in [
                (r["timestamp"], 155, C["subtext"]),
                (r["event_type"].upper(), 90, clr),
                (os.path.basename(r["file_path"])[:38], 300, C["text"]),
                (str(r["threat_score"]), 65, clr),
                (r.get("detail","")[:60], 0, C["subtext"]),
            ]:
                ctk.CTkLabel(row, text=val, font=_mono_font(10),
                             text_color=tc, width=w if w else 0, anchor="w"
                             ).pack(side="left",
                                    padx=(12 if w==155 else 4, 4), pady=3)

    def _ctx_trust(self, filepath: str):
        try:
            if messagebox.askyesno("Trust File",
                                   f"Add to whitelist?\n\n{filepath}",
                                   parent=self.master):
                self._whitelist.add(filepath)
                self._refresh_wl()
                log.info(f"Whitelisted via context menu: {filepath}")
        except Exception as e:
            log.warning(f"Context menu error: {e}")

    # ── CHART TAB ─────────────────────────────────────────────────────────────
    def _build_chart_tab(self):
        tab = ctk.CTkFrame(self._tab_frame, fg_color=C["bg"])
        self._tabs["chart"] = tab

        ctk.CTkLabel(tab, text="Event Analytics",
                     font=_mono_font(14, bold=True),
                     text_color=C["white"]).pack(pady=(18, 4), padx=20, anchor="w")

        self._chart_w = ChartWidget(tab, self._scorer)
        self._chart_w.pack(fill="x", padx=20, pady=6, ipady=8)

        # Risk table
        rf = ctk.CTkFrame(tab, fg_color=C["card"], corner_radius=12,
                          border_width=1, border_color=C["border"])
        rf.pack(fill="x", padx=20, pady=6)
        ctk.CTkLabel(rf, text="FILE TYPE RISK MULTIPLIERS",
                     font=_mono_font(10),
                     text_color=C["subtext"]).pack(anchor="w", padx=16, pady=(12, 6))
        grid = ctk.CTkFrame(rf, fg_color="transparent")
        grid.pack(fill="x", padx=16, pady=(0, 12))
        for i, (ext, lvl) in enumerate(
                sorted(HIGH_RISK_EXT.items(), key=lambda x: -x[1])):
            clr = (C["red"] if lvl >= 5 else
                   C["orange"] if lvl >= 4 else C["yellow"])
            f = ctk.CTkFrame(grid, fg_color=C["panel"], corner_radius=6)
            f.grid(row=i//7, column=i%7, padx=3, pady=3)
            ctk.CTkLabel(f, text=f"{ext}  ×{lvl}",
                         font=_mono_font(9), text_color=clr
                         ).pack(padx=8, pady=4)

        # Score history
        hf = ctk.CTkFrame(tab, fg_color=C["card"], corner_radius=12,
                          border_width=1, border_color=C["border"])
        hf.pack(fill="both", expand=True, padx=20, pady=6)
        ctk.CTkLabel(hf, text="RECENT SCORE HISTORY",
                     font=_mono_font(10),
                     text_color=C["subtext"]).pack(anchor="w", padx=16, pady=(12, 4))
        self._hist_box = ctk.CTkScrollableFrame(hf, fg_color="transparent",
                                                 corner_radius=0)
        self._hist_box.pack(fill="both", expand=True, padx=8, pady=(0, 8))

    def _update_hist(self):
        self._clear_frame(self._hist_box)
        for ts, score in reversed(self._scorer._history[-60:]):
            clr = (C["red"] if score>=75 else
                   C["orange"] if score>=50 else
                   C["yellow"] if score>=20 else C["green"])
            f = ctk.CTkFrame(self._hist_box, fg_color="transparent")
            f.pack(fill="x", pady=1)
            ctk.CTkLabel(f, text=ts.strftime("%H:%M:%S"),
                         font=_mono_font(9), text_color=C["subtext"],
                         width=80).pack(side="left")
            ctk.CTkLabel(f, text=f"{score:6.1f}",
                         font=_mono_font(9, bold=True),
                         text_color=clr, width=55).pack(side="left")
            bw = max(2, int(score * 1.8))
            ctk.CTkFrame(f, fg_color=clr, height=10, width=bw,
                         corner_radius=4).pack(side="left", padx=4)

    # ── WHITELIST TAB ─────────────────────────────────────────────────────────
    def _build_whitelist_tab(self):
        tab = ctk.CTkFrame(self._tab_frame, fg_color=C["bg"])
        self._tabs["whitelist"] = tab

        ctk.CTkLabel(tab, text="Trusted Files & Folders",
                     font=_mono_font(14, bold=True),
                     text_color=C["white"]).pack(pady=(18, 2), padx=20, anchor="w")
        ctk.CTkLabel(tab, text="Files in this list will never trigger alerts.",
                     font=_mono_font(10),
                     text_color=C["subtext"]).pack(padx=20, anchor="w", pady=(0, 10))

        br = ctk.CTkFrame(tab, fg_color="transparent")
        br.pack(fill="x", padx=20, pady=(0, 6))
        ctk.CTkButton(br, text="+ Add File", font=_mono_font(12),
                      fg_color=C["accent2"], width=130, height=38,
                      corner_radius=8,
                      command=self._wl_add_file).pack(side="left", padx=(0, 8))
        ctk.CTkButton(br, text="+ Add Folder", font=_mono_font(12),
                      fg_color=C["border"], width=130, height=38,
                      corner_radius=8,
                      command=self._wl_add_folder).pack(side="left")

        self._wl_box = ctk.CTkScrollableFrame(tab, fg_color=C["card"],
                                               corner_radius=12,
                                               border_width=1,
                                               border_color=C["border"])
        self._wl_box.pack(fill="both", expand=True, padx=20, pady=6)
        self._refresh_wl()

    def _refresh_wl(self):
        self._clear_frame(self._wl_box)
        if not self._whitelist.all:
            ctk.CTkLabel(self._wl_box, text="No trusted files yet.",
                         font=_mono_font(11),
                         text_color=C["subtext"]).pack(pady=20)
            return
        for path in self._whitelist.all:
            row = ctk.CTkFrame(self._wl_box, fg_color=C["panel"],
                               corner_radius=6)
            row.pack(fill="x", padx=4, pady=3)
            ctk.CTkLabel(row, text=f"🔒  {path}",
                         font=_mono_font(10),
                         text_color=C["green"]).pack(side="left", padx=10, pady=8)
            ctk.CTkButton(row, text="Remove", font=_mono_font(10),
                          fg_color=C["red"], hover_color="#CC2244",
                          width=72, height=28, corner_radius=6,
                          command=lambda p=path: self._wl_remove(p)
                          ).pack(side="right", padx=8)

    def _wl_add_file(self):
        f = filedialog.askopenfilename(
            title="Select file to trust", parent=self.master)
        if f:
            self._whitelist.add(f)
            self._refresh_wl()

    def _wl_add_folder(self):
        f = filedialog.askdirectory(
            title="Select folder to trust", parent=self.master)
        if f:
            self._whitelist.add(f)
            self._refresh_wl()

    def _wl_remove(self, path: str):
        self._whitelist.remove(path)
        self._refresh_wl()

    # ── SETTINGS TAB ──────────────────────────────────────────────────────────
    def _build_settings_tab(self):
        tab = ctk.CTkFrame(self._tab_frame, fg_color=C["bg"])
        self._tabs["settings"] = tab

        ctk.CTkLabel(tab, text="Settings", font=_mono_font(14, bold=True),
                     text_color=C["white"]).pack(pady=(18, 6), padx=20, anchor="w")

        ctk.CTkButton(tab, text="⚙  Open Full Settings Panel",
                      font=_mono_font(13, bold=True),
                      fg_color=C["accent2"], hover_color="#6D28D9",
                      text_color=C["white"], height=48, corner_radius=10,
                      command=self._open_settings
                      ).pack(fill="x", padx=20, pady=(0, 10))

        # Info card
        info = ctk.CTkFrame(tab, fg_color=C["card"], corner_radius=12,
                            border_width=1, border_color=C["border"])
        info.pack(fill="x", padx=20, pady=6)
        ctk.CTkLabel(info, text="DATA LOCATIONS", font=_mono_font(10),
                     text_color=C["subtext"]).pack(anchor="w", padx=16, pady=(12, 6))
        for label, path in [
            ("Base Dir",    str(BASE_DIR)),
            ("Backups",     str(BACKUP_DIR)),
            ("Quarantine",  str(QUARANTINE)),
            ("App Log",     str(LOG_PATH)),
            ("Crash Log",   str(CRASH_LOG)),
        ]:
            row = ctk.CTkFrame(info, fg_color="transparent")
            row.pack(fill="x", padx=16, pady=2)
            ctk.CTkLabel(row, text=f"{label}:", font=_mono_font(10),
                         text_color=C["subtext"], width=110,
                         anchor="w").pack(side="left")
            ctk.CTkLabel(row, text=str(path), font=_mono_font(10),
                         text_color=C["accent"]).pack(side="left", padx=4)

        ctk.CTkFrame(info, height=1, fg_color=C["border"]
                     ).pack(fill="x", padx=16, pady=8)
        ctk.CTkButton(info, text="📂 Open Quarantine Folder",
                      font=_mono_font(11), fg_color=C["yellow"],
                      hover_color="#CCA800", text_color=C["bg"],
                      height=36, corner_radius=8,
                      command=self._open_quarantine
                      ).pack(padx=16, pady=(0, 12), anchor="w")

        # Capability status
        cap = ctk.CTkFrame(tab, fg_color=C["card"], corner_radius=12,
                           border_width=1, border_color=C["border"])
        cap.pack(fill="x", padx=20, pady=6)
        ctk.CTkLabel(cap, text="OPTIONAL FEATURES STATUS",
                     font=_mono_font(10),
                     text_color=C["subtext"]).pack(anchor="w", padx=16, pady=(12, 6))
        for name, avail, install in [
            ("Matplotlib (charts)", HAS_MPL,   "pip install matplotlib"),
            ("Plyer (toast alerts)", HAS_PLYER, "pip install plyer"),
            ("Pystray (tray icon)",  HAS_TRAY,  "pip install pystray"),
        ]:
            row = ctk.CTkFrame(cap, fg_color="transparent")
            row.pack(fill="x", padx=16, pady=3)
            status = "✔  Active" if avail else f"✘  {install}"
            clr    = C["green"] if avail else C["subtext"]
            ctk.CTkLabel(row, text=name, font=_mono_font(10),
                         text_color=C["text"], width=200,
                         anchor="w").pack(side="left")
            ctk.CTkLabel(row, text=status, font=_mono_font(10),
                         text_color=clr).pack(side="left", padx=8)
        ctk.CTkFrame(cap, height=1, fg_color=C["border"]
                     ).pack(fill="x", padx=16, pady=8)
        ctk.CTkLabel(cap, text=f"OS: {platform.system()} {platform.release()}  "
                              f"|  Python {PY_VERSION.major}.{PY_VERSION.minor}.{PY_VERSION.micro}  "
                              f"|  {APP_NAME} v{APP_VERSION}",
                     font=_mono_font(9),
                     text_color=C["subtext"]).pack(padx=16, pady=(0, 12))

    def _open_settings(self):
        SettingsPanel(self.master, self._settings,
                      on_save=self._apply_settings)

    def _apply_settings(self):
        dark = self._settings.get("dark_theme", True)
        apply_theme(dark)
        self._theme_var.set(dark)
        log.info("Settings applied")

    def _open_quarantine(self):
        p = str(QUARANTINE)
        try:
            if IS_WINDOWS:
                os.startfile(p)
            elif IS_MAC:
                os.system(f'open "{p}"')
            else:
                os.system(f'xdg-open "{p}"')
        except Exception as e:
            messagebox.showinfo("Quarantine",
                                f"Folder: {p}\n\nCould not open: {e}")

    # ── FOLDER / MONITOR ──────────────────────────────────────────────────────
    def _add_folder(self):
        try:
            folder = filedialog.askdirectory(
                title="Select Folder to Monitor", parent=self.master)
            if not folder:
                return
            if folder in self._folders:
                messagebox.showinfo("Already Monitored",
                                    "This folder is already in the list.")
                return
            self._folders.append(folder)
            names = [os.path.basename(f) or f for f in self._folders]
            self._folder_lbl.configure(
                text="📁  " + "  |  ".join(names), text_color=C["text"])
            self._status.configure(
                text="⬤  Building baseline…", text_color=C["yellow"])
            threading.Thread(target=self._baseline_bg,
                             args=(folder,), daemon=True).start()
        except Exception as e:
            log.error(f"_add_folder: {e}")
            self._safe_status(f"Error adding folder: {e}", C["red"])

    def _baseline_bg(self, folder: str):
        try:
            n = self._engine.build_baseline(folder)
            self.after(0, lambda: self._status.configure(
                text=f"✔  Baseline: {n} file(s) hashed & backed up",
                text_color=C["green"]))
        except Exception as e:
            log.error(f"Baseline error: {e}")
            self.after(0, lambda: self._safe_status(
                f"Baseline error: {e}", C["red"]))

    def _toggle_monitor(self):
        if not self._folders:
            messagebox.showwarning("No Folder",
                                   "Add at least one folder first.",
                                   parent=self.master)
            return
        if self._running:
            self._stop_monitor()
        else:
            self._start_monitor()

    def _start_monitor(self):
        # Schedule check
        if self._settings.get("schedule_enabled"):
            now_s = datetime.datetime.now().strftime("%H:%M")
            start = self._settings.get("schedule_start", "00:00")
            end   = self._settings.get("schedule_end",   "23:59")
            if not (start <= now_s <= end):
                messagebox.showinfo("Schedule",
                    f"Outside monitoring hours ({start}–{end}).\n"
                    "Disable schedule in Settings to monitor now.",
                    parent=self.master)
                return
        try:
            for folder in self._folders:
                handler = FIMHandler(
                    self._engine, self._scorer, self._event_log,
                    self._whitelist, folder, self._settings,
                    self._on_event)
                obs = Observer()
                obs.schedule(handler, folder, recursive=True)
                obs.start()
                self._observers.append(obs)
                log.info(f"Observer started: {folder}")

            self._running = True
            self._mon_btn.configure(
                text="■  STOP", fg_color=C["red"], hover_color="#CC2244")
            self._status.configure(
                text=f"⬤  Monitoring {len(self._folders)} folder(s)",
                text_color=C["green"])
        except Exception as e:
            log.error(f"Start monitor failed: {e}")
            messagebox.showerror("Monitor Error",
                                 f"Could not start monitoring:\n{e}",
                                 parent=self.master)

    def _stop_monitor(self):
        try:
            for obs in self._observers:
                obs.stop()
            for obs in self._observers:
                obs.join(timeout=3)
            self._observers.clear()
            log.info("All observers stopped")
        except Exception as e:
            log.warning(f"Stop monitor error: {e}")
        self._running = False
        self._mon_btn.configure(
            text="▶  START", fg_color=C["accent2"], hover_color="#6D28D9")
        self._status.configure(text="⬤  Monitoring stopped",
                                text_color=C["yellow"])

    def _on_heal_toggle(self):
        self._settings.set("self_heal", self._heal_var.get())

    # ── EVENT CALLBACK ────────────────────────────────────────────────────────
    def _on_event(self, rec: Dict, healed: bool, quar: bool, score: float):
        """Called from watchdog thread – dispatched to GUI thread."""
        self.after(0, lambda: self._add_row(rec, healed, quar, score))

    def _add_row(self, rec: Dict, healed: bool, quar: bool, score: float):
        try:
            self._ev_count += 1
            if healed: self._heal_count += 1
            if quar:   self._quar_count += 1

            evt = rec["event_type"]
            ec  = {"modified": C["yellow"], "deleted":  C["red"],
                   "created":  C["accent"], "restored": C["green"]}
            clr      = ec.get(evt, C["text"])
            ext      = Path(rec["file_path"]).suffix.lower()
            risk_lvl = HIGH_RISK_EXT.get(ext, 1)
            risk_clr = (C["red"]    if risk_lvl >= 5 else
                        C["orange"] if risk_lvl >= 4 else
                        C["yellow"] if risk_lvl >= 3 else C["subtext"])

            row = ctk.CTkFrame(
                self._feed,
                fg_color=C["panel"] if self._ev_count%2==0 else C["card"],
                corner_radius=4)
            row.pack(fill="x", padx=4, pady=1)
            row.bind("<Button-3>",
                     lambda e, fp=rec["file_path"]: self._ctx_trust(fp))

            for val, w, tc in [
                (rec["timestamp"],                           150, C["subtext"]),
                (evt.upper(),                                 82, clr),
                (os.path.basename(rec["file_path"])[:33],   270, C["text"]),
                (str(rec["threat_score"]),                    60, clr),
                (f"{ext or 'N/A'}  ×{risk_lvl}",             68, risk_clr),
                (rec.get("detail","")[:55],                    0, C["subtext"]),
            ]:
                ctk.CTkLabel(row, text=val, font=_mono_font(10),
                             text_color=tc, width=w if w else 0, anchor="w"
                             ).pack(side="left",
                                    padx=(12 if w==150 else 4, 4), pady=3)

            # Auto-scroll
            try:
                self._feed._parent_canvas.yview_moveto(1.0)
            except Exception: pass

            # Update counters
            self._ev_lbl.configure(text=str(self._ev_count))
            self._heal_lbl.configure(text=str(self._heal_count))
            self._quar_lbl.configure(text=str(self._quar_count))
            self._update_threat(score)

            # Alerts
            threshold = int(self._settings.get("alert_threshold", 75))
            if score >= threshold and score > self._last_alert + 8:
                self._last_alert = score
                level, _ = self._scorer.level
                if self._settings.get("sound_alerts", True):
                    threading.Thread(target=play_alert, daemon=True).start()
                if self._settings.get("toast_notifications", True):
                    threading.Thread(
                        target=send_toast,
                        args=(f"{APP_NAME} – {level} ALERT",
                              f"{evt.upper()}: "
                              f"{os.path.basename(rec['file_path'])}\n"
                              f"Score: {score}"),
                        daemon=True).start()
                self._tray.update_color(C["red"] if score>=75 else C["orange"])

            # Prune feed rows safely
            try:
                kids = list(self._feed.winfo_children())
                if len(kids) > self.MAX_ROWS:
                    kids[0].destroy()
            except Exception:
                pass

            # Update chart if visible
            if self._active_tab == "chart":
                self._chart_w.update_chart()
                self._update_hist()

        except Exception as e:
            log.error(f"_add_row error: {e}\n{traceback.format_exc()}")

    def _clear_feed(self):
        self._clear_frame(self._feed)
        self._ev_count = self._heal_count = self._quar_count = 0
        self._ev_lbl.configure(text="0")
        self._heal_lbl.configure(text="0")
        self._quar_lbl.configure(text="0")

    # ── THREAT DISPLAY ────────────────────────────────────────────────────────
    def _update_threat(self, score: float = None):
        try:
            if score is None: score = self._scorer.score
            level, clr = self._scorer.level
            self._score_lbl.configure(text=f"{score:.1f}", text_color=clr)
            self._level_lbl.configure(text=level, text_color=clr)
            self._gauge_bar.set(score / 100.0)
            self._gauge_bar.configure(progress_color=clr)
            self._gauge_lbl.configure(text=f"{score:.1f} / 100")
            self._gauge_lvl.configure(text=level, text_color=clr)
            self._tray.update_color(clr)
        except Exception: pass

    # ── PDF ───────────────────────────────────────────────────────────────────
    def _export_pdf(self):
        recs = self._event_log.records
        if not recs:
            messagebox.showinfo("No Data", "No events to export yet.",
                                parent=self.master)
            return
        self._safe_status("⬤  Generating PDF report…", C["yellow"])
        threading.Thread(target=self._pdf_bg, daemon=True).start()

    def _pdf_bg(self):
        try:
            path = self._reporter.build(self._event_log.records,
                                        self._scorer, self._folders)
            def _done():
                self._safe_status(f"✔  PDF: {Path(path).name}", C["green"])
                messagebox.showinfo("Report Exported",
                                    f"Saved to:\n{path}",
                                    parent=self.master)
            self.after(0, _done)
        except Exception as e:
            log.error(f"PDF export error: {e}")
            _e = str(e)
            self.after(0, lambda: messagebox.showerror(
                "PDF Error", f"Could not generate PDF:\n{_e}",
                parent=self.master))

    # ── EMAIL ─────────────────────────────────────────────────────────────────
    def _email_report(self):
        if not self._settings.get("email_alerts"):
            messagebox.showinfo("Email",
                                "Configure email credentials in Settings first.",
                                parent=self.master)
            return
        recs = self._event_log.records
        if not recs:
            messagebox.showinfo("No Data", "No events to email.",
                                parent=self.master)
            return
        self._safe_status("⬤  Sending email…", C["yellow"])
        threading.Thread(target=self._email_bg, daemon=True).start()

    def _email_bg(self):
        try:
            path = self._reporter.build(self._event_log.records,
                                        self._scorer, self._folders)
            ok, err = self._emailer.send(self._settings, path)
            _ok, _err = ok, err
            def _done():
                self._safe_status(
                    "✔  Email sent!" if _ok else f"✘  Email failed: {_err}",
                    C["green"] if _ok else C["red"])
                messagebox.showinfo("Email",
                                    "Report sent successfully!" if _ok
                                    else f"Failed:\n{_err}",
                                    parent=self.master)
            self.after(0, _done)
        except Exception as e:
            log.error(f"Email bg error: {e}")
            _e = str(e)
            self.after(0, lambda: self._safe_status(f"Email error: {_e}", C["red"]))

    # ── SCHEDULE WATCHER ──────────────────────────────────────────────────────
    def _start_schedule_watcher(self):
        def _watch():
            while True:
                try:
                    time.sleep(60)
                    if not self._settings.get("schedule_enabled"):
                        continue
                    now_s  = datetime.datetime.now().strftime("%H:%M")
                    start  = self._settings.get("schedule_start", "09:00")
                    end    = self._settings.get("schedule_end",   "18:00")
                    inside = start <= now_s <= end
                    if inside and not self._running and self._folders:
                        self.after(0, self._start_monitor)
                    elif not inside and self._running:
                        self.after(0, self._stop_monitor)
                except Exception as e:
                    log.warning(f"Schedule watcher: {e}")
        threading.Thread(target=_watch, daemon=True).start()

    # ── THEME ─────────────────────────────────────────────────────────────────
    def _toggle_theme(self):
        dark = self._theme_var.get()
        apply_theme(dark)
        self._settings.set("dark_theme", dark)
        try:
            ctk.set_appearance_mode("dark" if dark else "light")
        except Exception: pass
        messagebox.showinfo("Theme",
                            "Theme changed. Restart for full effect.",
                            parent=self.master)

    # ── TICK ──────────────────────────────────────────────────────────────────
    def _tick(self):
        try:
            self._clock_lbl.configure(
                text=datetime.datetime.now().strftime(
                    "%a %d %b %Y  %H:%M:%S"))
            self._update_threat()
        except Exception: pass
        self.after(1000, self._tick)

    # ── HELPERS ───────────────────────────────────────────────────────────────
    def _safe_status(self, text: str, color: str):
        try:
            self._status.configure(text=text, text_color=color)
        except Exception: pass

    @staticmethod
    def _clear_frame(frame):
        """Safely destroy all children of a CTkScrollableFrame."""
        try:
            children = list(frame.winfo_children())
            for w in children:
                try:
                    w.destroy()
                except Exception:
                    pass
        except Exception:
            pass

# ─────────────────────────────────────────────────────────────────────────────
#  APPLICATION ROOT
# ─────────────────────────────────────────────────────────────────────────────
class IntegraSafeApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        try:
            ctk.set_appearance_mode("dark")
            ctk.set_default_color_theme("blue")
        except Exception as e:
            log.warning(f"CTk theme init: {e}")

        self._settings = Settings()
        apply_theme(self._settings.get("dark_theme", True))

        self.title(f"{APP_NAME} v{APP_VERSION} – Self-Healing FIM System")
        self.geometry("1390x840")
        self.minsize(1100, 700)
        self.configure(fg_color=C["bg"])
        self.protocol("WM_DELETE_WINDOW", self._on_close)

        # OS-specific window tweaks
        if IS_WINDOWS:
            try:
                self.after(100, lambda: None)  # let window settle
            except Exception: pass

        self._auth       = AuthManager()
        self._login_frm: Optional[LoginFrame] = None
        self._dash:      Optional[Dashboard]  = None
        self._show_login()

    def _show_login(self):
        try:
            if self._dash:
                self._dash.destroy()
            self._login_frm = LoginFrame(self, self._auth, self._on_auth)
        except Exception as e:
            log.critical(f"Login frame error: {e}")
            messagebox.showerror("Startup Error",
                                 f"Could not build login screen:\n{e}")

    def _on_auth(self, username: str):
        try:
            if self._login_frm:
                self._login_frm.destroy()
            self._dash = Dashboard(self, username, self._settings)
        except Exception as e:
            log.critical(f"Dashboard error: {e}")
            messagebox.showerror("Dashboard Error",
                                 f"Could not load dashboard:\n{e}\n\n"
                                 f"See log: {LOG_PATH}")

    def _on_close(self):
        log.info("Application closing")
        try:
            if self._dash:
                if self._dash._running:
                    self._dash._stop_monitor()
                self._dash._tray.stop()
        except Exception as e:
            log.warning(f"Close cleanup: {e}")
        finally:
            try:
                self.destroy()
            except Exception: pass

# ─────────────────────────────────────────────────────────────────────────────
#  GRACEFUL SIGNAL HANDLING  (Ctrl+C in terminal)
# ─────────────────────────────────────────────────────────────────────────────
def _handle_signal(sig, frame):
    log.info(f"Signal {sig} received – shutting down")
    try:
        root = tk._default_root
        if root:
            root.after(0, root.destroy)
    except Exception:
        sys.exit(0)

signal.signal(signal.SIGINT,  _handle_signal)
signal.signal(signal.SIGTERM, _handle_signal)

# ─────────────────────────────────────────────────────────────────────────────
#  ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    log.info(f"{'='*60}")
    log.info(f"  {APP_NAME} v{APP_VERSION} starting")
    log.info(f"  OS:     {platform.system()} {platform.release()}")
    log.info(f"  Python: {PY_VERSION.major}.{PY_VERSION.minor}.{PY_VERSION.micro}")
    log.info(f"  Base:   {BASE_DIR}")
    log.info(f"{'='*60}")

    try:
        app = IntegraSafeApp()
        app.mainloop()
    except Exception as e:
        log.critical(f"Fatal error: {e}\n{traceback.format_exc()}")
        try:
            r = tk.Tk(); r.withdraw()
            messagebox.showerror(
                "Fatal Error",
                f"IntegraSafe encountered a fatal error:\n\n{e}\n\n"
                f"Log: {LOG_PATH}\nCrash: {CRASH_LOG}")
            r.destroy()
        except Exception: pass
        sys.exit(1)

from __future__ import annotations

import csv
import json
import queue
import re
import sys
import threading
import time
import tkinter as tk
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, font as tkfont, messagebox, ttk

# Enable crisp High-DPI rendering on Windows 10/11
if sys.platform == "win32":
    try:
        import ctypes

        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        try:
            ctypes.windll.user32.SetProcessDPIAware()
        except Exception:
            pass

from vpnmon.cisco import (
    DEFAULT_DISCONNECT_COMMAND,
    OLD_DEFAULT_DISCONNECT_COMMAND,
    VpnSession,
    clean_text,
    disconnect_command_templates,
    disconnect_webvpn_session,
    fetch_router_usernames_ssh,
    fetch_session_details_ssh,
    fetch_webvpn_sessions,
    ipv4_sort_key,
    parse_router_usernames,
    parse_webvpn_sessions,
)
from vpnmon.config import (
    HISTORY_LOG_FILE,
    ICON_FILE,
    IP_CACHE_FILE,
    SETTINGS_FILE,
    STATS_DB_FILE,
    decode_password,
    encode_password,
    update_settings,
)
from vpnmon.geo import IPINFO_URL, fetch_ipinfo, format_ip_summary, is_private_or_local_ip
from vpnmon.storage import ConnectionStatsStore

LIGHT_PALETTE = {
    "bg": "#f1f5f9",
    "surface": "#ffffff",
    "surface_alt": "#f8fafc",
    "border": "#e2e8f0",
    "sidebar_bg": "#0f172a",
    "sidebar_item_bg": "#0f172a",
    "sidebar_item_active": "#1e293b",
    "sidebar_text": "#94a3b8",
    "sidebar_text_active": "#ffffff",
    "sidebar_accent": "#3b82f6",
    "text": "#0f172a",
    "muted": "#64748b",
    "primary": "#2563eb",
    "primary_hover": "#1d4ed8",
    "danger": "#dc2626",
    "danger_hover": "#b91c1c",
    "good": "#16a34a",
    "warning": "#d97706",
    "info": "#0284c7",
    "tree_heading_bg": "#f1f5f9",
    "tree_heading_fg": "#334155",
    "tree_selected_bg": "#dbeafe",
    "tree_selected_fg": "#1e3a8a",
    "entry_bg": "#f8fafc",
    "btn_bg": "#f1f5f9",
    "btn_fg": "#1e293b",
    "btn_active_bg": "#e2e8f0",
    "inactive_row_bg": "#fef2f2",
    "inactive_row_fg": "#991b1b",
}

DARK_PALETTE = {
    "bg": "#0b1120",
    "surface": "#111827",
    "surface_alt": "#1e293b",
    "border": "#1f2937",
    "sidebar_bg": "#030712",
    "sidebar_item_bg": "#030712",
    "sidebar_item_active": "#111827",
    "sidebar_text": "#9ca3af",
    "sidebar_text_active": "#f9fafb",
    "sidebar_accent": "#3b82f6",
    "text": "#f3f4f6",
    "muted": "#9ca3af",
    "primary": "#3b82f6",
    "primary_hover": "#2563eb",
    "danger": "#ef4444",
    "danger_hover": "#dc2626",
    "good": "#22c55e",
    "warning": "#f59e0b",
    "info": "#38bdf8",
    "tree_heading_bg": "#1f2937",
    "tree_heading_fg": "#e5e7eb",
    "tree_selected_bg": "#1d4ed8",
    "tree_selected_fg": "#ffffff",
    "entry_bg": "#1f2937",
    "btn_bg": "#1f2937",
    "btn_fg": "#f3f4f6",
    "btn_active_bg": "#374151",
    "inactive_row_bg": "#2c1618",
    "inactive_row_fg": "#fca5a5",
}


class Win32TrayIcon:
    """Native Windows System Tray icon & Balloon notifications via ctypes."""

    NIM_ADD = 0x00000000
    NIM_MODIFY = 0x00000001
    NIM_DELETE = 0x00000002
    NIF_MESSAGE = 0x00000001
    NIF_ICON = 0x00000002
    NIF_TIP = 0x00000004
    NIF_INFO = 0x00000010
    NIIF_INFO = 0x00000001
    IMAGE_ICON = 1
    LR_LOADFROMFILE = 0x00000010
    LR_DEFAULTSIZE = 0x00000040

    def __init__(self, app: "App", icon_path: Path, tooltip: str = "Cisco AnyConnect Monitor"):
        self.app = app
        self.icon_path = icon_path
        self.tooltip = tooltip
        self.available = sys.platform == "win32"
        self._hwnd = None
        self._hicon = None
        self._added = False
        self._nid_type = None
        if self.available:
            self._init_win32()

    def _init_win32(self):
        try:
            import ctypes
            from ctypes import wintypes

            self.ctypes = ctypes
            self.user32 = ctypes.windll.user32
            self.shell32 = ctypes.windll.shell32

            class NOTIFYICONDATAW(ctypes.Structure):
                _fields_ = [
                    ("cbSize", wintypes.DWORD),
                    ("hWnd", wintypes.HWND),
                    ("uID", wintypes.UINT),
                    ("uFlags", wintypes.UINT),
                    ("uCallbackMessage", wintypes.UINT),
                    ("hIcon", wintypes.HICON),
                    ("szTip", wintypes.WCHAR * 128),
                    ("dwState", wintypes.DWORD),
                    ("dwStateMask", wintypes.DWORD),
                    ("szInfo", wintypes.WCHAR * 256),
                    ("uTimeoutOrVersion", wintypes.UINT),
                    ("szInfoTitle", wintypes.WCHAR * 64),
                    ("dwInfoFlags", wintypes.DWORD),
                ]

            self._nid_type = NOTIFYICONDATAW
            self.app.update_idletasks()
            frame_id = self.app.wm_frame()
            self._hwnd = int(frame_id, 16) if isinstance(frame_id, str) and frame_id.startswith("0x") else self.app.winfo_id()

            if self.icon_path.exists():
                self._hicon = self.user32.LoadImageW(
                    0,
                    str(self.icon_path),
                    self.IMAGE_ICON,
                    0,
                    0,
                    self.LR_LOADFROMFILE | self.LR_DEFAULTSIZE,
                )
            if not self._hicon:
                self._hicon = self.user32.LoadIconW(0, 32512)
        except Exception:
            self.available = False

    def show_icon(self):
        if not self.available or not self._nid_type or self._added:
            return
        try:
            nid = self._nid_type()
            nid.cbSize = self.ctypes.sizeof(self._nid_type)
            nid.hWnd = self._hwnd
            nid.uID = 1
            nid.uFlags = self.NIF_ICON | self.NIF_TIP
            nid.hIcon = self._hicon
            nid.szTip = self.tooltip[:127]
            self.shell32.Shell_NotifyIconW(self.NIM_ADD, self.ctypes.byref(nid))
            self._added = True
        except Exception:
            pass

    def notify(self, title: str, message: str):
        if not self.available or not self._nid_type:
            return
        try:
            if not self._added:
                self.show_icon()
            nid = self._nid_type()
            nid.cbSize = self.ctypes.sizeof(self._nid_type)
            nid.hWnd = self._hwnd
            nid.uID = 1
            nid.uFlags = self.NIF_ICON | self.NIF_TIP | self.NIF_INFO
            nid.hIcon = self._hicon
            nid.szTip = self.tooltip[:127]
            nid.szInfoTitle = title[:63]
            nid.szInfo = message[:255]
            nid.uTimeoutOrVersion = 4000
            nid.dwInfoFlags = self.NIIF_INFO
            self.shell32.Shell_NotifyIconW(self.NIM_MODIFY, self.ctypes.byref(nid))
        except Exception:
            pass

    def remove_icon(self):
        if not self.available or not self._nid_type or not self._added:
            return
        try:
            nid = self._nid_type()
            nid.cbSize = self.ctypes.sizeof(self._nid_type)
            nid.hWnd = self._hwnd
            nid.uID = 1
            self.shell32.Shell_NotifyIconW(self.NIM_DELETE, self.ctypes.byref(nid))
            self._added = False
        except Exception:
            pass


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Cisco AnyConnect Monitor")
        self._set_initial_window_geometry()
        if ICON_FILE.exists():
            try:
                self.iconbitmap(str(ICON_FILE))
            except tk.TclError:
                pass

        self.sessions: list[VpnSession] = []
        self.filtered: list[VpnSession] = []
        self.previous_session_map: dict[tuple[str, str, str], VpnSession] = {}
        self.first_refresh_done = False

        self.stats_store = ConnectionStatsStore(STATS_DB_FILE)

        self.columns = (
            "context",
            "login",
            "ip",
            "country",
            "org",
            "connections",
            "connects_90d",
            "created",
            "last_used",
        )
        self.column_titles = {
            "context": "Контекст",
            "login": "Пользователь",
            "ip": "IP клиента",
            "country": "Страна / Город",
            "org": "Провайдер",
            "connections": "Потоков",
            "connects_90d": "За 3 мес.",
            "created": "Вход",
            "last_used": "Активность",
        }
        self.column_weights = {
            "context": 10,
            "login": 14,
            "ip": 12,
            "country": 14,
            "org": 22,
            "connections": 7,
            "connects_90d": 7,
            "created": 7,
            "last_used": 7,
        }
        self.column_min_widths = {
            "context": 80,
            "login": 100,
            "ip": 105,
            "country": 110,
            "org": 140,
            "connections": 68,
            "connects_90d": 75,
            "created": 72,
            "last_used": 78,
        }

        self.sort_column: str = "login"
        self.sort_descending: bool = False

        self.auto_refresh_job: str | None = None
        self.loading = False
        self.password_visible = False

        self.settings = self.load_settings()
        self.dark_mode: bool = bool(self.settings.get("dark_mode", True))
        self.palette = dict(DARK_PALETTE if self.dark_mode else LIGHT_PALETTE)

        self.ip_cache: dict[str, dict] = self.load_ip_cache()
        self.ip_lookup_inflight: set[str] = set()
        self.ip_lookup_queue: queue.Queue = queue.Queue()

        self.themed_frames: list[tuple[tk.Widget, str, str | None]] = []
        self.themed_labels: list[tuple[tk.Label, str, str]] = []
        self.kpi_cards: list[dict] = []
        self.nav_buttons: dict[str, dict] = {}
        self.views: dict[str, tk.Frame] = {}
        self.current_view: str = "sessions"
        self.tray_window: tk.Toplevel | None = None
        self.audit_rows_cache: list[dict] = []

        self.configure(bg=self.palette["bg"])
        self.configure_style()
        self.build_ui()
        self.bind_shortcuts()

        self.tray = Win32TrayIcon(self, ICON_FILE)
        self.tray.show_icon()
        self.protocol("WM_DELETE_WINDOW", self.on_close_window)
        self.bind("<Unmap>", self.on_window_unmap)

        self.after(250, self.poll_ip_lookup_queue)
        self.apply_filter()
        self.refresh_audit_tab()
        self.refresh_log_tab()
        self.switch_view("sessions")

        # Auto-connect on startup if credentials are saved and option is enabled
        if (
            self.auto_connect_var.get()
            and self.host_var.get().strip()
            and self.username_var.get().strip()
            and self.password_var.get()
        ):
            self.after(450, lambda: self.refresh_now(automatic=True))
        elif self.auto_refresh_var.get():
            self.schedule_auto_refresh()

    def _set_initial_window_geometry(self):
        try:
            sw = self.winfo_screenwidth()
            sh = self.winfo_screenheight()
            w = max(1080, min(int(sw * 0.86), 1540))
            h = max(650, min(int(sh * 0.84), 920))
            x = max(0, (sw - w) // 2)
            y = max(0, (sh - h) // 2 - 20)
            self.geometry(f"{w}x{h}+{x}+{y}")
            self.minsize(960, 580)
        except Exception:
            self.geometry("1280x780")
            self.minsize(960, 580)

    # -------------------------------------------------------------------------
    # Persistence (with Password Saving)
    # -------------------------------------------------------------------------
    def load_settings(self) -> dict:
        try:
            return json.loads(SETTINGS_FILE.read_text(encoding="utf-8"))
        except Exception:
            return {}

    def save_settings(self):
        remember_pw = bool(self.remember_password_var.get())
        encoded_pw = encode_password(self.password_var.get()) if remember_pw else ""
        data = {
            "host": self.host_var.get().strip(),
            "port": self.safe_int(self.port_var.get(), 22),
            "username": self.username_var.get().strip(),
            "remember_password": remember_pw,
            "password_encoded": encoded_pw,
            "auto_connect_on_start": bool(self.auto_connect_var.get()),
            "auto_refresh_enabled": bool(self.auto_refresh_var.get()),
            "refresh_seconds": self.safe_int(self.interval_var.get(), 30),
            "disconnect_command": self.disconnect_command_var.get().strip() or DEFAULT_DISCONNECT_COMMAND,
            "dark_mode": bool(self.dark_mode),
            "minimize_to_tray": bool(self.minimize_to_tray_var.get()),
            "notifications_enabled": bool(self.notify_var.get()),
        }
        try:
            # Merge so keys owned by the web server (admin password, Telegram) survive.
            update_settings(data)
        except Exception:
            pass

    def load_ip_cache(self) -> dict[str, dict]:
        try:
            raw = json.loads(IP_CACHE_FILE.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                return raw
        except Exception:
            pass
        return {}

    def save_ip_cache(self):
        try:
            IP_CACHE_FILE.write_text(
                json.dumps(self.ip_cache, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
        except Exception:
            pass

    def log_event(self, event_type: str, message: str):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        line = f"[{timestamp}] [{event_type}] {message}\n"
        try:
            with open(HISTORY_LOG_FILE, "a", encoding="utf-8") as handle:
                handle.write(line)
        except Exception:
            pass
        if hasattr(self, "log_text_box"):
            self.refresh_log_tab()

    @staticmethod
    def safe_int(value: str, default: int) -> int:
        try:
            return int(str(value).strip())
        except ValueError:
            return default

    # -------------------------------------------------------------------------
    # Theme & Styles
    # -------------------------------------------------------------------------
    def configure_style(self):
        self.style = ttk.Style(self)
        try:
            self.style.theme_use("clam")
        except tk.TclError:
            pass

        default_font = tkfont.nametofont("TkDefaultFont")
        default_font.configure(family="Segoe UI", size=9)
        self.option_add("*Font", default_font)

        self.apply_theme_styles()

    def apply_theme_styles(self):
        p = self.palette
        self.configure(bg=p["bg"])
        self.style.configure("TFrame", background=p["bg"])
        self.style.configure("Surface.TFrame", background=p["surface"])
        self.style.configure("TLabel", background=p["bg"], foreground=p["text"])
        self.style.configure("Surface.TLabel", background=p["surface"], foreground=p["text"])
        self.style.configure("Muted.TLabel", background=p["bg"], foreground=p["muted"])
        self.style.configure("SurfaceMuted.TLabel", background=p["surface"], foreground=p["muted"])

        self.style.configure(
            "TEntry",
            fieldbackground=p["entry_bg"],
            foreground=p["text"],
            insertcolor=p["text"],
            bordercolor=p["border"],
            lightcolor=p["border"],
            darkcolor=p["border"],
            padding=(7, 5),
        )
        self.style.configure(
            "TButton",
            background=p["btn_bg"],
            foreground=p["btn_fg"],
            bordercolor=p["border"],
            lightcolor=p["border"],
            darkcolor=p["border"],
            padding=(11, 5),
            borderwidth=1,
            focusthickness=0,
        )
        self.style.map(
            "TButton",
            background=[("active", p["btn_active_bg"])],
            foreground=[("active", p["btn_fg"])],
        )
        self.style.configure(
            "Accent.TButton",
            background=p["primary"],
            foreground="#ffffff",
            padding=(14, 6),
            borderwidth=0,
            font=("Segoe UI", 9, "bold"),
        )
        self.style.map(
            "Accent.TButton",
            background=[("active", p["primary_hover"])],
            foreground=[("active", "#ffffff")],
        )
        self.style.configure(
            "Danger.TButton",
            background=p["danger"],
            foreground="#ffffff",
            padding=(12, 5),
            borderwidth=0,
            font=("Segoe UI", 9, "bold"),
        )
        self.style.map(
            "Danger.TButton",
            background=[("active", p["danger_hover"])],
            foreground=[("active", "#ffffff")],
        )
        self.style.configure(
            "TCheckbutton",
            background=p["surface"],
            foreground=p["text"],
            padding=(4, 3),
        )
        self.style.map(
            "TCheckbutton",
            background=[("active", p["surface"])],
            foreground=[("active", p["text"])],
        )
        self.style.configure(
            "TRadiobutton",
            background=p["surface"],
            foreground=p["text"],
            padding=(4, 3),
        )
        self.style.map(
            "TRadiobutton",
            background=[("active", p["surface"])],
            foreground=[("active", p["text"])],
        )
        self.style.configure(
            "TPanedwindow",
            background=p["bg"],
        )
        self.style.configure(
            "Treeview",
            background=p["surface"],
            fieldbackground=p["surface"],
            foreground=p["text"],
            rowheight=33,
            borderwidth=0,
        )
        self.style.configure(
            "Treeview.Heading",
            background=p["tree_heading_bg"],
            foreground=p["tree_heading_fg"],
            relief="flat",
            padding=(8, 8),
            font=("Segoe UI", 9, "bold"),
        )
        self.style.map(
            "Treeview.Heading",
            background=[("active", p["border"])],
        )
        self.style.map(
            "Treeview",
            background=[("selected", p["tree_selected_bg"])],
            foreground=[("selected", p["tree_selected_fg"])],
        )

    def toggle_dark_mode(self):
        self.dark_mode = not self.dark_mode
        self.palette = dict(DARK_PALETTE if self.dark_mode else LIGHT_PALETTE)
        self.apply_theme_styles()

        p = self.palette
        if hasattr(self, "theme_btn"):
            self.theme_btn.config(
                text="☀ Светлая тема" if self.dark_mode else "🌙 Тёмная тема"
            )

        for widget, bg_key, border_key in self.themed_frames:
            try:
                cfg = {"bg": p[bg_key]}
                if border_key:
                    cfg["highlightbackground"] = p[border_key]
                widget.configure(**cfg)
            except Exception:
                pass

        for lbl, bg_key, fg_key in self.themed_labels:
            try:
                lbl.configure(bg=p[bg_key], fg=p[fg_key])
            except Exception:
                pass

        for kpi in self.kpi_cards:
            try:
                kpi["card"].configure(bg=p["surface"], highlightbackground=p["border"])
                kpi["bar"].configure(bg=p[kpi["accent"]])
                kpi["body"].configure(bg=p["surface"])
                kpi["title"].configure(bg=p["surface"], fg=p["muted"])
                kpi["val"].configure(bg=p["surface"], fg=p["text"])
            except Exception:
                pass

        for tree_widget in (
            getattr(self, "tree", None),
            getattr(self, "audit_user_tree", None),
            getattr(self, "audit_hist_tree", None),
        ):
            if tree_widget is not None:
                tree_widget.tag_configure("odd", background=p["surface_alt"], foreground=p["text"])
                tree_widget.tag_configure("even", background=p["surface"], foreground=p["text"])
                tree_widget.tag_configure(
                    "inactive",
                    background=p["inactive_row_bg"],
                    foreground=p["inactive_row_fg"],
                )

        if hasattr(self, "log_text_box"):
            self.log_text_box.configure(
                bg=p["surface"], fg=p["text"], insertbackground=p["text"]
            )
            self.refresh_log_tab()

        self._update_sidebar_active_styles()
        self.save_settings()

    # -------------------------------------------------------------------------
    # Modern Sidebar + Dashboard Layout Construction
    # -------------------------------------------------------------------------
    def build_ui(self):
        p = self.palette

        # Restore saved settings including password
        self.host_var = tk.StringVar(value=self.settings.get("host", ""))
        self.port_var = tk.StringVar(value=str(self.settings.get("port", 22)))
        self.username_var = tk.StringVar(value=self.settings.get("username", ""))

        remember_pw_default = bool(self.settings.get("remember_password", True))
        saved_pw = ""
        if remember_pw_default:
            saved_pw = decode_password(str(self.settings.get("password_encoded", "")))
            if not saved_pw and self.settings.get("password"):
                saved_pw = str(self.settings.get("password", ""))
        self.password_var = tk.StringVar(value=saved_pw)
        self.remember_password_var = tk.BooleanVar(value=remember_pw_default)

        self.auto_connect_var = tk.BooleanVar(
            value=bool(self.settings.get("auto_connect_on_start", True))
        )
        self.auto_refresh_var = tk.BooleanVar(
            value=bool(self.settings.get("auto_refresh_enabled", False))
        )
        self.interval_var = tk.StringVar(value=str(self.settings.get("refresh_seconds", 30)))

        saved_disconnect_command = self.settings.get("disconnect_command", DEFAULT_DISCONNECT_COMMAND)
        if saved_disconnect_command == OLD_DEFAULT_DISCONNECT_COMMAND:
            saved_disconnect_command = DEFAULT_DISCONNECT_COMMAND
        self.disconnect_command_var = tk.StringVar(value=saved_disconnect_command)

        self.search_var = tk.StringVar(value="")
        self.search_var.trace_add("write", lambda *_: self.apply_filter())

        self.minimize_to_tray_var = tk.BooleanVar(
            value=bool(self.settings.get("minimize_to_tray", False))
        )
        self.notify_var = tk.BooleanVar(
            value=bool(self.settings.get("notifications_enabled", True))
        )

        # Root layout: Left Sidebar (215px) + Right Main Workspace
        root_container = tk.Frame(self, bg=p["bg"])
        root_container.pack(fill="both", expand=True)
        self.themed_frames.append((root_container, "bg", None))

        # ---------------------------------------------------------------------
        # 1. Left Navigation Sidebar
        # ---------------------------------------------------------------------
        sidebar = tk.Frame(root_container, bg=p["sidebar_bg"], width=215)
        sidebar.pack(side="left", fill="y")
        sidebar.pack_propagate(False)
        self.themed_frames.append((sidebar, "sidebar_bg", None))

        brand_box = tk.Frame(sidebar, bg=p["sidebar_bg"])
        brand_box.pack(fill="x", padx=16, pady=(18, 16))
        self.themed_frames.append((brand_box, "sidebar_bg", None))

        brand_title = tk.Label(
            brand_box,
            text="Cisco AnyConnect",
            bg=p["sidebar_bg"],
            fg="#ffffff",
            font=("Segoe UI", 13, "bold"),
            anchor="w",
        )
        brand_title.pack(fill="x")

        brand_sub = tk.Label(
            brand_box,
            text="VPN Monitor & User Audit",
            bg=p["sidebar_bg"],
            fg=p["sidebar_text"],
            font=("Segoe UI", 8),
            anchor="w",
        )
        brand_sub.pack(fill="x", pady=(2, 0))

        # Navigation items
        nav_frame = tk.Frame(sidebar, bg=p["sidebar_bg"])
        nav_frame.pack(fill="x", padx=8)
        self.themed_frames.append((nav_frame, "sidebar_bg", None))

        self._create_nav_item(nav_frame, "sessions", "Активные сессии", "0")
        self._create_nav_item(nav_frame, "audit", "Аудит (1–3 мес.)", "0")
        self._create_nav_item(nav_frame, "logs", "Журнал событий", "")
        self._create_nav_item(nav_frame, "settings", "Настройки", "")

        # Bottom status & utility controls inside sidebar
        sidebar_bottom = tk.Frame(sidebar, bg=p["sidebar_bg"])
        sidebar_bottom.pack(side="bottom", fill="x", padx=12, pady=14)
        self.themed_frames.append((sidebar_bottom, "sidebar_bg", None))

        self.status_label = tk.Label(
            sidebar_bottom,
            text="● Готов к работе",
            bg=p["sidebar_bg"],
            fg="#e2e8f0",
            font=("Segoe UI", 8, "bold"),
            anchor="w",
            justify="left",
            wraplength=185,
        )
        self.status_label.pack(fill="x", pady=(0, 10))

        self.theme_btn = tk.Button(
            sidebar_bottom,
            text="☀ Светлая тема" if self.dark_mode else "🌙 Тёмная тема",
            bg="#1e293b",
            fg="#f8fafc",
            activebackground="#334155",
            activeforeground="#ffffff",
            relief="flat",
            bd=0,
            padx=10,
            pady=6,
            font=("Segoe UI", 9),
            cursor="hand2",
            command=self.toggle_dark_mode,
        )
        self.theme_btn.pack(fill="x", pady=(0, 6))

        tray_btn = tk.Button(
            sidebar_bottom,
            text="Свернуть в трей",
            bg="#1e293b",
            fg="#cbd5e1",
            activebackground="#334155",
            activeforeground="#ffffff",
            relief="flat",
            bd=0,
            padx=10,
            pady=6,
            font=("Segoe UI", 9),
            cursor="hand2",
            command=self.minimize_to_tray_mode,
        )
        tray_btn.pack(fill="x")

        # ---------------------------------------------------------------------
        # 2. Right Main Workspace
        # ---------------------------------------------------------------------
        main_area = tk.Frame(root_container, bg=p["bg"])
        main_area.pack(side="left", fill="both", expand=True, padx=14, pady=12)
        self.themed_frames.append((main_area, "bg", None))

        # Top Connection Card (with Saved Password + Show/Hide + Auto-refresh)
        conn_card = tk.Frame(
            main_area,
            bg=p["surface"],
            highlightbackground=p["border"],
            highlightthickness=1,
        )
        conn_card.pack(fill="x", pady=(0, 10))
        self.themed_frames.append((conn_card, "surface", "border"))

        conn_row = ttk.Frame(conn_card, style="Surface.TFrame")
        conn_row.pack(fill="x", padx=12, pady=9)

        ttk.Label(conn_row, text="IP роутера:", style="SurfaceMuted.TLabel").pack(
            side="left", padx=(0, 4)
        )
        self.host_entry = ttk.Entry(conn_row, textvariable=self.host_var, width=15)
        self.host_entry.pack(side="left", padx=(0, 10))
        self.host_entry.bind("<Return>", lambda _: self.refresh_now())

        ttk.Label(conn_row, text="Порт:", style="SurfaceMuted.TLabel").pack(
            side="left", padx=(0, 4)
        )
        ttk.Entry(conn_row, textvariable=self.port_var, width=5).pack(
            side="left", padx=(0, 10)
        )

        ttk.Label(conn_row, text="Логин:", style="SurfaceMuted.TLabel").pack(
            side="left", padx=(0, 4)
        )
        ttk.Entry(conn_row, textvariable=self.username_var, width=13).pack(
            side="left", padx=(0, 10)
        )

        ttk.Label(conn_row, text="Пароль:", style="SurfaceMuted.TLabel").pack(
            side="left", padx=(0, 4)
        )
        self.password_entry = ttk.Entry(
            conn_row, textvariable=self.password_var, width=15, show="•"
        )
        self.password_entry.pack(side="left", padx=(0, 3))
        self.password_entry.bind("<Return>", lambda _: self.refresh_now())

        self.show_pw_btn = ttk.Button(
            conn_row,
            text="👁",
            width=3,
            command=self.toggle_password_visibility,
        )
        self.show_pw_btn.pack(side="left", padx=(0, 8))

        ttk.Checkbutton(
            conn_row,
            text="Запомнить",
            variable=self.remember_password_var,
            command=self.save_settings,
        ).pack(side="left", padx=(0, 10))

        ttk.Button(
            conn_row,
            text="⟳ Подключить / Обновить",
            style="Accent.TButton",
            command=self.refresh_now,
        ).pack(side="left", padx=(0, 10))

        ttk.Checkbutton(
            conn_row,
            text="Авто (с):",
            variable=self.auto_refresh_var,
            command=self.toggle_auto_refresh,
        ).pack(side="left", padx=(0, 3))
        ttk.Entry(conn_row, textvariable=self.interval_var, width=4).pack(
            side="left", padx=(0, 4)
        )

        # ---------------------------------------------------------------------
        # KPI Metric Strip (4 clickable modern cards)
        # ---------------------------------------------------------------------
        kpi_strip = tk.Frame(main_area, bg=p["bg"])
        kpi_strip.pack(fill="x", pady=(0, 10))
        self.themed_frames.append((kpi_strip, "bg", None))
        for i in range(4):
            kpi_strip.columnconfigure(i, weight=1, uniform="kpi")

        self.kpi_sessions_lbl = self._create_kpi_card(
            kpi_strip, 0, "АКТИВНЫЕ СЕССИИ", "0", "info", lambda: self.switch_view("sessions")
        )
        self.kpi_conns_lbl = self._create_kpi_card(
            kpi_strip, 1, "АКТИВНЫХ ПОТОКОВ", "0", "primary", lambda: self.switch_view("sessions")
        )
        self.kpi_active_users_lbl = self._create_kpi_card(
            kpi_strip,
            2,
            "РАБОТАЛИ ЗА МЕСЯЦ",
            "0",
            "good",
            lambda: self._open_audit_filtered("active"),
        )
        self.kpi_inactive_users_lbl = self._create_kpi_card(
            kpi_strip,
            3,
            "НЕАКТИВНЫ (НА УДАЛЕНИЕ)",
            "0",
            "danger",
            lambda: self._open_audit_filtered("inactive"),
        )

        # ---------------------------------------------------------------------
        # View Stack Container (Switches between Sessions, Audit, Logs, Settings)
        # ---------------------------------------------------------------------
        self.view_container = tk.Frame(
            main_area,
            bg=p["surface"],
            highlightbackground=p["border"],
            highlightthickness=1,
        )
        self.view_container.pack(fill="both", expand=True)
        self.themed_frames.append((self.view_container, "surface", "border"))

        for key in ("sessions", "audit", "logs", "settings"):
            frame = tk.Frame(self.view_container, bg=p["surface"])
            self.views[key] = frame
            self.themed_frames.append((frame, "surface", None))

        self._build_sessions_view(self.views["sessions"])
        self._build_audit_view(self.views["audit"])
        self._build_logs_view(self.views["logs"])
        self._build_settings_view(self.views["settings"])

    def _create_nav_item(self, parent: tk.Widget, key: str, title: str, badge_text: str):
        p = self.palette
        row = tk.Frame(parent, bg=p["sidebar_item_bg"], cursor="hand2")
        row.pack(fill="x", pady=2)

        indicator = tk.Frame(row, bg=p["sidebar_item_bg"], width=4, height=38)
        indicator.pack(side="left", fill="y")

        lbl = tk.Label(
            row,
            text=title,
            bg=p["sidebar_item_bg"],
            fg=p["sidebar_text"],
            font=("Segoe UI", 10),
            anchor="w",
            padx=12,
        )
        lbl.pack(side="left", fill="both", expand=True)

        badge = tk.Label(
            row,
            text=badge_text,
            bg=p["sidebar_item_bg"],
            fg=p["sidebar_text"],
            font=("Segoe UI", 8, "bold"),
            padx=8,
        )
        badge.pack(side="right")

        for w in (row, indicator, lbl, badge):
            w.bind("<Button-1>", lambda _e, k=key: self.switch_view(k))

        self.nav_buttons[key] = {
            "row": row,
            "indicator": indicator,
            "label": lbl,
            "badge": badge,
        }

    def switch_view(self, key: str):
        self.current_view = key
        for k, frame in self.views.items():
            frame.pack_forget()
        self.views[key].pack(fill="both", expand=True)
        self._update_sidebar_active_styles()
        if key == "audit":
            self.refresh_audit_tab()
        elif key == "logs":
            self.refresh_log_tab()

    def _update_sidebar_active_styles(self):
        p = self.palette
        for k, item in self.nav_buttons.items():
            is_act = k == self.current_view
            bg = p["sidebar_item_active"] if is_act else p["sidebar_item_bg"]
            fg = p["sidebar_text_active"] if is_act else p["sidebar_text"]
            ind_bg = p["sidebar_accent"] if is_act else p["sidebar_item_bg"]
            font_val = ("Segoe UI", 10, "bold") if is_act else ("Segoe UI", 10)
            item["row"].configure(bg=bg)
            item["indicator"].configure(bg=ind_bg)
            item["label"].configure(bg=bg, fg=fg, font=font_val)
            item["badge"].configure(bg=bg, fg=fg)

    def _create_kpi_card(
        self,
        parent: tk.Widget,
        col_idx: int,
        title: str,
        value: str,
        accent: str,
        on_click,
    ) -> tk.Label:
        p = self.palette
        pad_right = 0 if col_idx == 3 else 8
        card = tk.Frame(
            parent,
            bg=p["surface"],
            highlightbackground=p["border"],
            highlightthickness=1,
            height=58,
            cursor="hand2",
        )
        card.grid(row=0, column=col_idx, sticky="ew", padx=(0, pad_right))
        card.pack_propagate(False)

        bar = tk.Frame(card, bg=p[accent], width=4)
        bar.pack(side="left", fill="y")

        body = tk.Frame(card, bg=p["surface"])
        body.pack(side="left", fill="both", expand=True, padx=12, pady=6)

        title_lbl = tk.Label(
            body,
            text=title,
            bg=p["surface"],
            fg=p["muted"],
            font=("Segoe UI", 8, "bold"),
            anchor="w",
        )
        title_lbl.pack(fill="x")

        val_lbl = tk.Label(
            body,
            text=value,
            bg=p["surface"],
            fg=p["text"],
            font=("Segoe UI", 13, "bold"),
            anchor="w",
        )
        val_lbl.pack(fill="x", pady=(1, 0))

        for w in (card, bar, body, title_lbl, val_lbl):
            w.bind("<Button-1>", lambda _e: on_click())

        self.kpi_cards.append(
            {
                "card": card,
                "bar": bar,
                "body": body,
                "title": title_lbl,
                "val": val_lbl,
                "accent": accent,
            }
        )
        return val_lbl

    def _open_audit_filtered(self, mode: str):
        self.audit_mode_var.set(mode)
        self.switch_view("audit")

    def toggle_password_visibility(self):
        self.password_visible = not self.password_visible
        self.password_entry.configure(show="" if self.password_visible else "•")

    # -------------------------------------------------------------------------
    # View 1: Active Sessions
    # -------------------------------------------------------------------------
    def _build_sessions_view(self, parent: tk.Frame):
        p = self.palette
        toolbar = ttk.Frame(parent, style="Surface.TFrame")
        toolbar.pack(fill="x", padx=12, pady=(10, 8))

        ttk.Label(toolbar, text="🔍 Поиск:", style="SurfaceMuted.TLabel").pack(
            side="left", padx=(0, 6)
        )
        self.search_entry = ttk.Entry(toolbar, textvariable=self.search_var, width=30)
        self.search_entry.pack(side="left", padx=(0, 4))
        self.search_entry.bind("<Escape>", lambda _: self.clear_search())

        ttk.Button(
            toolbar,
            text="✕",
            width=3,
            command=self.clear_search,
        ).pack(side="left", padx=(0, 12))

        ttk.Button(
            toolbar,
            text="✕ Отключить сессию (Del)",
            style="Danger.TButton",
            command=self.disconnect_selected,
        ).pack(side="right")

        ttk.Button(
            toolbar,
            text="Экспорт CSV",
            command=self.export_csv,
        ).pack(side="right", padx=(0, 6))

        ttk.Button(
            toolbar,
            text="Из буфера",
            command=self.parse_clipboard,
        ).pack(side="right", padx=(0, 6))

        ttk.Button(
            toolbar,
            text="IP инфо",
            command=self.show_selected_ipinfo,
        ).pack(side="right", padx=(0, 6))

        ttk.Button(
            toolbar,
            text="Детали сессии",
            command=self.show_selected_session_details,
        ).pack(side="right", padx=(0, 6))

        table_frame = ttk.Frame(parent, style="Surface.TFrame")
        table_frame.pack(fill="both", expand=True, padx=12, pady=(0, 12))

        self.tree = ttk.Treeview(table_frame, columns=self.columns, show="headings")
        for column in self.columns:
            self.tree.heading(
                column,
                text=self.column_titles[column],
                command=lambda col=column: self.sort_by_column(col),
            )
            anchor = (
                "center"
                if column in ("connections", "connects_90d", "created", "last_used")
                else "w"
            )
            self.tree.column(
                column,
                width=self.column_min_widths[column],
                minwidth=self.column_min_widths[column],
                anchor=anchor,
                stretch=True,
            )
        self.update_heading_indicators()

        y_scroll = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        x_scroll = ttk.Scrollbar(table_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=y_scroll.set, xscrollcommand=x_scroll.set)

        table_frame.rowconfigure(0, weight=1)
        table_frame.columnconfigure(0, weight=1)
        self.tree.grid(row=0, column=0, sticky="nsew")
        y_scroll.grid(row=0, column=1, sticky="ns")
        x_scroll.grid(row=1, column=0, sticky="ew")

        self.tree.tag_configure("odd", background=p["surface_alt"], foreground=p["text"])
        self.tree.tag_configure("even", background=p["surface"], foreground=p["text"])
        self.tree.bind("<Double-1>", self.on_tree_double_click)
        self.tree.bind("<Button-3>", self.on_tree_right_click)
        self.tree.bind("<Configure>", self._on_sessions_tree_resize)

        self.row_menu = tk.Menu(self, tearoff=0)
        self.row_menu.add_command(
            label="Статистика пользователя за 1–3 мес.",
            command=self.show_selected_user_stats,
        )
        self.row_menu.add_command(
            label="Детали сессии Cisco (Ctrl+D)",
            command=self.show_selected_session_details,
        )
        self.row_menu.add_command(
            label="Информация по IP (ipinfo.io) (Ctrl+I)",
            command=self.show_selected_ipinfo,
        )
        self.row_menu.add_separator()
        self.row_menu.add_command(
            label="Копировать логин", command=lambda: self.copy_selected_field("login")
        )
        self.row_menu.add_command(
            label="Копировать IP", command=lambda: self.copy_selected_field("ip")
        )
        self.row_menu.add_separator()
        self.row_menu.add_command(
            label="Отключить сессию (Del)", command=self.disconnect_selected
        )

    def _on_sessions_tree_resize(self, event):
        total_w = event.width - 4
        if total_w < 600:
            return
        total_weight = sum(self.column_weights.values())
        for col in self.columns:
            w = max(
                self.column_min_widths[col],
                int(total_w * self.column_weights[col] / total_weight),
            )
            self.tree.column(col, width=w)

    # -------------------------------------------------------------------------
    # View 2: User Activity Audit & 30d/90d Stats
    # -------------------------------------------------------------------------
    def _build_audit_view(self, parent: tk.Frame):
        p = self.palette
        bar = ttk.Frame(parent, style="Surface.TFrame")
        bar.pack(fill="x", padx=12, pady=(10, 8))

        ttk.Label(bar, text="Период:", style="SurfaceMuted.TLabel").pack(
            side="left", padx=(0, 4)
        )
        self.audit_period_var = tk.StringVar(value="30")
        for label_text, val in (
            ("1 мес (30д)", "30"),
            ("3 мес (90д)", "90"),
            ("7 дней", "7"),
            ("Всё время", "0"),
        ):
            ttk.Radiobutton(
                bar,
                text=label_text,
                value=val,
                variable=self.audit_period_var,
                command=self.refresh_audit_tab,
            ).pack(side="left", padx=(0, 6))

        ttk.Label(bar, text=" |  Показать:", style="SurfaceMuted.TLabel").pack(
            side="left", padx=(4, 4)
        )
        self.audit_mode_var = tk.StringVar(value="all")
        for label_text, val in (
            ("Все", "all"),
            ("Активные", "active"),
            ("Неактивные (0 входов)", "inactive"),
        ):
            ttk.Radiobutton(
                bar,
                text=label_text,
                value=val,
                variable=self.audit_mode_var,
                command=self.refresh_audit_tab,
            ).pack(side="left", padx=(0, 6))

        ttk.Label(bar, text=" |  Поиск:", style="SurfaceMuted.TLabel").pack(
            side="left", padx=(4, 4)
        )
        self.audit_filter_var = tk.StringVar(value="")
        self.audit_filter_var.trace_add("write", lambda *_: self.refresh_audit_tab())
        ttk.Entry(bar, textvariable=self.audit_filter_var, width=16).pack(
            side="left", padx=(0, 4)
        )
        ttk.Button(
            bar, text="✕", width=3, command=lambda: self.audit_filter_var.set("")
        ).pack(side="left", padx=(0, 8))

        ttk.Button(
            bar,
            text="Команды удаления (CLI)",
            style="Danger.TButton",
            command=self.generate_inactive_cleanup_list,
        ).pack(side="right")

        ttk.Button(
            bar,
            text="Экспорт CSV",
            command=self.export_audit_csv,
        ).pack(side="right", padx=(0, 6))

        ttk.Button(
            bar,
            text="+ Список юзеров",
            command=self.open_import_users_dialog,
        ).pack(side="right", padx=(0, 6))

        ttk.Button(
            bar,
            text="⟳ Юзеры с Cisco",
            style="Accent.TButton",
            command=self.sync_users_from_router,
        ).pack(side="right", padx=(0, 6))

        paned = ttk.PanedWindow(parent, orient="vertical")
        paned.pack(fill="both", expand=True, padx=12, pady=(0, 12))

        upper_pane = ttk.Frame(paned, style="Surface.TFrame")
        lower_pane = ttk.Frame(paned, style="Surface.TFrame")
        paned.add(upper_pane, weight=3)
        paned.add(lower_pane, weight=2)

        self.audit_cols = (
            "status_label",
            "login",
            "connects_period",
            "connects_30d",
            "connects_90d",
            "active_days",
            "work_time",
            "unique_ips",
            "last_connected",
            "days_idle_str",
            "last_ip",
            "last_country",
        )
        self.audit_titles = {
            "status_label": "Статус",
            "login": "Пользователь",
            "connects_period": "Входов (период)",
            "connects_30d": "За 1 мес",
            "connects_90d": "За 3 мес",
            "active_days": "Дней работы",
            "work_time": "Время в сети",
            "unique_ips": "Уник. IP",
            "last_connected": "Последний раз в сети",
            "days_idle_str": "Простой",
            "last_ip": "Последний IP",
            "last_country": "Страна / Город",
        }
        self.audit_weights = {
            "status_label": 9,
            "login": 13,
            "connects_period": 9,
            "connects_30d": 7,
            "connects_90d": 7,
            "active_days": 8,
            "work_time": 8,
            "unique_ips": 6,
            "last_connected": 13,
            "days_idle_str": 7,
            "last_ip": 10,
            "last_country": 11,
        }
        self.audit_sort_state = {"col": "connects_period", "desc": True}

        self.audit_user_tree = ttk.Treeview(
            upper_pane, columns=self.audit_cols, show="headings"
        )
        for col in self.audit_cols:
            self.audit_user_tree.heading(
                col,
                text=self.audit_titles[col],
                command=lambda c=col: self.sort_audit_table(c),
            )
            anchor = (
                "w" if col in ("login", "last_country", "status_label") else "center"
            )
            self.audit_user_tree.column(
                col, width=90, minwidth=65, anchor=anchor, stretch=True
            )

        au_scroll = ttk.Scrollbar(
            upper_pane, orient="vertical", command=self.audit_user_tree.yview
        )
        self.audit_user_tree.configure(yscrollcommand=au_scroll.set)
        upper_pane.rowconfigure(0, weight=1)
        upper_pane.columnconfigure(0, weight=1)
        self.audit_user_tree.grid(row=0, column=0, sticky="nsew")
        au_scroll.grid(row=0, column=1, sticky="ns")

        self.audit_user_tree.tag_configure(
            "odd", background=p["surface_alt"], foreground=p["text"]
        )
        self.audit_user_tree.tag_configure(
            "even", background=p["surface"], foreground=p["text"]
        )
        self.audit_user_tree.tag_configure(
            "inactive",
            background=p["inactive_row_bg"],
            foreground=p["inactive_row_fg"],
        )
        self.audit_user_tree.bind("<<TreeviewSelect>>", self._on_audit_user_select)
        self.audit_user_tree.bind("<Configure>", self._on_audit_tree_resize)

        hist_header = ttk.Frame(lower_pane, style="Surface.TFrame")
        hist_header.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(8, 4))

        self.audit_detail_label = tk.Label(
            hist_header,
            text="История подключений пользователя (выберите строку выше)",
            bg=p["surface"],
            fg=p["text"],
            font=("Segoe UI", 9, "bold"),
        )
        self.audit_detail_label.pack(side="left")
        self.themed_labels.append((self.audit_detail_label, "surface", "text"))

        self.audit_summary_badge = tk.Label(
            hist_header,
            text="",
            bg=p["surface"],
            fg=p["muted"],
            font=("Segoe UI", 9),
        )
        self.audit_summary_badge.pack(side="right")
        self.themed_labels.append((self.audit_summary_badge, "surface", "muted"))

        self.hist_cols = (
            "first_seen_iso",
            "last_seen_iso",
            "duration_str",
            "context",
            "ip",
            "country",
            "org",
            "created_raw",
            "peak_connections",
        )
        hist_titles = {
            "first_seen_iso": "Время входа",
            "last_seen_iso": "Последняя активность",
            "duration_str": "Время работы",
            "context": "Контекст",
            "ip": "IP клиента",
            "country": "Страна / Город",
            "org": "Провайдер",
            "created_raw": "Создана (Cisco)",
            "peak_connections": "Потоков",
        }

        self.audit_hist_tree = ttk.Treeview(
            lower_pane, columns=self.hist_cols, show="headings", height=6
        )
        for col in self.hist_cols:
            self.audit_hist_tree.heading(col, text=hist_titles[col])
            anchor = (
                "center"
                if col in ("duration_str", "peak_connections", "created_raw")
                else "w"
            )
            self.audit_hist_tree.column(
                col, width=110, minwidth=70, anchor=anchor, stretch=True
            )

        ah_scroll = ttk.Scrollbar(
            lower_pane, orient="vertical", command=self.audit_hist_tree.yview
        )
        self.audit_hist_tree.configure(yscrollcommand=ah_scroll.set)
        lower_pane.rowconfigure(1, weight=1)
        lower_pane.columnconfigure(0, weight=1)
        self.audit_hist_tree.grid(row=1, column=0, sticky="nsew")
        ah_scroll.grid(row=1, column=1, sticky="ns")
        self.audit_hist_tree.tag_configure(
            "odd", background=p["surface_alt"], foreground=p["text"]
        )
        self.audit_hist_tree.tag_configure(
            "even", background=p["surface"], foreground=p["text"]
        )

    def _on_audit_tree_resize(self, event):
        total_w = event.width - 4
        if total_w < 600:
            return
        total_weight = sum(self.audit_weights.values())
        for col in self.audit_cols:
            w = max(65, int(total_w * self.audit_weights[col] / total_weight))
            self.audit_user_tree.column(col, width=w)

    # -------------------------------------------------------------------------
    # View 3: Event Log
    # -------------------------------------------------------------------------
    def _build_logs_view(self, parent: tk.Frame):
        p = self.palette
        bar = ttk.Frame(parent, style="Surface.TFrame")
        bar.pack(fill="x", padx=12, pady=(10, 8))

        ttk.Label(bar, text="🔍 Фильтр лога:", style="SurfaceMuted.TLabel").pack(
            side="left", padx=(0, 6)
        )
        self.log_filter_var = tk.StringVar(value="")
        self.log_filter_var.trace_add("write", lambda *_: self.refresh_log_tab())
        ttk.Entry(bar, textvariable=self.log_filter_var, width=30).pack(
            side="left", padx=(0, 6)
        )

        ttk.Button(
            bar, text="Очистить лог", style="Danger.TButton", command=self.clear_event_log
        ).pack(side="right")
        ttk.Button(bar, text="Копировать всё", command=self.copy_event_log).pack(
            side="right", padx=(0, 6)
        )
        ttk.Button(bar, text="⟳ Обновить", command=self.refresh_log_tab).pack(
            side="right", padx=(0, 6)
        )

        log_frame = ttk.Frame(parent, style="Surface.TFrame")
        log_frame.pack(fill="both", expand=True, padx=12, pady=(0, 12))

        self.log_text_box = tk.Text(
            log_frame,
            wrap="none",
            bg=p["surface"],
            fg=p["text"],
            insertbackground=p["text"],
            font=("Consolas", 9),
            relief="flat",
            borderwidth=0,
        )
        ly_scroll = ttk.Scrollbar(
            log_frame, orient="vertical", command=self.log_text_box.yview
        )
        lx_scroll = ttk.Scrollbar(
            log_frame, orient="horizontal", command=self.log_text_box.xview
        )
        self.log_text_box.configure(
            yscrollcommand=ly_scroll.set, xscrollcommand=lx_scroll.set
        )

        log_frame.rowconfigure(0, weight=1)
        log_frame.columnconfigure(0, weight=1)
        self.log_text_box.grid(row=0, column=0, sticky="nsew")
        ly_scroll.grid(row=0, column=1, sticky="ns")
        lx_scroll.grid(row=1, column=0, sticky="ew")

    # -------------------------------------------------------------------------
    # View 4: Embedded Settings View
    # -------------------------------------------------------------------------
    def _build_settings_view(self, parent: tk.Frame):
        body = ttk.Frame(parent, style="Surface.TFrame")
        body.pack(fill="both", expand=True, padx=24, pady=20)

        ttk.Label(
            body,
            text="Настройки подключения и автоматизации",
            style="Surface.TLabel",
            font=("Segoe UI", 12, "bold"),
        ).pack(anchor="w", pady=(0, 12))

        ttk.Checkbutton(
            body,
            text="Сохранять пароль роутера в настройках (зашифровано для текущего пользователя Windows)",
            variable=self.remember_password_var,
            command=self.save_settings,
        ).pack(anchor="w", pady=4)

        ttk.Checkbutton(
            body,
            text="Автоматически подключаться к роутеру при открытии программы",
            variable=self.auto_connect_var,
            command=self.save_settings,
        ).pack(anchor="w", pady=4)

        ttk.Checkbutton(
            body,
            text="Показывать всплывающие уведомления Windows при входе и выходе пользователей",
            variable=self.notify_var,
            command=self.save_settings,
        ).pack(anchor="w", pady=4)

        ttk.Checkbutton(
            body,
            text="Сворачивать программу в системный трей при закрытии окна",
            variable=self.minimize_to_tray_var,
            command=self.save_settings,
        ).pack(anchor="w", pady=4)

        ttk.Label(
            body,
            text="Шаблон команды отключения сессии (Cisco IOS CLI):",
            style="Surface.TLabel",
            font=("Segoe UI", 10, "bold"),
        ).pack(anchor="w", pady=(18, 4))

        cmd_entry = ttk.Entry(body, textvariable=self.disconnect_command_var, width=80)
        cmd_entry.pack(fill="x", pady=(0, 4))

        ttk.Label(
            body,
            text="Доступные переменные: {login}, {ip}, {context}, {connections}, {created}, {last_used}. Можно указать несколько команд через ';'.",
            style="SurfaceMuted.TLabel",
        ).pack(anchor="w", pady=(0, 14))

        btn_row = ttk.Frame(body, style="Surface.TFrame")
        btn_row.pack(anchor="w")

        ttk.Button(
            btn_row,
            text="Сохранить настройки",
            style="Accent.TButton",
            command=self._save_settings_with_feedback,
        ).pack(side="left", padx=(0, 8))

        ttk.Button(
            btn_row,
            text="Сбросить шаблон команды",
            command=lambda: self.disconnect_command_var.set(DEFAULT_DISCONNECT_COMMAND),
        ).pack(side="left", padx=(0, 8))

        ttk.Button(
            btn_row,
            text="Очистить записи старше 90 дней",
            command=self._purge_old_records,
        ).pack(side="left")

    def _save_settings_with_feedback(self):
        self.save_settings()
        self.status_label.config(text="● Настройки и пароль сохранены")

    def _purge_old_records(self):
        if messagebox.askyesno(
            "Очистка истории",
            "Удалить неактивные записи подключений старше 90 дней (3 месяцев)?",
        ):
            removed = self.stats_store.purge_older_than(days=90)
            self.refresh_audit_tab()
            messagebox.showinfo(
                "Очистка истории", f"Удалено старых записей: {removed}."
            )

    def refresh_log_tab(self):
        if not hasattr(self, "log_text_box"):
            return
        if HISTORY_LOG_FILE.exists():
            try:
                lines = HISTORY_LOG_FILE.read_text(
                    encoding="utf-8", errors="replace"
                ).splitlines()
            except Exception as exc:
                lines = [f"Ошибка чтения лога: {exc}"]
        else:
            lines = []

        needle = (
            self.log_filter_var.get().strip().lower()
            if hasattr(self, "log_filter_var")
            else ""
        )
        if needle:
            lines = [ln for ln in lines if needle in ln.lower()]

        self.log_text_box.configure(state="normal")
        self.log_text_box.delete("1.0", "end")
        if lines:
            self.log_text_box.insert("1.0", "\n".join(lines) + "\n")
            self.log_text_box.see("end")
        else:
            self.log_text_box.insert("1.0", "Журнал событий пуст.")
        self.log_text_box.configure(state="disabled")

    def copy_event_log(self):
        if not hasattr(self, "log_text_box"):
            return
        content = self.log_text_box.get("1.0", "end").strip()
        self.clipboard_clear()
        self.clipboard_append(content)
        self.status_label.config(text="● Журнал скопирован в буфер")

    def clear_event_log(self):
        if messagebox.askyesno(
            "Журнал событий", "Очистить файл журнала session_history.log?"
        ):
            try:
                HISTORY_LOG_FILE.write_text("", encoding="utf-8")
            except Exception:
                pass
            self.refresh_log_tab()

    # -------------------------------------------------------------------------
    # Keyboard Shortcuts & Context Menu
    # -------------------------------------------------------------------------
    def bind_shortcuts(self):
        self.bind("<F5>", lambda _: self.refresh_now())
        self.bind("<Control-r>", lambda _: self.refresh_now())
        self.bind("<Control-R>", lambda _: self.refresh_now())
        self.bind("<Control-f>", lambda _: self.focus_search())
        self.bind("<Control-F>", lambda _: self.focus_search())
        self.bind("<Control-u>", lambda _: self.show_selected_user_stats())
        self.bind("<Control-U>", lambda _: self.show_selected_user_stats())
        self.bind("<Control-d>", lambda _: self.show_selected_session_details())
        self.bind("<Control-D>", lambda _: self.show_selected_session_details())
        self.bind("<Control-i>", lambda _: self.show_selected_ipinfo())
        self.bind("<Control-I>", lambda _: self.show_selected_ipinfo())
        self.bind("<Control-l>", lambda _: self.switch_view("logs"))
        self.bind("<Control-L>", lambda _: self.switch_view("logs"))
        self.bind("<Control-e>", lambda _: self.export_csv())
        self.bind("<Control-E>", lambda _: self.export_csv())
        self.bind("<Control-t>", lambda _: self.toggle_dark_mode())
        self.bind("<Control-T>", lambda _: self.toggle_dark_mode())
        self.bind("<Delete>", self.on_delete_key)

    def focus_search(self):
        self.switch_view("sessions")
        self.search_entry.focus_set()
        self.search_entry.selection_range(0, "end")

    def clear_search(self):
        self.search_var.set("")

    def on_delete_key(self, event):
        focused = self.focus_get()
        if isinstance(focused, ttk.Entry):
            return
        self.disconnect_selected()

    def on_tree_right_click(self, event):
        row_id = self.tree.identify_row(event.y)
        if row_id:
            self.tree.selection_set(row_id)
            try:
                self.row_menu.tk_popup(event.x_root, event.y_root)
            finally:
                self.row_menu.grab_release()

    def copy_selected_field(self, attr: str):
        session = self.selected_session()
        if not session:
            return
        val = str(getattr(session, attr, ""))
        self.clipboard_clear()
        self.clipboard_append(val)
        self.status_label.config(text=f"● Скопировано: {val}")

    # -------------------------------------------------------------------------
    # System Tray & Background Notifications
    # -------------------------------------------------------------------------
    def on_window_unmap(self, event):
        if event.widget is self and self.state() == "iconic":
            if self.minimize_to_tray_var.get():
                self.after(50, self.minimize_to_tray_mode)

    def on_close_window(self):
        self.save_settings()
        if self.minimize_to_tray_var.get():
            self.minimize_to_tray_mode()
            return
        self.quit_application()

    def minimize_to_tray_mode(self):
        self.withdraw()
        if self.notify_var.get():
            self.tray.notify(
                "Cisco AnyConnect Monitor",
                "Мониторинг продолжает работать в фоновом режиме.",
            )
        self.show_tray_controller()

    def show_tray_controller(self):
        if self.tray_window and self.tray_window.winfo_exists():
            self.tray_window.lift()
            return
        p = self.palette
        win = tk.Toplevel(self)
        win.title("AnyConnect Трей")
        win.geometry("290x115+40+40")
        win.resizable(False, False)
        win.attributes("-topmost", True)
        win.configure(bg=p["surface"])
        if ICON_FILE.exists():
            try:
                win.iconbitmap(str(ICON_FILE))
            except tk.TclError:
                pass

        lbl = tk.Label(
            win,
            text="Cisco AnyConnect Monitor (Фон)",
            bg=p["surface"],
            fg=p["text"],
            font=("Segoe UI", 9, "bold"),
        )
        lbl.pack(anchor="w", padx=12, pady=(10, 2))

        self.tray_status_lbl = tk.Label(
            win,
            text=f"Активных сессий: {len(self.sessions)}",
            bg=p["surface"],
            fg=p["muted"],
            font=("Segoe UI", 8),
        )
        self.tray_status_lbl.pack(anchor="w", padx=12, pady=(0, 8))

        btn_bar = ttk.Frame(win, style="Surface.TFrame")
        btn_bar.pack(fill="x", padx=12, pady=(0, 10))
        ttk.Button(
            btn_bar,
            text="Развернуть",
            style="Accent.TButton",
            command=self.restore_from_tray,
        ).pack(side="left", padx=(0, 6))
        ttk.Button(btn_bar, text="Обновить", command=self.refresh_now).pack(
            side="left", padx=(0, 6)
        )
        ttk.Button(
            btn_bar, text="Выход", style="Danger.TButton", command=self.quit_application
        ).pack(side="left")
        win.protocol("WM_DELETE_WINDOW", self.restore_from_tray)
        self.tray_window = win

    def restore_from_tray(self):
        if self.tray_window and self.tray_window.winfo_exists():
            self.tray_window.destroy()
            self.tray_window = None
        self.deiconify()
        self.state("normal")
        self.lift()
        self.focus_force()

    def quit_application(self):
        self.save_settings()
        self.save_ip_cache()
        self.tray.remove_icon()
        self.destroy()

    # -------------------------------------------------------------------------
    # GeoIP / ISP Caching & Background Lookup
    # -------------------------------------------------------------------------
    def enrich_sessions_with_ip_cache(self, sessions: list[VpnSession]):
        missing_ips: list[str] = []
        for s in sessions:
            if is_private_or_local_ip(s.ip):
                s.country = "LAN / Локальная"
                s.org = "Локальная сеть"
                continue
            cached = self.ip_cache.get(s.ip)
            if cached:
                s.country, s.org = format_ip_summary(cached)
            else:
                s.country = "Загрузка..."
                s.org = "Загрузка..."
                if s.ip not in self.ip_lookup_inflight and s.ip not in missing_ips:
                    missing_ips.append(s.ip)

        for ip in missing_ips:
            self.ip_lookup_inflight.add(ip)
            threading.Thread(
                target=self._background_ip_worker, args=(ip,), daemon=True
            ).start()

    def _background_ip_worker(self, ip: str):
        try:
            data = fetch_ipinfo(ip, timeout=10)
            self.ip_lookup_queue.put(("ok", ip, data))
        except Exception as exc:
            self.ip_lookup_queue.put(("err", ip, str(exc)))

    def poll_ip_lookup_queue(self):
        updated = False
        try:
            while True:
                status, ip, payload = self.ip_lookup_queue.get_nowait()
                self.ip_lookup_inflight.discard(ip)
                if status == "ok" and isinstance(payload, dict):
                    self.ip_cache[ip] = payload
                    loc_str, org_str = format_ip_summary(payload)
                    self.stats_store.update_geo_for_ip(ip, loc_str, org_str)
                    for s in self.sessions:
                        if s.ip == ip:
                            s.country = loc_str
                            s.org = org_str
                    updated = True
                else:
                    for s in self.sessions:
                        if s.ip == ip and s.country == "Загрузка...":
                            s.country = "—"
                            s.org = "—"
                    updated = True
        except queue.Empty:
            pass

        if updated:
            self.save_ip_cache()
            self.apply_filter()
            self.refresh_audit_tab()

        self.after(300, self.poll_ip_lookup_queue)

    # -------------------------------------------------------------------------
    # Session Change Tracking & Notifications
    # -------------------------------------------------------------------------
    def process_session_changes(self, new_sessions: list[VpnSession]):
        self.stats_store.record_snapshot(new_sessions)
        counts_90d = self.stats_store.get_user_counts_map(days=90)
        for s in new_sessions:
            s.connects_90d = counts_90d.get(s.login, 1)

        new_map = {s.key(): s for s in new_sessions}
        if not self.first_refresh_done:
            self.previous_session_map = new_map
            self.first_refresh_done = True
            self.log_event(
                "SNAPSHOT",
                f"Начальный снимок: активных сессий — {len(new_sessions)}.",
            )
            self.refresh_audit_tab()
            return

        connected = [s for k, s in new_map.items() if k not in self.previous_session_map]
        disconnected = [
            s for k, s in self.previous_session_map.items() if k not in new_map
        ]
        self.previous_session_map = new_map

        for s in connected:
            loc_info = (
                f" ({s.country}, {s.org})"
                if s.country and s.country != "Загрузка..."
                else ""
            )
            self.log_event(
                "CONNECTED",
                f"Подключился '{s.login}' с IP {s.ip}{loc_info} "
                f"[context={s.context}, created={s.created}, 90d={s.connects_90d}]",
            )
        for s in disconnected:
            self.log_event(
                "DISCONNECTED",
                f"Отключился '{s.login}' ({s.ip}) [context={s.context}, last_used={s.last_used}]",
            )

        if self.notify_var.get() and (connected or disconnected):
            parts = []
            if connected:
                names = ", ".join(f"{s.login} ({s.ip})" for s in connected[:3])
                if len(connected) > 3:
                    names += f" +{len(connected) - 3}"
                parts.append(f"Вход: {names}")
            if disconnected:
                names = ", ".join(f"{s.login} ({s.ip})" for s in disconnected[:3])
                if len(disconnected) > 3:
                    names += f" +{len(disconnected) - 3}"
                parts.append(f"Выход: {names}")
            self.tray.notify("Cisco AnyConnect", " | ".join(parts))

        if (
            self.tray_window
            and self.tray_window.winfo_exists()
            and hasattr(self, "tray_status_lbl")
        ):
            self.tray_status_lbl.config(text=f"Активных сессий: {len(new_sessions)}")

        self.refresh_audit_tab()

    # -------------------------------------------------------------------------
    # Sorting & Filtering (Active Sessions)
    # -------------------------------------------------------------------------
    def sort_by_column(self, column: str):
        if self.sort_column == column:
            self.sort_descending = not self.sort_descending
        else:
            self.sort_column = column
            self.sort_descending = column in ("connections", "connects_90d")
        self.update_heading_indicators()
        self.apply_filter()

    def update_heading_indicators(self):
        if not hasattr(self, "tree"):
            return
        for col in self.columns:
            base = self.column_titles[col]
            if col == self.sort_column:
                arrow = " ▼" if self.sort_descending else " ▲"
                self.tree.heading(col, text=base + arrow)
            else:
                self.tree.heading(col, text=base)

    def sort_sessions_list(self, items: list[VpnSession]) -> list[VpnSession]:
        col = self.sort_column
        if col == "connections":
            key_fn = lambda s: (s.connections, s.login.lower())
        elif col == "connects_90d":
            key_fn = lambda s: (s.connects_90d, s.login.lower())
        elif col == "ip":
            key_fn = lambda s: (ipv4_sort_key(s.ip), s.login.lower())
        else:
            key_fn = lambda s: (str(getattr(s, col, "")).lower(), s.login.lower())
        return sorted(items, key=key_fn, reverse=self.sort_descending)

    def apply_filter(self, autosize: bool = False):
        selected_key = None
        current_sel = self.selected_session()
        if current_sel:
            selected_key = current_sel.key()

        needle = self.search_var.get().strip().lower()
        matched = []
        for session in self.sessions:
            row_text = " ".join(str(value) for value in asdict(session).values()).lower()
            if not needle or needle in row_text:
                matched.append(session)

        self.filtered = self.sort_sessions_list(matched)

        self.tree.delete(*self.tree.get_children())
        restore_item_id = None
        for index, session in enumerate(self.filtered):
            tags = ("odd",) if index % 2 else ("even",)
            item_id = self.tree.insert(
                "",
                "end",
                values=(
                    session.context,
                    session.login,
                    session.ip,
                    session.country or "—",
                    session.org or "—",
                    session.connections,
                    session.connects_90d,
                    session.created,
                    session.last_used,
                ),
                tags=tags,
            )
            if selected_key and session.key() == selected_key:
                restore_item_id = item_id

        if restore_item_id:
            self.tree.selection_set(restore_item_id)

        if "sessions" in self.nav_buttons:
            self.nav_buttons["sessions"]["badge"].config(text=str(len(self.filtered)))
        self._update_kpi_cards()

    def _update_kpi_cards(self):
        conns_sum = sum(s.connections for s in self.filtered)
        if hasattr(self, "kpi_sessions_lbl"):
            self.kpi_sessions_lbl.config(
                text=f"{len(self.filtered)}"
                if len(self.filtered) == len(self.sessions)
                else f"{len(self.filtered)} / {len(self.sessions)}"
            )
        if hasattr(self, "kpi_conns_lbl"):
            self.kpi_conns_lbl.config(text=str(conns_sum))

        rows_30d = self.stats_store.get_all_users_summary(days=30)
        act_30d = sum(1 for r in rows_30d if r["connects_period"] > 0)
        inact_30d = sum(1 for r in rows_30d if r["connects_period"] == 0)
        if hasattr(self, "kpi_active_users_lbl"):
            self.kpi_active_users_lbl.config(text=str(act_30d))
        if hasattr(self, "kpi_inactive_users_lbl"):
            self.kpi_inactive_users_lbl.config(text=str(inact_30d))
        if "audit" in self.nav_buttons:
            self.nav_buttons["audit"]["badge"].config(text=f"{act_30d}/{len(rows_30d)}")

    # -------------------------------------------------------------------------
    # Audit View Logic
    # -------------------------------------------------------------------------
    def sort_audit_table(self, col: str):
        if self.audit_sort_state["col"] == col:
            self.audit_sort_state["desc"] = not self.audit_sort_state["desc"]
        else:
            self.audit_sort_state["col"] = col
            self.audit_sort_state["desc"] = col not in ("login", "status_label")
        self.refresh_audit_tab()

    def refresh_audit_tab(self):
        if not hasattr(self, "audit_user_tree"):
            return
        days_val = int(self.audit_period_var.get())
        raw_rows = self.stats_store.get_all_users_summary(days=days_val)
        needle = self.audit_filter_var.get().strip().lower()
        mode = self.audit_mode_var.get()

        filtered_rows = []
        for r in raw_rows:
            if mode == "active" and r["connects_period"] == 0:
                continue
            if mode == "inactive" and r["connects_period"] > 0:
                continue
            if needle and not (
                needle in r["login"].lower()
                or needle in r["last_ip"].lower()
                or needle in r["last_country"].lower()
                or needle in r["last_org"].lower()
            ):
                continue
            filtered_rows.append(r)

        col = self.audit_sort_state["col"]
        sort_key_col = {
            "status_label": "status",
            "work_time": "work_seconds",
            "days_idle_str": "days_idle",
        }.get(col, col)

        filtered_rows.sort(
            key=lambda r: (
                r[sort_key_col].lower()
                if isinstance(r[sort_key_col], str)
                else r[sort_key_col],
                r["login"].lower(),
            ),
            reverse=self.audit_sort_state["desc"],
        )

        for c in self.audit_cols:
            base = self.audit_titles[c]
            if c == col:
                self.audit_user_tree.heading(
                    c, text=base + (" ▼" if self.audit_sort_state["desc"] else " ▲")
                )
            else:
                self.audit_user_tree.heading(c, text=base)

        self.audit_rows_cache = filtered_rows
        self.audit_user_tree.delete(*self.audit_user_tree.get_children())

        first_item = None
        for i, r in enumerate(filtered_rows):
            if r["connects_period"] == 0:
                tags = ("inactive",)
            else:
                tags = ("odd",) if i % 2 else ("even",)
            iid = self.audit_user_tree.insert(
                "",
                "end",
                values=(
                    r["status_label"],
                    r["login"],
                    r["connects_period"],
                    r["connects_30d"],
                    r["connects_90d"],
                    r["active_days"],
                    r["work_time"],
                    r["unique_ips"],
                    r["last_connected"],
                    r["days_idle_str"],
                    r["last_ip"],
                    r["last_country"],
                ),
                tags=tags,
            )
            if first_item is None:
                first_item = iid

        active_cnt = sum(1 for r in raw_rows if r["connects_period"] > 0)
        inactive_cnt = sum(1 for r in raw_rows if r["connects_period"] == 0)
        self.audit_summary_badge.config(
            text=f"Активных: {active_cnt}   •   Неактивных (на удаление): {inactive_cnt}   •   Всего: {len(raw_rows)}"
        )
        self._update_kpi_cards()

        if first_item:
            self.audit_user_tree.selection_set(first_item)
            self._on_audit_user_select()
        else:
            self._on_audit_user_select()

    def _on_audit_user_select(self, _event=None):
        sel = self.audit_user_tree.selection()
        self.audit_hist_tree.delete(*self.audit_hist_tree.get_children())
        if not sel:
            self.audit_detail_label.config(
                text="История подключений пользователя (выберите строку выше)"
            )
            return
        idx = self.audit_user_tree.index(sel[0])
        if not (0 <= idx < len(self.audit_rows_cache)):
            return
        user_row = self.audit_rows_cache[idx]
        login_name = user_row["login"]
        days_val = int(self.audit_period_var.get())
        sessions_hist = self.stats_store.get_user_sessions_history(
            login_name, days=days_val
        )
        monthly = self.stats_store.get_user_monthly_breakdown(login_name, days=days_val)
        monthly_str = (
            "   •   По месяцам: " + ", ".join(f"{ym}: {cnt}" for ym, cnt in monthly)
            if monthly
            else ""
        )
        self.audit_detail_label.config(
            text=(
                f"Пользователь '{login_name}' ({user_row['status_label']}) — "
                f"входов: {len(sessions_hist)}, время в сети: {user_row['work_time']}{monthly_str}"
            )
        )
        for i, h in enumerate(sessions_hist):
            tags = ("odd",) if i % 2 else ("even",)
            self.audit_hist_tree.insert(
                "",
                "end",
                values=(
                    h["first_seen_iso"],
                    h["last_seen_iso"],
                    h["duration_str"],
                    h["context"],
                    h["ip"],
                    h["country"] or "—",
                    h["org"] or "—",
                    h["created_raw"],
                    h["peak_connections"],
                ),
                tags=tags,
            )

    def sync_users_from_router(self):
        try:
            host, username, password, port = self.get_connection_values()
        except ValueError as exc:
            messagebox.showerror("Синхронизация пользователей", str(exc))
            return

        self.status_label.config(text=f"● Загрузка юзеров с {host}...")
        self.config(cursor="watch")
        q: queue.Queue = queue.Queue()

        def worker():
            try:
                q.put(
                    (
                        "done",
                        *fetch_router_usernames_ssh(host, username, password, port=port),
                    )
                )
            except Exception as exc:
                q.put(("error", exc))

        def poll():
            try:
                msg = q.get_nowait()
            except queue.Empty:
                self.after(100, poll)
                return
            self.config(cursor="")
            if msg[0] == "done":
                _, users, _ = msg
                if users:
                    added = self.stats_store.register_known_users(
                        users, source="cisco_router"
                    )
                    self.refresh_audit_tab()
                    self.status_label.config(
                        text=f"● Юзеров с роутера: {len(users)} (+{added})"
                    )
                    messagebox.showinfo(
                        "Синхронизация с Cisco",
                        f"Найдено учётных записей на роутере: {len(users)}\n"
                        f"Добавлено новых в базу аудита: {added}",
                    )
                else:
                    self.status_label.config(
                        text="● Локальные юзеры в конфиге не найдены"
                    )
                    messagebox.showinfo(
                        "Синхронизация с Cisco",
                        "Строки 'username <login> ...' не найдены в выводе роутера.\n"
                        "Используйте кнопку '+ Список юзеров' для ручной вставки списка.",
                    )
            else:
                self.status_label.config(text="● Ошибка синхронизации")
                messagebox.showerror("Синхронизация с Cisco", str(msg[1]))

        threading.Thread(target=worker, daemon=True).start()
        self.after(100, poll)

    def open_import_users_dialog(self):
        p = self.palette
        imp = tk.Toplevel(self)
        imp.title("Добавить список пользователей для аудита")
        imp.geometry("520x380")
        imp.transient(self)
        imp.configure(bg=p["surface"])

        body = ttk.Frame(imp, style="Surface.TFrame")
        body.pack(fill="both", expand=True, padx=14, pady=12)

        ttk.Label(
            body,
            text="Вставьте логины (по одному на строку, через пробел/запятую или строки 'username ...' из конфига Cisco):",
            style="Surface.TLabel",
        ).pack(anchor="w", pady=(0, 6))

        txt = tk.Text(
            body,
            wrap="word",
            height=13,
            bg=p["entry_bg"],
            fg=p["text"],
            insertbackground=p["text"],
            font=("Consolas", 9),
        )
        txt.pack(fill="both", expand=True, pady=(0, 10))

        def do_import():
            raw = txt.get("1.0", "end").strip()
            if not raw:
                imp.destroy()
                return
            parsed_cisco = parse_router_usernames(raw)
            if parsed_cisco:
                candidates = parsed_cisco
            else:
                candidates = [
                    tok.strip()
                    for tok in re.split(r"[,;\s]+", raw)
                    if tok.strip() and not tok.strip().startswith("#")
                ]
            added = self.stats_store.register_known_users(
                candidates, source="manual_import"
            )
            imp.destroy()
            self.refresh_audit_tab()
            self.status_label.config(
                text=f"● Импортировано юзеров: {len(candidates)} (+{added})"
            )

        b_row = ttk.Frame(body, style="Surface.TFrame")
        b_row.pack(fill="x")
        ttk.Button(
            b_row, text="Сохранить в базу", style="Accent.TButton", command=do_import
        ).pack(side="right", padx=(6, 0))
        ttk.Button(b_row, text="Отмена", command=imp.destroy).pack(side="right")

    def export_audit_csv(self):
        if not self.audit_rows_cache:
            messagebox.showinfo("Экспорт CSV", "Нет данных для экспорта.")
            return
        filename = filedialog.asksaveasfilename(
            defaultextension=".csv",
            initialfile=f"vpn_user_audit_{self.audit_period_var.get()}d.csv",
            filetypes=[("CSV", "*.csv")],
        )
        if not filename:
            return
        export_fields = [
            "status",
            "login",
            "connects_period",
            "connects_30d",
            "connects_90d",
            "active_days",
            "work_time",
            "unique_ips",
            "last_connected",
            "days_idle_str",
            "last_ip",
            "last_country",
            "last_org",
        ]
        with open(filename, "w", newline="", encoding="utf-8-sig") as handle:
            writer = csv.DictWriter(
                handle, fieldnames=export_fields, extrasaction="ignore"
            )
            writer.writeheader()
            for row in self.audit_rows_cache:
                writer.writerow(row)
        self.status_label.config(
            text=f"● Экспортировано в CSV ({len(self.audit_rows_cache)} строк)"
        )

    def generate_inactive_cleanup_list(self):
        days_val = int(self.audit_period_var.get())
        all_rows = self.stats_store.get_all_users_summary(days=days_val)
        inactive_users = [r for r in all_rows if r["connects_period"] == 0]
        if not inactive_users:
            messagebox.showinfo(
                "Неактивные пользователи",
                "Неактивных пользователей (0 подключений за выбранный период) не найдено.\n\n"
                "Нажмите '⟳ Юзеры с Cisco' или '+ Список юзеров', чтобы загрузить полный список аккаунтов.",
            )
            return

        period_label = f"{days_val} дн." if days_val > 0 else "всё время"
        lines = [
            f"=== НЕАКТИВНЫЕ ПОЛЬЗОВАТЕЛИ (0 входов за {period_label}) — Всего: {len(inactive_users)} ===",
            "",
            "--- 1. Список логинов ---",
        ]
        for r in inactive_users:
            lines.append(f"{r['login']}  (Последний вход: {r['last_connected']})")

        lines.extend(
            [
                "",
                "--- 2. Готовые команды удаления для Cisco IOS CLI (configure terminal) ---",
                "configure terminal",
            ]
        )
        for r in inactive_users:
            lines.append(f"no username {r['login']}")
        lines.append("end")
        lines.append("write memory")

        def remove_inactive_from_roster():
            if messagebox.askyesno(
                "Удалить из локального списка",
                f"Удалить эти {len(inactive_users)} неактивных логинов из локальной базы учёта?",
            ):
                self.stats_store.remove_known_users([r["login"] for r in inactive_users])
                self.refresh_audit_tab()

        self.show_text_dialog(
            f"Неактивные пользователи на удаление ({len(inactive_users)})",
            "\n".join(lines),
            extra_button=("Удалить из локального списка", remove_inactive_from_roster),
        )

    # -------------------------------------------------------------------------
    # Refresh & SSH Actions
    # -------------------------------------------------------------------------
    def refresh_now(self, automatic: bool = False):
        if self.loading:
            if automatic:
                self.status_label.config(text="● Автообновление пропущено: занято")
                self.schedule_auto_refresh()
            return

        host = self.host_var.get().strip()
        username = self.username_var.get().strip()
        password = self.password_var.get()
        port = self.safe_int(self.port_var.get(), 22)

        if not host or not username or not password:
            if automatic:
                self.status_label.config(
                    text="● Пауза: укажите IP, логин и пароль"
                )
                self.schedule_auto_refresh()
                return
            messagebox.showerror(
                "Cisco AnyConnect Monitor",
                "Укажите IP роутера, логин и пароль.",
            )
            return

        self.save_settings()
        self.loading = True
        self.status_label.config(text=f"● Подключение к {host}:{port}...")
        self.config(cursor="watch")
        q: queue.Queue = queue.Queue()

        def worker():
            try:
                q.put(
                    (
                        "done",
                        *fetch_webvpn_sessions(
                            host, username, password, port=port, timeout=25
                        ),
                    )
                )
            except Exception as exc:
                q.put(("error", exc))

        def poll():
            try:
                message = q.get_nowait()
            except queue.Empty:
                self.after(100, poll)
                return

            self.loading = False
            self.config(cursor="")
            if message[0] == "done":
                _, sessions, raw_output = message
                self.enrich_sessions_with_ip_cache(sessions)
                self.process_session_changes(sessions)
                self.sessions = sessions
                self.apply_filter()
                if not sessions and raw_output.strip():
                    self.status_label.config(
                        text=f"● Нет активных сессий ({time.strftime('%H:%M:%S')})"
                    )
                else:
                    self.status_label.config(
                        text=f"● Обновлено в {time.strftime('%H:%M:%S')}"
                    )
            else:
                err_text = str(message[1])
                self.status_label.config(text="● Ошибка подключения")
                self.log_event("ERROR", f"Ошибка обновления {host}:{port} — {err_text}")
                if automatic:
                    self.status_label.config(text="● Ошибка автообновления")
                else:
                    messagebox.showerror("Cisco AnyConnect Monitor", err_text)
            self.schedule_auto_refresh()

        threading.Thread(target=worker, daemon=True).start()
        self.after(100, poll)

    def get_connection_values(self) -> tuple[str, str, str, int]:
        host = self.host_var.get().strip()
        username = self.username_var.get().strip()
        password = self.password_var.get()
        port = self.safe_int(self.port_var.get(), 22)
        if not host or not username or not password:
            raise ValueError("Укажите IP роутера, логин и пароль.")
        return host, username, password, port

    def selected_session(self) -> VpnSession | None:
        selected = self.tree.selection()
        if not selected:
            return None
        index = self.tree.index(selected[0])
        if 0 <= index < len(self.filtered):
            return self.filtered[index]
        return None

    def session_for_item(self, item_id: str) -> VpnSession | None:
        if not item_id:
            return None
        index = self.tree.index(item_id)
        if 0 <= index < len(self.filtered):
            return self.filtered[index]
        return None

    def on_tree_double_click(self, event):
        if self.tree.identify_region(event.x, event.y) != "cell":
            return
        column_id = self.tree.identify_column(event.x)
        try:
            column = self.columns[int(column_id.lstrip("#")) - 1]
        except (ValueError, IndexError):
            return
        session = self.session_for_item(self.tree.identify_row(event.y))
        if not session:
            return
        if column in ("ip", "country", "org"):
            self.show_ipinfo(session.ip)
        elif column == "connects_90d":
            self.show_user_stats_dialog(initial_login=session.login)
        else:
            self.show_session_details(session)

    def show_selected_user_stats(self):
        session = self.selected_session()
        login = session.login if session else None
        self.show_user_stats_dialog(initial_login=login)

    def show_user_stats_dialog(self, initial_login: str | None = None):
        self.switch_view("audit")
        if initial_login is not None:
            self.audit_filter_var.set(initial_login)
        else:
            self.refresh_audit_tab()

    # -------------------------------------------------------------------------
    # IP Info Dialog
    # -------------------------------------------------------------------------
    def show_selected_ipinfo(self):
        session = self.selected_session()
        if not session:
            messagebox.showinfo("IP инфо", "Сначала выберите сессию в таблице.")
            return
        self.show_ipinfo(session.ip)

    def show_ipinfo(self, ip: str, force_refresh: bool = False):
        if not force_refresh and ip in self.ip_cache:
            data = self.ip_cache[ip]
            text = (
                f"Источник: {IPINFO_URL.format(ip=ip)} (из кэша)\n\n"
                f"{json.dumps(data, indent=2, ensure_ascii=False)}"
            )
            self.show_text_dialog(
                f"IP инфо: {ip}",
                text,
                extra_button=(
                    "Обновить с ipinfo.io",
                    lambda: self.show_ipinfo(ip, force_refresh=True),
                ),
            )
            return

        self.status_label.config(text=f"● Запрос {ip} в ipinfo.io...")
        q: queue.Queue = queue.Queue()

        def worker():
            try:
                q.put(("done", fetch_ipinfo(ip)))
            except Exception as exc:
                q.put(("error", exc))

        def poll():
            try:
                message = q.get_nowait()
            except queue.Empty:
                self.after(100, poll)
                return

            if message[0] == "done":
                data = message[1]
                self.ip_cache[ip] = data
                self.save_ip_cache()
                loc_str, org_str = format_ip_summary(data)
                self.stats_store.update_geo_for_ip(ip, loc_str, org_str)
                for s in self.sessions:
                    if s.ip == ip:
                        s.country = loc_str
                        s.org = org_str
                self.apply_filter()
                self.status_label.config(text=f"● Получены данные IP для {ip}")
                text = (
                    f"Источник: {IPINFO_URL.format(ip=ip)}\n\n"
                    f"{json.dumps(data, indent=2, ensure_ascii=False)}"
                )
                self.show_text_dialog(f"IP инфо: {ip}", text)
            else:
                self.status_label.config(text=f"● Ошибка запроса IP для {ip}")
                messagebox.showerror("IP инфо", str(message[1]))

        threading.Thread(target=worker, daemon=True).start()
        self.after(100, poll)

    # -------------------------------------------------------------------------
    # Detailed Session View by User
    # -------------------------------------------------------------------------
    def show_selected_session_details(self):
        session = self.selected_session()
        if not session:
            messagebox.showinfo("Детали сессии", "Сначала выберите сессию в таблице.")
            return
        self.show_session_details(session)

    def show_session_details(self, session: VpnSession):
        cached_ip = self.ip_cache.get(session.ip, {})
        user_hist_90d = self.stats_store.get_user_sessions_history(
            session.login, days=90
        )
        monthly_90d = self.stats_store.get_user_monthly_breakdown(
            session.login, days=90
        )
        monthly_text = (
            ", ".join(f"{ym}: {cnt}" for ym, cnt in monthly_90d)
            if monthly_90d
            else "—"
        )

        summary_lines = [
            "=== Сводка по сессии ===",
            f"Пользователь:        {session.login}",
            f"Контекст:            {session.context}",
            f"IP клиента:          {session.ip}",
            f"Страна / Город:      {session.country or '—'}",
            f"Провайдер:           {session.org or '—'}",
            f"Активных потоков:    {session.connections}",
            f"Входов за 90 дней:   {len(user_hist_90d)} (По месяцам: {monthly_text})",
            f"Время входа:         {session.created}",
            f"Последняя активн.:   {session.last_used}",
        ]
        if user_hist_90d:
            summary_lines.append("")
            summary_lines.append(
                "=== Последние подключения пользователя (до 10 записей) ==="
            )
            for h in user_hist_90d[:10]:
                summary_lines.append(
                    f"  • {h['first_seen_iso']} (длительность {h['duration_str']}) — IP: {h['ip']} "
                    f"[{h['country'] or '—'} / {h['org'] or '—'}], Cisco Created: {h['created_raw']}"
                )
        if cached_ip:
            summary_lines.append("")
            summary_lines.append("=== Данные GeoIP / Провайдера (ipinfo.io) ===")
            summary_lines.append(json.dumps(cached_ip, indent=2, ensure_ascii=False))

        host = self.host_var.get().strip()
        username = self.username_var.get().strip()
        password = self.password_var.get()
        port = self.safe_int(self.port_var.get(), 22)

        if not host or not username or not password:
            self.show_text_dialog(
                f"Детали сессии: {session.login} ({session.ip})",
                "\n".join(summary_lines),
                extra_button=(
                    "Перейти в Аудит пользователя",
                    lambda: self.show_user_stats_dialog(initial_login=session.login),
                ),
            )
            return

        self.status_label.config(text=f"● Запрос деталей {session.login}...")
        self.config(cursor="watch")
        q: queue.Queue = queue.Queue()

        def worker():
            try:
                cmd, out = fetch_session_details_ssh(
                    host, username, password, session, port=port, timeout=20
                )
                q.put(("done", cmd, out))
            except Exception as exc:
                q.put(("error", exc))

        def poll():
            try:
                message = q.get_nowait()
            except queue.Empty:
                self.after(100, poll)
                return

            self.config(cursor="")
            if message[0] == "done":
                _, cmd, raw_out = message
                self.status_label.config(
                    text=f"● Детали загружены для {session.login}"
                )
                full_text = (
                    "\n".join(summary_lines)
                    + f"\n\n=== Вывод Cisco CLI ({cmd}) ===\n"
                    + raw_out.strip()
                )
                self.show_text_dialog(
                    f"Детали сессии: {session.login} ({session.ip})",
                    full_text,
                    extra_button=(
                        "Перейти в Аудит пользователя",
                        lambda: self.show_user_stats_dialog(initial_login=session.login),
                    ),
                )
            else:
                self.status_label.config(
                    text=f"● Ошибка деталей для {session.login}"
                )
                full_text = (
                    "\n".join(summary_lines)
                    + f"\n\n=== Ошибка Cisco CLI ===\n{message[1]}"
                )
                self.show_text_dialog(
                    f"Детали сессии: {session.login} ({session.ip})",
                    full_text,
                    extra_button=(
                        "Перейти в Аудит пользователя",
                        lambda: self.show_user_stats_dialog(initial_login=session.login),
                    ),
                )

        threading.Thread(target=worker, daemon=True).start()
        self.after(100, poll)

    # -------------------------------------------------------------------------
    # Disconnect Session
    # -------------------------------------------------------------------------
    def disconnect_selected(self):
        if self.loading:
            return
        session = self.selected_session()
        if not session:
            messagebox.showinfo(
                "Отключение сессии", "Сначала выберите VPN-сессию в таблице."
            )
            return

        command_template = (
            self.disconnect_command_var.get().strip() or DEFAULT_DISCONNECT_COMMAND
        )
        command_templates = disconnect_command_templates(command_template)
        try:
            command = command_templates[0].format(**asdict(session)).strip()
        except (KeyError, ValueError) as exc:
            messagebox.showerror(
                "Отключение сессии", f"Некорректный шаблон команды:\n{exc}"
            )
            return

        if not messagebox.askyesno(
            "Отключение сессии",
            f"Отключить VPN-сессию пользователя?\n\n"
            f"Пользователь: {session.login}\n"
            f"IP: {session.ip}\n"
            f"Контекст: {session.context}\n\n"
            f"Команда:\n{command}",
        ):
            return

        try:
            host, username, password, port = self.get_connection_values()
        except ValueError as exc:
            messagebox.showerror("Отключение сессии", str(exc))
            return

        self.save_settings()
        self.loading = True
        self.status_label.config(text=f"● Отключение {session.login}...")
        self.config(cursor="watch")
        q: queue.Queue = queue.Queue()

        def worker():
            try:
                q.put(
                    (
                        "done",
                        *disconnect_webvpn_session(
                            host,
                            username,
                            password,
                            session,
                            command_template,
                            port=port,
                            timeout=25,
                        ),
                    )
                )
            except Exception as exc:
                q.put(("error", exc))

        def poll():
            try:
                message = q.get_nowait()
            except queue.Empty:
                self.after(100, poll)
                return

            self.loading = False
            self.config(cursor="")
            if message[0] == "done":
                _, sent_command, raw_output = message
                self.status_label.config(text=f"● Сессия {session.login} отключена")
                self.log_event(
                    "KICKED",
                    f"Отключён администратором '{session.login}' ({session.ip}, context={session.context}) командой '{sent_command}'",
                )
                messagebox.showinfo(
                    "Отключение сессии",
                    f"Выполнена команда:\n{sent_command}\n\nОтвет:\n{clean_text(raw_output)[-900:]}",
                )
                self.refresh_now()
            else:
                self.status_label.config(
                    text=f"● Не удалось отключить {session.login}"
                )
                self.log_event(
                    "ERROR",
                    f"Ошибка отключения '{session.login}' ({session.ip}): {message[1]}",
                )
                self.show_text_dialog("Ошибка отключения", str(message[1]))

        threading.Thread(target=worker, daemon=True).start()
        self.after(100, poll)

    # -------------------------------------------------------------------------
    # Dialogs, Clipboard, Auto-Refresh, CSV Export
    # -------------------------------------------------------------------------
    def show_text_dialog(
        self,
        title: str,
        text: str,
        extra_button: tuple[str, callable] | None = None,
    ):
        p = self.palette
        dialog = tk.Toplevel(self)
        dialog.title(title)
        dialog.geometry("780x520")
        dialog.transient(self)
        dialog.configure(bg=p["bg"])

        frame = ttk.Frame(dialog)
        frame.pack(fill="both", expand=True, padx=10, pady=10)

        text_box = tk.Text(
            frame,
            wrap="word",
            height=20,
            bg=p["surface"],
            fg=p["text"],
            insertbackground=p["text"],
            font=("Consolas", 9),
        )
        text_box.insert("1.0", text)
        text_box.configure(state="disabled")

        y_scroll = ttk.Scrollbar(frame, orient="vertical", command=text_box.yview)
        text_box.configure(yscrollcommand=y_scroll.set)

        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)
        text_box.grid(row=0, column=0, sticky="nsew")
        y_scroll.grid(row=0, column=1, sticky="ns")

        btn_row = ttk.Frame(dialog)
        btn_row.pack(pady=(0, 10))

        def copy_all():
            self.clipboard_clear()
            self.clipboard_append(text)
            self.status_label.config(text="● Текст скопирован в буфер")

        ttk.Button(
            btn_row, text="Копировать в буфер", style="Accent.TButton", command=copy_all
        ).pack(side="left", padx=5)
        if extra_button:
            btn_label, btn_cmd = extra_button

            def run_extra():
                dialog.destroy()
                btn_cmd()

            ttk.Button(btn_row, text=btn_label, command=run_extra).pack(
                side="left", padx=5
            )
        ttk.Button(btn_row, text="Закрыть", command=dialog.destroy).pack(
            side="left", padx=5
        )

    def parse_clipboard(self):
        try:
            text = self.clipboard_get()
        except tk.TclError:
            messagebox.showerror("Cisco AnyConnect Monitor", "Буфер обмена пуст.")
            return

        parsed = parse_webvpn_sessions(text)
        self.enrich_sessions_with_ip_cache(parsed)
        self.process_session_changes(parsed)
        self.sessions = parsed
        self.apply_filter()
        self.status_label.config(
            text=f"● Из буфера ({time.strftime('%H:%M:%S')})"
        )
        if not self.sessions:
            messagebox.showinfo(
                "Cisco AnyConnect Monitor",
                "В тексте буфера обмена не найдено строк сессий WebVPN.",
            )

    def toggle_auto_refresh(self):
        self.save_settings()
        if self.auto_refresh_var.get():
            self.schedule_auto_refresh()
        elif self.auto_refresh_job:
            self.after_cancel(self.auto_refresh_job)
            self.auto_refresh_job = None

    def schedule_auto_refresh(self):
        if self.auto_refresh_job:
            self.after_cancel(self.auto_refresh_job)
            self.auto_refresh_job = None
        if not self.auto_refresh_var.get():
            return
        if self.loading:
            self.auto_refresh_job = self.after(
                1000, lambda: self.refresh_now(automatic=True)
            )
            return
        interval = max(5, self.safe_int(self.interval_var.get(), 30))
        self.auto_refresh_job = self.after(
            interval * 1000, lambda: self.refresh_now(automatic=True)
        )

    def export_csv(self):
        if not self.filtered:
            messagebox.showinfo("Экспорт CSV", "Нет строк для экспорта.")
            return
        filename = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV", "*.csv")],
        )
        if not filename:
            return
        with open(filename, "w", newline="", encoding="utf-8-sig") as handle:
            writer = csv.DictWriter(
                handle, fieldnames=list(asdict(self.filtered[0]).keys())
            )
            writer.writeheader()
            for session in self.filtered:
                writer.writerow(asdict(session))
        self.status_label.config(text="● Таблица выгружена в CSV")


def main():
    if len(sys.argv) > 1:
        text = Path(sys.argv[1]).read_text(encoding="utf-8", errors="ignore")
        for session in parse_webvpn_sessions(text):
            print(asdict(session))
        return
    App().mainloop()


if __name__ == "__main__":
    main()
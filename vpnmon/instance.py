from __future__ import annotations

import hashlib
import logging
import socket
import sys
from http.server import ThreadingHTTPServer

from .config import DATA_DIR

ERROR_ALREADY_EXISTS = 183
ERROR_ACCESS_DENIED = 5

_mutex_handle = None


def acquire_single_instance(name: str = "CiscoAnyConnectMonitorServer") -> bool:
    """Return False if a server for this data folder is already running.

    A named mutex is released by Windows when the process dies, so a crash never
    leaves a stale lock behind. The folder hash lets a test copy elsewhere run alongside.
    "Global\\" makes the lock visible across sessions: the scheduled task runs in session 0,
    an admin who starts Start-Server.bat over RDP is in another one.
    """
    global _mutex_handle
    if sys.platform != "win32":
        return True
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateMutexW.restype = wintypes.HANDLE
    kernel32.CreateMutexW.argtypes = [wintypes.LPVOID, wintypes.BOOL, wintypes.LPCWSTR]
    tag = hashlib.sha1(str(DATA_DIR).lower().encode("utf-8")).hexdigest()[:12]
    for scope in ("Global", "Local"):
        handle = kernel32.CreateMutexW(None, False, f"{scope}\\{name}-{tag}")
        error = ctypes.get_last_error()
        if handle:
            if error == ERROR_ALREADY_EXISTS:
                kernel32.CloseHandle(handle)
                return False
            _mutex_handle = handle
            return True
        if error == ERROR_ACCESS_DENIED:
            # The mutex exists but belongs to another account (e.g. the SYSTEM task): it is running.
            return False
    return True  # can't tell; better to start than to refuse


def is_interactive_session() -> bool:
    """False in session 0, where services and "run whether logged on" tasks live with no desktop."""
    if sys.platform != "win32":
        return sys.stdin is not None and sys.stdin.isatty()
    try:
        import ctypes
        from ctypes import wintypes

        session = wintypes.DWORD()
        if ctypes.windll.kernel32.ProcessIdToSessionId(ctypes.windll.kernel32.GetCurrentProcessId(),
                                                       ctypes.byref(session)):
            return session.value != 0
    except Exception:
        pass
    return True


def release_single_instance():
    """Let a restarted copy take over before this process has fully exited."""
    global _mutex_handle
    if _mutex_handle and sys.platform == "win32":
        import ctypes

        ctypes.WinDLL("kernel32").CloseHandle(_mutex_handle)
    _mutex_handle = None


class ExclusiveHTTPServer(ThreadingHTTPServer):
    # On Windows SO_REUSEADDR lets a second process bind the same port and silently share it.
    allow_reuse_address = False
    daemon_threads = True

    def server_bind(self):
        if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        super().server_bind()

    def enable_tls(self, context):
        # The handshake runs on the first read in the request thread, so a client that connects
        # and stays silent can't block accept() for everyone.
        self.socket = context.wrap_socket(self.socket, server_side=True, do_handshake_on_connect=False)

    def handle_error(self, request, client_address):
        # Plain HTTP sent to the HTTPS port, dropped connections: not worth a traceback.
        exc = sys.exc_info()[1]
        logging.getLogger("vpnmon.server").debug("Соединение %s: %s", client_address, exc)


def tell_user(title: str, text: str, error: bool = False):
    """Report the result of a command-line action: console if there is one, otherwise a dialog."""
    stream = sys.stderr if error else sys.stdout
    if stream is not None:
        try:
            print(f"{title}\n{text}", file=stream, flush=True)
            return
        except (OSError, ValueError):
            pass
    if sys.platform == "win32" and is_interactive_session():
        try:
            import ctypes

            ctypes.windll.user32.MessageBoxW(None, text, title, 0x10 if error else 0x40)
        except Exception:
            pass


def show_error_box(title: str, text: str):
    """The server runs without a console (pythonw / windowed EXE), so startup errors need a dialog.

    Never in session 0: nobody can see the dialog there and it would block the process forever.
    """
    if sys.platform != "win32" or not is_interactive_session():
        return
    try:
        import ctypes

        ctypes.windll.user32.MessageBoxW(None, text, title, 0x10)  # MB_ICONERROR
    except Exception:
        pass

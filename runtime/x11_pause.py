"""Pause only a launcher's own, focused PCSX2 X11 game window.

The private launcher must configure Hotkeys/TogglePause to Keyboard/Pause (or
explicitly selected F13) before boot and
force Qt's xcb platform. Native Wayland is unsupported. This is not an OS
permission bypass: the supplied display must already permit X11/XTest access.
X11 properties are assertions by clients, not a security boundary against a
malicious X client. No process discovery, focus stealing, or environment lookup
is performed. PINE calls must themselves have finite transport timeouts.
"""

import ctypes as C
import math
import re
import threading
import time
from contextlib import contextmanager

from .pine import Status

SOTC_UUID = "C19A374E"
_X_LOCK = threading.RLock()  # Xlib's error handler is process-global.


class PauseError(RuntimeError):
    pass


class ResumeError(PauseError):
    """The controller cannot confirm that its pause was safely undone."""


class X11Backend:
    """ctypes adapter; construction loads only existing system libraries."""

    def __init__(self):
        try:
            self.x = C.CDLL("libX11.so.6")
            self.xt = C.CDLL("libXtst.so.6")
        except OSError as exc:
            raise PauseError("X11/XTest libraries unavailable") from exc
        ptr, ulong, integer = C.c_void_p, C.c_ulong, C.c_int
        signatures = {
            "XOpenDisplay": (ptr, [C.c_char_p]),
            "XCloseDisplay": (integer, [ptr]),
            "XGetInputFocus": (integer, [ptr, C.POINTER(ulong), C.POINTER(integer)]),
            "XQueryTree": (
                integer,
                [
                    ptr,
                    ulong,
                    C.POINTER(ulong),
                    C.POINTER(ulong),
                    C.POINTER(C.POINTER(ulong)),
                    C.POINTER(C.c_uint),
                ],
            ),
            "XInternAtom": (ulong, [ptr, C.c_char_p, integer]),
            "XGetWindowProperty": (
                integer,
                [
                    ptr,
                    ulong,
                    ulong,
                    C.c_long,
                    C.c_long,
                    integer,
                    ulong,
                    C.POINTER(ulong),
                    C.POINTER(integer),
                    C.POINTER(ulong),
                    C.POINTER(ulong),
                    C.POINTER(C.POINTER(C.c_ubyte)),
                ],
            ),
            "XFree": (integer, [ptr]),
            "XStringToKeysym": (ulong, [C.c_char_p]),
            "XKeysymToKeycode": (C.c_ubyte, [ptr, ulong]),
            "XSync": (integer, [ptr, integer]),
            "XGrabServer": (integer, [ptr]),
            "XUngrabServer": (integer, [ptr]),
            "XSetErrorHandler": (ptr, [ptr]),
        }
        for name, (result, args) in signatures.items():
            fn = getattr(self.x, name)
            fn.restype, fn.argtypes = result, args
        self.xt.XTestQueryExtension.argtypes = [ptr] + [C.POINTER(integer)] * 4
        self.xt.XTestQueryExtension.restype = integer
        self.xt.XTestFakeKeyEvent.argtypes = [ptr, C.c_uint, integer, ulong]
        self.xt.XTestFakeKeyEvent.restype = integer

    def open(self, display):
        self.display = self.x.XOpenDisplay(display.encode())
        if not self.display:
            raise PauseError("cannot open explicit X11 display")
        self.errors = []
        self.handler = C.CFUNCTYPE(C.c_int, C.c_void_p, C.c_void_p)(
            lambda *_: self.errors.append(True) or 0
        )
        self.old_handler = self.x.XSetErrorHandler(C.cast(self.handler, C.c_void_p))
        values = [C.c_int() for _ in range(4)]
        if not self.xt.XTestQueryExtension(self.display, *(C.byref(v) for v in values)):
            raise PauseError("XTest extension unavailable")

    def close(self):
        if getattr(self, "display", None):
            try:
                self.x.XCloseDisplay(self.display)
            finally:
                if hasattr(self, "old_handler"):
                    self.x.XSetErrorHandler(self.old_handler)
                self.display = None

    def sync(self):
        self.x.XSync(self.display, 0)
        if self.errors:
            raise PauseError("X11 request failed")

    def grab(self):
        self.x.XGrabServer(self.display)

    def ungrab(self):
        self.x.XUngrabServer(self.display)

    def focus(self):
        window, revert = C.c_ulong(), C.c_int()
        if not self.x.XGetInputFocus(self.display, C.byref(window), C.byref(revert)):
            raise PauseError("cannot read X11 focus")
        return window.value

    def parent(self, window):
        root, parent, count = C.c_ulong(), C.c_ulong(), C.c_uint()
        children = C.POINTER(C.c_ulong)()
        try:
            if not self.x.XQueryTree(
                self.display,
                window,
                C.byref(root),
                C.byref(parent),
                C.byref(children),
                C.byref(count),
            ):
                raise PauseError("cannot read focus ancestry")
            return parent.value
        finally:
            if children:
                self.x.XFree(children)

    def atom(self, name):
        atom = self.x.XInternAtom(self.display, name.encode(), 0)
        if not atom:
            raise PauseError("cannot resolve X11 atom")
        return atom

    def property(self, window, name, expected_type, expected_format):
        actual, fmt, count, remaining = C.c_ulong(), C.c_int(), C.c_ulong(), C.c_ulong()
        data = C.POINTER(C.c_ubyte)()
        try:
            result = self.x.XGetWindowProperty(
                self.display,
                window,
                self.atom(name),
                0,
                4096,
                0,
                0,
                C.byref(actual),
                C.byref(fmt),
                C.byref(count),
                C.byref(remaining),
                C.byref(data),
            )
            if result != 0 or remaining.value:
                raise PauseError("invalid/oversized X11 property")
            if not actual.value:
                return None
            if actual.value != self.atom(expected_type) or fmt.value != expected_format:
                raise PauseError("unexpected X11 property type")
            if expected_format == 32:
                return list(C.cast(data, C.POINTER(C.c_ulong))[: count.value])
            return C.string_at(data, count.value)
        finally:
            if data:
                self.x.XFree(data)

    def metadata(self, window):
        pid = self.property(window, "_NET_WM_PID", "CARDINAL", 32)
        title = self.property(window, "_NET_WM_NAME", "UTF8_STRING", 8)
        if title is None:
            title = self.property(window, "WM_NAME", "STRING", 8)
        cls = self.property(window, "WM_CLASS", "STRING", 8) or b""
        types = self.property(window, "_NET_WM_WINDOW_TYPE", "ATOM", 32) or []
        transient = self.property(window, "WM_TRANSIENT_FOR", "WINDOW", 32)
        return (
            pid[0] if pid and len(pid) == 1 else None,
            (title or b"").decode("utf-8", "replace"),
            cls.decode("utf-8", "replace"),
            bool(transient) or self.atom("_NET_WM_WINDOW_TYPE_DIALOG") in types,
        )

    def keycode(self, name):
        symbol = self.x.XStringToKeysym(name.encode())
        return self.x.XKeysymToKeycode(self.display, symbol) if symbol else 0

    def key(self, keycode, pressed):
        return bool(self.xt.XTestFakeKeyEvent(self.display, keycode, pressed, 0))


class X11PauseController:
    """The supplied PID must be the owned process's X11-client namespace PID.

    For a sandboxed emulator, a launcher must verify its host process identity
    and translate via that process's NSpid metadata before constructing this
    controller. A bare small PID is not proof of ownership.
    """

    def __init__(
        self,
        display,
        owned_pid,
        *,
        title_match="Shadow of the Colossus",
        pause_keysym="Pause",
        backend=None,
        timeout=2.0,
        poll_interval=0.01,
        clock=time.monotonic,
        sleep=time.sleep,
    ):
        if not isinstance(display, str) or not display.strip() or "\0" in display:
            raise ValueError("explicit DISPLAY required")
        if type(owned_pid) is not int or owned_pid <= 0:
            raise ValueError("explicit owned PCSX2 PID required")
        if not isinstance(title_match, str) or not title_match.strip():
            raise ValueError("nonempty game title match required")
        if pause_keysym not in ("Pause", "F13"):
            raise ValueError("private launcher must configure Pause or F13")
        if not all(math.isfinite(v) and v > 0 for v in (timeout, poll_interval)):
            raise ValueError("finite positive timing required")
        self.display, self.owned_pid = display, owned_pid
        self.title_match, self.pause_keysym = title_match.casefold(), pause_keysym
        self.backend = backend
        self.timeout, self.poll_interval = timeout, poll_interval
        self.clock, self.sleep = clock, sleep

    def _verify_window(self, backend):
        window, seen, matched = backend.focus(), set(), False
        for _ in range(64):
            if window in (0, 1):  # None / PointerRoot are not owned windows.
                break
            if window in seen:
                raise PauseError("cyclic focus ancestry")
            seen.add(window)
            pid, title, cls, dialog = backend.metadata(window)
            if dialog or re.search(r"error|dialog", title + " " + cls, re.IGNORECASE):
                raise PauseError("focused error/dialog window rejected")
            if pid is not None and pid != self.owned_pid:
                raise PauseError("foreign focused window rejected")
            if pid == self.owned_pid and self.title_match in title.casefold():
                matched = True
                break
            window = backend.parent(window)
        if not matched:
            raise PauseError("focused window is not the owned game window")

    def toggle(self):
        """Check focus under a short server grab, then send paired pause-key events."""
        with _X_LOCK:
            backend = self.backend if self.backend is not None else X11Backend()
            grabbed = False
            try:
                backend.open(self.display)
                backend.grab()
                grabbed = True
                self._verify_window(backend)
                code = backend.keycode(self.pause_keysym)
                if not code:
                    raise PauseError(f"{self.pause_keysym} has no X11 keycode")
                backend.sync()  # Fail before input on asynchronous property errors.
                try:
                    if not backend.key(code, True):
                        raise PauseError("XTest key press failed")
                finally:
                    if not backend.key(code, False):
                        raise PauseError("XTest key release failed")
                backend.sync()
            finally:
                try:
                    if grabbed:
                        backend.ungrab()
                        backend.sync()
                finally:
                    backend.close()

    @staticmethod
    def _identity(client):
        if client.uuid().upper() != SOTC_UUID:
            raise PauseError("PINE game UUID is not C19A374E")

    def _wait(self, client, expected):
        deadline = self.clock() + self.timeout
        # Iteration cap also bounds a faulty/injected clock that stops advancing.
        for _ in range(math.ceil(self.timeout / self.poll_interval) + 1):
            self._identity(client)
            status = client.status()
            now = self.clock()
            if now > deadline:
                break
            if status == expected:
                return
            if status not in (Status.RUNNING, Status.PAUSED):
                raise PauseError("emulator stopped during pause transition")
            remaining = deadline - now
            if remaining <= 0:
                break
            self.sleep(min(self.poll_interval, remaining))
        raise PauseError(f"timed out waiting for {expected.name}")

    @contextmanager
    def pause(self, client):
        """Preserve an existing pause; never blindly toggle after failed entry.

        A failed pause acknowledgement leaves state unknown and sends no further
        input. On exit, resume failure is raised (chaining any body exception).
        Do not run overlapping contexts or change the emulator outside this
        controller while a context is active.
        """
        self._identity(client)
        status = client.status()
        if status not in (Status.RUNNING, Status.PAUSED):
            raise PauseError("emulator is not running or paused")
        paused_here = status == Status.RUNNING
        if paused_here:
            self.toggle()
            self._wait(client, Status.PAUSED)
        try:
            yield client
        finally:
            if paused_here:
                try:
                    self._identity(client)
                    status = client.status()
                    if status == Status.PAUSED:
                        self.toggle()
                        self._wait(client, Status.RUNNING)
                    elif status != Status.RUNNING:
                        raise PauseError("emulator stopped before resume")
                except Exception as exc:
                    raise ResumeError(
                        "could not safely confirm emulator resume"
                    ) from exc

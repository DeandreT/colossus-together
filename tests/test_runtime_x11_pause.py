"""Offline only: no X libraries, desktop, emulator, or sockets are opened."""

import pytest

from runtime.pine import Status
from runtime.x11_pause import PauseError, ResumeError, X11PauseController


class FakeBackend:
    def __init__(self):
        self.windows = {10: (123, "Shadow of the Colossus | PCSX2", "PCSX2", False)}
        self.parents = {}
        self.focused = 10
        self.events = []
        self.closed = 0
        self.opens = []
        self.grabbed = False
        self.available = True
        self.code = 191
        self.press_ok = self.release_ok = True

    def open(self, display):
        self.opens.append(display)
        if not self.available:
            raise PauseError("no XTest")

    def close(self):
        self.closed += 1

    def grab(self):
        self.grabbed = True

    def ungrab(self):
        self.grabbed = False

    def sync(self):
        pass

    def focus(self):
        return self.focused

    def parent(self, window):
        return self.parents.get(window, 0)

    def metadata(self, window):
        return self.windows[window]

    def keycode(self, name):
        assert name in ("Pause", "F13")
        return self.code

    def key(self, code, pressed):
        assert self.grabbed
        self.events.append((code, pressed))
        return self.press_ok if pressed else self.release_ok


class FakeClient:
    def __init__(self, statuses):
        self.statuses = iter(statuses)
        self.identity = "c19a374e"

    def uuid(self):
        return self.identity

    def status(self):
        return next(self.statuses)


def controller(backend=None):
    backend = backend or FakeBackend()
    return X11PauseController(
        ":test",
        123,
        backend=backend,
        timeout=0.02,
        poll_interval=0.01,
        clock=lambda: 0,
        sleep=lambda _: None,
    ), backend


def test_pause_resume_and_display_cleanup():
    c, b = controller()
    client = FakeClient([Status.RUNNING, Status.PAUSED, Status.PAUSED, Status.RUNNING])
    with c.pause(client) as yielded:
        assert yielded is client
        assert b.events == [(191, True), (191, False)]
    assert b.events == [(191, True), (191, False)] * 2
    assert b.opens == [":test", ":test"] and b.closed == 2
    assert not b.grabbed


@pytest.mark.parametrize(
    "metadata",
    [
        (456, "Shadow of the Colossus", "PCSX2", False),
        (123, "PCSX2 Settings", "PCSX2", False),
        (123, "Shadow of the Colossus Error", "PCSX2", False),
        (123, "Shadow of the Colossus", "Dialog", False),
        (123, "Shadow of the Colossus", "QDialog", False),
        (123, "Shadow of the Colossus", "PCSX2", True),
    ],
)
def test_reject_foreign_title_and_dialog(metadata):
    c, b = controller()
    b.windows[10] = metadata
    with pytest.raises(PauseError):
        c.toggle()
    assert not b.events and b.closed == 1 and not b.grabbed


def test_focus_child_finds_game_title_on_parent():
    c, b = controller()
    b.focused = 11
    b.windows[11] = (None, "", "", False)
    b.parents[11] = 10
    c.toggle()
    assert b.events == [(191, True), (191, False)]


@pytest.mark.parametrize(
    "metadata",
    [
        (456, "", "", False),
        (None, "Error", "", False),
        (None, "", "", True),
    ],
)
def test_bad_child_not_authorized_by_good_ancestor(metadata):
    c, b = controller()
    b.focused = 11
    b.windows[11] = metadata
    b.parents[11] = 10
    with pytest.raises(PauseError):
        c.toggle()
    assert not b.events


def test_already_paused_does_not_touch_x11():
    c, b = controller()
    with c.pause(FakeClient([Status.PAUSED])):
        pass
    assert not b.opens and not b.events


def test_wrong_identity_fails_before_x11():
    c, b = controller()
    client = FakeClient([])
    client.identity = "OTHER"
    with pytest.raises(PauseError), c.pause(client):
        pytest.fail("must not enter")
    assert not b.opens


def test_changed_identity_never_resumes():
    c, b = controller()
    client = FakeClient([Status.RUNNING, Status.PAUSED])
    with pytest.raises(ResumeError), c.pause(client):
        client.identity = "OTHER"
    assert len(b.events) == 2


def test_pause_timeout_no_blind_resume():
    c, b = controller()
    client = FakeClient([Status.RUNNING] * 4)
    with pytest.raises(PauseError, match="timed out"), c.pause(client):
        pytest.fail("must not enter")
    assert len(b.events) == 2 and b.closed == 1


def test_resume_timeout_surfaces():
    c, b = controller()
    client = FakeClient([Status.RUNNING, Status.PAUSED] + [Status.PAUSED] * 4)
    with pytest.raises(ResumeError) as caught, c.pause(client):
        pass
    assert "timed out" in str(caught.value.__cause__)
    assert len(b.events) == 4 and b.closed == 2


def test_focus_changed_before_resume():
    c, b = controller()
    client = FakeClient([Status.RUNNING, Status.PAUSED, Status.PAUSED])
    with pytest.raises(ResumeError), c.pause(client):
        b.windows[10] = (999, "Shadow of the Colossus", "PCSX2", False)
    assert len(b.events) == 2 and b.closed == 2


@pytest.mark.parametrize("fault", ["available", "code", "press_ok", "release_ok"])
def test_backend_failure_cleanup_and_release(fault):
    c, b = controller()
    setattr(b, fault, False)
    with pytest.raises(PauseError):
        c.toggle()
    assert b.closed == 1 and not b.grabbed
    if fault in ("press_ok", "release_ok"):
        assert b.events == [(191, True), (191, False)]
    else:
        assert not b.events


def test_body_exception_resumes_and_propagates():
    c, b = controller()
    client = FakeClient([Status.RUNNING, Status.PAUSED, Status.PAUSED, Status.RUNNING])
    with pytest.raises(ValueError, match="body"), c.pause(client):
        raise ValueError("body")
    assert len(b.events) == 4


@pytest.mark.parametrize("focus", [0, 1])
def test_no_focused_window(focus):
    c, b = controller()
    b.focused = focus
    with pytest.raises(PauseError):
        c.toggle()
    assert not b.events and b.closed == 1


def test_cycle_in_focus_tree_fails_closed():
    c, b = controller()
    b.windows[10] = (None, "", "", False)
    b.parents[10] = 10
    with pytest.raises(PauseError, match="cyclic"):
        c.toggle()
    assert not b.events and b.closed == 1


def test_async_x11_error_before_input_fails_closed(monkeypatch):
    c, b = controller()

    def error():
        raise PauseError("X11 request failed")

    monkeypatch.setattr(b, "sync", error)
    with pytest.raises(PauseError):
        c.toggle()
    assert not b.events and b.closed == 1 and not b.grabbed


def test_external_resume_is_not_toggled_back_to_pause():
    c, b = controller()
    with c.pause(FakeClient([Status.RUNNING, Status.PAUSED, Status.RUNNING])):
        pass
    assert len(b.events) == 2


def test_late_acknowledgement_is_not_accepted():
    c, b = controller()
    ticks = iter([0.0, 0.03])
    c.clock = lambda: next(ticks)
    client = FakeClient([Status.RUNNING, Status.PAUSED])
    with pytest.raises(PauseError, match="timed out"), c.pause(client):
        pytest.fail("late pause must not enter")
    assert len(b.events) == 2 and b.closed == 1


@pytest.mark.parametrize(
    "options",
    [
        {"display": ""},
        {"display": None},
        {"owned_pid": 0},
        {"owned_pid": True},
        {"title_match": ""},
        {"pause_keysym": "F12"},
        {"timeout": float("inf")},
        {"poll_interval": 0},
    ],
)
def test_explicit_configuration(options):
    with pytest.raises(ValueError):
        X11PauseController(**({"display": ":test", "owned_pid": 123} | options))

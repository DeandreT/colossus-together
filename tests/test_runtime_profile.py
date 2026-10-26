"""Private-profile tests use synthetic files, never a real emulator profile."""

import configparser
import hashlib
import json
from pathlib import Path

import pytest

from runtime.profile import ProfileError, prepare_profile


@pytest.fixture
def source(tmp_path):
    root = tmp_path / "source"
    for name in ("inis", "bios", "memcards", "gamesettings"):
        (root / name).mkdir(parents=True)
    (root / "bios" / "test.bin").write_bytes(b"synthetic bios")
    (root / "memcards" / "card.ps2").write_bytes(b"personal progress")
    (root / "inis" / "PCSX2.ini").write_text(
        "[Folders]\nBios = bios\nMemoryCards = memcards\n"
        "GameSettings = gamesettings\nSnapshots = snaps\n"
        "[Filenames]\nBIOS = test.bin\n[MemoryCards]\nSlot1_Filename = card.ps2\n"
        "[Hotkeys]\nTogglePause = Keyboard/Space\nSaveState = Keyboard/F1\n"
        "[Pad1]\nCross = Keyboard/K\n[UI]\nPauseOnFocusLoss = true\n"
        "InhibitScreensaver = false\n[EmuCore]\nEnablePINE = false\nPINESlot = 28011\n"
        "[EmuCore/GS]\nRenderer = 12\n"
    )
    return root


def snapshot(root):
    return {
        str(p.relative_to(root)): p.read_bytes() for p in root.rglob("*") if p.is_file()
    }


def load(path):
    parser = configparser.ConfigParser()
    parser.read(path)
    return parser


def test_copies_preserves_original_and_rewrites_all_folders(source, tmp_path):
    before = snapshot(source)
    destination = tmp_path / "private"
    manifest = prepare_profile(source, destination)
    private = destination / "PCSX2"
    config = load(private / "inis" / "PCSX2.ini")
    assert snapshot(source) == before
    assert (private / "memcards/card.ps2").read_bytes() == b"personal progress"
    assert (private / "memcards/card.ps2").stat().st_ino != (
        source / "memcards/card.ps2"
    ).stat().st_ino
    assert config["Folders"]["Bios"] == str(private / "bios")
    assert config["Folders"]["MemoryCards"] == str(private / "memcards")
    assert all(
        Path(value).is_relative_to(private) for value in config["Folders"].values()
    )
    assert config["Filenames"]["BIOS"] == "test.bin"
    assert config["MemoryCards"]["Slot1_Filename"] == "card.ps2"
    assert config["Hotkeys"]["TogglePause"] == "Keyboard/Pause"
    assert config["Hotkeys"]["SaveState"] == "Keyboard/F1"
    assert config["Pad1"]["Cross"] == "Keyboard/K"
    assert config["EmuCore"]["EnablePINE"] == "true"
    assert config["EmuCore"]["PINESlot"] == "28124"
    assert config["EmuCore/GS"]["Renderer"] == "14"
    assert config["UI"]["PauseOnFocusLoss"] == "false"
    assert config["UI"]["InhibitScreensaver"] == "false"
    assert (
        manifest["source_config_sha256"]
        == hashlib.sha256(before["inis/PCSX2.ini"]).hexdigest()
    )
    assert json.loads((destination / "profile-manifest.json").read_text()) == manifest


def test_idempotent_without_writes_then_preserves_modified_progress(source, tmp_path):
    destination = tmp_path / "private"
    manifest = prepare_profile(source, destination)
    before = {p: p.stat().st_mtime_ns for p in destination.rglob("*")}
    assert prepare_profile(source, destination) == manifest
    assert before == {p: p.stat().st_mtime_ns for p in destination.rglob("*")}
    card = destination / "PCSX2/memcards/card.ps2"
    card.write_bytes(b"new private progress")
    with pytest.raises(ProfileError, match="changed"):
        prepare_profile(source, destination)
    assert card.read_bytes() == b"new private progress"
    assert (source / "memcards/card.ps2").read_bytes() == b"personal progress"


@pytest.mark.parametrize("enabled", ["false", "true"])
def test_missing_card_is_permitted_only_when_explicitly_disabled(
    source, tmp_path, enabled
):
    path = source / "inis/PCSX2.ini"
    path.write_text(
        path.read_text().replace(
            "Slot1_Filename = card.ps2",
            "Slot1_Filename = card.ps2\n"
            f"Multitap1_Slot2_Enable = {enabled}\n"
            "Multitap1_Slot2_Filename = missing.ps2",
        )
    )
    destination = tmp_path / "private"
    if enabled == "true":
        with pytest.raises(ProfileError, match="Missing"):
            prepare_profile(source, destination)
        assert not destination.exists()
    else:
        prepare_profile(source, destination)
        config = load(destination / "PCSX2/inis/PCSX2.ini")
        assert config["MemoryCards"]["Multitap1_Slot2_Filename"] == "missing.ps2"
        assert not (destination / "PCSX2/memcards/missing.ps2").exists()


@pytest.mark.parametrize("value", [0, -1, 65536, True, "28124"])
def test_invalid_slots_fail_without_writes(source, tmp_path, value):
    with pytest.raises(ProfileError, match="slot"):
        prepare_profile(source, tmp_path / "private", pine_slot=value)
    assert not (tmp_path / "private").exists()


def test_nonempty_destination_never_overwritten(source, tmp_path):
    destination = tmp_path / "private"
    destination.mkdir()
    (destination / "card.ps2").write_bytes(b"important")
    with pytest.raises(ProfileError, match="nonempty"):
        prepare_profile(source, destination)
    assert snapshot(destination) == {"card.ps2": b"important"}


def test_dry_run_and_empty_destination(source, tmp_path):
    destination = tmp_path / "private"
    result = prepare_profile(source, destination, dry_run=True)
    assert not destination.exists()
    destination.mkdir()
    assert prepare_profile(source, destination) == result


@pytest.mark.parametrize(
    "replacement", ["../escape", "/unapproved/bios", "bios/../../escape"]
)
def test_unapproved_folder_paths_fail(source, tmp_path, replacement):
    path = source / "inis/PCSX2.ini"
    path.write_text(path.read_text().replace("Bios = bios", f"Bios = {replacement}"))
    with pytest.raises(ProfileError):
        prepare_profile(source, tmp_path / "private")
    assert not (tmp_path / "private").exists()


@pytest.mark.parametrize(
    "location", ["bios/test.bin", "memcards/card.ps2", "inis/PCSX2.ini"]
)
def test_symlink_files_rejected(source, tmp_path, location):
    path = source / location
    data = path.read_bytes()
    path.unlink()
    outside = tmp_path / "outside"
    outside.write_bytes(data)
    path.symlink_to(outside)
    with pytest.raises(ProfileError, match="Symlink"):
        prepare_profile(source, tmp_path / "private")


def test_directory_symlink_rejected_even_inside_root(source, tmp_path):
    (source / "bios" / "alias").symlink_to(
        source / "memcards", target_is_directory=True
    )
    with pytest.raises(ProfileError, match="Symlink"):
        prepare_profile(source, tmp_path / "private")


def test_explicit_external_source_and_absolute_card_name(source, tmp_path):
    approved = tmp_path / "approved"
    approved.mkdir()
    card = approved / "external.ps2"
    card.write_bytes(b"approved personal card")
    path = source / "inis/PCSX2.ini"
    path.write_text(path.read_text().replace("card.ps2", str(card)))
    with pytest.raises(ProfileError, match="approved"):
        prepare_profile(source, tmp_path / "private")
    prepare_profile(source, tmp_path / "private", allowed_source_dirs=[approved])
    private = tmp_path / "private/PCSX2"
    assert (private / "memcards/external.ps2").read_bytes() == card.read_bytes()
    assert (
        load(private / "inis/PCSX2.ini")["MemoryCards"]["Slot1_Filename"]
        == "external.ps2"
    )


def test_selected_game_only_and_no_external_path_leaks(source, tmp_path):
    (source / "gamesettings/SCUS-97472_AAAAAAAA.ini").write_text(
        "[EmuCore]\nFastBoot = true\n"
    )
    (source / "gamesettings/OTHER-12345.ini").write_text(
        "[Folders]\nBios = /private/user\n"
    )
    prepare_profile(source, tmp_path / "private", selected_serial="SCUS-97472")
    assert [p.name for p in (tmp_path / "private/PCSX2/gamesettings").iterdir()] == [
        "SCUS-97472_AAAAAAAA.ini"
    ]
    (source / "gamesettings/SCUS-97472_AAAAAAAA.ini").write_text(
        "[Other]\nPath = /private/user\n"
    )
    with pytest.raises(ProfileError, match="paths"):
        prepare_profile(source, tmp_path / "other", selected_serial="SCUS-97472")


def test_extra_ini_folders_rewritten_and_settings_optional(source, tmp_path):
    (source / "inis/Extra.ini").write_text(
        "[Folders]\nSnapshots = snaps\n[UI]\nPauseOnFocusLoss = true\n"
    )
    prepare_profile(source, tmp_path / "private")
    config = load(tmp_path / "private/PCSX2/inis/Extra.ini")
    assert config["Folders"]["Snapshots"] == str(tmp_path / "private/PCSX2/snaps")
    assert config["UI"]["PauseOnFocusLoss"] == "false"
    prepare_profile(source, tmp_path / "minimal", copy_source_settings=False)
    assert not (tmp_path / "minimal/PCSX2/inis/Extra.ini").exists()
    assert not load(tmp_path / "minimal/PCSX2/inis/PCSX2.ini").has_section("Pad1")


def test_changed_request_and_overlapping_roots_rejected(source, tmp_path):
    prepare_profile(source, tmp_path / "private")
    with pytest.raises(ProfileError, match="differs"):
        prepare_profile(source, tmp_path / "private", pine_slot=28125)
    with pytest.raises(ProfileError, match="overlap"):
        prepare_profile(source, source / "private")


def test_traversal_card_and_serial_rejected(source, tmp_path):
    path = source / "inis/PCSX2.ini"
    path.write_text(path.read_text().replace("card.ps2", "../card.ps2"))
    with pytest.raises(ProfileError, match="Unsafe"):
        prepare_profile(source, tmp_path / "private")
    with pytest.raises(ProfileError, match="serial"):
        prepare_profile(source, tmp_path / "private", selected_serial="../OTHER")


def test_private_config_and_symlink_destination_preserved(source, tmp_path):
    destination = tmp_path / "private"
    prepare_profile(source, destination)
    path = destination / "PCSX2/inis/PCSX2.ini"
    path.write_text("private user edit")
    with pytest.raises(ProfileError, match="changed"):
        prepare_profile(source, destination)
    assert path.read_text() == "private user edit"
    alias = tmp_path / "alias"
    alias.symlink_to(destination, target_is_directory=True)
    with pytest.raises(ProfileError, match="Symlink"):
        prepare_profile(source, alias)


def test_symlink_parent_and_missing_card_fail_before_writing(source, tmp_path):
    alias = tmp_path / "alias"
    alias.symlink_to(source, target_is_directory=True)
    with pytest.raises(ProfileError, match="Symlink"):
        prepare_profile(alias, tmp_path / "private")
    (source / "memcards/card.ps2").unlink()
    with pytest.raises(ProfileError, match="Missing"):
        prepare_profile(source, tmp_path / "private")
    assert not (tmp_path / "private").exists()

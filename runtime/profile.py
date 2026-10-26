"""Prepare a private Linux PCSX2 profile, without launching anything.

Use ``prepare_profile(source_root, destination_parent)`` or
``python -m runtime.profile SOURCE DESTINATION --dry-run``. Pass DESTINATION
to PCSX2's ``-datapath``: PCSX2 itself appends ``PCSX2``. Never point this at
your normal profile. A new destination must be absent or completely empty;
an existing generated destination is validated, never refreshed or overwritten.
Changed private cards/settings deliberately fail validation and remain intact.

Sources must be stable while preparing. Symlinks are rejected, including parent
components. Configured source folders outside source_root need explicit
``allowed_source_dirs`` approval; approval permits reads, never source writes.
Only a selected serial's game settings are copied. This is a profile preparer,
not a mod installer, launcher, or guarantee of safe in-game qualification.
"""

import argparse
import configparser
import hashlib
import io
import json
import os
import re
import shutil
import tempfile
from pathlib import Path


class ProfileError(ValueError):
    """Unsafe, ambiguous, or non-idempotent profile request."""


def _path(value):
    path = Path(os.path.abspath(value))
    for part in (path, *path.parents):
        if part.is_symlink():
            raise ProfileError(f"Symlink is not an approved source/destination: {part}")
    return path


def _inside(path, roots):
    return any(path.is_relative_to(root) for root in roots)


def _resolve(value, root, allowed):
    value = value.strip().strip('"')
    if ".." in Path(value).parts or "\\" in value:
        raise ProfileError(f"Unsafe source path: {value}")
    result = _path(Path(value) if Path(value).is_absolute() else root / value)
    if not _inside(result, allowed):
        raise ProfileError(
            f"Source outside approved roots; explicitly approve its directory: {result}"
        )
    return result


def _ini(data):
    config = configparser.ConfigParser(interpolation=None, strict=True)
    config.optionxform = str
    try:
        config.read_string(data.decode("utf-8-sig"))
    except (UnicodeError, configparser.Error) as exc:
        raise ProfileError(f"Invalid source INI: {exc}") from exc
    if config.defaults():
        raise ProfileError("INI DEFAULT entries are unsupported")
    return config


def _set(config, section, key, value):
    if not config.has_section(section):
        config.add_section(section)
    for existing in list(config[section]):
        if existing.casefold() == key.casefold():
            config.remove_option(section, existing)
    config.set(section, key, value)


def _dump(config):
    stream = io.StringIO()
    config.write(stream, space_around_delimiters=True)
    return stream.getvalue().encode("utf-8")


def _hash(data):
    return hashlib.sha256(data).hexdigest()


def prepare_profile(
    source_root,
    destination_parent,
    pine_slot=28124,
    renderer=14,
    copy_source_settings=True,
    *,
    selected_serial=None,
    allowed_source_dirs=(),
    dry_run=False,
):
    """Return a JSON-safe manifest with source and copied-file SHA-256 hashes.

    ``source_root`` is the directory containing ``inis/PCSX2.ini`` (not its
    parent). ``allowed_source_dirs`` explicitly authorizes additional local
    source directories. Slot is 1..65535; renderer must be a nonnegative int.
    No source files, running processes, Steam settings, or remote assets change.
    """
    if type(pine_slot) is not int or not 1 <= pine_slot <= 65535:
        raise ProfileError("PINE slot must be an integer in 1..65535")
    if type(renderer) is not int or renderer < 0:
        raise ProfileError("Renderer must be a nonnegative integer")
    if selected_serial is not None and not re.fullmatch(
        r"[A-Za-z0-9]+(?:-[A-Za-z0-9]+)*", selected_serial
    ):
        raise ProfileError("Invalid selected game serial")
    root, destination = _path(source_root), _path(destination_parent)
    allowed = (root, *(_path(p) for p in allowed_source_dirs))
    if any(_inside(destination, (p,)) or _inside(p, (destination,)) for p in allowed):
        raise ProfileError("Destination and approved source roots must not overlap")
    if not root.is_dir() or any(not p.is_dir() for p in allowed):
        raise ProfileError("Every approved source root must be an existing directory")
    private = destination / "PCSX2"
    files, sources, folders, extra_directories = {}, {}, {}, set()

    def read(path):
        path = _path(path)
        if not _inside(path, allowed) or not path.is_file():
            raise ProfileError(f"Missing or unapproved source file: {path}")
        data = path.read_bytes()
        sources[str(path)] = _hash(data)
        return data

    def add(relative, data):
        name = str(Path("PCSX2") / relative)
        if name in files and files[name] != data:
            raise ProfileError(f"Conflicting destination files: {name}")
        files[name] = data

    source_config = read(root / "inis" / "PCSX2.ini")
    original = _ini(source_config)
    config = _ini(source_config) if copy_source_settings else _ini(b"")
    canonical = {
        "bios": "bios",
        "memorycards": "memcards",
        "memcards": "memcards",
        "gamesettings": "gamesettings",
        "savestates": "sstates",
        "snapshots": "snaps",
        "cheatsws": "cheats_ws",
        "cheatsni": "cheats_ni",
    }
    for key, value in (
        original.items("Folders") if original.has_section("Folders") else ()
    ):
        if not re.fullmatch(r"[A-Za-z0-9_-]+", key):
            raise ProfileError(f"Unsafe folder key: {key}")
        folders[key.casefold()] = (
            _resolve(value, root, allowed)
            if value.strip()
            else root / canonical.get(key.casefold(), key.lower())
        )
        target = canonical.get(key.casefold(), key.lower())
        _set(config, "Folders", key, str(private / target))
    for key, target in {
        "Bios": "bios",
        "MemoryCards": "memcards",
        "GameSettings": "gamesettings",
        "Savestates": "sstates",
        "Snapshots": "snaps",
        "Logs": "logs",
        "Cheats": "cheats",
        "CheatsWS": "cheats_ws",
        "CheatsNI": "cheats_ni",
        "Cache": "cache",
        "Textures": "textures",
        "InputProfiles": "inputprofiles",
    }.items():
        _set(config, "Folders", key, str(private / target))

    bios_dir = folders.get("bios", root / "bios")
    card_dir = folders.get("memorycards", folders.get("memcards", root / "memcards"))
    for source_dir, target_dir in ((bios_dir, "bios"), (card_dir, "memcards")):
        source_dir = _path(source_dir)
        if not source_dir.is_dir():
            raise ProfileError(f"Missing source directory: {source_dir}")
        for entry in sorted(source_dir.rglob("*")):
            _path(entry)
            if entry.is_file():
                add(Path(target_dir) / entry.relative_to(source_dir), read(entry))
            elif not entry.is_dir():
                raise ProfileError(f"Unsupported source entry: {entry}")

    # Referenced absolute card paths are allowed only inside approved sources.
    # Normalize only after copying that exact file, not a same-named substitute.
    for section in original.sections():
        for key, value in original.items(section):
            lower = key.casefold()
            if (
                "filename" in lower
                and ("memorycard" in lower or section.casefold() == "memorycards")
                and value.strip()
            ):
                source = _resolve(value, card_dir, allowed)
                enable_key = lower.replace("_filename", "_enable")
                enabled = next(
                    (
                        v
                        for k, v in original.items(section)
                        if k.casefold() == enable_key
                    ),
                    None,
                )
                if (
                    not source.exists()
                    and enabled is not None
                    and enabled.strip().casefold() in ("false", "0", "no", "off")
                ):
                    _set(config, section, key, source.name)
                    continue
                add(Path("memcards") / source.name, read(source))
                _set(config, section, key, source.name)
            elif (
                lower == "bios" and section.casefold() == "filenames" and value.strip()
            ):
                source = _resolve(value, bios_dir, allowed)
                add(Path("bios") / source.name, read(source))
                _set(config, section, key, source.name)

    _set(config, "EmuCore", "EnablePINE", "true")
    _set(config, "EmuCore", "PINESlot", str(pine_slot))
    _set(config, "EmuCore/GS", "Renderer", str(renderer))
    _set(config, "Hotkeys", "TogglePause", "Keyboard/Pause")
    _set(config, "UI", "PauseOnFocusLoss", "false")
    _set(config, "UI", "InhibitScreensaver", "false")
    # Remove duplicate old values wherever a version stored these controls.
    for section in config.sections():
        for key in list(config[section]):
            overrides = {
                "enablepine": "true",
                "pineslot": str(pine_slot),
                "pauseonfocusloss": "false",
                "inhibitscreensaver": "false",
            }
            if key.casefold() in overrides:
                config.set(section, key, overrides[key.casefold()])
    add(Path("inis") / "PCSX2.ini", _dump(config))
    if copy_source_settings:
        for entry in sorted((root / "inis").iterdir()):
            _path(entry)
            if (
                entry.name != "PCSX2.ini"
                and entry.is_file()
                and entry.suffix.lower() == ".ini"
            ):
                extra = _ini(read(entry))
                if extra.has_section("Folders"):
                    for key, value in list(extra.items("Folders")):
                        if not re.fullmatch(r"[A-Za-z0-9_-]+", key):
                            raise ProfileError(f"Unsafe folder key: {key}")
                        if value.strip():
                            _resolve(value, root, allowed)
                        target = private / canonical.get(key.casefold(), key.lower())
                        _set(extra, "Folders", key, str(target))
                        extra_directories.add(str(target.relative_to(destination)))
                for section in extra.sections():
                    for key in list(extra[section]):
                        controls = {
                            "pauseonfocusloss": "false",
                            "inhibitscreensaver": "false",
                            "enablepine": "true",
                            "pineslot": str(pine_slot),
                            "renderer": str(renderer),
                        }
                        if key.casefold() in controls:
                            extra.set(section, key, controls[key.casefold()])
                add(Path("inis") / entry.name, _dump(extra))
    if selected_serial:
        game_dir = _path(folders.get("gamesettings", root / "gamesettings"))
        if game_dir.exists():
            for entry in sorted(game_dir.iterdir()):
                _path(entry)
                if re.fullmatch(
                    re.escape(selected_serial) + r"(?:_[0-9A-Fa-f]{8})?\.ini",
                    entry.name,
                ):
                    game = _ini(read(entry))
                    if game.has_section("Folders") or any(
                        "/" in value or "\\" in value
                        for section in game.sections()
                        for _, value in game.items(section)
                        if not value.startswith("Keyboard/")
                    ):
                        raise ProfileError(
                            "Selected game settings contain paths; explicit migration required"
                        )
                    add(Path("gamesettings") / entry.name, _dump(game))

    directories = sorted(
        {
            "PCSX2/inis",
            *extra_directories,
            *(
                str(Path(v).relative_to(destination))
                for _, v in config.items("Folders")
            ),
        }
    )
    manifest = {
        "version": 1,
        "source_root": str(root),
        "datapath": str(destination),
        "profile_root": str(private),
        "source_config": str(root / "inis" / "PCSX2.ini"),
        "source_config_sha256": _hash(source_config),
        "sources": sources,
        "files": {name: _hash(data) for name, data in sorted(files.items())},
        "directories": directories,
    }
    marker = destination / "profile-manifest.json"
    if destination.exists() and (
        not destination.is_dir() or any(destination.iterdir())
    ):
        try:
            saved = json.loads(_path(marker).read_text())
        except (OSError, ValueError) as exc:
            raise ProfileError(
                "Destination is nonempty and not this exact generated profile"
            ) from exc
        if saved != manifest:
            raise ProfileError(
                "Existing profile differs from this request; use a new empty destination"
            )
        expected = set(files) | {marker.name}
        actual = set()
        for entry in destination.rglob("*"):
            _path(entry)
            if entry.is_file():
                actual.add(str(entry.relative_to(destination)))
            elif not entry.is_dir():
                raise ProfileError(f"Unsupported private entry: {entry}")
        if actual != expected or any(
            _hash(_path(destination / name).read_bytes()) != digest
            for name, digest in manifest["files"].items()
        ):
            raise ProfileError("Private files changed; preserved without overwriting")
        if any(not _path(destination / name).is_dir() for name in directories):
            raise ProfileError("Private directory missing")
        return manifest
    if dry_run:
        return manifest
    destination.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=".pcsx2-profile-", dir=destination.parent))
    try:
        for name in directories:
            (staging / name).mkdir(parents=True, exist_ok=True)
        for name, data in files.items():
            target = staging / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        (staging / marker.name).write_text(json.dumps(manifest, indent=2) + "\n")
        staging.rename(destination)
    finally:
        if staging.exists():
            shutil.rmtree(staging)
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source_root")
    parser.add_argument("destination_parent")
    parser.add_argument("--pine-slot", type=int, default=28124)
    parser.add_argument("--renderer", type=int, default=14)
    parser.add_argument("--selected-serial")
    parser.add_argument("--allowed-source-dir", action="append", default=[])
    parser.add_argument("--no-copy-source-settings", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    try:
        result = prepare_profile(
            args.source_root,
            args.destination_parent,
            args.pine_slot,
            args.renderer,
            not args.no_copy_source_settings,
            selected_serial=args.selected_serial,
            allowed_source_dirs=args.allowed_source_dir,
            dry_run=args.dry_run,
        )
    except (ProfileError, OSError) as exc:
        parser.exit(2, f"Profile not prepared: {exc}\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()

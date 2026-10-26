# Colossus Together

An unofficial, work-in-progress local co-op project for *Shadow of the Colossus*.
This repository contains tools and implementation components for the
NTSC-U PS2 release, `SCUS-97472` / executable CRC `C19A374E`.

**This is not a playable release or a complete installer.** The public repository
contains source and synthetic tests, not the private development profiles,
experimental savestates, generated game-code copies or game assets.

The design keeps the original campaign and save authority with player one, gives
player two a separate character and input state, and renders a separate camera
view for each player. Game-specific code must distinguish per-player simulation
from once-per-frame rendering and shared campaign events.

Campaign progress, unlocks and checkpoints are shared. Health, stamina, controls
and equipped weapons are player-specific. Player one remains the authority for
scripted campaign events, and either player's death restarts the team at the
shared checkpoint. The single Agro is controlled by its current rider.

## Components

- `runtime/`: bounded PINE communication, checked patch transactions and linking
  of locally built MIPS helper objects.
- `lifecycle/`: generation-scoped construction, teardown and resource-unload
  coordination. Object addresses are invalidated when their lifetime ends.
- `injection/`: game-side lifecycle telemetry and its host-side interpretation.
- `commands/`: indexed game-thread command mailbox; no arbitrary host-supplied
  function addresses.
- `game/`: checked model metadata and view-local presentation packet generation.
- `assets/`: bounded, read-only ISO9660 access to the user's local disc image.
- `native_lifecycle/`: game-thread ownership actions, allocation tracking and
  guarded canonical-player admission hooks.
- `resource_safety/`: read-only sheet-dependency and release-effect classification.
- `render_state/`: bounded, fence-checked snapshots of explicitly supplied ranges.
- `bootstrap/`: an offline plan for a guarded one-shot game-thread allocation.
- `streaming/`: two-player streaming-interest planning and native adapter components.
- `tests/`: synthetic protocol, linking, patch-safety and lifecycle tests.

These packages are building blocks, not an automatic game installer. Running
their tests neither starts an emulator nor modifies a game.

## Development

Use Python 3.11 or newer. From the repository root:

```sh
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements-dev.txt
python -m pytest -q
```

On Windows, activate with `.venv\Scripts\Activate.ps1` instead. Python-only
tests need no game files. C tests additionally require a host C compiler; some
exercise AddressSanitizer and UndefinedBehaviorSanitizer. Runtime profile and
emulator-control helpers currently target Linux, Unix sockets and X11.

Optional EE assembly tests discover `mips64r5900el-ps2-elf-*` tools on PATH.
`SOTC_EE_CC` and `SOTC_EE_AS` can select the compiler and assembler explicitly;
their companion tools must be installed too. Toolchains and proprietary SDK
components are not included.

Optional original-module checks use `SOTC_ORIGINAL_DIR`, or the ignored
`.local-game-inputs/` directory. Supply your own original `GAMECORE.XFF`,
`MANAGER.XFF` and `KERNEL.XFF` there. Tests skip these checks when inputs or
optional tools are absent. Never commit that directory or generated output.

## Roadmap and repository scope

Finish and qualify local split-screen co-op first. The future native Linux port
will live in a **separate repository**, with co-op support; online play follows
there. Difficulty changes will be considered after online play, not as part of
the current implementation.

There is no open-source license grant yet. See [NOTICE.md](NOTICE.md) for the
source, rights and redistribution boundary.

The standalone `runtime.xff` reader parses module metadata without the
decompilation workspace. Its modules work with `runtime.xff_bindings`; reading
and resolving metadata does not authorize loading, patching or executing it.

## Address conventions

Do not interchange a loaded section address and an address used as the origin of
the retained disassembly listings. For this XFF revision, actual `.text` starts
`0x38` bytes after the listing's module origin. The existing command, injection
and lifecycle-hook generators use the **listing origin** with offsets such as
GAMECORE `+0xC678`. The standalone `bootstrap.allocator` uses the **actual `.text`
address**, so that same call is `+0xC640`. Symbol values from `runtime.xff` are
section-relative and require the actual loaded section address. Validate the
resolved instruction and target rather than inferring a base from its name.

## Safety and data

Use the supported game revision from the user's own disc image. Do not distribute
the disc, BIOS, assets, reconstructed game binaries or proprietary SDK tools.
Generated helpers that incorporate original game instructions remain local to
the user's build.

Runtime integration must verify the game identity, loaded instruction guards,
memory ownership and execution state before writing. Capture every applied
change. Never restore stale bytes over another writer's changes or reuse an
object address without a new lifetime generation.

Resource unloading remains asynchronous. A lifecycle barrier belongs in the
resource worker before dependency release, not in an API that merely queues an
unload request. The controller must finish deleting its borrowed-resource users
before permitting the worker to continue. See `injection/BARRIERS.md` for the
supported segment barrier and its coverage limits.

Synthetic tests establish component contracts; actual two-player gameplay,
rendering, transitions and performance require separate emulator qualification.

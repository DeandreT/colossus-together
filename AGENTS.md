# Colossus Together

This repository contains source-only development components for the PS2 local
co-op project. It is not a playable release or the future native Linux port.
The native port belongs in a separate repository, with co-op support.

## Publication boundary

- Never commit game assets, BIOS files, disc images, savestates, memory captures,
  personal profiles, proprietary SDKs, reconstructed executables, generated
  original-game function copies, patch receipts or local investigation output.
- Keep private runtime experiments and capture-specific regression cases outside
  this repository. Public tests should use synthetic data or explicitly supplied
  original inputs; do not discover personal files automatically.
- Keep optional local inputs in the ignored `.local-game-inputs/` directory or
  select them with `SOTC_ORIGINAL_DIR`. Discover EE tools through PATH,
  `SOTC_EE_CC` and `SOTC_EE_AS`; do not add personal absolute paths.
- No open-source license has been selected. Do not grant or change licensing
  without the owner's approval. See `NOTICE.md`.

## Validation

Run `python -m pytest -q` and `ruff check .` from this directory. Optional
original-file and EE-tool tests may skip when those inputs are absent. Do not
present synthetic test success as emulator, gameplay or full-game qualification.
Preserve fail-closed identity, memory-ownership, lifetime and graphics-fence checks.

Complete local co-op before the separate native port and online work. Difficulty
changes are a later discussion after online play, not current scope.

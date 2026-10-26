# Colossus Together

This repository contains source-only development components for the PS2 local
co-op project. It is not a playable release.

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
- Original project code and documentation use the MIT license in `LICENSE`.
  Preserve copyright notices and the third-party exclusions in `NOTICE.md`;
  the project license does not license the original game or its assets.

## Validation

Run `python -m pytest -q` and `ruff check .` from this directory. Optional
original-file and EE-tool tests may skip when those inputs are absent. Do not
present synthetic test success as emulator, gameplay or full-game qualification.
Preserve fail-closed identity, memory-ownership, lifetime and graphics-fence checks.

Complete and qualify local split-screen co-op. Difficulty changes are outside
the current scope.

## Work tracking

Track implementation and remaining qualification in GitHub issues. Reuse an
existing issue for the same outcome and link scoped pull requests to it. Keep
incomplete gameplay qualification open when a supporting code change merges.
Issues and pull requests must follow the same source-only publication boundary
as the repository; never attach private game data or local investigation files.

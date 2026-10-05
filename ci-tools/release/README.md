# Development draft releases

The fork-only [Development Draft Release 2.2 workflow](../../.github/workflows/dev-draft-release.yml)
builds reproducible development snapshots without modifying the official nightly
or component-release workflows.

The workflow lives on the fork's default branch, `main`. Its `source-ref` input
selects the software to build; the default is `caliptra-dev-2.2`. Push the source
commit to `mhatrevi/caliptra-sw` before dispatching:

```sh
gh workflow run dev-draft-release.yml \
  --repo mhatrevi/caliptra-sw --ref main \
  -f source-ref=caliptra-dev-2.2
```

For an exact snapshot, pass the full development commit SHA instead of the
branch name. The workflow resolves the input once and all build steps use that
immutable SHA. The workflow definition's `main` commit is recorded separately.

## Validation and hardware pins

The build uses `CALIPTRA_HW_REV=2.2` and the checked-out source's Rust toolchain.
It initializes submodules recursively at their recorded commits, verifies that
the standalone RTL/I3C/Adams Bridge copies match the Caliptra-SS tree, and never
uses `git submodule update --remote`.

Before packaging, it checks formatting, runs emulator peripheral and ICCM-bounds
tests, executes targeted boot/update/warm-reset/failure and PCR-policy/quote
regressions, and builds ROM, FMC, Runtime, and driver test firmware. A failed
validation or build prevents release creation. This is a development build gate,
not the official release qualification matrix.

## Artifacts and draft policy

The workflow uses the existing [release bundle script](./build_release.sh).
It adds a machine-readable `build-metadata.json` containing software, workflow,
recursive hardware commit, toolchain, and validation provenance, development
release notes, and `SHA256SUMS`. The metadata and notes are also inside the ZIP.
The ZIP, metadata, notes, and checksums are retained as workflow artifacts and
attached to the GitHub draft release.

Tags have the form
`dev-2.2-YYYYMMDD.RUN_NUMBER.RUN_ATTEMPT-gCOMMIT_PREFIX`, so re-runs do not
overwrite an earlier snapshot. Releases are always drafts and prereleases and
are explicitly marked not-latest. They are not automatically published.

The build job has read-only repository permissions. Only the separate publication
job receives `contents: write`; it downloads and checks the finished artifacts
without checking out or executing the development source.

## Deployment limitations

These are development/test-key-signed artifacts, not production releases.
Production 2.2 firmware requires subsystem mode; production passive loads are
intentionally rejected. Warm/hitless ICCM boot-region re-arm still requires the
pending RTL fix. The emulator models that intended reset behavior, and this
workflow does not perform FPGA testing or RTL simulation.

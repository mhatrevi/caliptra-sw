The `caliptra-registers` crate re-exports generated hardware register accessors.
`CALIPTRA_HW_REV=2.1` selects `hw/rev-2_1/registers`; an unset variable or
`CALIPTRA_HW_REV=latest` selects `hw/latest/registers`.

Each hardware revision uses its `caliptra-ss` commit as the source of truth for
register generation:

```text
hw/<revision>/caliptra-ss
|-- src/                                  Caliptra-SS registers
`-- third_party/
    |-- caliptra-rtl/                      Caliptra core registers
    |   `-- submodules/adams-bridge/       Adams Bridge registers
    `-- i3c-core/                         I3C registers
```

The generator derives these paths from Caliptra-SS instead of accepting
independently selected RTL and I3C repositories. Generated headers record all four
source commits. The extra EL2 PIC RDL remains in `registers/bin/extra-rdl`.

## Regenerating a pinned revision

Run from the repository root:

```sh
registers/update.sh latest
registers/update.sh rev-2_1
```

The script initializes Caliptra-SS if necessary and recursively checks out the
dependency commits recorded by its selected commit. It does not advance any
dependency to its branch tip or change an already selected Caliptra-SS commit.

To verify that committed accessors match the sources without rewriting them:

```sh
cargo run --locked -p caliptra_registers_generator -- --check \
    hw/latest/caliptra-ss registers/bin/extra-rdl hw/latest/registers/src
```

Use `hw/rev-2_1` in place of `hw/latest` to check the 2.1 snapshot.

## Updating latest hardware

Advance only Caliptra-SS to its upstream `main`, then regenerate:

```sh
git submodule update --init hw/latest/caliptra-ss
git -C hw/latest/caliptra-ss fetch origin main
git -C hw/latest/caliptra-ss switch --detach origin/main
registers/update.sh latest
```

The separate `hw/latest/rtl` and `hw/latest/i3c-core-rtl` checkouts are still used
by other tooling. Keep them aligned with the pins recorded by Caliptra-SS, rather
than updating them independently:

```sh
git submodule update --init hw/latest/rtl hw/latest/i3c-core-rtl
git -C hw/latest/rtl switch --detach \
    "$(git -C hw/latest/caliptra-ss rev-parse HEAD:third_party/caliptra-rtl)"
git -C hw/latest/i3c-core-rtl switch --detach \
    "$(git -C hw/latest/caliptra-ss rev-parse HEAD:third_party/i3c-core)"
git -C hw/latest/rtl submodule update --init --recursive
git -C hw/latest/i3c-core-rtl submodule update --init --recursive
```

If a recorded commit is unavailable in a separate checkout, fetch its origin
before switching. Review and commit the updated Caliptra-SS, RTL, and I3C pins
alongside `hw/latest/registers`. Do not advance `hw/rev-2_1` when updating latest
hardware.

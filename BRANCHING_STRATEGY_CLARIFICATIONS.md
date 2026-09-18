# Branching Strategy Clarifications

## Version-Selection Mechanism

1. What exact construct will select a version: a custom Rust `cfg`, Cargo
   features, versioned crates, generated modules, or another mechanism?

   **Recommendation:** Use Cargo features because they integrate well with
   `rust-analyzer`.

2. Will the selector represent a hardware revision, a product release, a
   firmware contract version, or some combination?
3. How will the selection propagate consistently through every crate, build
   script, code generator, test, emulator invocation, C-header build, and other
   build entry points?
4. How will nested or repeated version checks be prevented from spreading
   through shared functions?

## Areas Requiring Version Control

At a minimum, the following areas require explicit per-version handling:

1. Persistent memory layout and contents
2. Firmware Handoff Table layout and contents
3. Data Vault contents
4. Key Vault contents
5. Mailbox ABI
6. Certificate and CSR profiles
7. Firmware image format and verification contract
8. Authorization manifest formats
9. Memory map and load contract, including ROM, ICCM, DCCM, stack,
   persistent-data, boot-status, and mailbox addresses and sizes
10. DICE and cryptographic policy, including CDI and key derivation flows,
    derivation labels, algorithm selection, key lifetime, and reset behavior
11. Measurement and event-log schemas, including PCR assignments, PCR log entry
    IDs and lengths, stash-measurement records, and fuse log entry IDs
12. Recovery and DMA protocol, including recovery capabilities, status and
    reason values, transfer limits, and I3C recovery behavior
13. Externally visible status and error contracts, including boot-status values
    and error-code values and meanings
14. Model behavior: the hardware model and emulator must implement the same
    selected mailbox, vault, reset, fuse, and peripheral semantics as the
    firmware

## CI and Merge Requirements

1. When a change applies to all supported versions, CI for 2.0, 2.1, and 2.2
   must all pass before merge.

## Non-Register Differences Exposed by PR #4064

[PR #4064](https://github.com/chipsalliance/caliptra-sw/pull/4064) should be used
as an acceptance test for the proposed architecture. The design needs concrete
answers to the following questions:

1. How will both the 2.0/2.1 and 2.2 FMC Alias certificate templates be stored,
   generated, reviewed, and selected?
2. How will version-specific template parameter structs and call sites avoid
   forcing `cfg` checks through the X.509 generator, ROM flow, tests, and
   consumers?
3. How will Key Vault assignments and security policy remain auditable when the
   same constant names map to different slots or semantics by version?
4. Can a reviewer see a coherent implementation for one release, or must the
   reviewer mentally evaluate many interleaved conditional paths?

## Maintainability and Reviewability

1. Will version-specific implementations live in separate modules with a small
   facade, or will individual types, fields, constants, and statements be
   conditionally compiled?
2. How will the project measure whether unification actually reduces effort?
3. At what complexity threshold would a release move back to a servicing
   branch?

## Security, Compliance, and Auditability

1. How will reviewers and auditors inspect one complete release configuration,
   including code that is inactive in normal development builds?

## Release Stabilization and Servicing

1. How can one release enter stabilization while development for the next
   release continues on the same branch?
2. From what point are point releases cut? Are they always cut from the tip of
   the branch?

## Minimum Acceptance Criteria

1. A prototype demonstrating hardware-specific changes, with the new stash
   measurement flow as a potential candidate.
2. A prototype showing how PR #4064 builds and tests as 2.0, 2.1, and 2.2 while
   preserving the older certificate, API, storage, and reset-flow contracts.
3. Rules limiting conditional compilation and keeping version-specific behavior
   at reviewable architectural boundaries.

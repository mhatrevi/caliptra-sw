# Emulator for Caliptra

This repository contains code for creating an emulator for the Caliptra hardware.

## Peripheral emulation

### HMAC

The root bus selects the HMAC protocol using its hardware version. Versions 2.0
and 2.1 retain implicit outer-hash completion after every block. Version 2.2
requires `HMAC512_CTRL.LAST` together with `INIT` or `NEXT` on the final padded
message block, and uses six 32-bit LFSR seed registers.

In the pinned 2.2 RTL, intermediate commands assert `READY` and `VALID` with the
inner SHA digest. Only a command carrying `LAST` produces the final HMAC tag.
Firmware must therefore arm key-vault tag output only for the final block, not
for intermediate blocks. Standalone emulator runs select this behavior with
`--hw-version 2.2`; the CLI's default remains 2.1.

### Mailbox

#### Class diagram

![alternative text](http://www.plantuml.com/plantuml/proxy?cache=no&src=https://raw.githubusercontent.com/attzonko/plantuml_test/main/test.puml)

#### State diagram

The UML state diagram depicted below represents the behavior of the mailbox state machine. The notation follows the UML conventions:

![alternative text](http://www.plantuml.com/plantuml/proxy?cache=no&src=https://raw.githubusercontent.com/rusty1968/rust_documentation/main/docs/mb_state_diagram.puml)

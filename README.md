# Sindri

Sindri is a Hardware Security Modules (HSM) written in Rust.
It provides cryptographic services to clients running on other cores:

- Key generation and secure storage
- Key use (encryption, decryption, signing, verification) without revealing key material
- Cryptographically secure pseudorandom number generator (CSPRNG)

Unlike software based cryptographic providers, an HSM preserves the secrecy of the stored key material even
if hte users of the HSM are compromised.     

## Status

Sindri is still in early development and is currently in the prototyping phase.

## Supported Cryptographic Algorithms

- [ChaCha20](https://crates.io/crates/rand_chacha) based cryptographically secure pseudorandom number generator (CSPRNG) seeded by the hardware.

## Debugging on STM32H745I-DISCO

### Installation
1. Install whatever package provides `arm-none-eabi-gdb`.
   See [here](https://docs.rust-embedded.org/book/intro/install/linux.html#packages) for some examples.

2. Install `openocd`

### Start GDB Server
Connect the board and do ([source](https://docs.rust-embedded.org/book/start/hardware.html#debugging)):

```
$ cd stm32h745i
$ openocd
```

<details>
<summary>Example output</summary>

Open On-Chip Debugger 0.11.0<br>
Licensed under GNU GPL v2<br>
For bug reports, read<br>
http://openocd.org/doc/doxygen/bugs.html<br>
Info : auto-selecting first available session transport "hla_swd". To override use 'transport select <transport>'.<br>
Info : The selected transport took over low-level target control. The results might differ compared to plain JTAG/SWD<br>
Info : Listening on port 6666 for tcl connections<br>
Info : Listening on port 4444 for telnet connections<br>
Info : clock speed 1800 kHz<br>
Info : STLINK V3J3M2 (API v3) VID:PID 0483:374E<br>
Info : Target voltage: 3.284462<br>
Info : stm32h7x.cpu0: hardware has 8 breakpoints, 4 watchpoints<br>
Info : starting gdb server for stm32h7x.cpu0 on 3333<br>
Info : Listening on port 3333 for gdb connections<br>

</details>

### Connect a GDB Client
In a second terminal, do ([source]()):

```
$ cd sindri
$ arm-none-eabi-gdb -x openocd.gdb target/thumbv7em-none-eabihf/debug/rng_single_core [--tui]
```

# STM32H745I-DISCO

This example runs a Heimlig core and a client in separate
[Embassy](https://embassy.dev/)
tasks on the Cortex-M7 of a
[STM32H745I-DISCO](https://www.st.com/en/evaluation-tools/stm32h745i-disco.html)
discovery board.

## Quickstart

1. Obtain a
[STM32H745I-DISCO](https://www.st.com/en/evaluation-tools/stm32h745i-disco.html)
discovery board
2. Install
[probe-run](https://crates.io/crates/probe-run):
`cargo install probe-run`
3. Switch to the example directory: `cd examples/stm32h745i/cm7`
4. Connect the board via its `STLK` (`CN14`) Micro USB socket
5. Run the example: `cargo run --bin rng_single_core`

The output should look similar to the following:

```output
cargo run --bin rng_single_core
    Finished dev [unoptimized + debuginfo] target(s) in 0.09s
     Running `probe-run -v --chip STM32H745XIHx target/thumbv7em-none-eabihf/debug/rng_single_core`
(HOST) DEBUG vector table: VectorTable { initial_stack_pointer: 24020000, hard_fault: 8032011 }
└─ probe_run::elf @ ${HOME}/.cargo/registry/src/github.com-1ecc6299db9ec823/probe-run-0.3.3/src/elf.rs:29
[...]
(HOST) DEBUG Successfully attached RTT
└─ probe_run @ ${HOME}/.cargo/registry/src/github.com-1ecc6299db9ec823/probe-run-0.3.3/src/main.rs:407
────────────────────────────────────────────────────────────────────────────────
0.000000 INFO  Main task started
└─ rng_single_core::____embassy_main_task::{async_fn#0} @ src/bin/rng_single_core.rs:163
0.000518 INFO  Client task started
└─ rng_single_core::__client_task_task::{async_fn#0} @ src/bin/rng_single_core.rs:127
0.001037 INFO  HSM task started
└─ rng_single_core::__hsm_task_task::{async_fn#0} @ src/bin/rng_single_core.rs:99
0.002075 INFO  New random seed (size=32, data=[11, e1, 39, a3, 16, 13, 38, 3c, bb, b5, 7c, 38, 26, 5c, 54, 1a, ee, d5, f1, c9, 58, a2, 3c, 47, dd, 0f, b6, bd, d3, 71, 9a, 82])
└─ rng_single_core::{impl#0}::random_seed::{closure#0} @ src/bin/rng_single_core.rs:45
1.001129 INFO  Sending request: random data (size=16)
└─ rng_single_core::__client_task_task::{async_fn#0} @ src/bin/rng_single_core.rs:137
1.028442 INFO  Received response: random data (size=16): [6f, df, 12, d2, ce, 89, 80, 13, 92, 17, 43, 6c, af, 53, 89, 18]
└─ rng_single_core::__client_task_task::{async_fn#0} @ src/bin/rng_single_core.rs:146
```

## Limitations

The motivation for the choice of the
[STM32H745I-DISCO](https://www.st.com/en/evaluation-tools/stm32h745i-disco.html)
board is the fact that it features both a Cortex-M4 and a Cortex-M7 microprocessor.
This allows for a setup where one processor runs the Heimlig core and the other one acts as a client.
However, the current setup runs both as separate tasks on a single core.

## Debugging on STM32H745I-DISCO

## Installation

Debugging requires `arm-none-eabi-gdb` and `openocd`.
For information on how to install them, have a look at
[this](https://docs.rust-embedded.org/book/intro/install/linux.html#packages)
of the Embedded Rust Book.

## Start GDB Server

Connect the board and run the following commands
([source](https://docs.rust-embedded.org/book/start/hardware.html#debugging)):

```sh
cd examples/stm32h745i
openocd
```

Example output:

```output
Open On-Chip Debugger 0.11.0<br>
Licensed under GNU GPL v2<br>
For bug reports, read<br>
<http://openocd.org/doc/doxygen/bugs.html><br>
Info : auto-selecting first available session transport "hla_swd". To override use 'transport
select <transport>'.<br>
Info : The selected transport took over low-level target control. The results might differ compared
to plain JTAG/SWD<br>
Info : Listening on port 6666 for tcl connections<br>
Info : Listening on port 4444 for telnet connections<br>
Info : clock speed 1800 kHz<br>
Info : STLINK V3J3M2 (API v3) VID:PID 0483:374E<br>
Info : Target voltage: 3.284462<br>
Info : stm32h7x.cpu0: hardware has 8 breakpoints, 4 watchpoints<br>
Info : starting gdb server for stm32h7x.cpu0 on 3333<br>
Info : Listening on port 3333 for gdb connections<br>
```

## Connect a GDB Client

In a second terminal run:

```sh
cd examples/stm32h745i
arm-none-eabi-gdb -x openocd.gdb cm7/target/thumbv7em-none-eabihf/debug/rng_single_core [--tui]
```

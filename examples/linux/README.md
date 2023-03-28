# Demonstrating Heimlig on a Local Linux Machine

This directory contains an example setup of a Heimlig core and a client running in separate
[Embassy](https://embassy.dev/)
tasks.

The client continuously sends requests for random data to the core and prints the response to
standard output.
The communication between client and core is implemented using
[heapless queues](https://docs.rs/heapless/latest/heapless/spsc/struct.Queue.html).

## Quickstart

```bash
cd examples/linux
cargo run
```

Example output:

```output
    Finished dev [unoptimized + debuginfo] target(s) in 0.07s
     Running `target/debug/linux`
2022-11-25T14:16:01.055Z INFO  [CLIENT] Sending request: random data (size=16)
2022-11-25T14:16:01.065Z INFO  [CLIENT] Received response: random data (size=16): 346edeb787c093f2ec35b1c0b7ba58c6
```

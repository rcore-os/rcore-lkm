# Demo for `rcore-lkm` in user space

## How to run

Requirements: Linux with Rust toolchain.

```shell
make
```

## Bugs

* `mock-kernel` will raise a segfault when `init_module`.

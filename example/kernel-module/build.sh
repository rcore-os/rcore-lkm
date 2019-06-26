#!/bin/bash
echo "Step 1. Fetching dependencies according to cargo."
cargo build --target=x86_64-unknown-linux-musl

echo "Step 2. Compile the library"
rustc --edition=2018 --crate-name kernel_module src/lib.rs \
--color always --crate-type staticlib  -C debuginfo=2 \
--out-dir ./target/debug/objs \
--target x86_64-unknown-linux-musl \
-L dependency=target/debug/deps \
--emit=obj --sysroot `rustc --print sysroot` \
-L all=../mock-kernel/target/x86_64-unknown-linux-musl/debug/deps

echo "Step 3. Packing the library into kernel module."
ld -shared -o target/debug/kernel_module.ko target/debug/objs/*.o

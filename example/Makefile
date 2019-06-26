all:
	rustup target add x86_64-unknown-linux-musl
	cd mock-kernel && cargo build --target x86_64-unknown-linux-musl
	cd kernel-module && ./build.sh
	cd mock-kernel && \
		nm target/x86_64-unknown-linux-musl/debug/mock-kernel > symbol && \
		cargo run --target x86_64-unknown-linux-musl
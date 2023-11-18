export RUSTUP_DIST_SERVER=https://mirrors.ustc.edu.cn/rust-static
export RUSTUP_UPDATE_ROOT=https://mirrors.ustc.edu.cn/rust-static/rustup

OUTPUT_DIR = $(DADK_BUILD_CACHE_DIR_NOVA_SHELL_0_1_0)
TMP_INSTALL_DIR=$(OUTPUT_DIR)/tmp_install

all: build

build:
	RUSTFLAGS='-C target-feature=+crt-static -C link-arg=-no-pie' cargo build --target=x86_64-unknown-linux-musl --release

install:
	mkdir -p $(TMP_INSTALL_DIR)
	mkdir -p $(OUTPUT_DIR)

	RUSTFLAGS='-C target-feature=+crt-static -C link-arg=-no-pie' cargo install --target=x86_64-unknown-linux-musl --path .  --root $(TMP_INSTALL_DIR)
	mv $(TMP_INSTALL_DIR)/bin/NovaShell $(OUTPUT_DIR)/NovaShell
	rm -rf $(TMP_INSTALL_DIR)

clean:
	cargo clean


fmt:
	cargo fmt

fmt-check:
	cargo fmt --check

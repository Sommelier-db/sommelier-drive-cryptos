cargo +nightly build --release &&
rustup run nightly cbindgen --config cbindgen.toml --crate sommelier-drive-cryptos --output sommelier_drive_cryptos.h
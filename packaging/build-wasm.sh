#!/bin/sh
# Build the Howdah core as WebAssembly and place it where the static demo
# (site/demo/) loads it. Requires: rustup target add wasm32-unknown-unknown
set -eu
cd "$(dirname "$0")/.."
cargo build -p howdah-wasm --target wasm32-unknown-unknown --release
mkdir -p site/demo
cp target/wasm32-unknown-unknown/release/howdah_wasm.wasm site/demo/howdah_wasm.wasm
ls -l site/demo/howdah_wasm.wasm

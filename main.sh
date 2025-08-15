#!/bin/bash
set -e

echo "Bash script start..."

echo "Install ossl dependencies"
sudo apt-get install pkg-config libssl-dev

echo "cargo build"
cargo build
./target/debug/datex-crypt

echo "release"
cargo build --release
./target/release/datex-crypt

echo "Bash script end..."

#!/bin/bash
set -e

echo "Bash script start..."

echo "Install ossl dependencies"
sudo apt-get install pkg-config libssl-dev

echo "cargo build"
cargo build

echo "run"
./target/debug/datex-crypt

echo "Bash script end..."

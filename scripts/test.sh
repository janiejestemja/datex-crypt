#!/bin/bash
set -e

echo "Bash script start..."

echo "Install ossl dependencies"
sudo apt-get install pkg-config libssl-dev

echo "cargo build"
cargo test

echo "Bash script end..."

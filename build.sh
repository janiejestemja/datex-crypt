#!/bin/bash

echo "Start script..."

cargo build --features server
echo "Copy server..."
cp target/debug/datex-crypt test/server.elf

cargo build --features client
echo "Copy client..."
cp target/debug/datex-crypt test/client.elf

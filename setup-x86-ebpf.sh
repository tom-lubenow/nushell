#!/bin/bash
# Setup script for x86_64 eBPF testing

echo "Setting up x86_64 Lima VM for eBPF testing..."

# Update and install dependencies
sudo apt-get update
sudo apt-get install -y \
    build-essential \
    pkg-config \
    libssl-dev \
    linux-headers-$(uname -r) \
    clang \
    llvm \
    bpftrace \
    curl \
    git

# Install Rust
if ! command -v rustc &> /dev/null; then
    echo "Installing Rust..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
else
    echo "Rust already installed"
fi

# Install nightly toolchain
echo "Installing nightly toolchain..."
rustup install nightly

# Add eBPF target
echo "Adding eBPF target..."
rustup +nightly target add bpfel-unknown-none

echo "Setup complete!"
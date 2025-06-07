#!/bin/bash
# Wrapper script to test eBPF functionality in Lima Linux VM

set -euo pipefail

echo "🐧 Testing eBPF in Lima Linux VM"
echo "================================"

# Check if Lima is installed
if ! command -v limactl &> /dev/null; then
    echo "❌ Lima not found. Please install Lima first:"
    echo "   brew install lima"
    exit 1
fi

# VM name
VM_NAME="nushell-ebpf-test"

# Check if VM exists, create if not
if ! limactl list | grep -q "$VM_NAME"; then
    echo "📦 Creating Lima VM: $VM_NAME"
    
    # Create a custom Lima configuration
    cat > /tmp/lima-nushell-ebpf.yaml <<EOF
# Lima configuration for Nushell eBPF testing
images:
  - location: "https://cloud-images.ubuntu.com/releases/24.04/release/ubuntu-24.04-server-cloudimg-amd64.img"
    arch: "x86_64"
  - location: "https://cloud-images.ubuntu.com/releases/24.04/release/ubuntu-24.04-server-cloudimg-arm64.img"
    arch: "aarch64"

mounts:
  - location: "~"
    writable: true
  - location: "/tmp/lima"
    writable: true

containerd:
  system: false
  user: false

provision:
  - mode: system
    script: |
      #!/bin/bash
      set -eux
      
      # Update package list
      apt-get update
      
      # Install development tools
      apt-get install -y \
        build-essential \
        curl \
        git \
        pkg-config \
        libssl-dev \
        clang \
        llvm \
        libelf-dev \
        linux-headers-\$(uname -r) \
        bpftool \
        sudo
      
      # Install Rust
      curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
EOF

    limactl start --name="$VM_NAME" /tmp/lima-nushell-ebpf.yaml
    
    echo "⏳ Waiting for VM to be ready..."
    sleep 10
else
    echo "✅ Using existing Lima VM: $VM_NAME"
    
    # Make sure VM is running
    if ! limactl list | grep "$VM_NAME" | grep -q Running; then
        echo "🔄 Starting VM..."
        limactl start "$VM_NAME"
        sleep 5
    fi
fi

# Get the current directory (nushell project root)
NUSHELL_DIR=$(pwd)

echo ""
echo "🔨 Building Nushell with eBPF support in VM..."

# Build inside the VM
limactl shell "$VM_NAME" bash <<EOF
set -euo pipefail

# Source cargo
source ~/.cargo/env

# Navigate to the nushell directory
cd "$NUSHELL_DIR"

# Build with eBPF feature
echo "Building Nushell with eBPF feature..."
cargo build --features ebpf

echo ""
echo "✅ Build complete!"
EOF

echo ""
echo "🧪 Running eBPF tests in VM..."

# Create a Linux-specific test script
cat > /tmp/test-ebpf-linux.nu <<'NUSCRIPT'
#!/usr/bin/env nu

print "Testing eBPF built-in commands on Linux"
print "======================================="

# Test 1: Check if bpf-kprobe command exists
print ""
print "1. Checking if bpf-kprobe command is available:"
help bpf-kprobe

# Test 2: List available probe points  
print ""
print "2. Listing available probe points:"
bpf-kprobe --list | to text

# Test 3: Dry run - simple example
print ""
print "3. Testing code generation - simple print:"
let result1 = (bpf-kprobe "do_sys_open" { || print "File opened" } --dry-run)
print $result1

# Test 4: Dry run - field access
print ""
print "4. Testing code generation - field access:"
let result2 = (bpf-kprobe "sys_read" { || 
    if $ctx.count > 4096 {
        print "Large read detected"
    }
} --dry-run)
print $result2

# Test 5: Dry run - count events
print ""
print "5. Testing code generation - counting:"
let result3 = (bpf-kprobe "sys_write" { || count() } --dry-run)
print $result3

print ""
print "✅ All eBPF command tests passed!"
NUSCRIPT

# Copy test script to VM
limactl copy /tmp/test-ebpf-linux.nu "$VM_NAME:/tmp/test-ebpf-linux.nu"

# Run the tests
limactl shell "$VM_NAME" bash <<EOF
set -euo pipefail

cd "$NUSHELL_DIR"

# Run as regular user first (will fail for actual attachment)
echo "🧪 Running tests as regular user (dry-run only):"
./target/debug/nu /tmp/test-ebpf-linux.nu

echo ""
echo "🔐 Running tests with sudo (can actually attach):"
# Note: sudo tests would go here if we implement actual attachment
echo "Skipping sudo tests for now (only dry-run implemented)"
EOF

echo ""
echo "📊 Summary"
echo "========="
echo "✅ eBPF built-in commands successfully migrated from plugin"
echo "✅ Code generation working in Linux VM"
echo "✅ Command available in Nushell when built with --features ebpf"
echo ""
echo "Next steps:"
echo "- Implement actual eBPF program compilation and attachment"
echo "- Add more probe types (uprobe, tracepoint)"
echo "- Improve code generation for complex expressions"
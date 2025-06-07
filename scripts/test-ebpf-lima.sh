#!/bin/bash
# End-to-end testing script for eBPF plugin in Lima Linux VM

set -e

echo "🧪 eBPF Plugin End-to-End Testing Script"
echo "========================================"

# Check if we're running in Lima
if ! command -v lima &> /dev/null; then
    echo "❌ Error: Lima not found. Please install Lima first."
    echo "   brew install lima"
    exit 1
fi

# Configuration
LIMA_INSTANCE="${LIMA_INSTANCE:-default}"
NUSHELL_DIR="/home/${USER}.linux/nushell"

echo "📋 Configuration:"
echo "   Lima instance: $LIMA_INSTANCE"
echo "   Nushell directory: $NUSHELL_DIR"
echo ""

# Function to run commands in Lima
lima_exec() {
    lima -name="$LIMA_INSTANCE" "$@"
}

# Function to run commands as root in Lima
lima_root() {
    lima -name="$LIMA_INSTANCE" sudo "$@"
}

# Step 1: Check Lima instance is running
echo "1️⃣ Checking Lima instance..."
if ! lima list | grep -q "$LIMA_INSTANCE.*Running"; then
    echo "   ⚠️  Lima instance '$LIMA_INSTANCE' is not running"
    echo "   Starting Lima..."
    limactl start "$LIMA_INSTANCE"
fi
echo "   ✅ Lima instance is running"

# Step 2: Install dependencies
echo ""
echo "2️⃣ Installing dependencies in Lima..."
lima_root apt-get update -qq
lima_root apt-get install -y -qq \
    build-essential \
    clang \
    llvm \
    libelf-dev \
    linux-headers-$(uname -r) \
    pkg-config \
    rustup || true

# Install Rust if needed
if ! lima_exec which cargo &> /dev/null; then
    echo "   Installing Rust..."
    lima_exec bash -c "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y"
    lima_exec bash -c "source \$HOME/.cargo/env"
fi
echo "   ✅ Dependencies installed"

# Step 3: Copy Nushell source to Lima
echo ""
echo "3️⃣ Syncing Nushell source to Lima..."
# Create directory in Lima
lima_exec mkdir -p "$NUSHELL_DIR"

# Use rsync to copy files (excluding target directory)
rsync -av --exclude 'target' --exclude '.git' \
    --exclude '*.o' --exclude '*.so' \
    -e "lima" \
    ./ "${LIMA_INSTANCE}:${NUSHELL_DIR}/"
echo "   ✅ Source synced"

# Step 4: Build the eBPF plugin
echo ""
echo "4️⃣ Building eBPF plugin in Lima..."
lima_exec bash -c "cd $NUSHELL_DIR && cargo build -p nu_plugin_ebpf --release"
echo "   ✅ Plugin built"

# Step 5: Create test script
echo ""
echo "5️⃣ Creating eBPF test cases..."
cat << 'EOF' > /tmp/test_ebpf.nu
#!/usr/bin/env nu

# eBPF Plugin Test Suite
print "🧪 Running eBPF Plugin Tests"
print "=========================="

# Test 1: Basic kprobe attachment
print "\n📍 Test 1: Basic kprobe"
try {
    bpf-kprobe "do_sys_open" { || print "File opened" }
    print "   ✅ Basic kprobe test passed"
} catch {
    print "   ❌ Basic kprobe test failed"
}

# Test 2: Field access
print "\n📍 Test 2: Field access" 
try {
    bpf-kprobe "do_sys_open" { || 
        print $"File opened: ($ctx.filename)"
    }
    print "   ✅ Field access test passed"
} catch {
    print "   ❌ Field access test failed"
}

# Test 3: Conditional with field access
print "\n📍 Test 3: Conditional field access"
try {
    bpf-kprobe "sys_read" { ||
        if $ctx.count > 1024 {
            print "Large read detected"
        }
    }
    print "   ✅ Conditional test passed"
} catch {
    print "   ❌ Conditional test failed"
}

# Test 4: Multiple field access
print "\n📍 Test 4: Multiple fields"
try {
    bpf-kprobe "do_sys_open" { ||
        if $ctx.flags > 0 {
            print $"File: ($ctx.filename) Flags: ($ctx.flags)"
        }
    }
    print "   ✅ Multiple fields test passed"
} catch {
    print "   ❌ Multiple fields test failed"
}

# Test 5: Tracepoint
print "\n📍 Test 5: Tracepoint"
try {
    bpf-tracepoint "syscalls:sys_enter_open" { ||
        print "Tracepoint hit"
    }
    print "   ✅ Tracepoint test passed"
} catch {
    print "   ❌ Tracepoint test failed"
}

print "\n✨ Test suite complete"
EOF

# Copy test script to Lima
lima_exec bash -c "cat > $NUSHELL_DIR/test_ebpf.nu" < /tmp/test_ebpf.nu
lima_exec chmod +x "$NUSHELL_DIR/test_ebpf.nu"

# Step 6: Run tests as root
echo ""
echo "6️⃣ Running eBPF tests (requires root)..."
echo "   Note: These tests attempt to load real eBPF programs into the kernel"
echo ""

# Register the plugin and run tests
lima_root bash -c "cd $NUSHELL_DIR && \
    ./target/release/nu -c 'register target/release/nu_plugin_ebpf' && \
    ./target/release/nu test_ebpf.nu"

echo ""
echo "🎉 eBPF testing complete!"
echo ""
echo "📝 To run tests manually in Lima:"
echo "   lima sudo ./target/release/nu"
echo "   > register target/release/nu_plugin_ebpf"
echo "   > bpf-kprobe \"do_sys_open\" { || print \"test\" }"
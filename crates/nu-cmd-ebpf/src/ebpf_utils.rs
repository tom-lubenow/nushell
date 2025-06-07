/// Utility functions for eBPF commands

#[cfg(target_os = "linux")]
pub fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

#[cfg(target_os = "linux")]
pub fn has_cap_bpf() -> bool {
    // In a full implementation, we would check for CAP_BPF capability
    // For now, just check if we're root
    is_root()
}

#[cfg(target_os = "linux")]
pub fn kernel_supports_ebpf() -> Result<bool, std::io::Error> {
    use std::fs;
    
    // Check if BPF syscall is available by looking for BPF filesystem
    Ok(fs::metadata("/sys/fs/bpf").is_ok())
}

#[cfg(target_os = "linux")]
pub fn has_btf_support() -> Result<bool, std::io::Error> {
    use std::fs;
    
    // Check if BTF is available
    Ok(fs::metadata("/sys/kernel/btf/vmlinux").is_ok())
}

/// Information about available eBPF features
#[cfg(target_os = "linux")]
pub struct EbpfCapabilities {
    pub has_root: bool,
    pub has_cap_bpf: bool,
    pub kernel_supports_ebpf: bool,
    pub has_btf: bool,
}

#[cfg(target_os = "linux")]
impl EbpfCapabilities {
    pub fn check() -> Self {
        Self {
            has_root: is_root(),
            has_cap_bpf: has_cap_bpf(),
            kernel_supports_ebpf: kernel_supports_ebpf().unwrap_or(false),
            has_btf: has_btf_support().unwrap_or(false),
        }
    }
    
    pub fn is_sufficient(&self) -> bool {
        (self.has_root || self.has_cap_bpf) && self.kernel_supports_ebpf
    }
    
    pub fn error_message(&self) -> String {
        let mut issues = Vec::new();
        
        if !self.has_root && !self.has_cap_bpf {
            issues.push("Requires root or CAP_BPF capability");
        }
        
        if !self.kernel_supports_ebpf {
            issues.push("Kernel does not support eBPF");
        }
        
        if !self.has_btf {
            issues.push("BTF (BPF Type Format) not available");
        }
        
        if issues.is_empty() {
            "eBPF is supported".to_string()
        } else {
            format!("eBPF issues: {}", issues.join(", "))
        }
    }
}
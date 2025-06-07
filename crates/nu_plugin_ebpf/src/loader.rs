/// Linux-specific eBPF program loading using Aya
/// This module provides the actual kernel interface for loading
/// and attaching eBPF programs on Linux systems

#[cfg(target_os = "linux")]
use aya::{
    programs::{KProbe, Program},
    maps::HashMap,
    Ebpf,
    EbpfLoader,
};


use std::path::Path;

/// Result type for eBPF operations
pub type EbpfResult<T> = Result<T, EbpfError>;

/// Errors that can occur during eBPF operations
#[derive(Debug)]
pub enum EbpfError {
    /// Failed to compile eBPF program
    CompilationError(String),
    /// Failed to load eBPF program into kernel
    LoadError(String),
    /// Failed to attach eBPF program to probe
    AttachError(String),
    /// Feature not supported on this platform
    NotSupported(String),
    /// I/O error
    IoError(std::io::Error),
}

impl std::fmt::Display for EbpfError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EbpfError::CompilationError(e) => write!(f, "eBPF compilation error: {}", e),
            EbpfError::LoadError(e) => write!(f, "eBPF load error: {}", e),
            EbpfError::AttachError(e) => write!(f, "eBPF attach error: {}", e),
            EbpfError::NotSupported(e) => write!(f, "Not supported: {}", e),
            EbpfError::IoError(e) => write!(f, "I/O error: {}", e),
        }
    }
}

impl From<std::io::Error> for EbpfError {
    fn from(e: std::io::Error) -> Self {
        EbpfError::IoError(e)
    }
}

/// Load and attach an eBPF kprobe program
#[cfg(target_os = "linux")]
pub fn load_kprobe_program(
    bytecode_path: &Path,
    function_name: &str,
    program_name: &str,
) -> EbpfResult<KProbeHandle> {
    eprintln!("🔧 Loading eBPF program from: {}", bytecode_path.display());
    
    // Load the eBPF bytecode
    let mut bpf = match EbpfLoader::new()
        .btf(aya::Btf::from_sys_fs().ok().as_ref())
        .load_file(bytecode_path)
    {
        Ok(bpf) => bpf,
        Err(e) => return Err(EbpfError::LoadError(format!("Failed to load eBPF file: {}", e))),
    };
    
    // Initialize eBPF logger for debugging
    if let Err(e) = aya_log::EbpfLogger::init(&mut bpf) {
        eprintln!("⚠️  Failed to initialize eBPF logger: {}", e);
    }
    
    // Get the kprobe program
    let program: &mut KProbe = match bpf.program_mut(program_name) {
        Some(Program::KProbe(prog)) => prog,
        _ => return Err(EbpfError::LoadError(
            format!("Program '{}' not found or is not a kprobe", program_name)
        )),
    };
    
    // Load the program into the kernel
    program.load()
        .map_err(|e| EbpfError::LoadError(format!("Failed to load program: {}", e)))?;
    
    // Attach to the kernel function
    program.attach(function_name, 0)
        .map_err(|e| EbpfError::AttachError(
            format!("Failed to attach to function '{}': {}", function_name, e)
        ))?;
    
    eprintln!("✅ Successfully attached eBPF program to function '{}'", function_name);
    
    // Create handle for managing the program
    Ok(KProbeHandle {
        _bpf: bpf,
        function_name: function_name.to_string(),
        program_name: program_name.to_string(),
    })
}

/// Handle for managing a loaded kprobe
#[cfg(target_os = "linux")]
pub struct KProbeHandle {
    _bpf: Ebpf,
    function_name: String,
    program_name: String,
}

#[cfg(target_os = "linux")]
impl KProbeHandle {
    /// Get the function being probed
    pub fn function_name(&self) -> &str {
        &self.function_name
    }
    
    /// Get the program name
    pub fn program_name(&self) -> &str {
        &self.program_name
    }
}

/// Stream events from eBPF maps to Nushell pipeline
#[cfg(target_os = "linux")]
pub fn stream_events(handle: &mut KProbeHandle) -> impl Iterator<Item = Value> {
    // TODO: Implement actual event streaming from perf buffers or ring buffers
    // For now, return a placeholder
    std::iter::empty()
}

/// Load a kprobe program (stub for non-Linux platforms)
#[cfg(not(target_os = "linux"))]
pub fn load_kprobe_program(
    _bytecode_path: &Path,
    _function_name: &str,
    _program_name: &str,
) -> EbpfResult<()> {
    Err(EbpfError::NotSupported(
        "eBPF loading is only supported on Linux".to_string()
    ))
}

/// Compile eBPF source to bytecode
pub fn compile_ebpf_source(
    rust_source: &str,
    output_path: &Path,
) -> EbpfResult<()> {
    use std::fs;
    use std::process::Command;
    
    // Create a temporary project directory
    let temp_dir = tempfile::tempdir()?;
    let project_path = temp_dir.path();
    
    // Create Cargo.toml for eBPF project
    let cargo_toml = r#"
[package]
name = "ebpf_program"
version = "0.1.0"
edition = "2021"

[dependencies]
aya-bpf = "0.1"
aya-log-ebpf = "0.1"

[[bin]]
name = "ebpf_program"
path = "src/main.rs"

[profile.release]
panic = "abort"
lto = true
opt-level = 3

[build]
target = "bpfel-unknown-none"
"#;
    
    fs::write(project_path.join("Cargo.toml"), cargo_toml)?;
    
    // Create src directory and write source
    let src_dir = project_path.join("src");
    fs::create_dir_all(&src_dir)?;
    fs::write(src_dir.join("main.rs"), rust_source)?;
    
    // Build with cargo-bpf
    eprintln!("🔨 Compiling eBPF program...");
    let output = Command::new("cargo")
        .args(&[
            "build",
            "--release",
            "--target", "bpfel-unknown-none",
            "-Z", "build-std=core",
        ])
        .current_dir(project_path)
        .env("CARGO_TARGET_BPFEL_UNKNOWN_NONE_LINKER", "rust-lld")
        .env("RUSTFLAGS", "-C link-arg=--btf")
        .output()
        .map_err(|e| EbpfError::CompilationError(
            format!("Failed to run cargo: {}", e)
        ))?;
    
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(EbpfError::CompilationError(
            format!("Compilation failed:\n{}", stderr)
        ));
    }
    
    // Copy the compiled program to output path
    let compiled_path = project_path
        .join("target")
        .join("bpfel-unknown-none")
        .join("release")
        .join("ebpf_program");
    
    fs::copy(&compiled_path, output_path)
        .map_err(|e| EbpfError::IoError(e))?;
    
    eprintln!("✅ eBPF program compiled to: {}", output_path.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_error_display() {
        let err = EbpfError::NotSupported("test feature".to_string());
        assert_eq!(err.to_string(), "Not supported: test feature");
    }
}
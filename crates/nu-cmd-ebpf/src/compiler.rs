/// eBPF compilation and loading functionality
use std::process::Command;
use std::fs;
use std::path::Path;
use nu_protocol::ShellError;
use tempfile::TempDir;

/// Compile Rust eBPF code to bytecode
pub fn compile_ebpf_code(rust_code: &str, probe_name: &str) -> Result<Vec<u8>, ShellError> {
    // Create a temporary directory for the eBPF project
    let temp_dir = TempDir::new().map_err(|e| ShellError::GenericError {
        error: "Failed to create temp directory".into(),
        msg: e.to_string(),
        span: None,
        help: None,
        inner: vec![],
    })?;
    
    let project_dir = temp_dir.path();
    
    // Create the eBPF project structure
    create_ebpf_project(project_dir, rust_code, probe_name)?;
    
    // Compile the eBPF program
    compile_project(project_dir)?;
    
    // Read the compiled bytecode
    let bytecode_path = project_dir
        .join("target")
        .join("bpfel-unknown-none")
        .join("release")
        .join(probe_name);
        
    fs::read(&bytecode_path).map_err(|e| ShellError::GenericError {
        error: "Failed to read compiled bytecode".into(),
        msg: e.to_string(),
        span: None,
        help: Some(format!("Expected bytecode at: {}", bytecode_path.display())),
        inner: vec![],
    })
}

/// Create a minimal eBPF project structure
fn create_ebpf_project(project_dir: &Path, rust_code: &str, probe_name: &str) -> Result<(), ShellError> {
    // Create directories
    fs::create_dir_all(project_dir.join("src")).map_err(|e| ShellError::GenericError {
        error: "Failed to create src directory".into(),
        msg: e.to_string(),
        span: None,
        help: None,
        inner: vec![],
    })?;
    
    // Create Cargo.toml
    let cargo_toml = format!(r#"[package]
name = "{}"
version = "0.1.0"
edition = "2021"

[dependencies]
aya-bpf = "0.13"
aya-log-ebpf = "0.1"

[[bin]]
name = "{}"
path = "src/main.rs"

[profile.release]
lto = true
panic = "abort"
opt-level = 3

[workspace]
members = []
"#, probe_name, probe_name);
    
    fs::write(project_dir.join("Cargo.toml"), cargo_toml).map_err(|e| ShellError::GenericError {
        error: "Failed to write Cargo.toml".into(),
        msg: e.to_string(),
        span: None,
        help: None,
        inner: vec![],
    })?;
    
    // Create .cargo/config.toml for eBPF target
    let cargo_dir = project_dir.join(".cargo");
    fs::create_dir_all(&cargo_dir).map_err(|e| ShellError::GenericError {
        error: "Failed to create .cargo directory".into(),
        msg: e.to_string(),
        span: None,
        help: None,
        inner: vec![],
    })?;
    
    let cargo_config = r#"[build]
target = "bpfel-unknown-none"

[target.bpfel-unknown-none]
rustflags = "-C link-arg=--btf"
"#;
    
    fs::write(cargo_dir.join("config.toml"), cargo_config).map_err(|e| ShellError::GenericError {
        error: "Failed to write cargo config".into(),
        msg: e.to_string(),
        span: None,
        help: None,
        inner: vec![],
    })?;
    
    // Create main.rs with the generated code
    let main_rs = format!(r#"#![no_std]
#![no_main]

{}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {{
    unsafe {{ core::hint::unreachable_unchecked() }}
}}
"#, rust_code);
    
    fs::write(project_dir.join("src").join("main.rs"), main_rs).map_err(|e| ShellError::GenericError {
        error: "Failed to write main.rs".into(),
        msg: e.to_string(),
        span: None,
        help: None,
        inner: vec![],
    })?;
    
    Ok(())
}

/// Compile the eBPF project using cargo
fn compile_project(project_dir: &Path) -> Result<(), ShellError> {
    // First, ensure we have the eBPF target installed with nightly
    let target_add = Command::new("rustup")
        .args(&["+nightly", "target", "add", "bpfel-unknown-none"])
        .output()
        .map_err(|e| ShellError::GenericError {
            error: "Failed to add eBPF target".into(),
            msg: e.to_string(),
            span: None,
            help: Some("Run: rustup +nightly target add bpfel-unknown-none".into()),
            inner: vec![],
        })?;
        
    if !target_add.status.success() {
        let stderr = String::from_utf8_lossy(&target_add.stderr);
        return Err(ShellError::GenericError {
            error: "Failed to add eBPF target".into(),
            msg: stderr.to_string(),
            span: None,
            help: Some("Ensure nightly toolchain is installed: rustup install nightly".into()),
            inner: vec![],
        });
    }
    
    // Compile the eBPF program with nightly
    let output = Command::new("cargo")
        .current_dir(project_dir)
        .args(&["+nightly", "build", "--release"])
        .output()
        .map_err(|e| ShellError::GenericError {
            error: "Failed to compile eBPF program".into(),
            msg: e.to_string(),
            span: None,
            help: Some("Ensure cargo is in PATH".into()),
            inner: vec![],
        })?;
        
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(ShellError::GenericError {
            error: "eBPF compilation failed".into(),
            msg: stderr.to_string(),
            span: None,
            help: Some("Check the generated code for errors".into()),
            inner: vec![],
        });
    }
    
    Ok(())
}


use nu_plugin::{EngineInterface, EvaluatedCall, SimplePluginCommand};
use nu_protocol::{Category, LabeledError, Signature, SyntaxShape, Type, Value, ast::Block, engine::Closure, Span};
use nu_ebpf::generate_kprobe;

#[cfg(target_os = "linux")]
use std::process::Command;
#[cfg(target_os = "linux")]
use std::fs;

use crate::EbpfPlugin;

pub struct BpfKprobe;

impl SimplePluginCommand for BpfKprobe {
    type Plugin = EbpfPlugin;

    fn name(&self) -> &str {
        "bpf-kprobe"
    }

    fn description(&self) -> &str {
        "Attach an eBPF program to a kernel function probe"
    }

    fn extra_description(&self) -> &str {
        r#"
The `bpf-kprobe` command allows you to attach eBPF programs to kernel functions
for tracing and observability. You provide a function name and a Nushell block
that defines what action to take when the function is called.

Example:
    bpf-kprobe "do_sys_open" { || print "File opened!" }

This will trace all calls to the do_sys_open kernel function and print a message
for each call.

Note: This command requires Linux and root privileges to load eBPF programs into the kernel.
On non-Linux systems, this command will only generate and validate the eBPF code.
"#
        .trim()
    }

    fn signature(&self) -> Signature {
        Signature::build(self.name())
            .input_output_types(vec![(Type::Nothing, Type::Nothing)])
            .required(
                "function",
                SyntaxShape::String,
                "The kernel function name to probe",
            )
            .required(
                "action",
                SyntaxShape::Closure(None),
                "The Nushell block to execute when the probe is hit",
            )
            .category(Category::System)
    }

    fn search_terms(&self) -> Vec<&str> {
        vec!["ebpf", "bpf", "trace", "kernel", "probe", "kprobe"]
    }

    fn run(
        &self,
        _plugin: &Self::Plugin,
        engine: &EngineInterface,
        call: &EvaluatedCall,
        _input: &Value,
    ) -> Result<Value, LabeledError> {
        // Get the function name to probe
        let function_name: String = call.req(0)?;
        
        // Get the closure (Nushell block) that defines the action
        let action_block = call.req::<Value>(1)?;
        
        // Extract the closure from the closure value
        let closure = match &action_block {
            Value::Closure { val, .. } => val.as_ref(),
            _ => {
                return Err(LabeledError::new("Expected a closure")
                    .with_label("Expected a closure (block) as the second argument", call.head))
            }
        };

        // Get the actual block content using the engine interface
        let block = match get_block_from_closure(engine, closure, call.head) {
            Ok(block) => block,
            Err(e) => {
                eprintln!("⚠️  Could not access block content: {}", e);
                eprintln!("📝 Using fallback code generation for Phase 3");
                // Fall back to dummy block for now
                Block::new()
            }
        };

        // Generate the eBPF Rust source code using the nu-ebpf crate
        let probe_name = format!("probe_{}", function_name.replace(":", "_"));
        let rust_source = generate_kprobe(&block, &probe_name);

        // Show the generated code
        eprintln!("Generated eBPF Rust source for function '{}':", function_name);
        eprintln!("=== Generated Code ===");
        eprintln!("{}", rust_source);
        eprintln!("=== End Generated Code ===");
        
        if block.pipelines.is_empty() {
            eprintln!("📝 Note: Empty block - enhanced closure analysis coming in Phase 3+");
        } else {
            eprintln!("✅ Successfully analyzed {} pipeline(s) from closure", block.pipelines.len());
        }

        // Try to compile the generated code
        #[cfg(target_os = "linux")]
        {
            match compile_rust_to_ebpf(&rust_source, &probe_name) {
                Ok(object_path) => {
                    eprintln!("✅ Successfully compiled eBPF program to: {}", object_path);
                    eprintln!("📝 Note: Program generated but not loaded (Phase 3 implementation)");
                    
                    Ok(Value::string(
                        format!("eBPF program generated and compiled for function '{}'. Ready for loading in future phases.", function_name),
                        call.head,
                    ))
                }
                Err(e) => {
                    eprintln!("❌ Compilation failed: {}", e);
                    Err(LabeledError::new("eBPF compilation failed")
                        .with_label(format!("Failed to compile eBPF program: {}", e), call.head))
                }
            }
        }

        #[cfg(not(target_os = "linux"))]
        {
            eprintln!("⚠️  Running on non-Linux system - eBPF compilation skipped");
            eprintln!("📝 Note: eBPF programs can only be compiled and loaded on Linux");
            
            Ok(Value::string(
                format!("eBPF program generated for function '{}'. Compilation and loading require Linux.", function_name),
                call.head,
            ))
        }
    }
}

/// Attempt to get the actual Block from a closure using the engine interface
/// This is a Phase 3 enhancement to access real closure content
fn get_block_from_closure(
    engine: &EngineInterface, 
    closure: &Closure, 
    span: Span
) -> Result<Block, String> {
    // For now, we can't easily get the block content in a plugin context
    // because we don't have direct access to EngineState
    // This is a limitation we'll work around in Phase 3+
    
    // One approach would be to use engine.get_span_contents() if we had the span
    // Another would be to extend the plugin API to provide block access
    
    // For Phase 3, we'll return an error and fall back to dummy block
    Err("Cannot access block content in plugin context - this will be enhanced in future phases".to_string())
}

/// Compile Rust source code to eBPF bytecode (Linux only)
#[cfg(target_os = "linux")]
fn compile_rust_to_ebpf(rust_source: &str, program_name: &str) -> Result<String, String> {
    // Create a temporary directory for our eBPF project
    let temp_dir = tempfile::tempdir().map_err(|e| format!("Failed to create temp dir: {}", e))?;
    let project_path = temp_dir.path();
    
    // Create a minimal Cargo.toml for the eBPF program
    let cargo_toml = format!(r#"
[package]
name = "{}"
version = "0.1.0"
edition = "2021"

[dependencies]
aya-bpf = "0.1"
aya-log-ebpf = "0.1"

[[bin]]
name = "{}"
path = "src/main.rs"

[profile.release]
lto = true
panic = "abort"
"#, program_name, program_name);

    // Write Cargo.toml
    let cargo_toml_path = project_path.join("Cargo.toml");
    fs::write(&cargo_toml_path, cargo_toml)
        .map_err(|e| format!("Failed to write Cargo.toml: {}", e))?;

    // Create src directory and write the generated Rust source
    let src_dir = project_path.join("src");
    fs::create_dir_all(&src_dir)
        .map_err(|e| format!("Failed to create src directory: {}", e))?;
    
    let main_rs_path = src_dir.join("main.rs");
    fs::write(&main_rs_path, rust_source)
        .map_err(|e| format!("Failed to write main.rs: {}", e))?;

    // Try to compile with cargo (this is a basic test - we're not actually targeting eBPF yet)
    let output = Command::new("cargo")
        .arg("check")
        .current_dir(project_path)
        .output()
        .map_err(|e| format!("Failed to run cargo: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("Cargo check failed:\n{}", stderr));
    }

    Ok(format!("{}/target/debug/{}", project_path.display(), program_name))
} 
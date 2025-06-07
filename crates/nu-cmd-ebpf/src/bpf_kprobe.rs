use nu_engine::command_prelude::*;
use nu_protocol::IntoPipelineData;

#[derive(Clone)]
pub struct BpfKprobe;

impl Command for BpfKprobe {
    fn name(&self) -> &str {
        "bpf-kprobe"
    }

    fn signature(&self) -> Signature {
        Signature::build("bpf-kprobe")
            .input_output_types(vec![(Type::Nothing, Type::Nothing)])
            .rest(
                "args",
                SyntaxShape::Any,
                "Probe name and program closure",
            )
            .switch(
                "dry-run",
                "Generate eBPF code without attaching",
                Some('d'),
            )
            .category(Category::System)
    }

    fn description(&self) -> &str {
        "Attach an eBPF program to a kernel probe point"
    }

    fn extra_description(&self) -> &str {
        r#"This command allows you to attach eBPF programs to kernel functions for monitoring
and tracing. The program is written as a Nushell closure and compiled to eBPF bytecode.

Requirements:
- Linux kernel 4.18+ with eBPF support
- Root privileges or CAP_BPF capability
- BTF (BPF Type Format) enabled kernel

Examples:
  # Monitor file opens
  bpf-kprobe "do_sys_open" { || print "File opened" }
  
  # Count system calls
  bpf-kprobe "sys_write" { || count() }
  
  # Filter and log large reads
  bpf-kprobe "sys_read" { || 
    if $ctx.count > 4096 {
      print "Large read detected"
    }
  }
  
  # Dry run to see generated code
  bpf-kprobe "sys_open" { || print "test" } --dry-run"#
    }

    fn search_terms(&self) -> Vec<&str> {
        vec!["trace", "kernel", "monitor", "probe", "ebpf", "bpf"]
    }

    fn examples(&self) -> Vec<Example> {
        vec![
            Example {
                description: "Monitor file opens",
                example: r#"bpf-kprobe "do_sys_open" { || print "File opened" }"#,
                result: None,
            },
            Example {
                description: "Generate eBPF code without attaching",
                example: r#"bpf-kprobe "sys_read" { || count() } --dry-run"#,
                result: None,
            },
        ]
    }

    fn run(
        &self,
        engine_state: &EngineState,
        stack: &mut Stack,
        call: &Call,
        _input: PipelineData,
    ) -> Result<PipelineData, ShellError> {
        // Check flags first (they work on all platforms)
        let dry_run = call.has_flag(engine_state, stack, "dry-run")?;
        
        // Get all arguments
        let args: Vec<Value> = call.rest(engine_state, stack, 0)?;
        
        if args.len() < 2 {
            return Err(ShellError::MissingParameter {
                param_name: "probe and program".into(),
                span: call.head,
            });
        }
        
        // Extract probe name
        let probe_name = args[0].as_str()?;
        
        // Get the closure expression from the second argument
        let closure_value = &args[1];
        let closure_expr = match closure_value {
            Value::Closure { val, .. } => {
                // Get the block from the closure
                engine_state.get_block(val.block_id).clone()
            }
            _ => {
                return Err(ShellError::TypeMismatch {
                    err_message: "Expected closure".into(),
                    span: call.head,
                });
            }
        };

        // We already have the block from the closure
        let block = closure_expr;
        
        // Handle dry-run (works on all platforms)
        if dry_run {
            return generate_and_display_code(&probe_name, &block, engine_state, call);
        }
        
        // Actual attachment requires Linux
        #[cfg(not(target_os = "linux"))]
        {
            return Err(ShellError::GenericError {
                error: "eBPF commands are only supported on Linux".into(),
                msg: "Attaching eBPF programs requires Linux with eBPF support".into(),
                span: Some(call.head),
                help: Some("Use --dry-run to see the generated code, or run on Linux to attach".into()),
                inner: vec![],
            });
        }

        #[cfg(target_os = "linux")]
        {
            // Attach and run the eBPF program
            attach_ebpf_program(&probe_name, &block, engine_state, call)
        }
    }
}

#[cfg(target_os = "linux")]
fn list_probe_points(_call: &Call) -> Result<PipelineData, ShellError> {
    let probe_points = vec![
        Value::record(
            record! {
                "name" => Value::string("do_sys_open", Span::unknown()),
                "description" => Value::string("File open operations", Span::unknown()),
                "fields" => Value::string("filename, flags, mode", Span::unknown()),
            },
            Span::unknown(),
        ),
        Value::record(
            record! {
                "name" => Value::string("sys_read", Span::unknown()),
                "description" => Value::string("File read operations", Span::unknown()),
                "fields" => Value::string("fd, buf, count", Span::unknown()),
            },
            Span::unknown(),
        ),
        Value::record(
            record! {
                "name" => Value::string("sys_write", Span::unknown()),
                "description" => Value::string("File write operations", Span::unknown()),
                "fields" => Value::string("fd, buf, count", Span::unknown()),
            },
            Span::unknown(),
        ),
        Value::record(
            record! {
                "name" => Value::string("tcp_connect", Span::unknown()),
                "description" => Value::string("TCP connection attempts", Span::unknown()),
                "fields" => Value::string("sk, addr_len", Span::unknown()),
            },
            Span::unknown(),
        ),
        Value::record(
            record! {
                "name" => Value::string("kmalloc", Span::unknown()),
                "description" => Value::string("Kernel memory allocation", Span::unknown()),
                "fields" => Value::string("size, flags", Span::unknown()),
            },
            Span::unknown(),
        ),
    ];

    Ok(Value::list(probe_points, Span::unknown()).into_pipeline_data())
}

fn generate_and_display_code(
    probe_name: &str,
    block: &nu_protocol::ast::Block,
    engine_state: &EngineState,
    call: &Call,
) -> Result<PipelineData, ShellError> {
    // Generate the eBPF code using our improved code generator with engine state
    let generated_code = crate::codegen::generate_ebpf_with_engine(
        block,
        probe_name,
        engine_state,
        &mut Stack::new(),
    )?;

    // Create output record
    let output = record! {
        "probe" => Value::string(probe_name, call.head),
        "generated_code" => Value::string(generated_code, call.head),
        "status" => Value::string("dry-run", call.head),
    };

    Ok(Value::record(output, call.head).into_pipeline_data())
}

#[cfg(target_os = "linux")]
fn attach_ebpf_program(
    probe_name: &str,
    block: &nu_protocol::ast::Block,
    engine_state: &EngineState,
    call: &Call,
) -> Result<PipelineData, ShellError> {
    use crate::ebpf_utils;
    
    // Check if running as root
    if !ebpf_utils::is_root() {
        return Err(ShellError::GenericError {
            error: "Insufficient privileges".into(),
            msg: "eBPF requires root or CAP_BPF capability".into(),
            span: Some(call.head),
            help: Some("Run with sudo or grant CAP_BPF capability".into()),
            inner: vec![],
        });
    }

    // Generate the eBPF code using our improved code generator with engine state
    let generated_code = crate::codegen::generate_ebpf_with_engine(
        block,
        probe_name,
        engine_state,
        &mut Stack::new(),  // Use a fresh stack for code generation
    )?;

    // Compile the generated Rust code to eBPF bytecode
    let bytecode = match crate::compiler::compile_ebpf_code(&generated_code, &format!("probe_{}", probe_name)) {
        Ok(bytes) => bytes,
        Err(e) => {
            // If compilation fails, return the error with the generated code for debugging
            return Ok(Value::record(
                record! {
                    "probe" => Value::string(probe_name, call.head),
                    "status" => Value::string("compilation_failed", call.head),
                    "error" => Value::string(e.to_string(), call.head),
                    "generated_code" => Value::string(generated_code, call.head),
                },
                call.head,
            ).into_pipeline_data());
        }
    };
    
    // Load and attach the eBPF program
    match crate::loader::load_and_attach_ebpf(&bytecode, probe_name, &format!("probe_{}", probe_name)) {
        Ok(program) => {
            // Start collecting events
            crate::loader::collect_events(program, call.head)
        }
        Err(e) => {
            // If loading fails, return the error
            Ok(Value::record(
                record! {
                    "probe" => Value::string(probe_name, call.head),
                    "status" => Value::string("load_failed", call.head),
                    "error" => Value::string(e.to_string(), call.head),
                    "generated_code" => Value::string(&generated_code[..500.min(generated_code.len())], call.head),
                },
                call.head,
            ).into_pipeline_data())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_examples() {
        use crate::test_examples;
        test_examples(BpfKprobe {})
    }
}
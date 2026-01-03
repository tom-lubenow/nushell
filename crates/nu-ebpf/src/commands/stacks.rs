//! Display stack traces from an eBPF probe

use nu_engine::command_prelude::*;

/// Display stack traces from an attached probe
#[derive(Clone)]
pub struct EbpfStacks;

impl Command for EbpfStacks {
    fn name(&self) -> &str {
        "ebpf stacks"
    }

    fn description(&self) -> &str {
        "Display stack traces collected by $ctx.kstack or $ctx.ustack in an eBPF closure."
    }

    fn extra_description(&self) -> &str {
        r#"Reads stack traces from an attached probe that uses $ctx.kstack (kernel stacks)
or $ctx.ustack (user stacks).

Each stack trace shows the instruction pointer addresses. Use --symbolize to
resolve kernel addresses to function names via /proc/kallsyms.

Example workflow:
  let id = ebpf attach 'kprobe:do_sys_openat2' {|ctx| $ctx.kstack | emit }
  sleep 2sec
  ebpf stacks $id --symbolize"#
    }

    fn signature(&self) -> Signature {
        Signature::build("ebpf stacks")
            .required("id", SyntaxShape::Int, "Probe ID to get stack traces from")
            .switch("kernel", "Show only kernel stacks (default)", Some('k'))
            .switch("user", "Show only user stacks", Some('u'))
            .switch(
                "symbolize",
                "Resolve kernel addresses to symbols",
                Some('s'),
            )
            .switch("raw", "Show raw addresses without formatting", Some('r'))
            .input_output_types(vec![(Type::Nothing, Type::table())])
            .category(Category::Experimental)
    }

    fn examples(&self) -> Vec<Example<'_>> {
        vec![
            Example {
                example: "let id = ebpf attach 'kprobe:do_sys_openat2' {|ctx| $ctx.kstack | emit }; sleep 2sec; ebpf stacks $id",
                description: "Collect and display kernel stack traces",
                result: None,
            },
            Example {
                example: "ebpf stacks $id --symbolize",
                description: "Show stack traces with kernel symbols resolved",
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
        super::run_on_linux!(engine_state, stack, call, run_stacks)
    }
}

#[cfg(target_os = "linux")]
fn run_stacks(
    engine_state: &EngineState,
    stack: &mut Stack,
    call: &Call,
) -> Result<PipelineData, ShellError> {
    use crate::loader::get_state;
    use crate::symbolize::{format_symbol, symbolize_kernel_stack};

    let id: i64 = call.req(engine_state, stack, 0)?;
    let id = super::validate_probe_id(id, call.head)?;
    let span = call.head;

    let show_kernel = call.has_flag(engine_state, stack, "kernel")?;
    let show_user = call.has_flag(engine_state, stack, "user")?;
    let symbolize = call.has_flag(engine_state, stack, "symbolize")?;
    let raw = call.has_flag(engine_state, stack, "raw")?;

    // Default to kernel if neither flag is set
    let show_kernel = show_kernel || !show_user;

    let state = get_state();
    let mut records: Vec<Value> = Vec::new();

    // Get kernel stacks
    if show_kernel {
        let stacks = state
            .get_kernel_stacks(id)
            .map_err(|e| ShellError::GenericError {
                error: "Failed to get kernel stacks".into(),
                msg: e.to_string(),
                span: Some(span),
                help: None,
                inner: vec![],
            })?;

        for stack_trace in stacks {
            let frames_value = if symbolize && !raw {
                // Resolve to symbols
                let symbols = symbolize_kernel_stack(&stack_trace.frames);
                let frame_strs: Vec<Value> = symbols
                    .iter()
                    .map(|sym| Value::string(format_symbol(sym), span))
                    .collect();
                Value::list(frame_strs, span)
            } else if raw {
                // Show raw hex addresses
                let frame_strs: Vec<Value> = stack_trace
                    .frames
                    .iter()
                    .map(|addr| Value::string(format!("0x{:x}", addr), span))
                    .collect();
                Value::list(frame_strs, span)
            } else {
                // Default: show hex addresses in a formatted way
                let frame_strs: Vec<Value> = stack_trace
                    .frames
                    .iter()
                    .map(|addr| Value::string(format!("0x{:016x}", addr), span))
                    .collect();
                Value::list(frame_strs, span)
            };

            records.push(Value::record(
                record! {
                    "id" => Value::int(stack_trace.id, span),
                    "type" => Value::string("kernel", span),
                    "frames" => frames_value,
                    "depth" => Value::int(stack_trace.frames.len() as i64, span),
                },
                span,
            ));
        }
    }

    // Get user stacks
    if show_user {
        let stacks = state
            .get_user_stacks(id)
            .map_err(|e| ShellError::GenericError {
                error: "Failed to get user stacks".into(),
                msg: e.to_string(),
                span: Some(span),
                help: None,
                inner: vec![],
            })?;

        for stack_trace in stacks {
            // User stacks can't be symbolized without reading /proc/<pid>/maps
            // For now, just show hex addresses
            let frame_strs: Vec<Value> = stack_trace
                .frames
                .iter()
                .map(|addr| {
                    if raw {
                        Value::string(format!("0x{:x}", addr), span)
                    } else {
                        Value::string(format!("0x{:016x}", addr), span)
                    }
                })
                .collect();

            records.push(Value::record(
                record! {
                    "id" => Value::int(stack_trace.id, span),
                    "type" => Value::string("user", span),
                    "frames" => Value::list(frame_strs, span),
                    "depth" => Value::int(stack_trace.frames.len() as i64, span),
                },
                span,
            ));
        }
    }

    Ok(Value::list(records, span).into_pipeline_data())
}

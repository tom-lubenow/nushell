//! `ebpf attach` command - attach an eBPF probe

use nu_engine::command_prelude::*;
use nu_protocol::engine::Closure;
use nu_protocol::{Record, record};

#[derive(Clone)]
pub struct EbpfAttach;

impl Command for EbpfAttach {
    fn name(&self) -> &str {
        "ebpf attach"
    }

    fn description(&self) -> &str {
        "Attach an eBPF probe to a kernel function, tracepoint, or userspace function."
    }

    fn extra_description(&self) -> &str {
        r#"This command compiles a Nushell closure to eBPF bytecode and attaches
it to the specified probe point. The closure runs in the kernel whenever
the probe point is hit.

Context parameter syntax (recommended):
  The closure can take a context parameter to access probe information:

  Universal fields (all probe types):
    {|ctx| $ctx.pid }     - Get process ID (thread ID)
    {|ctx| $ctx.tgid }    - Get thread group ID (process ID)
    {|ctx| $ctx.uid }     - Get user ID
    {|ctx| $ctx.gid }     - Get group ID
    {|ctx| $ctx.comm }    - Get process command name (first 8 bytes)
    {|ctx| $ctx.ktime }   - Get kernel timestamp in nanoseconds

  Kprobe/uprobe fields:
    {|ctx| $ctx.arg0 }    - Get function argument 0
    {|ctx| $ctx.arg1-5 }  - Get function arguments 1-5
    {|ctx| $ctx.retval }  - Get return value (kretprobe/uretprobe only)

  Tracepoint fields:
    Access fields specific to each tracepoint. Fields are read from tracefs.
    Example for syscalls/sys_enter_openat:
      {|ctx| $ctx.dfd }      - Directory file descriptor
      {|ctx| $ctx.filename } - Pointer to filename string
      {|ctx| $ctx.flags }    - Open flags
    Example for syscalls/sys_exit_*:
      {|ctx| $ctx.ret }      - Syscall return value

Output commands:
  emit              - Send value to userspace via perf buffer
  read-str          - Read string from memory pointer (userspace)
  read-kernel-str   - Read string from kernel memory (rare)

Aggregation commands:
  count             - Count occurrences by key
  histogram         - Add value to log2 histogram

Timing commands:
  start-timer       - Start latency timer (in entry probe)
  stop-timer        - Stop timer and return elapsed ns (in return probe)

Shared maps (--pin):
  Use --pin <group> to share maps between separate eBPF programs.
  This is required for latency measurement across kprobe/kretprobe pairs.
  Example:
    ebpf attach --pin latency 'kprobe:do_sys_open' {|ctx| start-timer }
    ebpf attach --pin latency -s 'kretprobe:do_sys_open' {|ctx| stop-timer | emit }

Filtering (using if expressions):
  Use if to filter events at the kernel level - the closure exits
  early if the condition is false:
    {|ctx| if $ctx.pid == 1234 { $ctx.pid | emit } }
    {|ctx| if $ctx.comm == "nginx" { ... } }
    {|ctx| if $ctx.uid == 0 and $ctx.gid == 0 { ... } }
    {|ctx| if $ctx.pid == 1234 or $ctx.uid == 0 { ... } }

Kernel probe formats:
  kprobe:function_name      - Attach to kernel function entry
  kretprobe:function_name   - Attach to kernel function return
  tracepoint:category/name  - Attach to a tracepoint

Userspace probe formats:
  uprobe:/path/to/bin:func  - Attach to userspace function entry
  uretprobe:/path/to/bin:fn - Attach to userspace function return
  uprobe:/path:0x1234       - Attach to offset in binary
  uprobe:/path:func+0x10    - Attach to function + offset
  uprobe:/path:func@1234    - Attach only to process with PID 1234

Captured variables:
  - Integer variables from outer scope can be captured and inlined:
      let pid = 1234; {|ctx| if $ctx.pid == $pid { ... } }  # OK
  - Non-integer captures (strings, lists, etc.) are not supported
  - Only a subset of Nushell operations are supported (no loops, closures, etc.)
  - String comparisons limited to 8 characters

Requirements:
  - Linux kernel 4.18+
  - CAP_BPF capability or root access"#
    }

    fn signature(&self) -> Signature {
        Signature::build("ebpf attach")
            .input_output_types(vec![
                (Type::Nothing, Type::Int),     // Returns probe ID (default)
                (Type::Nothing, Type::Binary),  // Returns ELF with --dry-run
                (Type::Nothing, Type::table()), // Streams events with --stream
            ])
            .required(
                "probe",
                SyntaxShape::String,
                "The probe point (e.g., 'kprobe:sys_clone').",
            )
            .required(
                "closure",
                SyntaxShape::Closure(None),
                "The closure to compile and run as eBPF bytecode in the kernel.",
            )
            .switch(
                "stream",
                "Stream events directly (Ctrl-C to stop)",
                Some('s'),
            )
            .switch(
                "dry-run",
                "Generate bytecode but don't load into kernel",
                Some('n'),
            )
            .named(
                "pin",
                SyntaxShape::String,
                "Pin maps to share between probes (e.g., --pin mygroup)",
                Some('p'),
            )
            .switch(
                "mir-compiler",
                "Use experimental MIR-based compiler (for testing)",
                None,
            )
            .category(Category::Experimental)
    }

    fn search_terms(&self) -> Vec<&str> {
        vec![
            "bpf",
            "kernel",
            "trace",
            "probe",
            "kprobe",
            "tracepoint",
            "uprobe",
            "uretprobe",
            "userspace",
        ]
    }

    fn examples(&self) -> Vec<Example<'_>> {
        vec![
            Example {
                example: "ebpf attach --stream 'kprobe:sys_clone' {|ctx| $ctx.pid | emit }",
                description: "Stream events from sys_clone (Ctrl-C to stop)",
                result: None,
            },
            Example {
                example: "ebpf attach -s 'kprobe:sys_read' {|ctx| $ctx.tgid | emit } | first 10",
                description: "Capture first 10 sys_read events",
                result: None,
            },
            Example {
                example: "ebpf attach -s 'kprobe:sys_read' {|ctx| if $ctx.pid == 1234 { $ctx.pid | emit } }",
                description: "Only trace sys_read for PID 1234 (kernel-side filtering)",
                result: None,
            },
            Example {
                example: "let id = ebpf attach 'kprobe:sys_read' {|ctx| $ctx.pid | emit }; ebpf detach $id",
                description: "Attach and then detach a probe manually",
                result: None,
            },
            Example {
                example: "ebpf attach -s 'uprobe:/usr/bin/python3:Py_Initialize' {|ctx| $ctx.pid | emit }",
                description: "Stream Python interpreter initialization events",
                result: None,
            },
            Example {
                example: "ebpf attach --pin lat 'kprobe:do_sys_open' {|ctx| start-timer }; ebpf attach --pin lat -s 'kretprobe:do_sys_open' {|ctx| stop-timer | emit }",
                description: "Measure file open latency using shared timestamp map",
                result: None,
            },
            Example {
                example: "ebpf attach -s 'tracepoint:syscalls/sys_enter_openat' {|ctx| $ctx.filename | emit }",
                description: "Stream filenames from openat syscalls using tracepoint",
                result: None,
            },
            Example {
                example: "ebpf attach -s 'tracepoint:syscalls/sys_exit_read' {|ctx| $ctx.ret | emit }",
                description: "Stream read syscall return values",
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
        super::run_on_linux!(engine_state, stack, call, run_attach)
    }
}

#[cfg(target_os = "linux")]
fn run_attach(
    engine_state: &EngineState,
    stack: &mut Stack,
    call: &Call,
) -> Result<PipelineData, ShellError> {
    use crate::compiler::{EbpfProgram, IrToEbpfCompiler, ProbeContext};
    use crate::loader::{LoadError, get_state, parse_probe_spec};

    let probe_spec: String = call.req(engine_state, stack, 0)?;
    let closure: Closure = call.req(engine_state, stack, 1)?;
    let dry_run = call.has_flag(engine_state, stack, "dry-run")?;
    let stream = call.has_flag(engine_state, stack, "stream")?;
    let pin_group: Option<String> = call.get_flag(engine_state, stack, "pin")?;
    let use_mir = call.has_flag(engine_state, stack, "mir-compiler")?;

    // MIR compiler path (experimental, not yet fully implemented)
    if use_mir {
        return Err(ShellError::GenericError {
            error: "MIR compiler not yet implemented".into(),
            msg: "The --mir-compiler flag enables the experimental MIR-based compiler, which is still under development".into(),
            span: Some(call.head),
            help: Some("Remove --mir-compiler to use the current compiler".into()),
            inner: vec![],
        });
    }

    // Parse the probe specification (includes validation)
    let (prog_type, target) =
        parse_probe_spec(&probe_spec).map_err(|e| match &e {
            crate::loader::LoadError::FunctionNotFound { name, suggestions } => {
                let help = if suggestions.is_empty() {
                    format!("Check the function name. Use 'sudo cat /sys/kernel/tracing/available_filter_functions | grep {name}' to find available functions.")
                } else {
                    format!("Did you mean: {}?", suggestions.join(", "))
                };
                ShellError::GenericError {
                    error: format!("Kernel function '{}' not found", name),
                    msg: "This function is not available for probing".into(),
                    span: Some(call.head),
                    help: Some(help),
                    inner: vec![],
                }
            }
            crate::loader::LoadError::TracepointNotFound { category, name } => {
                ShellError::GenericError {
                    error: format!("Tracepoint '{}/{}' not found", category, name),
                    msg: "This tracepoint does not exist".into(),
                    span: Some(call.head),
                    help: Some(format!(
                        "Use 'sudo ls /sys/kernel/tracing/events/{}' to see available tracepoints in this category",
                        category
                    )),
                    inner: vec![],
                }
            }
            crate::loader::LoadError::NeedsSudo => {
                ShellError::GenericError {
                    error: "Elevated privileges required".into(),
                    msg: "eBPF operations require root or CAP_BPF capability".into(),
                    span: Some(call.head),
                    help: Some("Run nushell with sudo: sudo nu".into()),
                    inner: vec![],
                }
            }
            _ => ShellError::GenericError {
                error: "Invalid probe specification".into(),
                msg: e.to_string(),
                span: Some(call.head),
                help: Some(
                    "Use format like 'kprobe:sys_clone', 'tracepoint:syscalls/sys_enter_read', or 'uprobe:/path/to/bin:function'".into(),
                ),
                inner: vec![],
            },
        })?;

    // Create probe context for the compiler
    let probe_context = ProbeContext::new(prog_type, &target);

    // Get the block for this closure
    let block = engine_state.get_block(closure.block_id);

    // Compile the closure's IR to eBPF
    let ir_block = block
        .ir_block
        .as_ref()
        .ok_or_else(|| ShellError::GenericError {
            error: "No IR available for closure".into(),
            msg: "The closure could not be compiled to IR".into(),
            span: Some(call.head),
            help: Some("Ensure the closure is a simple expression that can be compiled".into()),
            inner: vec![],
        })?;

    // Use compile_with_context to support:
    // - context parameter syntax like {|ctx| $ctx.pid }
    // - captured integer variables from outer scope like `let pid = 1234; {|| $pid }`
    // - probe-aware compilation (auto-detect userspace vs kernel reads, validate retval)
    let compile_result = IrToEbpfCompiler::compile_with_context(
        ir_block,
        engine_state,
        block,
        &closure.captures,
        probe_context,
    )
    .map_err(|e| ShellError::GenericError {
        error: "eBPF compilation failed".into(),
        msg: e.to_string(),
        span: Some(call.head),
        help: Some(
            "Check that the closure uses only supported BPF commands or context fields".into(),
        ),
        inner: vec![],
    })?;

    let mut program = EbpfProgram::with_maps(
        prog_type,
        &target,
        "nushell_ebpf",
        compile_result.bytecode,
        compile_result.maps,
        compile_result.relocations,
        compile_result.event_schema,
    );

    // Enable map pinning if --pin is specified
    // This allows maps to be shared between separate eBPF programs
    if pin_group.is_some() {
        program = program.with_pinning();
    }

    if dry_run {
        // Return the ELF bytes for inspection
        let elf = program.to_elf().map_err(|e| ShellError::GenericError {
            error: "Failed to generate ELF".into(),
            msg: e.to_string(),
            span: Some(call.head),
            help: None,
            inner: vec![],
        })?;

        return Ok(Value::binary(elf, call.head).into_pipeline_data());
    }

    // Load and attach the program
    let state = get_state();
    let probe_id = state
        .attach_with_pin(&program, pin_group.as_deref())
        .map_err(|e| {
            let (error, help) = match &e {
                LoadError::PermissionDenied => (
                    "Permission denied".into(),
                    Some("Try running with sudo or grant CAP_BPF capability".into()),
                ),
                _ => (e.to_string(), None),
            };
            ShellError::GenericError {
                error: "Failed to attach eBPF probe".into(),
                msg: error,
                span: Some(call.head),
                help,
                inner: vec![],
            }
        })?;

    if stream {
        // Stream events directly - return a ListStream
        let span = call.head;
        let signals = engine_state.signals().clone();
        let iter = EventStreamIterator::new(probe_id, span);
        let list_stream = nu_protocol::ListStream::new(iter, span, signals);
        Ok(PipelineData::ListStream(list_stream, None))
    } else {
        // Return probe ID for manual event polling
        Ok(Value::int(probe_id as i64, call.head).into_pipeline_data())
    }
}

/// Iterator that streams events from an attached eBPF probe
#[cfg(target_os = "linux")]
struct EventStreamIterator {
    probe_id: u32,
    span: nu_protocol::Span,
    pending_events: std::collections::VecDeque<Value>,
}

#[cfg(target_os = "linux")]
impl EventStreamIterator {
    fn new(probe_id: u32, span: nu_protocol::Span) -> Self {
        Self {
            probe_id,
            span,
            pending_events: std::collections::VecDeque::new(),
        }
    }

    fn poll_batch(&mut self) {
        use crate::loader::{BpfEventData, BpfFieldValue, get_state};
        use std::time::Duration;

        let state = get_state();
        if let Ok(events) = state.poll_events(self.probe_id, Duration::from_millis(100)) {
            for e in events {
                let value = match e.data {
                    BpfEventData::Record(fields) => {
                        let mut rec = Record::new();
                        for (name, value) in fields {
                            let val = match value {
                                BpfFieldValue::Int(v) => Value::int(v, self.span),
                                BpfFieldValue::String(s) => Value::string(s, self.span),
                            };
                            rec.push(name, val);
                        }
                        rec.push("cpu", Value::int(e.cpu as i64, self.span));
                        Value::record(rec, self.span)
                    }
                    _ => {
                        let value = match e.data {
                            BpfEventData::Int(v) => Value::int(v, self.span),
                            BpfEventData::String(s) => Value::string(s, self.span),
                            BpfEventData::Bytes(b) => Value::binary(b, self.span),
                            BpfEventData::Record(_) => unreachable!(),
                        };
                        Value::record(
                            record! {
                                "value" => value,
                                "cpu" => Value::int(e.cpu as i64, self.span),
                            },
                            self.span,
                        )
                    }
                };
                self.pending_events.push_back(value);
            }
        }
    }
}

#[cfg(target_os = "linux")]
impl Iterator for EventStreamIterator {
    type Item = Value;

    fn next(&mut self) -> Option<Self::Item> {
        // Return pending events first
        if let Some(event) = self.pending_events.pop_front() {
            return Some(event);
        }

        // Poll for more events (blocking briefly)
        self.poll_batch();
        self.pending_events.pop_front()
    }
}

#[cfg(target_os = "linux")]
impl Drop for EventStreamIterator {
    fn drop(&mut self) {
        // Detach the probe when the stream ends
        use crate::loader::get_state;
        let _ = get_state().detach(self.probe_id);
    }
}

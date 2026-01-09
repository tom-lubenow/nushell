//! Helper commands for eBPF closures
//!
//! These commands are used inside eBPF closures to perform actions:
//! - emit: Send a value to userspace via ring buffer
//! - filter: Exit early if condition is false
//! - count: Increment a counter by key
//! - histogram: Add value to log2 histogram
//! - start-timer: Start latency measurement
//! - stop-timer: Stop timer and return elapsed nanoseconds
//! - read-str: Read string from userspace memory pointer
//! - read-kernel-str: Read string from kernel memory pointer

use nu_engine::command_prelude::*;

// =============================================================================
// Output commands
// =============================================================================

/// Emit a value to the perf buffer
#[derive(Clone)]
pub struct Emit;

impl Command for Emit {
    fn name(&self) -> &str {
        "emit"
    }

    fn description(&self) -> &str {
        "Emit a value to the eBPF perf buffer for streaming to userspace."
    }

    fn extra_description(&self) -> &str {
        r#"Supports both single values (integers) and structured records.
When given a record, all fields are emitted as a single structured event.

Examples:
  {|ctx| $ctx.pid | emit }
  {|ctx| { pid: $ctx.pid, uid: $ctx.uid } | emit }"#
    }

    fn signature(&self) -> Signature {
        Signature::build("emit")
            .input_output_types(vec![(Type::Int, Type::Int), (Type::Any, Type::Any)])
            .category(Category::Experimental)
    }

    fn examples(&self) -> Vec<Example<'_>> {
        vec![
            Example {
                example: "ebpf attach -s 'kprobe:sys_read' {|ctx| $ctx.pid | emit }",
                description: "Emit the PID on each sys_read call",
                result: None,
            },
            Example {
                example: "ebpf attach -s 'kprobe:sys_read' {|ctx| { pid: $ctx.pid, uid: $ctx.uid } | emit }",
                description: "Emit a structured event",
                result: None,
            },
        ]
    }

    fn run(
        &self,
        _engine_state: &EngineState,
        _stack: &mut Stack,
        call: &Call,
        input: PipelineData,
    ) -> Result<PipelineData, ShellError> {
        // Stub for non-eBPF execution (e.g., help display)
        let value = input.into_value(call.head)?;
        Ok(value.into_pipeline_data())
    }
}

/// Filter events - exit early if condition is false
#[derive(Clone)]
pub struct Filter;

impl Command for Filter {
    fn name(&self) -> &str {
        "filter"
    }

    fn description(&self) -> &str {
        "Exit the eBPF program early if the input condition is false."
    }

    fn extra_description(&self) -> &str {
        r#"Takes a boolean value from the pipeline. If false (0), the eBPF
program exits immediately (returns 0), skipping all subsequent
operations. If true (non-zero), execution continues normally.

This is more efficient than emitting all events and filtering
in userspace, as filtered events never leave the kernel.

Examples:
  {|ctx| $ctx.uid == 0 | filter | $ctx.pid | emit }     # Only root
  {|ctx| $ctx.pid > 1000 | filter | $ctx.comm | emit }  # PIDs > 1000"#
    }

    fn signature(&self) -> Signature {
        Signature::build("filter")
            .input_output_types(vec![(Type::Bool, Type::Nothing)])
            .category(Category::Experimental)
    }

    fn examples(&self) -> Vec<Example<'_>> {
        vec![
            Example {
                example: "ebpf attach -s 'kprobe:do_sys_openat2' {|ctx| $ctx.uid == 0 | filter | $ctx.pid | emit }",
                description: "Only emit events for root user",
                result: None,
            },
            Example {
                example: "ebpf attach -s 'kprobe:ksys_read' {|ctx| $ctx.pid != (pgrep nu | first) | filter | $ctx.comm | emit }",
                description: "Filter out events from current shell",
                result: None,
            },
        ]
    }

    fn run(
        &self,
        _engine_state: &EngineState,
        _stack: &mut Stack,
        call: &Call,
        input: PipelineData,
    ) -> Result<PipelineData, ShellError> {
        // Stub for non-eBPF execution - acts as pass-through if true
        let value = input.into_value(call.head)?;
        if value.as_bool().unwrap_or(false) {
            Ok(Value::nothing(call.head).into_pipeline_data())
        } else {
            // In non-eBPF context, we can't really "exit early"
            // Just return nothing
            Ok(Value::nothing(call.head).into_pipeline_data())
        }
    }
}

/// Read a string from a memory pointer (userspace by default)
#[derive(Clone)]
pub struct ReadStr;

impl Command for ReadStr {
    fn name(&self) -> &str {
        "read-str"
    }

    fn description(&self) -> &str {
        "Read a string from a memory pointer and emit it (max 128 bytes)."
    }

    fn extra_description(&self) -> &str {
        r#"Reads a null-terminated string from the given pointer and emits it
to the perf buffer.

By default, reads from userspace memory which covers the most common
use cases:
- Syscall arguments (filenames, paths, buffers)
- Uprobe function arguments

For the rare case of reading from kernel memory (internal kernel
data structures), use read-kernel-str instead."#
    }

    fn signature(&self) -> Signature {
        Signature::build("read-str")
            .input_output_types(vec![(Type::Int, Type::String)])
            .category(Category::Experimental)
    }

    fn examples(&self) -> Vec<Example<'_>> {
        vec![
            Example {
                example: "ebpf attach -s 'kprobe:do_sys_openat2' {|ctx| $ctx.arg1 | read-str }",
                description: "Read filename from syscall argument",
                result: None,
            },
            Example {
                example: "ebpf attach -s 'uprobe:/bin/app:process_file' {|ctx| $ctx.arg0 | read-str }",
                description: "Read string argument from userspace function",
                result: None,
            },
        ]
    }

    fn run(
        &self,
        _engine_state: &EngineState,
        _stack: &mut Stack,
        call: &Call,
        input: PipelineData,
    ) -> Result<PipelineData, ShellError> {
        // Stub for non-eBPF execution
        let _ = input.into_value(call.head)?;
        Ok(Value::string("<string>", call.head).into_pipeline_data())
    }
}

/// Read a string from kernel memory (rare use case)
#[derive(Clone)]
pub struct ReadKernelStr;

impl Command for ReadKernelStr {
    fn name(&self) -> &str {
        "read-kernel-str"
    }

    fn description(&self) -> &str {
        "Read a string from kernel memory pointer and emit it (max 128 bytes)."
    }

    fn extra_description(&self) -> &str {
        r#"Reads a null-terminated string from kernel memory. This is for
advanced use cases where you need to read from internal kernel
data structures.

For most use cases (syscall arguments, uprobe arguments), use
read-str instead which reads from userspace memory."#
    }

    fn signature(&self) -> Signature {
        Signature::build("read-kernel-str")
            .input_output_types(vec![(Type::Int, Type::String)])
            .category(Category::Experimental)
    }

    fn examples(&self) -> Vec<Example<'_>> {
        vec![Example {
            example: "ebpf attach -s 'kprobe:vfs_read' {|ctx| $ctx.arg0 | read-kernel-str }",
            description: "Read from kernel buffer pointer",
            result: None,
        }]
    }

    fn run(
        &self,
        _engine_state: &EngineState,
        _stack: &mut Stack,
        call: &Call,
        input: PipelineData,
    ) -> Result<PipelineData, ShellError> {
        // Stub for non-eBPF execution
        let _ = input.into_value(call.head)?;
        Ok(Value::string("<kernel string>", call.head).into_pipeline_data())
    }
}

// =============================================================================
// Aggregation commands
// =============================================================================

/// Count occurrences by key
#[derive(Clone)]
pub struct Count;

impl Command for Count {
    fn name(&self) -> &str {
        "count"
    }

    fn description(&self) -> &str {
        "Count occurrences by key in an eBPF hash map."
    }

    fn extra_description(&self) -> &str {
        r#"Increments a counter for the input key. Use ebpf counters to read results.

Example:
  let id = ebpf attach 'kprobe:sys_read' {|ctx| $ctx.pid | count }
  sleep 5sec
  ebpf counters $id"#
    }

    fn signature(&self) -> Signature {
        Signature::build("count")
            .input_output_types(vec![(Type::Int, Type::Int)])
            .category(Category::Experimental)
    }

    fn examples(&self) -> Vec<Example<'_>> {
        vec![Example {
            example: "ebpf attach 'kprobe:sys_read' {|ctx| $ctx.pid | count }",
            description: "Count events per PID",
            result: None,
        }]
    }

    fn run(
        &self,
        _engine_state: &EngineState,
        _stack: &mut Stack,
        call: &Call,
        input: PipelineData,
    ) -> Result<PipelineData, ShellError> {
        // Stub for non-eBPF execution
        let value = input.into_value(call.head)?;
        Ok(value.into_pipeline_data())
    }
}

/// Add a value to a log2 histogram
#[derive(Clone)]
pub struct Histogram;

impl Command for Histogram {
    fn name(&self) -> &str {
        "histogram"
    }

    fn description(&self) -> &str {
        "Add a value to a log2 histogram in eBPF."
    }

    fn extra_description(&self) -> &str {
        r#"Computes the log2 bucket for the input value and increments that bucket.
Use ebpf histogram to read results.

Example:
  let id = ebpf attach 'kretprobe:sys_read' {|ctx| stop-timer | histogram }
  sleep 5sec
  ebpf histogram $id"#
    }

    fn signature(&self) -> Signature {
        Signature::build("histogram")
            .input_output_types(vec![(Type::Int, Type::Int)])
            .category(Category::Experimental)
    }

    fn examples(&self) -> Vec<Example<'_>> {
        vec![Example {
            example: "ebpf attach 'kretprobe:sys_read' {|ctx| stop-timer | histogram }",
            description: "Add latency to histogram",
            result: None,
        }]
    }

    fn run(
        &self,
        _engine_state: &EngineState,
        _stack: &mut Stack,
        call: &Call,
        input: PipelineData,
    ) -> Result<PipelineData, ShellError> {
        // Stub for non-eBPF execution
        let value = input.into_value(call.head)?;
        Ok(value.into_pipeline_data())
    }
}

// =============================================================================
// Timing commands
// =============================================================================

/// Start a timer for latency measurement
#[derive(Clone)]
pub struct StartTimer;

impl Command for StartTimer {
    fn name(&self) -> &str {
        "start-timer"
    }

    fn description(&self) -> &str {
        "Start a timer for latency measurement. Pair with stop-timer."
    }

    fn extra_description(&self) -> &str {
        r#"Stores the current kernel timestamp keyed by thread ID.
Use in entry probes (kprobe) and call stop-timer in return probes (kretprobe).

For cross-program timing, use --pin to share the timestamp map:
  ebpf attach --pin lat 'kprobe:func' {|ctx| start-timer }
  ebpf attach --pin lat -s 'kretprobe:func' {|ctx| stop-timer | emit }"#
    }

    fn signature(&self) -> Signature {
        Signature::build("start-timer")
            .input_output_types(vec![(Type::Nothing, Type::Nothing)])
            .category(Category::Experimental)
    }

    fn examples(&self) -> Vec<Example<'_>> {
        vec![Example {
            example: "ebpf attach --pin lat 'kprobe:sys_read' {|ctx| start-timer }",
            description: "Start timer in entry probe",
            result: None,
        }]
    }

    fn run(
        &self,
        _engine_state: &EngineState,
        _stack: &mut Stack,
        call: &Call,
        _input: PipelineData,
    ) -> Result<PipelineData, ShellError> {
        // Stub for non-eBPF execution
        Ok(Value::nothing(call.head).into_pipeline_data())
    }
}

/// Stop a timer and return elapsed nanoseconds
#[derive(Clone)]
pub struct StopTimer;

impl Command for StopTimer {
    fn name(&self) -> &str {
        "stop-timer"
    }

    fn description(&self) -> &str {
        "Stop timer and return elapsed nanoseconds. Pair with start-timer."
    }

    fn extra_description(&self) -> &str {
        r#"Looks up the start timestamp for the current thread, computes elapsed time,
and deletes the map entry. Returns 0 if no matching start-timer was called.

Use in return probes paired with start-timer in entry probes."#
    }

    fn signature(&self) -> Signature {
        Signature::build("stop-timer")
            .input_output_types(vec![(Type::Nothing, Type::Int)])
            .category(Category::Experimental)
    }

    fn examples(&self) -> Vec<Example<'_>> {
        vec![Example {
            example: "ebpf attach --pin lat -s 'kretprobe:sys_read' {|ctx| stop-timer | emit }",
            description: "Stop timer and emit the latency",
            result: None,
        }]
    }

    fn run(
        &self,
        _engine_state: &EngineState,
        _stack: &mut Stack,
        call: &Call,
        _input: PipelineData,
    ) -> Result<PipelineData, ShellError> {
        // Stub for non-eBPF execution
        Ok(Value::int(0, call.head).into_pipeline_data())
    }
}

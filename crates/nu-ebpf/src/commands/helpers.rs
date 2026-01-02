//! Helper commands for eBPF closures
//!
//! These commands are used inside eBPF closures to perform actions:
//! - emit: Send a value to userspace via perf buffer
//! - emit-comm: Send current process name to userspace
//! - count: Increment a counter by key
//! - histogram: Add value to log2 histogram
//! - start-timer: Start latency measurement
//! - stop-timer: Stop timer and return elapsed nanoseconds
//! - read-str: Read string from kernel memory pointer
//! - read-user-str: Read string from userspace memory pointer

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

/// Emit the current process name
#[derive(Clone)]
pub struct EmitComm;

impl Command for EmitComm {
    fn name(&self) -> &str {
        "emit-comm"
    }

    fn description(&self) -> &str {
        "Emit the current process name to the perf buffer as a string."
    }

    fn signature(&self) -> Signature {
        Signature::build("emit-comm")
            .input_output_types(vec![(Type::Nothing, Type::String)])
            .category(Category::Experimental)
    }

    fn examples(&self) -> Vec<Example<'_>> {
        vec![Example {
            example: "ebpf attach -s 'kprobe:sys_read' {|| emit-comm }",
            description: "Emit the current process name",
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
        Ok(Value::string("unknown", call.head).into_pipeline_data())
    }
}

/// Read a string from kernel memory
#[derive(Clone)]
pub struct ReadStr;

impl Command for ReadStr {
    fn name(&self) -> &str {
        "read-str"
    }

    fn description(&self) -> &str {
        "Read a string from kernel memory pointer and emit it (max 128 bytes)."
    }

    fn signature(&self) -> Signature {
        Signature::build("read-str")
            .input_output_types(vec![(Type::Int, Type::String)])
            .category(Category::Experimental)
    }

    fn examples(&self) -> Vec<Example<'_>> {
        vec![Example {
            example: "ebpf attach -s 'kprobe:sys_open' {|ctx| $ctx.arg1 | read-str }",
            description: "Read filename from first argument pointer",
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

/// Read a string from user-space memory
#[derive(Clone)]
pub struct ReadUserStr;

impl Command for ReadUserStr {
    fn name(&self) -> &str {
        "read-user-str"
    }

    fn description(&self) -> &str {
        "Read a string from user-space memory pointer and emit it (max 128 bytes)."
    }

    fn signature(&self) -> Signature {
        Signature::build("read-user-str")
            .input_output_types(vec![(Type::Int, Type::String)])
            .category(Category::Experimental)
    }

    fn examples(&self) -> Vec<Example<'_>> {
        vec![Example {
            example: "ebpf attach -s 'kprobe:do_sys_openat2' {|ctx| $ctx.arg1 | read-user-str }",
            description: "Read filename from user-space pointer",
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
        Ok(Value::string("<user string>", call.head).into_pipeline_data())
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

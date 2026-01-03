//! Display counter values from the `count` command

use nu_engine::command_prelude::*;

/// Display counter values from an attached probe
#[derive(Clone)]
pub struct EbpfCounters;

impl Command for EbpfCounters {
    fn name(&self) -> &str {
        "ebpf counters"
    }

    fn description(&self) -> &str {
        "Display counter values collected by the count command in an eBPF closure."
    }

    fn extra_description(&self) -> &str {
        r#"Reads the counter map from an attached probe that uses the `count` command.
Each row shows a key and the number of times that key was counted.

If the key is a process name (from using $ctx.comm), it will be displayed
as a string. Otherwise numeric keys are displayed as integers.

Example workflow:
  let id = ebpf attach 'kprobe:sys_read' {|ctx| $ctx.pid | count }
  sleep 5sec
  ebpf counters $id"#
    }

    fn signature(&self) -> Signature {
        Signature::build("ebpf counters")
            .required("id", SyntaxShape::Int, "Probe ID to get counters from")
            .input_output_types(vec![(Type::Nothing, Type::table())])
            .category(Category::Experimental)
    }

    fn examples(&self) -> Vec<Example<'_>> {
        vec![
            Example {
                example: "let id = ebpf attach 'kprobe:sys_read' {|ctx| $ctx.pid | count }; sleep 5sec; ebpf counters $id",
                description: "Count sys_read calls per PID and display results",
                result: None,
            },
            Example {
                example: "let id = ebpf attach 'kprobe:sys_read' {|ctx| $ctx.comm | count }; sleep 5sec; ebpf counters $id",
                description: "Count sys_read calls per process name",
                result: None,
            },
            Example {
                example: "ebpf counters $id | sort-by count --reverse",
                description: "Show counters sorted by count descending",
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
        super::run_on_linux!(engine_state, stack, call, run_counters)
    }
}

#[cfg(target_os = "linux")]
fn run_counters(
    engine_state: &EngineState,
    stack: &mut Stack,
    call: &Call,
) -> Result<PipelineData, ShellError> {
    use crate::loader::get_state;

    let id: i64 = call.req(engine_state, stack, 0)?;
    let id = super::validate_probe_id(id, call.head)?;
    let span = call.head;

    let state = get_state();

    let mut records: Vec<Value> = Vec::new();

    // Get integer counters
    let int_entries = state
        .get_counters(id)
        .map_err(|e| ShellError::GenericError {
            error: "Failed to get counters".into(),
            msg: e.to_string(),
            span: Some(span),
            help: None,
            inner: vec![],
        })?;

    for entry in int_entries {
        records.push(Value::record(
            record! {
                "key" => Value::int(entry.key, span),
                "count" => Value::int(entry.count, span),
            },
            span,
        ));
    }

    // Get string counters (from $ctx.comm | count)
    let string_entries = state
        .get_string_counters(id)
        .map_err(|e| ShellError::GenericError {
            error: "Failed to get string counters".into(),
            msg: e.to_string(),
            span: Some(span),
            help: None,
            inner: vec![],
        })?;

    for entry in string_entries {
        records.push(Value::record(
            record! {
                "key" => Value::string(entry.key, span),
                "count" => Value::int(entry.count, span),
            },
            span,
        ));
    }

    Ok(Value::list(records, span).into_pipeline_data())
}

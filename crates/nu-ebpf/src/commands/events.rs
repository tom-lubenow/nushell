//! `ebpf events` command - poll for events from an attached probe

use nu_engine::command_prelude::*;
use std::time::Duration;

#[derive(Clone)]
pub struct EbpfEvents;

impl Command for EbpfEvents {
    fn name(&self) -> &str {
        "ebpf events"
    }

    fn description(&self) -> &str {
        "Poll for events from an attached eBPF probe."
    }

    fn extra_description(&self) -> &str {
        r#"This command polls the perf event buffer from an attached probe
that uses bpf-emit. It returns events as records with the emitted
value and CPU information.

Use with probes that emit values via the bpf-emit command."#
    }

    fn signature(&self) -> Signature {
        Signature::build("ebpf events")
            .input_output_types(vec![(Type::Nothing, Type::table())])
            .required(
                "probe_id",
                SyntaxShape::Int,
                "The probe ID returned by 'ebpf attach'.",
            )
            .named(
                "timeout",
                SyntaxShape::Duration,
                "How long to wait for events",
                Some('t'),
            )
            .category(Category::Experimental)
    }

    fn examples(&self) -> Vec<Example<'_>> {
        vec![Example {
            example: "let id = ebpf attach 'kprobe:sys_clone' {|| bpf-pid | bpf-emit }; sleep 1sec; ebpf events $id",
            description: "Attach a probe and poll for events",
            result: None,
        }]
    }

    fn run(
        &self,
        engine_state: &EngineState,
        stack: &mut Stack,
        call: &Call,
        _input: PipelineData,
    ) -> Result<PipelineData, ShellError> {
        super::run_on_linux!(engine_state, stack, call, run_events)
    }
}

#[cfg(target_os = "linux")]
fn run_events(
    engine_state: &EngineState,
    stack: &mut Stack,
    call: &Call,
) -> Result<PipelineData, ShellError> {
    use crate::loader::{BpfEventData, BpfFieldValue, get_state};

    let probe_id: i64 = call.req(engine_state, stack, 0)?;
    let probe_id = super::validate_probe_id(probe_id, call.head)?;
    let timeout: Option<i64> = call.get_flag(engine_state, stack, "timeout")?;
    let span = call.head;

    let timeout_duration = timeout
        .map(|ns| Duration::from_nanos(ns as u64))
        .unwrap_or(Duration::from_secs(1));

    let state = get_state();
    let events =
        state
            .poll_events(probe_id, timeout_duration)
            .map_err(|e| ShellError::GenericError {
                error: "Failed to poll events".into(),
                msg: e.to_string(),
                span: Some(span),
                help: None,
                inner: vec![],
            })?;

    let values: Vec<Value> = events
        .into_iter()
        .map(|e| {
            match e.data {
                BpfEventData::Record(fields) => {
                    // Structured event - create a record with named fields
                    let mut rec = Record::new();
                    for (name, value) in fields {
                        let val = match value {
                            BpfFieldValue::Int(v) => Value::int(v, span),
                            BpfFieldValue::String(s) => Value::string(s, span),
                        };
                        rec.push(name, val);
                    }
                    // Add CPU field
                    rec.push("cpu", Value::int(e.cpu as i64, span));
                    Value::record(rec, span)
                }
                _ => {
                    // Simple event - wrap in a "value" field
                    let value = match e.data {
                        BpfEventData::Int(v) => Value::int(v, span),
                        BpfEventData::String(s) => Value::string(s, span),
                        BpfEventData::Bytes(b) => Value::binary(b, span),
                        BpfEventData::Record(_) => unreachable!(),
                    };
                    Value::record(
                        record! {
                            "value" => value,
                            "cpu" => Value::int(e.cpu as i64, span),
                        },
                        span,
                    )
                }
            }
        })
        .collect();

    Ok(Value::list(values, span).into_pipeline_data())
}

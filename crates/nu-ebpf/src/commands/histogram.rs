//! Display histogram values from bpf-histogram

use nu_engine::command_prelude::*;

/// Display histogram values from an attached probe
#[derive(Clone)]
pub struct EbpfHistogram;

impl Command for EbpfHistogram {
    fn name(&self) -> &str {
        "ebpf histogram"
    }

    fn description(&self) -> &str {
        "Display histogram values from a probe using bpf-histogram"
    }

    fn extra_description(&self) -> &str {
        r#"Displays the histogram data collected by bpf-histogram.
Each row shows a log2 bucket range and the count of values in that bucket.

The output includes:
- bucket: The bucket number (log2 of value)
- range: The value range for this bucket (e.g., "1024-2047")
- count: Number of values that fell in this bucket
- bar: Visual representation of the count

For latency histograms (from bpf-stop-timer), the range is shown in
nanoseconds by default. Use --unit to change the display unit."#
    }

    fn signature(&self) -> Signature {
        Signature::build("ebpf histogram")
            .required("id", SyntaxShape::Int, "Probe ID to get histogram from")
            .switch(
                "ns",
                "Show ranges as nanoseconds (default for latency)",
                None,
            )
            .input_output_types(vec![(Type::Nothing, Type::table())])
            .category(Category::Experimental)
    }

    fn examples(&self) -> Vec<Example<'_>> {
        vec![
            Example {
                example: "ebpf histogram 1",
                description: "Show histogram from probe 1",
                result: None,
            },
            Example {
                example: "ebpf histogram 1 --ns",
                description: "Show histogram with nanosecond ranges",
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
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (engine_state, stack, call);
            return Err(ShellError::GenericError {
                error: "eBPF is only supported on Linux".into(),
                msg: "This command requires a Linux system with eBPF support".into(),
                span: Some(call.head),
                help: None,
                inner: vec![],
            });
        }

        #[cfg(target_os = "linux")]
        {
            run_histogram(engine_state, stack, call)
        }
    }
}

#[cfg(target_os = "linux")]
fn run_histogram(
    engine_state: &EngineState,
    stack: &mut Stack,
    call: &Call,
) -> Result<PipelineData, ShellError> {
    use crate::loader::get_state;

    let id: i64 = call.req(engine_state, stack, 0)?;
    let id = super::validate_probe_id(id, call.head)?;
    let as_ns = call.has_flag(engine_state, stack, "ns")?;
    let span = call.head;

    let state = get_state();
    let entries = state.get_histogram(id).map_err(|e| ShellError::GenericError {
        error: "Failed to get histogram".into(),
        msg: e.to_string(),
        span: Some(span),
        help: None,
        inner: vec![],
    })?;

    if entries.is_empty() {
        return Ok(Value::list(vec![], span).into_pipeline_data());
    }

    // Find max count for scaling the bar
    let max_count = entries.iter().map(|e| e.count).max().unwrap_or(1);
    let bar_width = 40;

    // Convert entries to a table
    let records: Vec<Value> = entries
        .into_iter()
        .map(|entry| {
            let (low, high) = bucket_range(entry.bucket);

            // Format range based on options
            let range_str = if as_ns {
                if entry.bucket == 0 {
                    "0".to_string()
                } else {
                    format!("{} - {}", format_ns(low), format_ns(high))
                }
            } else if entry.bucket == 0 {
                "0".to_string()
            } else {
                format!("{} - {}", low, high)
            };

            // Create visual bar
            let bar_len = ((entry.count as f64 / max_count as f64) * bar_width as f64) as usize;
            let bar = "#".repeat(bar_len.max(1));

            Value::record(
                record! {
                    "bucket" => Value::int(entry.bucket, span),
                    "range" => Value::string(range_str, span),
                    "count" => Value::int(entry.count, span),
                    "bar" => Value::string(bar, span),
                },
                span,
            )
        })
        .collect();

    Ok(Value::list(records, span).into_pipeline_data())
}

/// Format a nanosecond value as a human-readable duration
#[cfg(target_os = "linux")]
fn format_ns(ns: i64) -> String {
    if ns < 1_000 {
        format!("{}ns", ns)
    } else if ns < 1_000_000 {
        format!("{}us", ns / 1_000)
    } else if ns < 1_000_000_000 {
        format!("{}ms", ns / 1_000_000)
    } else {
        format!("{:.1}s", ns as f64 / 1_000_000_000.0)
    }
}

/// Get the range description for a bucket
#[cfg(target_os = "linux")]
fn bucket_range(bucket: i64) -> (i64, i64) {
    if bucket == 0 {
        (0, 0)
    } else {
        let low = 1i64 << (bucket - 1);
        let high = (1i64 << bucket) - 1;
        (low, high)
    }
}

//! `ebpf detach` command - detach an eBPF probe

use nu_engine::command_prelude::*;

#[derive(Clone)]
pub struct EbpfDetach;

impl Command for EbpfDetach {
    fn name(&self) -> &str {
        "ebpf detach"
    }

    fn description(&self) -> &str {
        "Detach an eBPF probe by its ID."
    }

    fn signature(&self) -> Signature {
        Signature::build("ebpf detach")
            .input_output_types(vec![(Type::Nothing, Type::Nothing)])
            .required("id", SyntaxShape::Int, "The probe ID to detach.")
            .category(Category::Experimental)
    }

    fn examples(&self) -> Vec<Example<'_>> {
        vec![Example {
            example: "ebpf detach 1",
            description: "Detach probe with ID 1",
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
        super::run_on_linux!(engine_state, stack, call, run_detach)
    }
}

#[cfg(target_os = "linux")]
fn run_detach(
    engine_state: &EngineState,
    stack: &mut Stack,
    call: &Call,
) -> Result<PipelineData, ShellError> {
    use crate::loader::{get_state, LoadError};

    let id: i64 = call.req(engine_state, stack, 0)?;
    let id = super::validate_probe_id(id, call.head)?;

    let state = get_state();
    state.detach(id).map_err(|e| {
        let msg = match &e {
            LoadError::ProbeNotFound(id) => format!("No probe found with ID {id}"),
            _ => e.to_string(),
        };
        ShellError::GenericError {
            error: "Failed to detach probe".into(),
            msg,
            span: Some(call.head),
            help: Some("Use 'ebpf list' to see active probes".into()),
            inner: vec![],
        }
    })?;

    Ok(PipelineData::empty())
}

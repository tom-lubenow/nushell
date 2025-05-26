use nu_engine::command_prelude::*;

#[derive(Clone)]
pub struct BpfKprobe;

impl Command for BpfKprobe {
    fn name(&self) -> &str {
        "bpf_kprobe"
    }

    fn signature(&self) -> Signature {
        Signature::build("bpf_kprobe")
            .input_output_types(vec![(Type::Nothing, Type::Nothing)])
            .required(
                "function",
                SyntaxShape::String,
                "Kernel function name to probe.",
            )
            .required(
                "handler",
                SyntaxShape::Closure(Some(vec![SyntaxShape::Any])),
                "Closure to run when the probe is triggered.",
            )
            .category(Category::Experimental)
    }

    fn description(&self) -> &str {
        "Attach a kprobe to a kernel function"
    }

    fn search_terms(&self) -> Vec<&str> {
        vec!["ebpf", "kprobe"]
    }

    fn run(
        &self,
        _engine_state: &EngineState,
        _stack: &mut Stack,
        call: &Call,
        _input: PipelineData,
    ) -> Result<PipelineData, ShellError> {
        Err(ShellError::UnsupportedInput {
            msg: "bpf_kprobe is not implemented".to_string(),
            input: "value originates from here".into(),
            msg_span: call.head,
            input_span: call.head,
        })
    }

    fn examples(&self) -> Vec<Example> {
        vec![Example {
            description: "Attach kprobe (not implemented)",
            example: "bpf_kprobe \"do_sys_open\" {|ctx| echo $ctx }",
            result: None,
        }]
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

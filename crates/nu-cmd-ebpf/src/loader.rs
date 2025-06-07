/// eBPF program loading and attachment using Aya
use nu_protocol::{ShellError, Span, PipelineData, IntoPipelineData};

#[cfg(target_os = "linux")]
use aya::{
    Ebpf,
    programs::{KProbe, kprobe::KProbeLinkId},
};

/// Loaded eBPF program handle
#[cfg(target_os = "linux")]
pub struct LoadedProgram {
    pub bpf: Ebpf,
    pub link: KProbeLinkId,
    pub probe_name: String,
}

#[cfg(not(target_os = "linux"))]
pub struct LoadedProgram {
    pub probe_name: String,
}

/// Load and attach an eBPF program
#[cfg(target_os = "linux")]
pub fn load_and_attach_ebpf(
    bytecode: &[u8],
    probe_name: &str,
    function_name: &str,
) -> Result<LoadedProgram, ShellError> {
    // Load the eBPF program
    let mut bpf = Ebpf::load(bytecode).map_err(|e| ShellError::GenericError {
        error: "Failed to load eBPF program".into(),
        msg: e.to_string(),
        span: None,
        help: Some("Ensure the program is valid eBPF bytecode".into()),
        inner: vec![],
    })?;
    
    // Get the kprobe program
    let program = bpf
        .program_mut(function_name)
        .ok_or_else(|| ShellError::GenericError {
            error: "Program not found".into(),
            msg: format!("Could not find program '{}' in eBPF object", function_name),
            span: None,
            help: Some("Check the generated code for the correct function name".into()),
            inner: vec![],
        })?;
        
    let kprobe: &mut KProbe = program.try_into().map_err(|_| ShellError::GenericError {
        error: "Invalid program type".into(),
        msg: "Expected a kprobe program".into(),
        span: None,
        help: None,
        inner: vec![],
    })?;
    
    // Load the program
    kprobe.load().map_err(|e| ShellError::GenericError {
        error: "Failed to load kprobe".into(),
        msg: e.to_string(),
        span: None,
        help: Some("Ensure you have sufficient privileges (CAP_BPF or root)".into()),
        inner: vec![],
    })?;
    
    // Attach to the kernel function
    let link = kprobe.attach(probe_name, 0).map_err(|e| ShellError::GenericError {
        error: "Failed to attach kprobe".into(),
        msg: e.to_string(),
        span: None,
        help: Some(format!("Ensure '{}' is a valid kernel function", probe_name)),
        inner: vec![],
    })?;
    
    Ok(LoadedProgram {
        bpf,
        link,
        probe_name: probe_name.to_string(),
    })
}

/// Start collecting events from the eBPF program
#[cfg(target_os = "linux")]
pub fn collect_events(
    _program: LoadedProgram,
    span: Span,
) -> Result<PipelineData, ShellError> {
    use nu_protocol::{Value, record};
    
    // For now, just return a status message
    // In a full implementation, we would:
    // 1. Set up perf event arrays or ring buffers
    // 2. Start async event collection
    // 3. Stream events back to Nushell
    
    Ok(Value::record(
        record! {
            "status" => Value::string("attached", span),
            "probe" => Value::string(&_program.probe_name, span),
            "message" => Value::string("eBPF program attached and running", span),
            "info" => Value::string("Event streaming not yet implemented", span),
        },
        span,
    ).into_pipeline_data())
}

/// Stub implementation for non-Linux platforms
#[cfg(not(target_os = "linux"))]
pub fn load_and_attach_ebpf(
    _bytecode: &[u8],
    _probe_name: &str,
    _function_name: &str,
) -> Result<LoadedProgram, ShellError> {
    Err(ShellError::GenericError {
        error: "eBPF not supported".into(),
        msg: "eBPF is only supported on Linux".into(),
        span: None,
        help: None,
        inner: vec![],
    })
}

#[cfg(not(target_os = "linux"))]
pub fn collect_events(
    _program: LoadedProgram,
    _span: Span,
) -> Result<PipelineData, ShellError> {
    Err(ShellError::GenericError {
        error: "eBPF not supported".into(),
        msg: "eBPF is only supported on Linux".into(),
        span: None,
        help: None,
        inner: vec![],
    })
}
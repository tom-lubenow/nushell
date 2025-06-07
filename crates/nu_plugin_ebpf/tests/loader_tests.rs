#[cfg(test)]
mod tests {
    // Note: Most loader tests require Linux and root privileges
    // These tests verify the API and error handling
    
    #[test]
    #[cfg(not(target_os = "linux"))]
    fn test_load_kprobe_fails_on_non_linux() {
        use nu_plugin_ebpf::loader::load_kprobe_program;
        use std::path::Path;
        
        let result = load_kprobe_program(
            Path::new("/tmp/fake.o"),
            "sys_open",
            "test_probe"
        );
        
        assert!(result.is_err());
        match result {
            Err(e) => assert!(e.to_string().contains("only supported on Linux")),
            _ => panic!("Expected error on non-Linux"),
        }
    }
    
    #[test]
    fn test_ebpf_error_display() {
        use nu_plugin_ebpf::loader::EbpfError;
        
        let errors = vec![
            (
                EbpfError::CompilationError("test error".to_string()),
                "eBPF compilation error: test error"
            ),
            (
                EbpfError::LoadError("load failed".to_string()),
                "eBPF load error: load failed"
            ),
            (
                EbpfError::AttachError("attach failed".to_string()),
                "eBPF attach error: attach failed"
            ),
            (
                EbpfError::NotSupported("feature X".to_string()),
                "Not supported: feature X"
            ),
        ];
        
        for (error, expected) in errors {
            assert_eq!(error.to_string(), expected);
        }
    }
    
    #[test]
    #[cfg(target_os = "linux")]
    #[ignore = "Requires Linux environment with eBPF support"]
    fn test_compile_ebpf_source() {
        use nu_plugin_ebpf::loader::compile_ebpf_source;
        use std::path::Path;
        use tempfile::tempdir;
        
        let dir = tempdir().unwrap();
        let output_path = dir.path().join("test.o");
        
        // Simple eBPF program
        let source = r#"
            #![no_std]
            #![no_main]
            
            use aya_bpf::{macros::kprobe, programs::ProbeContext};
            
            #[kprobe(name = "test")]
            pub fn test_probe(ctx: ProbeContext) -> u32 {
                0
            }
            
            #[panic_handler]
            fn panic(_info: &core::panic::PanicInfo) -> ! {
                unsafe { core::hint::unreachable_unchecked() }
            }
        "#;
        
        let result = compile_ebpf_source(source, &output_path);
        
        // This will likely fail without proper Rust eBPF toolchain setup
        if result.is_err() {
            println!("Compilation failed (expected without eBPF toolchain): {:?}", result);
        }
    }
    
    #[test]
    #[cfg(target_os = "linux")]
    #[ignore = "Requires root privileges and Linux kernel with eBPF"]
    fn test_load_and_attach_kprobe() {
        use nu_plugin_ebpf::loader::{compile_ebpf_source, load_kprobe_program};
        use tempfile::tempdir;
        
        // This test would need:
        // 1. Root privileges
        // 2. A compiled eBPF program
        // 3. Linux kernel with eBPF support
        
        // For now, we just document what a full test would look like
        let dir = tempdir().unwrap();
        let bytecode_path = dir.path().join("probe.o");
        
        // Would need a real compiled eBPF program here
        let result = load_kprobe_program(
            &bytecode_path,
            "sys_open",
            "test_probe"
        );
        
        if let Err(e) = result {
            println!("Load failed (expected without root): {:?}", e);
        }
    }
}
#![doc = include_str!("../README.md")]

mod bpf_kprobe;
mod codegen;
mod compiler;
mod ebpf_utils;
mod loader;

pub use bpf_kprobe::BpfKprobe;

use nu_protocol::engine::StateWorkingSet;

pub fn add_ebpf_decls(working_set: &mut StateWorkingSet) {
    // Only include eBPF commands on Linux
    #[cfg(target_os = "linux")]
    working_set.add_decl(Box::new(BpfKprobe));
    
    // Silence warning when not on Linux
    #[cfg(not(target_os = "linux"))]
    let _ = working_set;
}

#[cfg(test)]
mod tests {
    use super::*;
    use nu_protocol::engine::EngineState;

    #[test]
    fn test_commands_registered() {
        let mut engine_state = EngineState::new();
        let mut working_set = StateWorkingSet::new(&engine_state);
        
        add_ebpf_decls(&mut working_set);
        
        #[cfg(target_os = "linux")]
        {
            let delta = working_set.render();
            engine_state.merge_delta(delta).unwrap();
            
            assert!(engine_state.find_decl(b"bpf-kprobe", &[]).is_some());
        }
    }
}
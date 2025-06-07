/// Registry of known probe contexts and their argument types
/// This allows us to generate proper field access code for common kernel functions

use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct ProbeArgument {
    pub name: String,
    pub rust_type: String,
    pub is_pointer: bool,
    pub is_string: bool,
}

#[derive(Debug, Clone)]
pub struct ProbeContext {
    pub function_name: String,
    pub arguments: Vec<ProbeArgument>,
}

impl ProbeContext {
    pub fn new(function_name: &str) -> Self {
        ProbeContext {
            function_name: function_name.to_string(),
            arguments: Vec::new(),
        }
    }
    
    pub fn arg(mut self, name: &str, rust_type: &str, is_pointer: bool, is_string: bool) -> Self {
        self.arguments.push(ProbeArgument {
            name: name.to_string(),
            rust_type: rust_type.to_string(),
            is_pointer,
            is_string,
        });
        self
    }
}

/// Registry of known kernel functions and their contexts
pub struct ProbeRegistry {
    contexts: HashMap<String, ProbeContext>,
}

impl ProbeRegistry {
    pub fn new() -> Self {
        let mut registry = ProbeRegistry {
            contexts: HashMap::new(),
        };
        
        // Register common kernel functions
        registry.register_common_probes();
        registry
    }
    
    fn register_common_probes(&mut self) {
        // File operations
        self.contexts.insert(
            "do_sys_open".to_string(),
            ProbeContext::new("do_sys_open")
                .arg("filename", "u8", true, true)
                .arg("flags", "i32", false, false)
                .arg("mode", "u16", false, false)
        );
        
        self.contexts.insert(
            "sys_open".to_string(),
            ProbeContext::new("sys_open")
                .arg("filename", "u8", true, true)
                .arg("flags", "i32", false, false)
                .arg("mode", "u16", false, false)
        );
        
        self.contexts.insert(
            "sys_read".to_string(),
            ProbeContext::new("sys_read")
                .arg("fd", "u32", false, false)
                .arg("buf", "u8", true, false)
                .arg("count", "usize", false, false)
        );
        
        self.contexts.insert(
            "sys_write".to_string(),
            ProbeContext::new("sys_write")
                .arg("fd", "u32", false, false)
                .arg("buf", "u8", true, false)
                .arg("count", "usize", false, false)
        );
        
        // Network operations
        self.contexts.insert(
            "tcp_connect".to_string(),
            ProbeContext::new("tcp_connect")
                .arg("sk", "sock", true, false)  // struct sock *
                .arg("uaddr", "sockaddr", true, false)  // struct sockaddr *
                .arg("addr_len", "i32", false, false)
        );
        
        self.contexts.insert(
            "tcp_sendmsg".to_string(),
            ProbeContext::new("tcp_sendmsg")
                .arg("sk", "sock", true, false)
                .arg("msg", "msghdr", true, false)
                .arg("size", "usize", false, false)
        );
        
        // Memory operations
        self.contexts.insert(
            "kmalloc".to_string(),
            ProbeContext::new("kmalloc")
                .arg("size", "usize", false, false)
                .arg("flags", "u32", false, false)
        );
        
        self.contexts.insert(
            "kfree".to_string(),
            ProbeContext::new("kfree")
                .arg("ptr", "u8", true, false)
        );
        
        // Process operations
        self.contexts.insert(
            "do_fork".to_string(),
            ProbeContext::new("do_fork")
                .arg("clone_flags", "u64", false, false)
                .arg("stack_start", "u64", false, false)
                .arg("stack_size", "u64", false, false)
                .arg("parent_tidptr", "i32", true, false)
                .arg("child_tidptr", "i32", true, false)
        );
        
        self.contexts.insert(
            "do_exit".to_string(),
            ProbeContext::new("do_exit")
                .arg("code", "i32", false, false)
        );
    }
    
    pub fn get_context(&self, function_name: &str) -> Option<&ProbeContext> {
        self.contexts.get(function_name)
    }
    
    pub fn get_field_type(&self, function_name: &str, field_name: &str) -> Option<&ProbeArgument> {
        self.contexts.get(function_name)
            .and_then(|ctx| ctx.arguments.iter().find(|arg| arg.name == field_name))
    }
}

impl Default for ProbeRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Generate code to access a probe context field
pub fn generate_field_access_code(
    function_name: &str,
    field_name: &str,
    registry: &ProbeRegistry,
) -> Result<String, String> {
    let context = registry.get_context(function_name)
        .ok_or_else(|| format!("Unknown probe function: {}", function_name))?;
    
    let (arg_index, arg) = context.arguments.iter().enumerate()
        .find(|(_, arg)| arg.name == field_name)
        .ok_or_else(|| format!("Unknown field '{}' for probe '{}'", field_name, function_name))?;
    
    if arg.is_string {
        // String field - needs special handling
        Ok(format!(r#"
    // Read string argument {}
    let {}_ptr: *const u8 = ctx.arg({}).ok()?;
    let mut {}_buf = [0u8; 256];
    unsafe {{
        bpf_probe_read_user_str_bytes({}_ptr, &mut {}_buf).ok()?;
    }}
    let {} = core::str::from_utf8(&{}_buf).ok()?;
"#, 
            field_name,
            field_name, arg_index,
            field_name,
            field_name, field_name,
            field_name, field_name
        ))
    } else if arg.is_pointer {
        // Pointer field - needs dereferencing
        Ok(format!(r#"
    // Read pointer argument {}
    let {}_ptr: *const {} = ctx.arg({}).ok()?;
    // Further dereferencing would happen here based on field access
"#,
            field_name,
            field_name, arg.rust_type, arg_index
        ))
    } else {
        // Simple value field
        Ok(format!(r#"
    // Read value argument {}
    let {}: {} = ctx.arg({}).ok()?;
"#,
            field_name,
            field_name, arg.rust_type, arg_index
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_probe_registry() {
        let registry = ProbeRegistry::new();
        
        // Test known function
        let ctx = registry.get_context("do_sys_open").unwrap();
        assert_eq!(ctx.function_name, "do_sys_open");
        assert_eq!(ctx.arguments.len(), 3);
        
        // Test field lookup
        let field = registry.get_field_type("do_sys_open", "filename").unwrap();
        assert_eq!(field.name, "filename");
        assert!(field.is_string);
        assert!(field.is_pointer);
    }
    
    #[test]
    fn test_field_access_code_generation() {
        let registry = ProbeRegistry::new();
        
        // Test string field
        let code = generate_field_access_code("do_sys_open", "filename", &registry).unwrap();
        assert!(code.contains("bpf_probe_read_user_str_bytes"));
        
        // Test simple value field
        let code = generate_field_access_code("sys_read", "fd", &registry).unwrap();
        assert!(code.contains("let fd: u32"));
    }
}
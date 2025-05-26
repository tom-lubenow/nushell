# Implementation Plan: eBPF Scripting in Nushell

## Introduction and Goals

**Objective:** Enable writing eBPF programs using the Nushell scripting language. This will give users a high-level, shell-like interface (akin to **bpftrace**) for eBPF development, but using Nushell’s modern pipeline syntax and structured data. Instead of writing eBPF code in C or learning a new DSL, users can leverage Nushell to define tracing logic and interact with kernel events.

**Background:** eBPF (extended Berkeley Packet Filter) allows sandboxed programs to run inside the Linux kernel, triggered on events like system calls, function entry/exit, tracepoints, etc. Traditionally, eBPF programs are written in C or restricted languages, then compiled to bytecode and loaded into the kernel. Tools like BCC and bpftrace have made eBPF more accessible:

* **BCC (BPF Compiler Collection)** provides Python/C++ APIs to embed C code and load eBPF programs. For example, a simple BCC Python script can embed a C function, load it via `BPF(text=...)`, attach to a kernel hook, and print output via `trace_pipe`.
* **bpftrace** offers a specialized high-level DSL inspired by AWK and C for one-liners and scripts. bpftrace uses LLVM as a backend to compile its scripts to eBPF bytecode, and relies on libbpf/bcc to load and attach probes. It supports built-in primitives (e.g. `pid`, `comm`, `args->field`) and common aggregations (counts, histograms) for quick tracing. The bpftrace language itself is designed for concise observability tools.

**Goal:** Achieve a similar high-level experience **within Nushell**, so users can write eBPF tracing scripts in a familiar shell environment. This involves:

* **Leveraging Nushell’s Language:** Use Nushell’s syntax (pipelines, closures/blocks, conditionals, etc.) to express the logic of eBPF programs. For example, a user might write a Nushell command that attaches to a kernel function and uses a Nushell closure to define the action on each event.
* **Rust eBPF Libraries Integration:** Utilize Rust-based eBPF frameworks (such as **Aya** or **RedBPF**) to compile, load, and manage eBPF programs. These libraries allow writing eBPF in Rust and provide user-space loaders, map access, and attachment APIs.
* **Shell-like Interface:** Provide a REPL-friendly and scriptable interface. Users can interactively run tracing commands, see output streaming in Nushell’s table structures, filter or pipe the results in real time, etc. Essentially, Nushell becomes a front-end to eBPF similar to how bpftrace is a purpose-built front-end.

The end result is a Nushell extension (or set of commands) that let users write, compile, and run eBPF programs on the fly, with high-level language features but under the hood producing safe eBPF bytecode.

## Architectural Approaches for Code Generation

Designing a Nushell-to-eBPF pipeline requires deciding how Nushell script constructs will be translated into eBPF-compatible programs. We consider several architectural options:

* **Option 1: Transpile Nushell to C/LLVM IR, then use Clang/LLVM:**
  Convert the relevant Nushell code (the eBPF portion of the script) into an equivalent C code snippet or LLVM IR, and invoke the LLVM toolchain to compile it to eBPF bytecode. This is analogous to how bpftrace works – bpftrace uses LLVM as a backend to generate eBPF bytecode at runtime. We could, for example, generate a C function based on the Nushell closure and call Clang with `-target bpf` to produce a `.o`. The compiled program would then be loaded via libbpf or a Rust binding. This approach leverages a proven compiler pipeline and can make use of C language features and optimizations (including BTF debugging info for CO-RE). However, it adds a **heavy dependency on Clang/LLVM** in the Nushell context and requires mapping Nushell’s AST to C semantics (which can be complex).

* **Option 2: Transpile Nushell to Rust eBPF code (Aya/RedBPF), then use Rust compiler:**
  Generate a Rust code snippet (using the restricted **no-std eBPF subset** of Rust) from the Nushell script and use the Rust compiler (nightly) to build eBPF bytecode. Rust gained the ability to compile to eBPF target in 2021, allowing eBPF programs to be written in idiomatic Rust. Frameworks like **Aya** and **RedBPF** support this by providing macros and libraries for eBPF context access and map definitions. For example, we could generate a small Rust program with an `#[xdp]` or `#[kprobe]` function containing the logic derived from Nushell, then compile it to BPF. Aya in particular advertises a “high level Rust API to write eBPF code – like bpftrace or the BCC DSL – but using plain Rust”. This option results in a pure-Rust toolchain (no clang needed) and lets us piggy-back on Rust’s type checking and the eBPF-safe standard library provided by Aya/RedBPF. The challenge is automating Rust code generation and managing the Rust compiler invocation at runtime. It may be heavy to spawn `rustc` for each script, but caching or ahead-of-time compilation for common scripts could mitigate this. We should note that **RedBPF** relies on the libbpf C library and has seen less recent maintenance (the community is leaning toward Aya). Aya is pure Rust (no libbpf dependency) and actively developed, making it a good choice.

* **Option 3: Direct eBPF Bytecode Generation (Custom Compiler/Assembler):**
  Write a compiler within Nushell (or a plugin) that directly translates Nushell’s IR into eBPF instructions and uses an assembler or loader to finalize the program. This could involve manually mapping high-level constructs to BPF opcodes or using an existing eBPF assembler library. For example, a loop or conditional in Nushell could be turned into a sequence of BPF jumps and operations. While this offers maximum control and could reduce external dependencies, it significantly increases development complexity – essentially writing a mini-compiler. Unless a suitable library exists to assemble instructions and handle relocation, this is the most ambitious route. (There are projects exploring alternate eBPF DSLs without LLVM – e.g., *Voyant* – but they still require implementing a code generator). Given the complexity, this is likely a **long-term or optional approach**; initial implementation should lean on existing compilers (Option 1 or 2) to quickly get a working system.

**Preferred approach:** Start with **Option 2 (Rust/Aya)** for a cohesive Rust-based stack, falling back to Option 1 (Clang) if needed for expediency in early phases. Aya provides both a kernel-space API (for writing the eBPF program in Rust) and a user-space library for loading programs and interacting with maps. By generating Rust code, we benefit from Rust’s safety and Aya’s features like built-in support for BPF maps and convenience macros. The Rust compiler’s eBPF backend will enforce many eBPF constraints at compile-time (e.g., no unsupported library calls), reducing trial-and-error with the kernel verifier. In contrast, generating C would require careful guardrails to avoid undefined behavior that the verifier rejects.

**Alternate interim approach:** As a quick proof-of-concept, we could initially use **BCC from Nushell**: for instance, expose a Nushell command that takes a string of C code (or a Nushell multiline string block) and uses BCC’s Python API (via FFI) to compile and load it. The user would still be writing C code in that case, so it doesn’t meet the ultimate goal of using Nushell syntax. However, this could validate the end-to-end flow (compilation, loading, attaching, data output) early in the project before the full Nushell-to-eBPF translation is in place.

## Supported Nushell Language Features Under eBPF Constraints

Not all of Nushell’s scripting capabilities can run inside an eBPF program. eBPF programs have strict constraints due to kernel safety rules and the eBPF verifier’s limitations. We must define a **subset of Nushell** that can be compiled to eBPF. Key considerations:

* **Data Types:** eBPF supports integers (up to 64-bit), fixed-length arrays, and structures. It does *not* support heap allocation or arbitrary-length strings in kernel space. Nushell’s rich types (strings, tables, etc.) must be either mapped to simpler types or used only in user-space. Likely, within BPF we will support:

  * Numeric types (ints, maybe booleans as 0/1).
  * Possibly fixed-size byte buffers for data like strings, if needed (e.g., storing a filename of limited length).
  * Pointers can only be used in limited ways (to context or map data). We cannot allow Nushell scripts to have arbitrary references.
  * No floats (BPF has no FPU support).
  * Structured data can be represented via maps or passed via context; for instance, an event record (like a struct with fields for a tracepoint) can be treated as a Nushell record when output to user-space.

* **Variables and Assignment:** Basic variables in Nushell that hold numbers or small values can be allowed. They would correspond to BPF registers or stack slots. We’ll allow `let` bindings of simple types (e.g., counters, flags). However, **no dynamic memory allocation** – so no growing arrays or dictionaries in BPF code (other than BPF Maps, which are pre-allocated kernel data structures accessed via helpers).

* **Arithmetic and Logic:** Supported. eBPF ALU operations (addition, subtraction, bitwise ops, comparisons) are available and can be mapped from Nushell expressions. We must ensure safe usage (e.g., avoid divide-by-zero – the verifier will reject if it can’t prove the divisor nonzero). We can either prohibit division unless the code explicitly checks the divisor, or auto-insert a check.

* **Conditionals:** **`if`/`else`** can be supported, as they compile naturally to conditional jumps. Nushell’s `if cond { block } else { block }` can be part of the DSL subset for BPF logic.

* **Loops:** Generally **disallowed** or heavily restricted. Early on, we will **not support arbitrary loops in the BPF code**, to avoid verifier complexity. The eBPF verifier either rejects loops or requires them to have static bounded iteration that it can unroll/simulate (bounded loops are supported in newer kernels but with a max total instruction limit). Even in Rust eBPF frameworks, loops are discouraged – a developer noted that in RedBPF “the Rust you get to work with is extremely limited: you don't get loops or native function calls… essentially no library support”. This is because any needed iteration (e.g., walking an array or string byte-by-byte) must be unrolled or done via BPF helper calls. For our Nushell DSL, we will **forbid loop constructs** (`loop`, `while`, etc.) inside eBPF closures initially. Iteration over data can often be achieved by BPF map operations or unrolled loops generated behind the scenes if absolutely needed (with caution that the loop bound is small and known).

* **Function Calls and Nushell Commands:** No user-defined function calls inside BPF (BPF doesn’t support calling normal kernel functions except approved helpers; it does support *BPF-to-BPF calls* for subprograms, but we will avoid introducing that complexity initially). Nushell is normally a shell that can run external commands or builtins – none of those can run in kernel. Inside the eBPF context, we **cannot call Nushell built-in commands** (like `open`, `echo`, `where`, etc.) as we normally would in a script. Instead, the BPF closure will use only a limited syntax of expressions, conditionals, and special **BPF built-ins** we introduce (see next point). For example, something like `sys | where size > 1kb` in Nushell is a pipeline filtering files in user-space – that pattern cannot run in kernel. However, an analogous filter on events (e.g., `if ($evt.size > 1024) { ... }` inside the BPF action) would be allowed.

* **BPF-specific built-ins:** We will design a set of **Nushell built-in keywords or functions** to represent common BPF operations that have no direct Nushell equivalent. For instance:

  * `map_insert(key, value)` to update a BPF map.
  * `count()` or `histogram(val)` to perform aggregations (like bpftrace’s `count()` and `hist()` which under the hood use maps).
  * `send(value)` to submit an event to user-space (e.g., writing to a perf ring buffer).
  * These could be implemented as special identifiers in the Nushell-to-BPF compiler that translate to calls to BPF helpers or macros. For example, `send($record)` might translate to calling `bpf_perf_event_output` or using a ring buffer helper to push data to user-space.

* **Access to Context/Data:** In eBPF, when attached to a hook, you get context like function arguments or tracepoint data. We need to expose that to the Nushell script in a friendly way. Our design will likely allow the closure to accept a parameter, say `|event|`, representing the event context. For example:

  ```nushell
  bpf_probe kernel:function("do_sys_open") {|event| 
      if $event.filename == "secret.txt" { send($event.pid) } 
  }
  ```

  Here `$event` could be a record with fields (like `filename`, `pid`, etc.) corresponding to data available at that probe. Under the hood, our compiler knows how to get `filename` from the context (e.g., for a kprobe on `do_sys_open`, it might know via kernel BTF what argument holds the filename pointer, and insert the appropriate BPF code to read that string). Initially, we might restrict context access to simple built-ins: e.g., provide magic variables like `$pid`, `$comm` (process name), `$arg1` etc., similar to bpftrace’s predefined variables. These would be documented and recognized by the translator. We will need to coordinate with kernel BTF or headers to know structure field offsets (more on BTF under *Constraints*).

* **Closures and Blocks:** Nushell supports passing closures (blocks of code) to commands as parameters. We will leverage this heavily: the user will pass a closure to our eBPF command to define the BPF program’s action. For instance, a command `bpf_tracepoint` might accept a closure `{|evt| ... }` that describes what to do each time the tracepoint fires. Nushell’s parser will treat this as a block (of type `Block` in Nushell’s IR). Our plugin can detect and compile that block separately. Because Nushell’s entire script is parsed to IR up front (and the IR won’t change at runtime), we can analyze the closure’s contents before execution. We will enforce that the closure contains only the allowed subset (no disallowed commands or loops, etc.) – if the user attempts something unsupported, we can throw a compile-time error explaining that the construct isn’t available in eBPF scripts.

* **Return values:** eBPF programs typically return an integer (e.g., for XDP or socket filters, returning a code like XDP\_PASS, or 0 for “ok” in tracing programs). We can hide this from the user for most tracing scenarios – our generated code can always return 0 (success) unless a special action requires otherwise. If we eventually support programs that need to drop packets or filter events, we might expose a way for Nushell code to indicate a non-zero return (perhaps via a special variable or function like `return 1` meaning "filter out this event").

* **Multiple Probes / Program Sections:** A single bpftrace script can define multiple probes (each with its own action block) in one script. For Nushell, initially we might handle one probe per command invocation. If users need multiple attachments, they could invoke multiple `bpf_...` commands in parallel or sequence. Eventually, we could allow a Nushell script to define several probes and load them together (e.g., via a higher-level command or a module that groups multiple attachments). This is a more advanced feature; the baseline is one probe per command.

By carefully whitelisting features, we ensure the Nushell-to-eBPF translation produces programs the kernel will accept. We will document the supported Nushell syntax for eBPF (essentially a mini-language within Nushell). This is analogous to how e.g. **redbpf limits Rust features** in eBPF programs (no unbounded loops, no dynamic memory, etc.). Our implementation will either statically prevent disallowed constructs (preferred) or detect them and error out with a clear message.

## Integration with Rust eBPF Frameworks (Aya/RedBPF)

To implement program loading and interaction, we will integrate with existing Rust eBPF libraries:

* **Aya:** A pure-Rust eBPF library that lets you write and load eBPF programs without libbpf. Aya provides:

  * A **proc-macro API** for kernel programs (e.g., attributes like `#[kprobe]` on a Rust function to mark it as a kprobe handler, `#[map]` to define maps).
  * A **userspace API** (`aya::Bpf` and related types) to load compiled bytecode, attach programs to hooks (kprobe, tracepoint, etc.), and read/write maps or perf buffers. Aya focuses on operability and dev experience (e.g., it wraps low-level details, provides error reporting, and supports features like eBPF CO-RE).
  * Unlike BCC, Aya does not need a C toolchain; it uses Rust’s built-in LLVM. Rust nightly (or a bundled LLVM) is the main dependency.

* **RedBPF:** Another Rust eBPF toolchain, which wraps libbpf (C). It offers similar capabilities (user library `redbpf` for loading, and `redbpf-probes` for writing programs in Rust with macros). RedBPF includes `cargo-bpf` to streamline building BPF code. However, RedBPF is somewhat older and, as noted, not as actively maintained as Aya as of recent years. It also requires kernel headers or BTF to generate bindings for context structs, and uses libbpf under the hood (meaning a libbpf dependency or FFI).

**Choice:** We will favor **Aya** for integration, due to its pure-Rust approach and active community support. Using Aya means our Nushell plugin can depend on the `aya` crate. We then have two possible strategies:

1. **Ahead-of-Time (AOT) Build with Aya:** Treat the eBPF program as a separate Rust module that gets built during development or installation. For example, we could pre-write some generic eBPF code in Rust and use Aya’s macros, leaving “holes” or parameters for the dynamic logic. However, because the user’s script logic is dynamic, AOT is not sufficient except for base scaffolding. We could compile a “template” eBPF object that includes helpers and an empty probe, then at runtime perhaps use eBPF tail calls or map-driven logic to customize behavior – but this is very complex and limited. It’s more straightforward to do…

2. **Just-in-Time Build with Aya:** At runtime, when the user invokes our `bpf` command with a Nushell block, our code generator will produce Rust source code for an eBPF program incorporating that logic. We then invoke the Rust compiler (with target bpf) to compile it to bytecode. This can be done by invoking `rustc` as a subprocess, or potentially by using `libafl` or other JIT libraries to invoke the compiler in-process (though subprocess is simpler and reliable). The output `.o` file can then be loaded via Aya’s `Bpf` loader.

   *Example:* The plugin receives a closure that, say, increments a counter in a map. We generate a Rust function:

   ```rust
   #[map(name = "counter_map")]
   static mut COUNTER: HashMap<u32, u64> = HashMap::with_max_entries(1024);

   #[kprobe(name="probe_do_sys_open", fn_name="do_sys_open")]
   pub fn probe_do_sys_open(ctx: aya::programs::KProbeContext) -> u32 {
       unsafe {
           let pid = bpf_core::bpf_get_current_pid_tgid() as u32;
           if /* filename == "secret.txt" logic */ {
               COUNTER.insert(&pid, 1, 0);
           }
       }
       0
   }
   ```

   The above is hypothetical, but shows how Nushell’s `$event.filename` check might be turned into a Rust `if` with a BPF helper call to get current PID and a map update. Aya’s macros and `HashMap` type handle the low-level details of map creation and BPF helper invocation.

   After compiling this, we use `Bpf::load_file("program.o")` (Aya’s API) to load it into the kernel, and then call e.g. `bpf.load_kprobe("probe_do_sys_open")` to attach it to the actual kernel symbol (Aya can attach by function name or offset). Aya would also allow us to open the `counter_map` from user-space to read its contents later.

The Nushell plugin will therefore have two main components:

* **Codegen:** Transform Nushell IR (the closure AST) into Rust source code for the eBPF program.
* **Loader/Runtime:** Use Aya to load the compiled eBPF program, attach it to events, and manage data transfer (maps or perf buffer) between kernel and Nushell.

Aya’s user-space API also supports reading from **perf buffers** or **ring buffers** – typically via a `Poll` or stream interface. We can use that to deliver event data from kernel to user. For example, if the BPF program calls `bpf_ringbuf_output` with a struct, Aya can provide a `ringbuf::RingBuffer` object we poll to get those structs in user-space.

**Alternative fallback:** If the Rust JIT approach proves too slow or complex for initial phases, we might integrate **libbpf** or use BCC’s static library. For instance, the plugin could write out a C file and call `clang` on it, then use libbpf (via `libbpf-rs` bindings or direct FFI) to load and attach. This would mimic what bpftrace does. We lose the pure-Rust advantage but could use well-trodden path of BCC/clang. In either case, integration points like attaching kprobes, reading maps, etc., are well-supported:

* **libbpf-rs** (if used) is a wrapper around libbpf, providing safe Rust methods to load .o files and attach.
* BCC’s approach (as seen in Kevin Sookocheff’s example) uses an internal loop reading `trace_pipe` for output, but we’ll prefer using modern techniques (perf buffers) for structured data.

**Map Integration:** Both Aya and RedBPF offer map abstractions (HashMap, Array, PerfMap, RingBuf, etc.). Our generated code can declare maps using these, and the plugin can use the user-space handle to retrieve data. For example, if a user’s Nushell script wants to count events per PID, we’d generate a HashMap (key=pid, value=count) in BPF. On the Nushell side, after the program runs (or periodically), we can query that map and present the results (perhaps as a Nushell table). Aya’s user API allows map lookups and iterations.

**Cleanup:** Integration also involves ensuring that when a Nushell process ends or the user stops the trace (Ctrl+C), we detach probes and unload programs to avoid leaking kernel resources. Aya provides a Drop for Bpf that will unload programs, but explicit detach calls might be needed for certain program types. We should handle signal interrupts in the plugin (Nushell’s plugin protocol might allow detecting pipeline termination) to gracefully remove BPF programs.

## Key Constraints and Mitigation Strategies

Designing within eBPF’s constraints is critical. We highlight major constraints and how to address them:

* **eBPF Verifier Constraints:** The kernel’s verifier analyzes the eBPF bytecode before allowing it to load. It rejects programs that could loop indefinitely, access invalid memory, or exceed resource limits. Mitigations:

  * *Program Size:* eBPF programs must typically be <4096 instructions (configurable in newer kernels). Our generated code should be as minimal as possible. If a user writes a very large Nushell block, we may need to split logic into multiple programs (advanced scenario) or simply document the limitation.
  * *Loops:* As discussed, we avoid runtime loops. If absolutely necessary (e.g., copying a string byte-by-byte), we will ensure a static bounded loop and test on target kernels. Bounded loops are allowed but “fussy” and the verifier will simulate each iteration up to a total instruction limit. We will prefer BPF helper calls for iteration when available (e.g., `bpf_probe_read_str` can copy a string from user memory up to a fixed size, avoiding manual byte loops).
  * *Memory Safety:* eBPF cannot do arbitrary pointer arithmetic or access memory not proven safe. If the Nushell script wants to access a pointer (say, a struct field in kernel memory), our codegen should utilize **BPF helper calls or BTF**. For example, to get `args.filename` in a tracepoint, bpftrace relies on compile-time knowledge of that field’s offset or uses `bpf_probe_read` under the hood. We will use BTF (BPF Type Format) whenever possible to resolve offsets of struct fields in kernel structures (Aya and RedBPF both support CO-RE, which uses BTF to adjust struct offsets at load time). By using CO-RE, our compiled eBPF can be portable across kernel versions without recompiling, as it will relocate field accesses based on the target kernel’s BTF.
  * *Verifier Error Handling:* When a program is rejected, we should capture the verifier log to help the user fix their script. Our tooling will intercept kernel log (Aya can provide the log on error). We can present a Nushell error with the relevant message (e.g., “verifier rejected program: unreachable instruction…”) and possibly tips (like “did you use a loop or an unsupported operation?”).

* **JIT vs. Interpreter:** Most kernels JIT-compile eBPF to native code for performance. This happens automatically after verification. We don’t have to do much here, but it’s worth noting that for performance-sensitive usage, JIT should be enabled (it usually is by default; if not, we can advise enabling `/proc/sys/net/core/bpf_jit_enable`). The plan doesn’t need to implement JIT – it’s a kernel feature – but we should ensure our userspace doesn’t inadvertently disable it. We might expose a flag for the user to request the program to run interpreted (for debugging) vs JIT, but by default rely on kernel JIT for speed.

* **User/Kernel Boundary and Data Transfer:** eBPF programs cannot print or output data directly to the console (except via the crude `bpf_trace_printk` which writes to a debug trace buffer). To get data out, we have two main mechanisms:

  * *Perf Event Buffers:* We can use **perf event arrays / ring buffers** to push custom event data to user-space asynchronously. Our BPF code can call a helper (e.g., `bpf_perf_event_output` or the newer `bpf_ringbuf_submit`) to send a struct to a ring buffer. In user-space, Aya or our code will listen on that buffer and emit the records to Nushell as pipeline output. This is ideal for streaming events (like printing each event or a custom message). We will likely implement a default structure for “printf events” containing, say, a format identifier and data, if we support printf-style output in scripts.
  * *Maps:* For aggregated data or values that need to be read on demand, BPF **maps** are the way to go. Maps (hash maps, arrays, histograms, etc.) reside in kernel memory but accessible from user-space via syscalls. For example, a Nushell script might populate a map (like a count of events by PID). The user can then query this map after stopping the trace. Our plugin can fetch the map content and present it. We should support common map types (HashMap, Per-CPU hashmap, LRU map, arrays, etc. as needed) – fortunately, Aya and RedBPF already have abstractions for many map types.
  * We will design the Nushell commands such that streaming outputs and map outputs can be piped into the Nushell pipeline. For instance, a `bpf_trace` command could by default stream each event as a row in Nushell (structured by the event’s fields), whereas an `bpf_stats` command (hypothetical) might accumulate counts in a map and only output when finished.

* **Security and Permissions:** Loading eBPF usually requires privileges. On modern systems, an unprivileged user can use eBPF only if certain conditions are met (like the program is pinned in LSM with proper permissions, or with new kernel features like unprivileged BPF with CAP\_BPF in newer kernels). To avoid complicating initial use, we may assume the user runs Nushell with root or CAP\_SYS\_ADMIN when using these features. We should clearly document that “root or appropriate capabilities are needed for eBPF usage” – akin to how bpftrace typically needs to run as root. In later phases, we can explore using Linux’s **CAP\_BPF** and **CAP\_PERFMON** to allow non-root usage (on kernels that support it) and handle permissions automatically if possible.

* **Performance Overhead:** One reason to embed logic in eBPF is to minimize context switches and data transfer by doing filtering/aggregation in kernel. We should ensure our generated code is efficient (though the compiler will optimize some). Using maps and ring buffers has overhead; we should avoid overly frequent syscalls. For example, writing every single event out to user-space might flood the ring buffer; if the script doesn’t require per-event output, better to aggregate in kernel and output summary. As best practice, we will encourage using maps for high-frequency events and only emitting essential data to user-space.

* **Limitations of Nushell environment:** Nushell’s IR is static, which is good for analysis, but Nushell is a dynamic environment otherwise. One thing to consider: can the eBPF script refer to Nushell variables defined outside? Probably not in kernel (unless their values are embedded as constants). We might allow something like capturing a constant from Nushell into the BPF program – e.g., if the user does:

  ```nushell
  let target = "eth0"
  bpf_trace net:xdp(packet) {|pkt| if $pkt.ifname == $target { ... } }
  ```

  If `$target` is a Nushell variable, we could capture its value at compile-time and embed it (e.g., embed "eth0" as a constant string to match against). Nushell closures close over variables, so it will have that available in the IR. We just need to ensure it’s a **parse-time constant** or known at compile time (Nushell supports `const` for truly compile-time constants). We will support capturing primitive constants (strings, ints) from the Nushell environment and embedding them in the eBPF code (for example, an integer threshold or string to compare). Non-constant or complex captures would either be rejected or we only use their value at the time of compilation (not dynamic after loading).

* **Error handling and Debugging:** We will incorporate ways to troubleshoot:

  * If compilation of BPF (Rust or C) fails (syntax error in generated code, etc.), we output the error and possibly the generated source (hidden behind a flag) for maintainers.
  * If the BPF verifier rejects the program, we output the verifier log (which Aya can provide) to the user, trimmed to relevant parts, along with guidance.
  * We could also allow a “dry run” mode that only generates the BPF code or does a verifier check without attaching, for users to inspect.
  * Leverage Nushell’s debugging commands: perhaps allow using Nushell’s `ast` or `view ir` on the closure for introspection (the IR of the closure might help advanced users understand what was parsed).

By anticipating constraints and using available frameworks (Aya’s type safety, BTF for relocations, etc.), we mitigate many potential issues. For example, using Rust’s eBPF target inherently disallows unsupported operations (no heap, no dynamic dispatch, etc.), and using BTF CO-RE means fewer hard-coded offsets (making our tool more robust across kernels). Each new eBPF feature we support (e.g., loops, or new helper functions) will be carefully tested on the lowest common denominator of kernel version we target (we might decide on a minimum kernel version, say 5.4 or 5.8, to ensure BTF availability and loop support).

## Handling Common BPF Program Types

We intend to support the **most common eBPF application types for tracing**. Each type may require slight differences in how programs are defined or attached. Here’s how we plan to handle them:

* **Kprobes (Kernel Function Entry/Exit):** Kprobes allow us to attach eBPF to essentially any kernel function at runtime. This is fundamental for tracing arbitrary kernel events. We will provide commands to attach kprobes and kretprobes:

  * For example, `bpf_kprobe <function_name> { ... }` for entry, and perhaps `bpf_kretprobe <function_name> { ... }` for return probes. We might unify these, e.g., an option `kind: "entry"/"return"`.
  * Under the hood, for kprobe we’ll generate a program of type `BPF_PROG_TYPE_KPROBE` (Aya’s `KProbe`), and use Aya to attach by function name. Aya can use kprobe PMU directly, or if BTF is available, it might choose `fentry` (which is a newer, more efficient mechanism) – but to start, using the classic kprobe interface is fine. We just need the function’s name or address.
  * We should allow specifying a kernel function symbol name. Optionally, we could support wildcard matching or offset, but initially exact name is enough. We may integrate with `/proc/kallsyms` or BTF to verify the symbol exists for user convenience, or let the kernel error surface if not found.
  * *Example usage:* `bpf_kprobe "vfs_read" {|ctx| send($ctx.pid) }` would attach to `vfs_read`. The context might allow `$ctx.fd` or similar if we can get arguments (which likely requires knowing the function prototype via kernel headers or BTF). Initially, we might just supply basic context like current PID, etc., unless we have argument info.

* **Uprobes (User-level Probes):** Uprobes attach to user-space functions in processes or libraries. This is useful for tracing application behavior (e.g., function calls in a running binary). Our plan:

  * Provide a command like `bpf_uprobe <path_to_binary> <symbol_or_offset> { ... }`.
  * We need the path to the executable or library, and either a function name (if the binary has symbols or has debuginfo) or a memory offset. We might use libbfd or an external tool to resolve symbol to offset. Alternatively, we require the user to provide an address if symbols are not present.
  * Under the hood, we open the ELF and set up the uprobe (this can be done via perf API by specifying the binary and offset). Aya likely has support for uprobes (similar to kprobes).
  * The context available in an uprobe is a user-space register state; if we have debuginfo (Dwarf), we could theoretically get argument info, but that’s advanced. Likely we only give minimal context (maybe registers or nothing beyond knowing it happened). bpftrace does support function arguments for uprobes if types are known.
  * We also support *uretprobes* (function return in user-space) similarly. Possibly via a flag or separate command.

* **Tracepoints:** Tracepoints are static instrumentation points in the kernel (e.g., `syscalls:sys_enter_open`, scheduler events, block I/O events). They are more stable across kernel versions than kprobes. Plan:

  * Command like `bpf_tracepoint <category>:<name> { ... }`. E.g., `bpf_tracepoint syscalls:sys_enter_open { ... }`.
  * The advantage is the kernel provides a struct with relevant data for each tracepoint. We will use BTF to automatically get the struct layout for that tracepoint event (the kernel supplies format info in `/sys/kernel/debug/tracing/events/.../format` as well, but BTF is easier if available). Our codegen can translate `$event.field` to reading the field from the context struct.
  * Attach via program type `TRACEPOINT`. Aya can attach by specifying category and event name, or by the tracepoint ID.
  * Tracepoints might require linking against the kernel’s provided format structure. With CO-RE, we can simply refer to `args` struct by name (Aya might generate CO-RE relocation code for tracepoints).
  * We'll support any tracepoint as long as the system has BTF or we can parse the format file. It would be good to allow the user to list available tracepoints or use tab-completion (out of scope for initial, but an idea for tooling support).

* **Performance Counter Events (perf\_events for sampling):** This refers to attaching eBPF to hardware or software perf events (e.g., CPU cycles, instructions, cache misses, or timer-based sampling). Use cases include sampling stack traces at intervals (`profile` in bpftrace).

  * We can implement a `bpf_perf_event` or shorthand like `bpf_profile frequency { ... }` where the program triggers at a fixed interval (e.g., 99 Hz) and can sample data (like call stack via `bpf_get_stack`).
  * Under the hood, this uses a `BPF_PROG_TYPE_PERF_EVENT`. We have to set up a perf event open (using `perf_event_open` syscall) for each CPU or a group, then attach the BPF program to it. For example, bpftrace’s `profile:hz:99` uses a perf event for CPU-clock at 99Hz.
  * Initially, we might not expose this unless there’s demand, focusing on kprobes/tracepoints. But leaving architectural room for it is wise. If implemented, we allow specifying event type (hardware counter or software event) and frequency or threshold. The eBPF program type is slightly different but Aya likely supports it too (perhaps via attaching to a perf fd).

* **Network packet processing (XDP / TC):** Although the question emphasizes tracing, eBPF is also used for networking (XDP programs, traffic control filters). Support for those would mean letting Nushell scripts express packet filtering or modification logic. This is a larger domain, but for completeness:

  * We could allow an `bpf_xdp ifname { ... }` to attach an XDP program to a network interface. The closure would operate on packet data (with context of type `xdp_md`). For instance, a Nushell script could drop or count packets based on content.
  * TC (traffic control) programs similarly could be attached at egress/ingress.
  * These use different program types and have stricter performance constraints (need to be extremely fast). It’s an extension goal to support them, and if we do, we’ll need to support accessing packet data (likely via pointer arithmetic in BPF, which is doable with helpers).
  * Because the question specifically mentioned “tracing, kprobes, uprobes, perf events,” we may deprioritize XDP/TC in this plan. But we note that the architecture (using Aya) is flexible enough to add those: Aya supports XDP, socket filters, etc., with corresponding macros.

* **LSM (Linux Security Modules) and other types:** eBPF can attach to LSM hooks or other subsystems. Probably out of scope for now, but architecturally, adding new program types is a matter of generating the appropriate attachment code. We design our codegen to be somewhat modular per program type – e.g., a trait or interface for “Probe” that knows how to wrap a user’s closure into a specific kind of BPF program.

For each program type we support, we will have example Nushell usage and ensure the generated code conforms to what the kernel expects. We’ll test on a recent kernel with BTF enabled to ease development (CO-RE). For older kernels (pre-5.3 without BTF, or pre-4.x that lack some features), we might require installing kernel headers for compilation, or we simply document a minimum kernel version for our tool (likely Linux 5.4+ or so, since that’s when BTF and global functions got widely available).

To summarize, **tracing use-cases (kprobes, uprobes, tracepoints)** will be first-class in our implementation. We provide intuitive Nushell commands for each:

* `bpf_probe kernel:<func>` (or separate `bpf_kprobe`) – hooks kernel function.
* `bpf_probe user:<binary>:<func>` (or `bpf_uprobe`) – hooks user function.
* `bpf_tracepoint category:name` – hooks kernel tracepoint.
* `bpf_interval hz:<rate>` or `bpf_perf_event <event>` – for sampling (later phase).

Each command takes a closure that describes the BPF program action. That closure’s content is translated to a function body in the eBPF program, using the appropriate context type. We’ll provide within the closure certain **predefined variables/structures**:

* e.g., `$ctx` or `$event` for context, with properties (depending on probe type, e.g., `$ctx.pid`, `$ctx.comm`, `$ctx.arg0`).
* Possibly some **aliases** like `$pid`, `$comm` directly if that simplifies usage (like bpftrace does).
* We must ensure these names don’t clash with Nushell variables; since they’ll only be valid inside the BPF closure, the compiler can treat them as special.

## Best Practices and Tooling Support

In developing this project, we will follow eBPF and shell best practices, and provide tooling to aid users:

* **Use of CO-RE (Compile Once, Run Everywhere):** We will strongly rely on CO-RE to make the eBPF programs portable. CO-RE, enabled by BTF type info in the kernel, allows our compiled programs to adapt to differences in kernel structures without requiring kernel headers on the system. For instance, instead of hard-coding an offset for `task_struct->pid`, our BPF code can use a BTF relocation to get it at load time. Both Aya and RedBPF support CO-RE/BTF. We’ll include BTF definitions either by using `vmlinux.h` or via Aya’s built-in mechanisms. As a fallback, if BTF is not available (older kernel or custom build without BTF), we might require the user to provide kernel headers or a vmlinux image – this is similar to RedBPF’s ability to generate bindings from BTF or headers. In documentation, we will recommend running on a distro with BTF available (most modern distributions provide `/sys/kernel/btf/vmlinux`).

* **Minimal Kernel Footprint:** Each loaded eBPF program should allocate minimal kernel resources. We clean up after ourselves by unloading programs and deleting any maps we created (unless the user explicitly pins them for sharing). Pinning maps/programs in bpffs could be an advanced feature (RedBPF supports pinning maps). Initially, we’ll manage lifetime internally, destroying maps on program exit so they don't persist unknowingly.

* **Testing and Compatibility:** We plan to test on multiple kernel versions (for example, 5.4 LTS, 5.10, 5.15, etc., up to latest) to ensure our generated BPF passes the verifier and behaves correctly. Automated tests will include simple Nushell scripts that trigger known events (perhaps using a dummy kernel module or triggering syscalls) and verifying that the expected output is received. We’ll also test failure cases (e.g., user tries a disallowed feature and gets a proper error). In CI, we can use tools like **bpftool** (from the Linux kernel) to dump the program’s instructions and ensure no obvious issues, and run in a VM or container with a real kernel to fully verify loading.

* **Nushell Integration & UX:** Since Nushell is our UI, we want the user experience to be smooth:

  * We will integrate tab-completion for certain arguments if possible. For example, completing tracepoint names or function names could greatly help. Nushell allows custom completions; we could make the plugin provide completion for known probe types (perhaps by reading `/sys/kernel/debug/tracing/available_filter_functions` for kprobes or the tracepoint directory).
  * Leverage Nushell’s table output. If an event yields a struct with fields, we can output it as a Nushell record (which displays as a table row). Users can then pipe that into other Nushell commands (like `where`, `sort`, `group-by`) *in user-space*. This is a powerful combination: heavy-lifting filters in kernel, then rich processing on the results in user-space.
  * Provide clear documentation in Nushell’s help/style. We’ll add entries in Nushell’s documentation (or plugin docs) showing examples of using these new commands. Perhaps we create a section in the Nushell book, or a separate Markdown manual, with examples akin to bpftrace’s tutorial but in Nushell form.

* **Tooling Support for Development:** For ourselves (developers of this feature), we will use:

  * Existing crates and tools: `aya` (for which there is an Aya book and examples), `cargo-bpf` (from RedBPF, if needed for reference of how it builds BPF code), and `bpftool` for debugging the BPF side.
  * We should also keep an eye on Nushell’s own compiler development (there was interest in a Nushell script -> binary compiler). If Nushell gains the ability to compile its scripts to native code, perhaps some of our work can align with that (though eBPF as a target is quite different).
  * We may consider using a logging or diagnostic mechanism in the plugin where if an environment variable is set (like `NU_BPF_DEBUG=1`), our codegen will print the generated Rust/C code to stderr or a file for debugging.

* **Community and Prior Work:** We will draw inspiration from prior art:

  * bpftrace’s open source implementation, to see how it handles parsing and what its AST -> IR -> codegen pipeline is. (bpftrace’s code is C++ with LLVM, so not directly portable, but conceptually useful).
  * The **Aya community** and examples – e.g., Aya’s GitHub and book might have patterns for writing tracing programs that we can mimic in our codegen output.
  * **RedBPF’s** approach to map and program macros can guide how we structure the Rust code templates (for instance, how to declare maps and attach points).
  * **Nushell’s plugin examples:** to ensure we use the plugin protocol correctly (we must output data in expected format, handle value types, etc.). Nushell plugins communicate via JSON or similar structured data. We’ll use the official `nu-plugin` crate to integrate seamlessly.

* **Safety and Stability:** Because eBPF runs in kernel, a buggy program could theoretically crash the system if it hit a verifier bug or if we misuse a helper (though the verifier should prevent most hazards). We will be conservative: prefer using higher-level library calls (Aya’s safe API) to raw BPF helper calls when generating code. For example, instead of writing our own inline asm to call a map update, we use `map.insert()` from Aya which wraps `bpf_map_update_elem` safely. This not only reduces our chance of error but also yields clearer verifier errors if something goes wrong (Aya often provides good context in errors).

* **Performance considerations:** We should measure the overhead of our approach. The critical path is:

  1. Parsing Nushell script (should be fine, Nushell’s parser is optimized and our additions are minor).
  2. Generating source code (string manipulation – negligible overhead relative to compilation).
  3. **Compilation time:** Calling `rustc` or `clang` at runtime is the heaviest step. We need to evaluate this. For a small BPF program, `rustc` with BPF target might compile in under a second or a few seconds (especially if we keep the code small). bpftrace using LLVM is usually fast for one-liners because it optimizes the IR only for that small program. We might explore caching compiled objects for identical scripts to avoid repeated compilation. In a REPL scenario, perhaps the user will iterate on a script – maybe we can reuse the previous object if unchanged. This is a stretch goal; initially, compile every invocation anew.
  4. Attaching and running: That part is usually very fast (loading a BPF program is milliseconds, attaching is trivial, the runtime cost is whatever the BPF does).

  If compilation proves too slow and burdensome, an alternative in future is to integrate an in-memory JIT library for eBPF. For example, the *ubpf* project provides a user-space eBPF interpreter/JIT that could potentially be used to assemble instructions directly. Or we could link LLVM and do in-process codegen. But these add complexity; we will first measure if the naive approach is acceptable (for many tracing scenarios, a 1-2 second setup time is okay, since the trace might run for minutes).

* **Extensibility:** We design the system so new BPF program types or helper functions can be added relatively easily. This means having an abstraction layer in our code generator for different probe contexts (so adding, say, an `lsm_probe` command later would involve creating a context with appropriate accessible fields and mapping it to an Aya LSM hook). It also means writing clean, maintainable code for the plugin – possibly splitting it into sub-crates (one for the codegen, one as the actual plugin binary).

* **Example and Prior Projects links:** We will maintain a list of references in our documentation for users who want to learn more:

  * Link to **bpftrace reference** (so users coming from bpftrace can map concepts).
  * Link to **Aya book** and **RedBPF tutorial** for those interested in the underlying Rust approach.
  * Link to **Nushell’s own documentation** on closures and blocks, so users understand the Nushell syntax being used.
  * Possibly link to relevant eBPF guides (like Brendan Gregg’s materials) to help users write effective tracing scripts.

By adhering to these best practices and leveraging robust tooling, we aim to deliver a reliable feature. We acknowledge up front that writing eBPF involves kernel interaction; our job is to simplify that and guide the user away from pitfalls (with good error messages and sensible defaults).

## Phased Implementation Timeline

To implement this project, we will proceed in incremental phases, delivering usable milestones:

**Phase 1: Research & Design (Week 1-2)**
*Outcome:* A detailed design (this document) and a plan for a minimal prototype.

* Study Nushell’s plugin system and IR to understand how to extract a closure’s AST and inject compilation steps.
* Experiment with writing a simple eBPF program in Rust (Aya) and loading it via a small Rust program, to ensure we know the end-to-end steps (outside of Nushell).
* Decide initial target kernel version and ensure development environment with BTF is ready (e.g., use a modern kernel for development).
* Design the Nushell command syntax for a simple use-case (e.g., a `bpf_kprobe` that prints “Hello World” on each event) and verify syntax is parseable in Nushell. For example, create a dummy Nushell command that accepts a closure and just prints the AST (`ast` command output) to verify we can capture it.

**Phase 2: Minimal Viable Prototype – Single kprobe with Print (Week 3-4)**
*Outcome:* A Nushell plugin that can attach a kprobe and print a message for each hit.

* Implement a Nushell plugin command (e.g., `bpf_probe`) that takes a function name and a closure. Initially ignore closure content, or only allow a very simple closure (like an empty block or a call to a built-in print).
* Hardcode a small eBPF program in the plugin (e.g., in C or Rust) that on each kprobe hit calls `bpf_trace_printk("hit")`. Load that when the command is run, attach to the specified function, and read from `trace_pipe` to output to user.
* Even though this bypasses the Nushell script logic, it proves that plugin can load a BPF and stream output to Nushell. Use BCC or Aya for this.
* Verify you see output in Nushell when triggering the function (e.g., if probing `sys_execve`, run some command to trigger it and see output). This step ensures environment and basic plumbing works.

**Phase 3: Basic Codegen & Rust Compilation (Week 5-7)**
*Outcome:* The closure’s content is translated to a real eBPF program (Rust), compiled with Aya, and attached.

* Implement the code generation for a limited set of constructs. For example, support closure with no parameters that simply calls a new built-in `emit` or so. Or closure that references a few predefined variables like `$pid`. For now, we might generate a fixed Rust program template:

  * A global map (for output or count).
  * One kprobe function with the user’s code in the body (manually inserted).

* Programmatically invoke `rustc` to compile this Rust code to BPF (`target bpfel-unknown-none`). Capture errors from rustc and report if fails.

* Load the compiled program using Aya in the plugin, attach kprobe.

* For output, perhaps use a perf ringbuffer. For simplicity, in this phase, if the user’s code calls something like `emit($pid)`, we implement `emit` to store the PID in a perf buffer. The plugin reads from perf buffer and prints the value. (Alternatively, use `bpf_trace_printk` again if perf buffer reading is not ready, but prefer perf).

* Test the whole pipeline: write a Nushell script like: `bpf_probe "do_sys_open" { || emit($pid) } | take 5`. Execute and confirm it prints PIDs of processes calling `open` (or similar). This shows real data flowing.

* Note: This phase is the first end-to-end demonstration of **Nushell -> eBPF compilation**. It will likely reveal a lot of integration issues (ensuring rustc is installed, handling permissions to load BPF, etc.). We’ll resolve those as we go.

**Phase 4: Expand Language Support (Week 8-12)**
*Outcome:* Support more Nushell features in the BPF closure and more probe types.

* Add support for basic expressions: arithmetic (`+ - *`), comparisons (`== != < >`), logical ops (`&& ||`). Map these in codegen to Rust equivalents (which in turn become BPF ops).
* Implement conditional `if ... else` in the closure. This involves generating Rust `if` or the ternary-like expression, which should translate to BPF conditional jumps.
* Introduce limited **built-in functions** in the DSL:

  * For example, a `count()` aggregator: if user calls `count()`, we implement it by updating a counter map.
  * A `print()` or `emit()` that can output either to trace or to a ring buffer.
  * Possibly a `log($msg)` that prints a message (for debugging; could use trace\_printk internally).
* Add support for reading common context data:

  * For kprobes, allow accessing registers or well-known arguments if possible. If BTF info for function arguments is available, use it; if not, might wait on this.
  * For tracepoints, parse the format and allow e.g. `$event.fieldname`.
  * Provide generic variables: `$pid`, `$tgid`, `$uid`, `$comm` (process name) by calling relevant BPF helpers (`bpf_get_current_pid_tgid`, etc.). Implement these as magic variables in codegen.
* Expand to other program types:

  * **Tracepoints:** Implement `bpf_tracepoint` command. Use Aya to attach tracepoint. The codegen will use a different context struct in Rust (e.g., generated function takes `args: SomeTracepointStruct` as argument if Aya supports, or use raw context and then BPF helpers to get data).
  * **Uprobes:** Implement `bpf_uprobe`. This requires specifying a target binary; use Aya’s `UProbe` attach (Aya needs path and symbol offset).
  * **Return Probes:** Possibly add a flag or separate command for kretprobe/uretprobe. The codegen might share logic but ensure we attach to the return address. At return, you often can get the function’s return value. If we can, expose that as e.g. `$retval` variable in the closure.
* During this phase, for each new feature, write example Nushell scripts and test on a live system:

  * e.g., tracepoint example: `bpf_tracepoint syscalls:sys_enter_openat { || printf($"Opened file: ($event.filename)") }` – verify it prints file names as processes open files.
  * uprobe example: attach to a known library call in a process we spawn, verify we catch it.
* Ensure that when multiple probes are used (even if via separate commands concurrently), the system remains stable (this likely means if you run two `bpf_probe` commands, our plugin may load two separate BPF programs – which should be fine).
* By end of Phase 4, we should have a reasonably functional system covering the main tracing scenarios.

**Phase 5: Robustness, Optimizations, and Tooling (Week 13-16)**
*Outcome:* Polish the implementation, add quality-of-life improvements, and extensive testing.

* **Error handling:** Go through all error cases and make sure we handle them gracefully:

  * If rustc is not found or compilation fails, present a clear Nushell error (not a Rust backtrace). Possibly instruct user to install Rust nightly if needed.
  * If attach fails (e.g., invalid function name for kprobe), catch that and inform user (the kernel might give ENOENT, we translate to “function not found”).
  * If the script uses an unsupported feature, catch it in the parser/IR stage if possible and give specific message (e.g., “error: loops are not allowed in eBPF scripts”).
  * Verify that pressing Ctrl+C in Nushell stops the tracing cleanly. We may need to implement a signal handler or check for a cancellation token from Nushell and then detach BPF and stop polling.
* **Performance tuning:** If compilation is slow, experiment with ways to speed it:

  * Perhaps keep the Rust compiler process running (though `rustc` doesn’t work as a daemon by default; there is `rustc_server` concept but not mature).
  * At least ensure we pass `-O2` or appropriate optimizations to rustc for BPF (to reduce instruction count). Also possibly try `-O0` for faster compile during development, and measure if the BPF is still accepted (may need at least some optimization to avoid heavy code).
  * If certain patterns produce too many instructions (verifier near the limit), see if we can optimize the generated code (maybe simpler logic or use of BPF built-ins).
* **Map output and formatting:** Implement a nicer way to output map data. For example, if a script uses a map to count events by key, when the command finishes (or periodically), fetch the map and output its content as a Nushell table (with columns key & value). We might decide that a command like `bpf_probe` by default prints each event, whereas another command `bpf_stats` could be a variant that aggregates and prints a summary at the end. Alternatively, we let the user script decide: if they use `count()` we know to output a summary of counts rather than one line per event.
* **Documentation and Examples:** Write a section in Nushell’s book (or a README for the plugin) documenting usage, supported syntax, and examples. Include comparisons to bpftrace for users familiar with it (e.g., how a bpftrace one-liner translates to Nushell usage).
* **Link with Nushell native features:** Possibly integrate Nushell’s `histogram` or `chart` commands if present, to visualize data from BPF maps. For instance, if the BPF collected a histogram, we could feed it into Nushell’s histogram chart for a quick view. This is more of a stretch goal for user experience.
* **Completeness:** At this stage, common tracing tasks should all be possible:

  * Trace system calls or kernel functions with filters and actions.
  * Uprobe into user processes (maybe for known processes with symbols).
  * Count events and print counts.
  * Get stack traces on events (if we expose something like a `backtrace()` helper that uses `bpf_get_stack` and sends it).
  * We likely will not cover every eBPF helper, but we aim for the most used (like `bpf_ktime_get_ns`, `bpf_get_current_pid_tgid`, `bpf_probe_read_user`/`kernel`, map ops, perf event output).
* **Testing & Debugging:** Before release, test on various scenarios:

  * Long-running trace, ensure memory doesn’t leak.
  * Rapid-fire events (e.g., trace a high-frequency event) to see if our user-space can keep up. If not, document that dropping events can happen if overwhelmed (just like any tracing tool).
  * Different kernel versions, ensure compatibility or detect if something isn’t supported and inform user (e.g., if user tries to use a helper not available in their kernel, the program might get rejected; we could catch that via errno/ verifier message and tell them it requires a newer kernel).
  * Multi-user environment: if multiple Nushell sessions run eBPF traces, should be fine (each is separate). Just be mindful of system limits (max number of loaded programs, map memory usage). Possibly advise on increasing `ulimit -l` if locking memory is needed for maps (some distros require raising memlock ulimit for BPF).
* **Release Phase:** Once stable, we would release the plugin (maybe as `nu_plugin_ebpf` crate) and ensure it’s versioned alongside Nushell’s releases (since plugin protocol requires matching versions).

**Phase 6: Future Enhancements (post-MVP)** – *not strictly in this timeline, but notes*:

* Add convenience features like **USDT (User-level Statically Defined Tracing)** support (these are special uprobes that require resolving providers in binaries, e.g., in languages runtimes; bpftrace supports `usdt:` syntax).
* Possibly integrate a **UI** or structured output for frequent patterns (like auto-generate a summary after a tracepoint count).
* Investigate supporting **Windows eBPF** (since eBPF is being ported to Windows and other OS, Nushell is cross-platform; this is speculative and likely far off, but our codegen could target uBPF or Windows eBPF in future).
* Monitor Nushell’s evolution: if Nushell moves towards compiled scripts or adding type system improvements, ensure our integration keeps working and maybe benefits from any new hooks (for example, if Nushell allows custom syntax extensions in future, we might integrate more naturally rather than just commands with closures).

Each phase will produce a working increment that can be tested. By phasing the implementation, we ensure we deliver core functionality first (tracing with kprobes/tracepoints) and then build out to cover more scenarios. Throughout the project, we will continuously sync with Nushell maintainers (if this is to be merged upstream) and the eBPF community for feedback.

## Relevant Prior Work and References

* **bpftrace** – High-level tracing language for eBPF: uses LLVM to compile scripts to BPF and leverages libbpf/bcc for kernel interaction. Its language influenced our design (using high-level filters and actions instead of C). *(GitHub: iovisor/bpftrace, reference manual)*.
* **BCC (BPF Compiler Collection)** – Tools and Python bindings for eBPF, demonstrating dynamic compilation of C and output via trace pipe. Inspired initial prototyping ideas (embedding C).
* **Aya** – Rust eBPF library (by Alessandro Decina and community): allows writing entire eBPF applications in Rust, focuses on developer experience. We plan to utilize Aya for both program writing and loading. *(Deepfence Blog on Aya, Aya Book)*.
* **RedBPF** – Rust eBPF toolkit by Red Sift: provides macros for eBPF programs and a Cargo integration. Showed how to generate Rust bindings from BTF and support many program types. Even if we use Aya, RedBPF’s approach to macros and its limitations (no loops, etc.) informed our subset design.
* **Nushell Language and Plugins** – Nushell’s documentation on blocks and closures, and its plugin system were crucial to understand how to integrate new commands. The static IR design of Nushell gives us a point to intercept and compile code before execution.
* **Hacker News Discussion on eBPF in Rust** – Provided insight that eBPF restricts language features severely (no heap, limited loops), reinforcing why our Nushell subset must be constrained.
* **CloudChirp “Picking the Right eBPF Stack”** – Noted that RedBPF is less maintained and community leans towards Aya, influencing our library choice.

By referencing these resources and building on their knowledge, our implementation stands on the shoulders of prior work in both eBPF and shell design. The end result will be a fusion of Nushell’s modern shell capabilities with eBPF’s powerful introspection – enabling users to write observability and debugging tools in an intuitive way, without leaving their Nushell environment.

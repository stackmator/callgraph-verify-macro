# callgraph-verify-macro

⚠️ **Alpha** — only 32-bit x86 PE targets are supported currently. x86_64, ARM, and ARM64 are planned.

Compile-time anti-hallucination call-graph verification for binary reverse-engineering rebuilds. The macro disassembles the target binary at build time and compares its call graph against your Rust function body — any invented call is a hard `compile_error!`.

## Crates

| Crate | Purpose |
|-------|---------|
| `callgraph-verify` | Core library + CLI: PE parsing, iced-x86 disassembly, call-graph analysis, skeleton emitter |
| `callgraph-verify-macro` | Proc-macro `#[origin(0xADDR)]` / `#[callgraph_verify(0xADDR)]` that runs the verifier at compile time |

## Architecture

- **Target binary**: 32-bit x86 PE (x86_64 / ARM / ARM64 planned)
- **Host**: x86_64 (proc-macros always build for host; iced-x86 never enters the i686 target build)
- **Dependencies**: Pure Rust — `iced-x86` for decoding, `goblin` for PE parsing, `syn`/`quote` for macro expansion

## Quick Start

### 1. Environment setup

Create `.cargo/config.toml` in your rebuild workspace root:

```toml
[env]
TARGET_EXE = "C:/path/to/target.exe"
REBUILD_ROOT = "C:/path/to/rebuild/source"
```

Optional strictness flags (off by default):

```toml
[env]
STRICT_OPERANDS = "1"  # diff in-image address literals (globals, vtables, RTTI, fn ptrs)
STRICT_ARGS = "1"      # per-call-site concrete arg-kind diff (immediate/field/global)
STRICT_CFG = "1"       # coarse CFG fingerprint diff (loops, switches, branching)
STRICT_MISSING = "1"   # make MISSING calls fatal (default: non-fatal)
DUP_STRICT = "1"       # one Rust fn per binary address (compile-time dup-addr gate)
```

### 2. Annotate a rebuild function

```rust
use callgraph_verify_macro::origin;

#[origin(0x004028d0)]
pub unsafe fn SomeFunction(this: *mut Context, x: i32, y: i32) -> *mut Result {
    // body must only call what the binary at 0x004028d0 calls
    // any invented call → compile_error!
    ...
}
```

### 3. Explicit facts (optional)

Pin calls, field offsets, globals, vtables, vcall slots, IAT slots:

```rust
#[origin(
    0x0070b780,
    calls = [0x00401f00, 0x00401f20],      // superset check (binary may call more)
    calls_exact = [0x00401f00],              // exact set check
    fields = [0x4, 0x6, 0xbc],               // field offsets the binary reads/writes
    globals = [0x00b12340, 0x00b12350],      // global addresses
    vtables = [0x00a7e38c],                  // vtable VAs
    vcall_slots = [0x14],                    // virtual call slot indices (byte offset = slot*4)
    iat = [0x00c00000],                      // IAT slot addresses
    unreferenced                            // waive ORIGIN-UNREFERENCED for boot anchors / gaps
)]
pub unsafe fn SomeFn(...) { ... }
```

### 4. VTable declarations with compile-time slot verification

```rust
use callgraph_verify_macro::vtable_table;

vtable_table! {
    name = renderer_vt,
    va = 0x00A88EA4,
    slots = 98,
    default = crate::vtable::vtable_unimplemented;
    1  = ni_dx9_renderer_get_rtti;
    21 = renderer_caps_flags;
    // ... each slot verified against engine vtable at 0x00A88EA4
}
```

---

## CLI: `callgraph-verify` binary

The workspace includes a standalone binary for exploration and skeleton generation.

### View call graph (text)

```bash
cargo run --bin callgraph_verify -- C:/path/to/target.exe 0x0076a420
```

Output includes:
- Direct calls (with displacement and target VA)
- Tail calls / jumps
- Global address references
- Immediate address literals
- IAT calls

### Generate reference skeleton (NASM-flavored)

```bash
cargo run --bin callgraph_verify -- C:/path/to/target.exe 0x0076a420 --skeleton
```

Emits a `.asm`-style skeleton showing every instruction with offsets — useful for manual matching or feeding to a decompiler diff.

### Other flags

| Flag | Purpose |
|------|---------|
| `--skeleton` | Emit NASM-style reference skeleton |
| `--json` | Machine-readable JSON output |
| `--cfg` | Include CFG fingerprint (loops, switches, conditionals) |

---

## How it works (macro)

On every `cargo check`/`cargo build`:

1. **Loads** `TARGET_EXE` and disassembles the function at the attributed address
2. **Scans** the rebuild source tree (`REBUILD_ROOT`) for `#[origin]` tags to build a `name → address` corpus (free fns, methods, inline helpers, declared vtables)
3. **Parses** the attributed function's body for:
   - Direct calls (`foo()`)
   - Method calls (`obj.bar()`)
   - Field accesses (`ptr.field`)
   - Hex literals (globals, vtables, RTTI, fn pointers)
   - Inline helper calls (recursively folded if unambiguous)
4. **Diffs** body calls against binary calls:
   - `HALLUCINATED` — body calls something binary never does → **fatal**
   - `MISSING` — binary calls something body doesn't → non-fatal (opt-in strict)
   - `VTABLE-DISPATCH` — direct call to a known vtable method → fatal (must use `vcall`)
   - `ARG-SHAPE` — concrete arg kinds mismatch (opt-in `STRICT_ARGS`)
   - `HALLUCINATED-ADDR` — body bakes in-image address binary never references (opt-in `STRICT_OPERANDS`)
   - `CFG` — structural CFG divergence (opt-in `STRICT_CFG`)
   - `DUP-ADDR` — multiple Rust fns claim same binary address (opt-in `DUP_STRICT`)
   - `FOLD-SKIP HOLE` — ambiguous inline helper with ported calls escapes verification
   - `ORIGIN-UNREFERENCED` — attributed address not called/jumped/stored in binary (waivable)

---

## Requirements

- Rust 1.70+ (edition 2021)
- `TARGET_EXE` pointing to a valid 32-bit PE
- Rebuild source tree with `#[origin]` tags for corpus resolution

---

## License

Internal tooling for binary reverse-engineering rebuild projects. Not published.
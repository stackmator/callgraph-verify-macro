# callgraph-verify-macro

⚠️ **Alpha** — 32-bit x86 PE and DOS4GW linear-executable (LE) targets are supported. x86_64, ARM, and ARM64 are planned.

Compile-time anti-hallucination call-graph verification for binary reverse-engineering rebuilds. The macro disassembles the target binary at build time and compares its call graph against your Rust function body — any invented call is a hard `compile_error!`.

## Crates

| Crate | Purpose |
|-------|---------|
| `callgraph-verify` | Core library + CLI: PE parsing, iced-x86 disassembly, call-graph analysis, skeleton emitter |
| `callgraph-verify-macro` | Proc-macro `#[origin(0xADDR)]` that runs the verifier at compile time |

## Architecture

- **Target binary**: 32-bit x86 PE or DOS4GW LE (x86_64 / ARM / ARM64 planned)
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

Required environment (set in `.cargo/config.toml` `[env]`):

```toml
[env]
TARGET_EXE = "C:/path/to/target.exe"   # the binary to verify against
REBUILD_ROOT = "C:/path/to/rebuild"     # rebuild source root for the corpus scan
```

Strict checks (`DUP-ADDR`, `MISSING`, `ARG-SHAPE`, `HALLUCINATED-ADDR`, `CFG`)
are always on. Earlier versions had `STRICT_*=0` / `DUP_STRICT=0` escape
hatches — those are removed. AI agents were flipping them off to silence
build failures; the macro is a strict gate, not a configurable knob. If a
check is wrong, fix the check.

### Single-function discipline (CFG check)

The macro's CFG-fingerprint diff compares the binary's CFG *at the attributed
entry* against the *literal body* you wrote. It does NOT walk into callee
declarations — by design. Concretely:

- If the binary function at `0xA` has 4 back-edges (loop heads) and your Rust
  body has zero `while` / `loop` / `for`, the build fails:
  `CFG: binary has 4 loop back-edge(s) but the body has no loop — missing iteration?`
- This fires whether the loops were extracted into helper functions, inlined
  away, or simply forgotten.

**Rule: the binary function is one Rust function.** When the engine inlines
iteration logic into a single contiguous range (e.g. a 200-byte block with
nested loops and no `CALL` between them), the faithful Rust port is one
function with matching nested loops — even if it is 200+ lines. Extracting the
loops into `pick_traverse` / `update_world_bound` helpers is a *structural*
divergence from the binary: the binary never calls them, and the verifier
correctly refuses to accept the split.

If you genuinely must extract (e.g. for readability across multiple rebuild
functions sharing the helper), each extracted helper is itself a separate
port: tag it with its own `#[origin(<callee_addr>)]` and reproduce the
binary's loop structure inside it. The macro will then verify each piece
against its own byte range — the entry against the entry's loops, the helper
against the helper's loops. Neither side gets a free pass.

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

Pin field offsets, globals, vtables, vcall slots, IAT slots:

```rust
#[origin(
    0x0070b780,
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

Slot indices are decimal, `va` accepts hex. The macro generates
`pub fn name() -> *const [usize; N]` (fat pointer — keeps the slot
count) and checks every wired slot against the binary's vtable bytes
at build time. There is no `vcall_*` call helper in the crates: the
faithful call form is an indirect call through the declared table
(register dispatch, e.g. `CALL [reg+slot]`); pin the byte offset with
`vcall_slots = [...]` on the caller and never call a declared vtable
method directly (that is `VTABLE-DISPATCH`, fatal).

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

### Ground-truth disassembly (port from this)

```bash
cargo run --bin callgraph_verify -- C:/path/to/target.exe 0x0076a420 --asm
```

Raw iced-x86 dump of the verified bytes at the address — this is the
ground truth. Always port from `--asm`; `--skeleton` below is a coarse
structural hint only.

### Generate reference skeleton (NASM-flavored)

```bash
cargo run --bin callgraph_verify -- C:/path/to/target.exe 0x0076a420 --skeleton
```

Emits a `.asm`-style skeleton showing every instruction with offsets — useful for manual matching or feeding to a decompiler diff.

### Enumerate / measure the binary

```bash
cargo run --bin callgraph_verify -- C:/path/to/target.exe --list [--max N]
cargo run --bin callgraph_verify -- C:/path/to/target.exe --count
cargo run --bin callgraph_verify -- C:/path/to/target.exe --summary
```

`--list` prints one line per function (`extent/calls/tails/indir_calls/
indir_jumps`); `--count` prints the function total; `--summary` prints
totals (functions, code bytes, direct calls).

### Other flags

| Flag | Purpose |
|------|---------|
| `--skeleton` | Emit NASM-style reference skeleton |
| `--asm` | Raw disassembly dump of the verified bytes (ground truth) |
| `--list [--max N]` | Enumerate functions with extent/call counts |
| `--count` | Print the function total |
| `--summary` | Print binary totals (functions, code bytes, calls) |
| `--declared 0xA,0xB --exact` | Verify an explicit call set for the address |

---

## How it works (macro)

On every `cargo check`/`cargo build`:

1. **Loads** `TARGET_EXE` and disassembles the function at the attributed address
2. **Scans** the rebuild source tree (`REBUILD_ROOT`) for `#[origin]` tags to build a `name → address` corpus (free fns, methods, declared vtables)
3. **Parses** the attributed function's body for:
   - Direct calls (`foo()`)
   - Method calls (`obj.bar()`)
   - Field accesses (`ptr.field`)
   - Hex literals (globals, vtables, RTTI, fn pointers)
4. **Diffs** body calls against binary calls (all checks always on —
   the old `STRICT_*=0` / `DUP_STRICT=0` escape hatches were removed):
    - `HALLUCINATED` — body calls something binary never does → **fatal**
    - `MISSING` — binary calls a corpus-known fn the body doesn't spell → **fatal**
      (calls to addresses with no `#[origin]` may be omitted with a `TODO`)
    - `VTABLE-DISPATCH` — direct call to a known vtable method → **fatal**
      (call indirectly through the declared table)
    - `ARG-SHAPE` — concrete arg-kind mismatch at a call site
    - `HALLUCINATED-ADDR` — body bakes an in-image address the binary never references
    - `CFG` — structural CFG divergence (coarse/tolerant)
    - `DUP-ADDR` — multiple Rust fns claim same binary address → **fatal**
    - `ORIGIN-UNREFERENCED` — attributed address never called/jumped/stored
      in the binary → waive with `#[origin(VA, unreferenced)]` (boot anchors only)

---

## Requirements

- Rust 1.70+ (edition 2021)
- `TARGET_EXE` pointing to a valid 32-bit PE or DOS4GW LE binary
- Rebuild source tree with `#[origin]` tags for corpus resolution

---

## License

Internal tooling for binary reverse-engineering rebuild projects. Not published.
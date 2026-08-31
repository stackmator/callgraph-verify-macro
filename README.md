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

### What `inline:` markers are for (and what they're NOT for)

The verifier supports three inline annotations:

| Annotation | Purpose |
|---|---|
| `/// inline: 0xADDR` (with address) | Registers a Rust helper as the inlined-by-the-engine version of the binary function at `0xADDR`. Calls to it from other rebuild fns classify as `inlined_ok` (not `hallucinated`). |
| `/// inline: <no-addr>` | Body fold-in: a pure-Rust idiom helper with no binary equivalent — its calls are folded into every caller so a call to `flag_helper()` doesn't introduce hidden invented calls. |
| `/// callgraph-inlined` / `/// callgraph-virtual` | Alternate syntax for the same two ideas above. |

**These markers are for cross-function call resolution. They do NOT relax
the CFG check on any attributed entry.** A `/// inline: 0xADDR`-tagged
helper is still verified against the bytes at `0xADDR` — its CFG must match,
its calls must match, its fields must match. The marker only tells the
*callers* of the helper "this name is recognised, don't HALLUCINATED-flag it."

Concretely, the pattern from the previous section is unchanged:

```text
/// inline: 0x00AABBCC           // ← this does NOT exempt you
fn pick_traverse(...) {          // ← from the CFG check at 0x959d60
    while ... { ... }            //
}                                //
                                 //
#[origin(0x959d60)]              //
fn outer(...) {                  //
    pick_traverse();             // ← still flagged: body has no loop,
    update_world_bound();        //   binary at 0x959d60 has 4 back-edges
}                                //
```

The annotation lives on `pick_traverse`'s *own* `#[origin(0x00AABBCC)]`
declaration, where it explains "the engine inlined this; callers may share
me." It does not, and cannot, make `outer`'s body structurally faithful to a
binary function whose loops were never extracted in the first place.

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
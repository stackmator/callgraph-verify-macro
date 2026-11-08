# Project Bible — `callgraph-verify-macro`

> Operating manual for the people and agents who maintain this repo.
> Read this before changing a gate, a harvester, a fixture, or an error message.
> The code is the source of truth; this document explains *why* it is shaped
> the way it is and which invariants must survive.

---

## 0. TL;DR

`callgraph-verify` is a compile-time anti-hallucination gate for binary
reverse-engineering rebuilds. A Rust function tagged `#[origin(0xADDR)]` is
checked against the **actual bytes** of a 32-bit x86 PE (or DOS4GW `LE`)
binary at that address. If the body invents a call, drops a real one, bakes an
invented address, or structurally diverges from the binary's control flow, the
build fails with a stable `CG-VERIFY-Exxx` diagnostic.

Everything is derived from disassembly. No Ghidra export, no decompiler, no
`.asm` sidecar, no runtime tracing.

### Non-negotiables

1. **The gate is always on.** No `STRICT_*=0` / `DUP_STRICT=0` escape hatches.
   If a check is wrong, fix the check. Agents historically flipped knobs off
   instead of fixing ports.
2. **Provenance is 1:1.** One binary address is implemented by exactly one
   Rust function (`DUP-ADDR`). Inlined work is reproduced inside the caller;
   the caller does not call the helper.
3. **Facts come from bytes.** The verifier may over-approximate acceptance,
   but it must never demand something the binary does not encode.
4. **Widening only.** Folds for tail calls, inlining, thunks, code-pointer
   immediates, declared indirect targets, and LE post-fixup images may only
   *add* acceptable spellings. They must never add a `MISSING` requirement.
5. **Diagnostics are a UI for agents.** Stable numeric codes, a span on the
   offending token when possible, a concrete fix line, and a self-contained
   message. Renumbering error codes is forbidden.

---

## 1. What this project is (and is not)

| Aspect | Value |
|---|---|
| Target binaries | 32-bit x86 PE (`PE32`, machine `0x14c`) and DOS4GW linear executables (`LE`) |
| Host | `x86_64` (proc-macros always build for the host) |
| Rust | edition 2021, MSRV 1.70 |
| License | MIT |
| Current version | 0.1.9 (workspace; release candidate pending CI) |
| Crate 1 | `callgraph-verify` — parser, disassembler, analysis, CLI |
| Crate 2 | `callgraph-verify-macro` — `#[origin]` and `vtable_table!` proc-macros |

It is **not** a decompiler, a semantic equivalence prover, or a whole-program
soundness proof. It is a structural gate: call edges, address references, CFG
shape, vtable wiring, and gross predicate-class divergence. Two functions with
the same call graph, addresses, and CFG can still have different arithmetic;
those differences need human review or tests.

---

## 2. Repository map

### Crates

| Path | Role |
|---|---|
| `callgraph-verify/src/lib.rs` | `Spec`, `diff_calls`, `diff_body_calls[_ext]`, address/branch caches |
| `callgraph-verify/src/pe.rs` | PE32 + DOS4GW LE loader, sections, fixup absorption, referenced-address scan |
| `callgraph-verify/src/disasm.rs` | Recursive-descent function walk, fact harvesting, call-site arg recovery |
| `callgraph-verify/src/skel.rs` | CFG blocks, dominators, `cfg_fingerprint`, NASM skeleton emitter |
| `callgraph-verify/src/main.rs` | CLI: `--asm`, `--skeleton`, `--list`, `--count`, `--summary`, `--json`, `--declared`, `--exact` |
| `callgraph-verify-macro/src/lib.rs` | Attribute parser, verification pipeline, `vtable_table!`, caches |
| `callgraph-verify-macro/src/body.rs` | Syn body visitor: call names, call args, condition counts, hex literals, fake-loop detection |
| `callgraph-verify-macro/src/corpus.rs` | Source-tree scan: `#[origin]` owners, name tables, declared vtables, `macro_rules!` defs |
| `callgraph-verify-macro/src/expand.rs` | Best-effort expansion of unambiguous local `macro_rules!` |
| `callgraph-verify-macro/src/error.rs` | Stable `Code` enum + `RichError` rendering |

### Tests

| Path | Contents |
|---|---|
| `callgraph-verify/tests/integration.rs` | Synthetic-PE integration tests (built in-process, no toolchain) |
| `callgraph-verify/tests/c_cpp_integration.rs` | Real MSVC/MinGW C and C++ fixture tests, `/O2` + `/Od` |
| `callgraph-verify/tests/dos_le_integration.rs` | Real Open Watcom DOS4GW LE fixture tests |
| `callgraph-verify/tests/jump_tables.rs` | Synthetic PE jump-table shapes |
| `callgraph-verify/tests/perf.rs` | Cache/scan performance regression guards |
| `callgraph-verify/tests/real_binary_sweep.rs` | Local-only sweep over a `CALLGRAPH_REAL_EXE` binary (e.g. a sample PE) |
| `callgraph-verify-macro/tests/ui/*` | `trybuild` compile-error snapshots (E001–E021) |
| `callgraph-verify-macro/tests/real_structure.rs` | Live-fixture E016/E013 pins, MSVC-only |
| `callgraph-verify-macro/tests/error_codes.rs` | Error-code stability contract |

### Fixtures and CI

| Path | Role |
|---|---|
| `callgraph-verify/test-fixtures/` | C, C++, DOS sources + `build_fixtures.py` |
| `.github/workflows/integration.yml` | Windows MSVC job + Ubuntu MinGW/Watcom job |
| `FEATURES.md` | Feature handoff notes (currently: `indirect_targets`) |
| `CHANGELOG.md` | Keep-a-Changelog history; every behavior change needs an entry |

---

## 3. Configuration and environment

Set these in the rebuild workspace's `.cargo/config.toml`:

```toml
[env]
TARGET_EXE   = "C:/path/to/target.exe"
REBUILD_ROOT = "C:/path/to/rebuild/source"
```

| Variable | Unset behavior | Set-but-invalid behavior |
|---|---|---|
| `TARGET_EXE` | Macro is a no-op (emits a NOTE). | Hard `E004 TARGET-EXE-UNLOADABLE`. A configured-but-broken binary must never produce a green unverified build. |
| `REBUILD_ROOT` | Body-call diff is skipped; explicit `fields/globals/vtables/...` checks, `E005/E006`, operand checks, and CFG checks still run. | `E008 CORPUS-GAP` if this function's own address is not in the scanned corpus. |
| `CALLGRAPH_REQUIRE_FIXTURES=1` | Missing fixtures skip during local runs when unset. | Missing CI fixtures become hard test failures. |
| `CALLGRAPH_REAL_EXE` | Real-binary sweep skips. | Loads the given PE and sweeps it. |

Fixture-path overrides (tests only): `CALLGRAPH_C_EXE/ADDRS`,
`CALLGRAPH_C_OD_EXE/ADDRS`, `CALLGRAPH_C_DBG_EXE/ADDRS`,
`CALLGRAPH_CPP_EXE/ADDRS`.

Deliberate exceptions to `CALLGRAPH_REQUIRE_FIXTURES`:
- `c_callgraph_dbg` — ILT thunks are an MSVC-only artifact; GNU ld cannot make one.

---

## 4. Compile-time pipeline

For each `#[origin(addr, ...)]` function, on every `cargo check`/`build`:

1. **Parse the item** as a free fn / impl method / trait method. A non-fn item
   is `E003 NOT-A-FUNCTION` (never a silent skip).
2. **Expand local macros** found in `REBUILD_ROOT` (unambiguous `macro_rules!`
   only) so call/CFG/hex harvests see through them. Unresolved invocations
   emit `OPAQUE-MACRO`.
3. **Load `TARGET_EXE`** (cached per path). LE fixup tables are absorbed at
   load. Parse failures are fatal `E004`.
4. **E005/E006**: the origin must be inside a section and referenced somewhere
   in the image (branch target or stored dword). Waive with `unreferenced`.
5. **E007 `Spec::check`**: explicit `fields/globals/vtables/vcall_slots/
   indirect_targets/iat` facts must be present at this origin.
6. **Corpus scan** (`REBUILD_ROOT`): build name → address tables, owner maps,
   declared vtables, macro defs. `E008` if this origin is missing from it;
   `E009` if more than one Rust fn owns the address.
7. **Resolve body calls**: plain/path calls against free fns, method calls
   against methods; `DENY` filters generic std/trait names. Qualified paths and
   generic names get a `miss_satisfied` escape for MISSING only.
8. **`diff_body_calls_ext`**: `E012 HALLUCINATED`, `E013 MISSING`,
   `E011 VTABLE-DISPATCH`, `UNPORTED-CALLS` note.
9. **`arg_shape_check`**: `E014 ARG-SHAPE` at unambiguous call sites.
10. **Operand check**: every in-image hex literal in the body must be
    referenced by the binary at this origin → `E015 HALLUCINATED-ADDR`.
11. **CFG check**: `E016 CFG` for missing loops/switches or gross
    under-branching; `E021 POLARITY-NOTE` advisory; fake-loop note.
12. **Emit diagnostics**: one `compile_error!` per finding, each with its own
    span. A summary count goes to stderr (visible with `-vv`).

The macro is cached per compiler process: PE loads, referenced-address scans,
corpus scans, vtable maps, and branch-target sets are keyed so two different
binaries never share results.

---

## 5. Binary model

### 5.1 Loader (`pe.rs`)

- **PE32**: validates `MZ`, `e_lfanew`, `PE\0\0`, machine `0x14c`, optional
  magic `0x10b`. Rejects PE32+ and non-i386 with an explanatory message.
- **LE**: recognizes `LE` at `e_lfanew`, walks the object/page maps, synthesizes
  a PE-like section table (image base 0), and reads fixup tables.
- **Sections**: executable means `CNT_CODE` or `MEM_EXECUTE`. `analyze` itself
  is permissive (`section_of`), so oddball images without flags still decode.
  Strict `is_executable_section_va` is used where an address must plausibly be
  code (vtable methods, `indirect_targets`).
- **LE fixups**:
  - `07` internal absolute records produce `(pre, post)` content pairs.
  - `08` self-relative records are validated but contribute no address pairs.
  - `02` selector records are skipped.
  - A record kind outside the proven grammar skips the tables loudly
    (`FixupStatus::Skipped` + `LE-FIXUP-SKIPPED` note); corruption stays fatal.
  - Instruction bytes and CFG structure stay pre-fixup. Recorded LE-08
    zero-placeholder `CALL rel32` sites resolve to runtime call targets for
    call-edge verification; `--asm` preserves raw bytes and annotates the
    resolved destination. Data-address acceptance also widens to post images.

### 5.2 Function walk (`analyze`)

- Worklist over reachable intra-function control flow, with a 64 KB
  (`0x10000`) span cap per function.
- Conditional branches push both taken and fallthrough; unconditional
  in-range jumps continue; out-of-range jumps become `tail_calls`.
- A **single-instruction entry block ending in `JMP`** is a tail call, not
  intra-function flow (MSVC sibling-call/ICF forwarders).
- `CALL` harvests a direct edge and a recovered call site. `IndirectCall`
  increments the count and records vtable/IAT/register targets where possible.
- `RET`/exception terminates; `int n` is **not** terminal (DOS/DPMI calls
  return).
- Jump-table recovery handles:
  - SIB-indexed `[base + idx*scale + TABLE]` (MSVC),
  - unindexed `[reg+TABLE]` with local base and switch evidence (Watcom),
  - register-table base built by `shl/add/mov` before `jmp reg` (GCC `-O0`).
  - Absolute `[disp]` indirect jumps are never followed (they name data/IAT).
- Decode failures are counted and sampled; a long run usually means a wrong
  entry address or embedded data.

### 5.3 Harvested facts (`CallGraph`)

| Field | Source |
|---|---|
| `direct_calls` | `CALL rel16/rel32` targets → site count |
| `call_sites` | per-call-site `ecx`, `edx`, stack argument kinds |
| `tail_calls` | `JMP` targets outside the walked body |
| `indirect_calls` / `indirect_jumps` | register/memory dispatch counts |
| `vcall_slots` | displacements of `CALL/JMP [reg+slot]` |
| `iat_calls` | absolute `CALL [slot]` targets that are IAT-like |
| `field_offsets` | `[reg+disp]` with `disp < 0x8000`, non-stack base, non-`LEA` |
| `globals` | absolute or large in-image memory displacements, non-`LEA` |
| `imm_addrs` | in-image immediate operands (vtable VAs, fn pointers, strings) |
| `signed/unsigned/equality_branches` | conditional-branch classes (`JL/JB/JE` families) |
| `max_end` | highest instruction end reached |

`footprint()` = direct calls + tail calls + IAT slots + globals + immediates.
It is the basis for inlining acceptance.

Call-site argument recovery (`recover_call_site` + `reg_params`) classifies a
short backward scan of the block. `reg_params` scans the callee's entry block
to decide whether ECX/EDX are thiscall/fastcall parameters. Only concrete
kinds on both sides are compared. This is deliberately conservative: unknown
reads as `Other` and is skipped.

### 5.4 Call-set semantics (`diff_body_calls_ext`)

Let:

- `bin_calls` (**narrow**) = direct `CALL` targets + tail-call `JMP` targets.
- `bin_calls_wide` = `bin_calls` plus:
  - executable-section code-pointer immediates,
  - declared `indirect_targets`,
  - one level of each tail target's direct calls,
  - one level of `JMP thunk` resolution.
- `bin_ported` = `bin_calls ∩ corpus`, excluding the function's own addresses.

Then:

- **HALLUCINATED** (`E012`): a resolved body call address is in neither
  `bin_calls_wide`, nor accepted as inlined, nor a known vtable method.
- **MISSING** (`E013`): a `bin_ported` address is not resolved by any body
  call name, is not `miss_satisfied`, or is a direct self-call the body does
  not spell.
- **UNPORTED-CALLS** (note, never fatal): a `bin_calls` address with no corpus
  origin. Bodies may omit it with a `TODO`, but the omission stays visible.
- **Inlining acceptance**: callee footprint must be a subset of the caller's
  footprint **and** contain at least two distinct in-image references. A single
  shared global/call target is coincidence, not proof.
- **VTABLE-DISPATCH** (`E011`): a direct body call to a method that the
  declared vtables show is dispatched virtually. The faithful form is an
  indirect call through the table.

### 5.5 CFG fingerprint (`skel.rs`)

Built from a local basic-block graph, with textbook dominance:

- `loops`: branch back to a dominator (natural loop back-edges). Forward
  `if (...) goto epilog` tails do not count because the tail does not dominate.
- `switch_cases`: recovered jump-table cases.
- `conditionals`: conditional-branch terminators.
- `returns`: returns / exceptions / out-of-function tail jumps.

Gate thresholds:

| Condition | Fires |
|---|---|
| `loops >= 2` and body has no loop | `E016` missing iteration |
| `switch_cases >= 3` and body has no `match` and fewer than 2 `if`s | `E016` missing switch |
| `conditionals >= 12` and body branchiness `<= 1` | `E016` heavy branching not reproduced |

Branchiness counts `if` + `match` + loops + short-circuit `&&`/`||`. Fake loops
(`loop { break; }`) are subtracted and reported as `FAKE-LOOP PLACEHOLDER`.

### 5.6 Reference set (`Pe::referenced_addrs`)

Used by `E006` and to widen LE fixup acceptance. Over-approximates by design:

- `JMP short rel8` (`0xEB`) targets,
- `CALL/JMP rel32` and `Jcc rel32` targets in `.text`,
- every little-endian `u32` at **every byte offset** of every section that lands
  inside the image (vtables, jump tables, baked pointers, data refs),
- on LE, the **post-fixup image** of every collected pre value (`07` records),
  so a slot-seeded callback stored as a link-time dword (`mov [slot],pre;
  call [slot]`) passes `E006` at the runtime VA a port bakes. Widening only.

A real function entry is reachable somehow; an address referenced nowhere is
almost certainly a misattributed origin. `unreferenced` is the loud waiver.

### 5.7 Vtables

`vtable_table!` generates `pub fn name() -> *const [usize; N]` (fat pointer,
length preserved) and verifies each wired slot against the binary:

- `E020 VTABLE-SLOT-OOB`: slot index ≥ declared `slots`.
- `E019 VTABLE-SLOT`: the binary's slot dword is not the address of the
  declared function.
- `E011 VTABLE-DISPATCH`: a direct body call targets a function that appears in
  a declared vtable.
- `VTABLE-ONLY DISPATCH` note: the origin is a declared vtable method and no
  `CALL/JMP/Jcc` in `.text` targets it (fine for an interface method, but
  verify the slot).

---

## 6. Gate reference

Every `#[origin]` collects findings and emits one `compile_error!` per finding.
Codes are stable and append-only. `E010` is intentionally unused.

| Code | Name | Severity | Meaning |
|---|---|---|---|
| `E001` | UNKNOWN-ATTR-KEY | fatal | Unknown `#[origin]` key (bad syntax) |
| `E002` | UNKNOWN-ATTR-FLAG | fatal | Unknown bare flag (only `unreferenced`) |
| `E003` | NOT-A-FUNCTION | fatal | Attribute applied to a non-function item |
| `E004` | TARGET-EXE-UNLOADABLE | fatal | `TARGET_EXE` set but missing/corrupt |
| `E005` | ORIGIN-OUTSIDE-SECTION | fatal | Origin address is outside every section |
| `E006` | ORIGIN-UNREFERENCED | fatal (waivable) | Origin is referenced nowhere in the image |
| `E007` | DECLARED-FACTS | fatal | A declared field/global/vtable/slot/IAT/indirect target is absent or invalid |
| `E008` | CORPUS-GAP | fatal | Own origin is missing from the scanned `REBUILD_ROOT` corpus |
| `E009` | DUP-ADDR | fatal | More than one Rust fn claims this binary address |
| `E011` | VTABLE-DISPATCH | fatal | Direct call to a known vtable method |
| `E012` | HALLUCINATED | fatal | Body calls something the binary never reaches (and did not inline) |
| `E013` | MISSING | fatal | Binary calls a ported fn the body does not spell (incl. direct self-call) |
| `E014` | ARG-SHAPE | fatal | Concrete argument kind/position mismatch at an unambiguous call site |
| `E015` | HALLUCINATED-ADDR | fatal | Body bakes an in-image address the binary never references here |
| `E016` | CFG | fatal | Gross CFG divergence: missing loops, switch, or branchiness |
| `E017` | ANALYZE | fatal | `analyze` failed for the origin |
| `E018` | CFG-FINGERPRINT | fatal | `cfg_fingerprint` failed for the origin |
| `E019` | VTABLE-SLOT | fatal | Declared vtable slot address does not match the binary |
| `E020` | VTABLE-SLOT-OOB | fatal | Slot index outside `slots = N` |
| `E021` | POLARITY | advisory NOTE | Binary tests a branch class the body never tests (code reserved) |

### Advisory notes (never fatal)

- `UNPORTED-CALLS` — real binary edges with no `#[origin]`; omitting them is
  allowed with a `TODO`.
- `FAKE-LOOP PLACEHOLDER` — `loop { break; }` scaffolding inflated the keyword
  counter.
- `OPAQUE-MACRO` — a macro invocation could not be expanded; calls/loops inside
  it are invisible to the gate.
- `VTABLE-ONLY DISPATCH` — origin reached only through a declared vtable slot.
- `LE-FIXUP-SKIPPED` — novel LE fixup record kind; address checks are
  pre-fixup only.
- `E021 POLARITY-NOTE` — wrong-class predicate hint. Advisory because
  downstream trees legitimately abstract predicates their HLE fixes.

### Diagnostic contract

`RichError` renders:

```
[CG-VERIFY-E012 HALLUCINATED] <message>
  -> fix: <concrete action>
```

- Each finding gets its own span; rustc points at the offending token.
- The summary header is printed to stderr, not duplicated into every
  `compile_error!`.
- Tests pin message wording where it is part of the contract; error numbers
  must never be renumbered.

---

## 7. Annotation reference

### `#[origin(addr, ...)]`

Only `addr` is required.

| Key | Form | Semantics |
|---|---|---|
| `fields` | `fields = [0x4, 0xbc]` | Field displacements the binary accesses at this origin |
| `globals` | `globals = [0x00b12340]` | Absolute data addresses referenced here |
| `vtables` | `vtables = [0x00a7e38c]` | In-image immediate addresses (vtable VA, fn ptr, string) |
| `vcall_slots` | `vcall_slots = [0x14]` | Indirect-call slot byte offsets (`slot*4`) |
| `indirect_targets` | `indirect_targets = [0xa9529]` | Callees reached only through register/memory indirect calls |
| `iat` | `iat = [0x00c00000]` | IAT slot addresses |
| `unreferenced` | bare flag | Waive `E006` for real boot anchors / external hooks |

`indirect_targets` is **acceptance-only**: a body may spell such a target as a
direct call, and it never becomes a `MISSING` requirement. Validation requires
the target to be in an executable section and the function to actually contain
at least one register/memory indirect call.

```rust
#[origin(0xad466, indirect_targets = [0xa9529])]
pub unsafe fn fn_ad466_2calls(..) { .. }
```

### `vtable_table!`

```rust
vtable_table! {
    name = renderer_vt,
    va = 0x00A88EA4,          // engine vtable VA
    slots = 98,               // slot count (decimal)
    default = crate::vtable::vtable_unimplemented;
    1  = renderer_get_rtti;   // slot = function
    21 = renderer_caps_flags;
}
```

Generates a `OnceLock`-backed `*const [usize; N]`. Every wired slot is checked
against the binary at compile time. Do not call a declared vtable method
directly; dispatch through the table.

### Local macro expansion

Only unambiguous `macro_rules!` definitions with simple matchers are expanded.
Repetitions, ambiguous names, proc macros, and builtins stay opaque and produce
`OPAQUE-MACRO`. Expansion is arity-only; spans from spliced bodies are dummy
and diagnostics anchor at the attribute line.

---

## 8. Testing strategy

### Layers

| Layer | What it proves |
|---|---|
| `pe.rs` unit tests | PE/LE parsing, synthetic fixups, malformed input, referenced scan |
| `disasm.rs` unit/integration tests | Walk semantics, arg recovery, jump tables, `int` fallthrough, thunks |
| `skel.rs` tests | CFG loops/dominance/switch counts |
| `integration.rs` | End-to-end `Spec` / diff / CFG behavior on in-process synthetic PEs |
| `c_cpp_integration.rs` | Real MSVC **and** MinGW C/C++ output (`/O2` and `/Od`) |
| `dos_le_integration.rs` | Real Open Watcom DOS4GW LE output |
| `perf.rs` | Cache behavior and scan scaling |
| `real_binary_sweep.rs` | Local whole-image agreement/diff-clean sweep |
| `tests/ui/*` | `trybuild` snapshots for every fatal code |
| `real_structure.rs` | Live-fixture E016/E013 pins, MSVC-only |
| `error_codes.rs` | Stable code numbering/labels |

### Fixture matrix

| Fixture | Source | Toolchains | Notes |
|---|---|---|---|
| C | `test-fixtures/c/callgraph.c` | MSVC `cl`, MinGW `gcc` | `/O2`; calls, branches, switch, globals, fields, indirect, tail pair, recursion |
| C-od | same | MSVC `/Od`, MinGW `-O0 -mno-accumulate-outgoing-args` | Weak-optimizer/EBP-frame shapes, PUSH args |
| C-dbg | same | MSVC `/Od` + `/INCREMENTAL` | ILT `JMP` thunks; MSVC-only |
| C++ | `test-fixtures/cpp/callgraph.cpp` | MSVC `/O2`, MinGW `g++ -O2` | Vtables, thiscall, virtual dispatch |
| DOS | `test-fixtures/dos/callgraph.c` | Open Watcom `owcc -bdos4g` | No optimization; LE fixups; shape-discovered functions |

### Running fixtures locally

Windows (x86 VS dev prompt for MSVC fixtures):

```powershell
python callgraph-verify/test-fixtures/build_fixtures.py --toolchain msvc --out target/fixtures
$env:CALLGRAPH_REQUIRE_FIXTURES = "1"
cargo test -p callgraph-verify --test c_cpp_integration
```

Linux / WSL (MinGW + Watcom):

```bash
export PATH=/path/to/i686-w64-mingw32/bin:$PATH
export WATCOM=/path/to/watcom
export INCLUDE=$WATCOM/h
export PATH=$WATCOM/binl64:$PATH
python3 callgraph-verify/test-fixtures/build_fixtures.py --toolchain mingw --out target/fixtures
CALLGRAPH_REQUIRE_FIXTURES=1 cargo test -p callgraph-verify \
  --test c_cpp_integration --test dos_le_integration
```

Full local verification matching both CI jobs:

```bash
cargo test --workspace                 # host + Windows full suite when MSVC is available
cargo test -p callgraph-verify --test c_cpp_integration
cargo test -p callgraph-verify --test dos_le_integration   # skips without owcc
cargo test -p callgraph-verify --test perf
cargo test -p callgraph-verify-macro
```

Real binary sweep:

```bash
CALLGRAPH_REAL_EXE=/path/to/sample.exe \
  cargo test -p callgraph-verify --test real_binary_sweep -- --nocapture
```

Local real-PE CFG pins (skipped when no binary is supplied):

```bash
CALLGRAPH_REAL_PE=/path/to/sample.exe \
  cargo test -p callgraph-verify --test integration cfg_pin_real_pe -- --nocapture
```

### CI jobs

- **windows (MSVC fixtures + full suite)**: `ilammy/msvc-dev-cmd` with
  `arch: x86`, builds fixtures, asserts artifacts, runs
  `cargo test --workspace --verbose`. Includes `test-bin` (`i686-pc-windows-msvc`)
  and the trybuild UI suite.
- **ubuntu (MinGW + Watcom fixtures + host suites)**: installs
  `gcc-mingw-w64-i686` / `g++-mingw-w64-i686` and Open Watcom, builds fixtures,
  then runs `c_cpp_integration`, `dos_le_integration`, `perf`, and the macro
  suite. The host-only `integration` suite needs the MSVC linker, so it does
  not run here.

`CALLGRAPH_REQUIRE_FIXTURES=1` is set in CI so a broken fixture build cannot
silently skip every real-compiler test.

### When you add or change a check

1. Write the failing synthetic test first (`integration.rs` or `pe.rs`).
2. Add a real-fixture assertion if compiler output can exercise it.
3. Add or update a `trybuild` `.rs`/`.stderr` pair when a diagnostic changes;
   re-bless intentionally and review the snapshot diff.
4. Update `CHANGELOG.md` under `[Unreleased]`.
5. Run both toolchain fixture suites you have access to; state which one you
   could not run.

---

## 9. Known limits and blind spots

These are deliberate, documented limits, not hidden bugs.

- **Static structure only.** No dataflow, no types, no arithmetic equivalence.
  Two ports with the same calls/addresses/CFG can still compute different
  values.
- **Tolerances.**
  - `E016` fires only on gross divergence (≥2 loops, ≥3 switch cases, ≥12
    conditionals with branchiness ≤1).
  - `E021` compares branch *classes*, not taken-arm polarity. `==` vs `!=`
    within the equality class is a hand audit.
  - `E021` is advisory, not fatal.
- **Name-based call resolution.** `DENY` excludes generic std/trait names, so a
  hallucinated call to a generically named ported fn is not caught. A
  same-named collateral call can satisfy `MISSING` (it can never fire
  `HALLUCINATED`).
- **Qualified/generic names.** `Self::m(..)` / `Type::m(..)` and generically
  named ports are covered by `miss_satisfied` for MISSING only.
- **Inlining heuristic.** Footprint subset with at least two distinct in-image
  references. A single shared reference is not accepted as proof.
- **Macros.** Only unambiguous local `macro_rules!` with simple matchers are
  expanded. Proc macros / repetitions / ambiguous names remain opaque and are
  reported, not silently trusted.
- **Function extent cap.** 64 KB. A pathological function crossing that span is
  truncated for analysis.
- **Thunk/tail folds are one level.** The diff resolves one level of `JMP`
  thunks and one level of tail-target calls.
- **`indirect_targets` is not proven per target.** The gate validates
  "executable section + function has an indirect call", not that this function
  actually reaches that specific target, and it does not correlate a target to
  a slot offset.
- **Field offsets are not auto-checked.** Small hex (`0x10`, `0xff`) is
  indistinguishable from constants; use explicit `fields = [...]`.
- **LE fixups.** Data addresses accept post-fixup images. Call graph and CFG
  stay pre-fixup. Jump-table entries read pre-fixup bytes, so some LE switch
  cases are recovered via fallthrough heuristics. Novel fixup records skip the
  tables loudly.
- **Pre-fixup pointer immediates.** A body may need to spell the pre-fixup
  value (e.g. `0x99529`) rather than the runtime value (`0xA9529`) in some
  images; the `unreferenced` waiver is the documented escape when the pointer
  immediate is mid-instruction.
- **ARG-SHAPE const-prop not shipped.** `let`-bound argument values are not
  resolved to concrete kinds; doing so exposed a positional model mismatch
  downstream. `classify_expr` stays literal-only.
- **32-bit x86 only.** PE32/LE. x86_64, ARM, ARM64 are planned, not supported.
- **`test-bin`/MSVC link requirement.** The host `integration` suite needs an
  MSVC linker and therefore does not run on the Ubuntu job.

---

## 10. Change playbooks

### Fix a harvest blind spot

1. Reproduce with a synthetic PE test (hand-assembled bytes) that fails before
   the fix.
2. Add or reuse a real-compiler fixture shape that exhibits the compiler idiom.
3. Keep acceptance widening separate from MISSING demands. New folds go into
   the wide set only.
4. Verify no existing function boundary moves; if it does, add a regression
   test that proves the new partitioning is correct.
5. Record the real-binary before/after in the changelog when available.

### Add a gate / error code

1. Append a variant to `Code` (never renumber; `E010` stays unused).
2. Emit `RichError` with a span and a concrete fix.
3. Add a `tests/ui/` fixture and `.stderr` snapshot.
4. Add `error_codes.rs` stability assertions.
5. Update this bible's gate table and the README check list.

### Touch fixture sources

- Keep every function reachable from `main` and `NOINLINE` (C/C++).
- Preserve the pinned shapes: caller/leaf/loop/nested loop/dense switch/
  if-chain/inlinable pair/indirect call/globals/field pair/self-recursion/
  virtual call (C++).
- Update `C_SYMBOLS` / `CPP_SYMBOLS` in `build_fixtures.py` when adding a
  manifest symbol.
- Rebuild both toolchains when possible; never assume MSVC shape equals MinGW.

### Release checklist

1. `CHANGELOG.md` `[Unreleased]` is complete and correctly categorized.
2. Version bumped in `Cargo.toml` if releasing.
3. Both CI jobs green on the release commit.
4. Tag `vX.Y.Z`; the changelog link block updated.
5. For behavior-affecting changes, include before/after evidence on a real
   binary (function counts, diagnostics, or fixture results).

### Agent rules

- Do not add config knobs that weaken checks.
- Do not delete a test to make CI green; fix the premise or the code, and say
  which real shape the test now pins.
- When a compiler lowers a construct differently (recursion → loop, tail call
  → `JMP`), pin the shape that actually exists per toolchain; do not blanket-
  skip a toolchain.
- Every diagnostic must tell the next agent what to change.

---

## 11. Troubleshooting cookbook

| Symptom | First checks |
|---|---|
| `E012 HALLUCINATED` | Is the call real? Check `--asm` at the origin. Is the callee inlined (footprint subset)? Is it reached only via `call [reg]` → declare `indirect_targets`. Is it a vtable method → dispatch via the table. |
| `E013 MISSING` | Check the direct `CALL`/tail `JMP` in `--asm`, including any `LE08 runtime target` annotation on a zero-displacement call. Spell the call, reproduce the callee's work inline, or port the callee with an `#[origin]`. Self-recursion must be spelled. |
| `E008 CORPUS-GAP` | `REBUILD_ROOT` wrong/empty, or a file failed to parse (the message names the skipped files). |
| `E006 ORIGIN-UNREFERENCED` | Verify the VA; if real but externally reached, use `unreferenced`. |
| `E005 ORIGIN-OUTSIDE-SECTION` | Wrong image base or transposed address; `--summary`/`--list` shows the real layout. |
| `E015 HALLUCINATED-ADDR` | Use the address the binary references; check LE pre/post fixup images; check tail-target globals are folded. |
| `E014 ARG-SHAPE` | Compare the call site in `--asm`; check register alignment (`reg_params`); ICF-folded stubs can produce noise. |
| `E016 CFG` | Port loops/switch inline at the attributed function. Extracted helpers need their own `#[origin]` and matching structure. |
| `E021 POLARITY-NOTE` | Advisory. Compare `je/jne` vs `jl/jg` in `--asm`; port the predicate class. |
| UI snapshot mismatch | Re-run with `TRYBUILD=overwrite` intentionally, inspect the `.stderr` diff, commit only the intended wording. |
| Fixture tests all skipped | Build artifacts missing. Run `build_fixtures.py`; check `CALLGRAPH_REQUIRE_FIXTURES`; check toolchain on PATH. |
| CI ubuntu fails but Windows passes | MinGW or Watcom codegen differs. Reproduce with the exact CI toolchain versions, not a newer local one. |

### CLI investigation

```bash
cargo run --bin callgraph_verify -- target.exe 0x401000 --asm       # ground truth
cargo run --bin callgraph_verify -- target.exe 0x401000 --skeleton  # structure hint
cargo run --bin callgraph_verify -- target.exe --list --max 50
cargo run --bin callgraph_verify -- target.exe --summary
cargo run --bin callgraph_verify -- target.exe --json --max 50
cargo run --bin callgraph_verify -- target.exe 0x401000 --declared 0x401050 --exact
```

Always port from `--asm`. The raw zero-displacement `CALL rel32` remains
visible as `call $+5`; when an LE-08 fixup supplies its runtime destination,
the instruction line appends that address. Use the opcode and annotation
together. The skeleton is a coarse structural hint, not ground truth.

---

## 12. Glossary

| Term | Meaning |
|---|---|
| Origin | The binary VA a Rust function claims to implement (`#[origin]`) |
| Corpus | All `#[origin]` tags scanned from `REBUILD_ROOT` (name ↔ address) |
| Narrow set | Direct calls + tail-call targets; the source of `MISSING` |
| Wide set | Narrow set + inlining/thunk/immediate/indirect-target acceptance; only for `HALLUCINATED` |
| Tail target | A `JMP` out of the walked body (sibling call / forwarder) |
| Thunk | A one-instruction `JMP` forwarder; resolved one level |
| Footprint | Addresses a function references (calls, tails, IAT, globals, immediates) |
| Fixup | LE relocation record; `07` absolute pairs are absorbed as `(pre, post)` |
| Natural loop | Back-edge to a dominating block (dominance-confirmed iteration) |
| Branchiness | `if` + `match` + loops + `&&`/`||` in a body |
| Acceptance-only | Widens what is not HALLUCINATED; never creates a MISSING demand |
| Real fixture | Binary produced by a genuine compiler in CI, not hand-assembled bytes |
| `REQUIRE_FIXTURES` | CI mode that turns a missing committed fixture into a failure |

---

## Appendix A — Public library surface

```rust
// callgraph-verify
pub fn analyze(pe: &Pe, entry: u64) -> Result<CallGraph, String>;
pub fn cfg_fingerprint(pe: &Pe, entry: u64) -> Result<CfgFingerprint, String>;
pub fn diff_calls(pe: &Pe, entry: u64, declared: &[u64], exact: bool) -> Result<Diff, String>;
pub fn diff_body_calls(/* ... */) -> Result<CorpusDiff, String>;
pub fn diff_body_calls_ext(/* + indirect_targets */) -> Result<CorpusDiff, String>;
pub fn reg_params(pe: &Pe, addr: u64) -> (bool, bool);
pub fn resolve_thunk(pe: &Pe, addr: u64) -> Option<u64>;
pub fn tail_referenced(pe: &Pe, cg: &CallGraph) -> BTreeSet<u64>;
pub fn has_direct_branch_target(pe: &Pe, target: u64) -> bool;

pub struct Spec { /* addr, calls, fields, globals, vtables, vcall_slots,
                     indirect_targets, iat */ }
pub struct Pe { /* load/parse/sections/read/referenced_addrs/fixups */ }
pub struct CallGraph { /* harvested facts */ }
pub struct CfgFingerprint { /* loops, switch_cases, conditionals, returns */ }
```

## Appendix B — Durable verification snapshot

At the time this bible was written, both CI jobs were reproduced locally on
Windows with the exact CI command shapes:

- Windows: MSVC x86 fixtures + `cargo test --workspace` — **pass**.
- Ubuntu equivalent: MinGW-w64 GCC 13.2 fixtures (`c_cpp_integration`) and
  Open Watcom `owcc -bdos4g` (`dos_le_integration`) — **pass**.
- Host suites: `perf`, macro unit tests, trybuild UI — **pass**.
- Local real binary: whole-image sweep — 47,896 entries / 10,988 direct
  calls, no disagreements — **pass**.

Re-run the commands in section 8 after any change; do not treat this snapshot
as current evidence.

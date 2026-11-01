# Feature handoff: `indirect_targets` (stack-slot / register indirect callbacks)

Status: **shipped in 0.1.6**. The feature landed together with the E021
advisory note, the ARG-SHAPE const-prop withdrawal, and the related CI
fixture fixes.

## Why

Some functions reach a callee only through a register/memory indirect call,
e.g. a stack-slot callback:

```asm
mov  ecx, 99529h        ; callback pointer (relocated to 0xA9529 at load)
call 0AD466h            ; formatter; does `call [esp+44h]`
```

The binary never issues a direct `CALL 0xA9529` from the caller, so a faithful
port that spells the callback as a direct Rust call was rejected with:

```
[CG-VERIFY-E012 HALLUCINATED] body calls `emit_byte_a9529` (0x000a9529)
-- binary at 0x000ad466 never calls it
```

`indirect_targets` lets the body declare such targets explicitly.

## Syntax

```rust
#[origin(0xad466, indirect_targets = [0xa9529])]
pub unsafe fn fn_ad466_2calls(..) -> u32 { .. }
```

Each entry is an address the function reaches through one of its
register/memory indirect calls. The list is a plain `[0xNN, ...]` array, like
`fields` / `globals` / `vtables` / `vcall_slots` / `iat`.

## Semantics

- **Acceptance-only.** A body call to a declared target is treated as faithful
  (it is added to the wide acceptance set, `bin_calls_wide`). It is **not**
  added to the MISSING requirement: the binary issues no direct CALL to it, so
  a body may legitimately omit the callback.
- **Validated.** Each target must be an executable-section VA, and the
  function must actually contain at least one `indirect_calls` (register/memory
  CALL). Otherwise `Spec::check` fails with `E007 DECLARED-FACTS`:
  - `indirect target 0x... is not in an executable section`
  - `indirect_targets declared, but the binary makes no register/memory indirect call at this address`
- Does not change the `diff_body_calls` behaviour when unused (the wrapper
  passes an empty set).

## Implementation map

`callgraph-verify/src/lib.rs`
- `Spec` gains `indirect_targets: Vec<u64>` (acceptance-only field).
- `Spec::indirect_targets(&[u64])` builder.
- `Spec::check` validates executable-section VAs and the presence of an
  indirect call.
- `diff_body_calls(...)` is now a wrapper around
  `diff_body_calls_ext(..., indirect_targets: &BTreeSet<u64>)`.
- `diff_body_calls_ext` extends `bin_calls_wide` with the declared targets.

`callgraph-verify-macro/src/lib.rs`
- `Args` gains `indirect_targets: Vec<u64>`.
- Parser accepts the key; `E001` / `E002` messages list it.
- `Spec::new(..).indirect_targets(&args.indirect_targets)`.
- The body diff calls `diff_body_calls_ext` with the declared set.

`callgraph-verify/tests/integration.rs`
- New `test_diff_body_calls_indirect_target_accepted`: a declared target is not
  hallucinated and not demanded as MISSING.

`callgraph-verify/tests/c_cpp_integration.rs`
- New `c_indirect_target_accepted_on_real_output`: on the real MSVC and MinGW
  C fixtures (`/O2` and `/Od`), a body that specializes `apply_twice`'s
  callback to the concrete `inc_fn` is HALLUCINATED without the declaration and
  accepted (never MISSING) with `indirect_targets = [inc_fn]`.

`callgraph-verify-macro/tests/ui/e001_unknown_attr_key.stderr`,
`.../e002_unknown_attr_flag.stderr`
- Re-blessed for the new key list.

`CHANGELOG.md`
- `[Unreleased] / Added` entry.

## Tests

```
cargo test --workspace          # all green (incl. trybuild ui snapshots)
cargo test -p callgraph-verify --test integration \
    test_diff_body_calls_indirect_target_accepted
```

## Downstream use (a real port)

Demonstrated end-to-end: with

```rust
#[origin(0xa9529, unreferenced)]           // relocated immediate: pre 0x99529
pub unsafe fn emit_byte_a9529(buf: u32, ch: u32) { .. }

#[origin(0xad466, indirect_targets = [0xa9529])]
pub unsafe fn fn_ad466_2calls(..) { .. }   // body calls emit_byte_a9529(..)
```

`cargo check` passes (`E012` gone). The `unreferenced` waiver on the emitter is
still needed because the gate scans the pre-fixup image, where the pointer
immediate is the mid-instruction `0x99529` rather than the runtime `0xA9529`.

## Known limitations / follow-ups

- The attribute does **not** tie a target to a specific slot offset. If slot
  pinning is wanted, combine with `vcall_slots = [0x44]` (already supported);
  the gate checks the slot exists but does not correlate slot -> target.
- The target is validated only by "executable + function has an indirect call".
  It is not proven that the function actually reaches that particular target.
- The pre-fixup -> post-fixup relocation of pointer immediates is still a gate
  blind spot; the `unreferenced` waiver is the current escape (documented in
  the macro).
- The remaining formatter work is unrelated to this gate feature: the
  StackSlot frame, the 9 callback sites, and the va_list dataflow in `ad466`
  must still be ported before `[0x203A4]` is filled.

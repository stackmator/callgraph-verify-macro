#!/usr/bin/env python3
"""Build the real C/C++ fixtures to 32-bit PEs and extract address manifests.

Used by `.github/workflows/integration.yml` and by developers reproducing CI
locally::

    python build_fixtures.py --out <dir>   # default: <repo>/target/fixtures

Toolchains (32-bit PE out, x86 code in):
  * Windows: MSVC `cl`/`link` (run from an x86 dev prompt, or use the
    `ilammy/msvc-dev-cmd` action with `arch: x86` in CI).
  * Linux:   `i686-w64-mingw32-gcc` / `-g++` (package `gcc-mingw-w64-i686` /
    `g++-mingw-w64-i686`).

For each fixture this writes `<name>.exe` plus `<name>_addrs.json`, a
`{symbol: "0xVA"}` map of the *preferred* VAs (what `callgraph-verify` parses
from the file headers, so ASLR at runtime is irrelevant). MSVC addresses come
from the linker `.map` "Publics by Value" section; MinGW addresses come from
`nm`. Both spell 32-bit cdecl symbols with a leading underscore (`_leaf_add`)
and MSVC may add stdcall `@N` suffixes — both are stripped, so the JSON keys
are the plain source names the Rust tests use.

Exit status is non-zero on any compile/extract failure; the file list it
expects is pinned in C_SYMBOLS / CPP_SYMBOLS below, so a renamed fixture
function fails loudly here instead of silently skipping tests.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
C_SRC = os.path.join(HERE, "c", "callgraph.c")
CPP_SRC = os.path.join(HERE, "cpp", "callgraph.cpp")
DOS_SRC = os.path.join(HERE, "dos", "callgraph.c")

C_SYMBOLS = [
    "leaf_add",
    "leaf_const",
    "inc_fn",
    "branch_caller",
    "parent_fn",
    "loop_sum",
    "nested_sum",
    "classify",
    "decision_chain",
    "tiny_sum",
    "uses_tiny",
    "g_k2",
    "main",
    "g_counter",
    "read_global",
    "write_global",
    "field_read",
    "field_write",
    "apply_twice",
    "use_apply",
]

CPP_SYMBOLS = [
    "cpp_leaf_fn",
    "cpp_caller_fn",
    "cpp_counter_fn",
    "cpp_field_fn",
    "cpp_use_virtual_fn",
    "cpp_shapes_fn",
    "main",
]

# Vtable addresses have toolchain-decorated names (MSVC `??_7Circle@@6B@`,
# Itanium `_ZTV6Circle`), so they are resolved by alias list: the first raw
# symbol that hits wins. Normalized-name matching would mangle the Itanium
# form (leading-underscore strip), so aliases match RAW map/nm names.
VTABLE_ALIASES = {
    "circle_vt": ["??_7Circle@@6B@", "_ZTV6Circle"],
    "square_vt": ["??_7Square@@6B@", "_ZTV6Square"],
}


def run(cmd: list[str], cwd: str) -> None:
    print("+", " ".join(cmd), flush=True)
    subprocess.run(cmd, cwd=cwd, check=True)


def demangle_symbol(raw: str) -> str:
    """Strip 32-bit toolchain decorations to the plain source name."""
    name = raw
    if name.startswith("_"):
        name = name[1:]
    # MSVC stdcall suffix: `foo@12`.
    name = re.sub(r"@\d+$", "", name)
    # MinGW can emit `foo@12` too; same strip applies.
    return name


def parse_msvc_map(map_path: str) -> dict[str, int]:
    """Parse MSVC linker's "Publics by Value" section: `seg:off name VA ...`.

    Returns RAW symbol names (leading underscores, stdcall suffixes intact);
    `write_manifest` normalizes and resolves aliases.
    """
    out: dict[str, int] = {}
    in_publics = False
    pat = re.compile(r"^\s*[0-9A-Fa-f]{4}:[0-9A-Fa-f]{8}\s+(\S+)\s+([0-9A-Fa-f]{8})\b")
    with open(map_path, encoding="utf-8", errors="replace") as f:
        for line in f:
            if "Publics by Value" in line:
                in_publics = True
                continue
            if in_publics and line.strip().startswith("entry point"):
                break
            if not in_publics:
                continue
            m = pat.match(line)
            if m:
                out.setdefault(m.group(1), int(m.group(2), 16))
    return out


def parse_nm(nm_path: str) -> dict[str, int]:
    """Parse `nm -n` output: `VVVVVVVV <type> name` (skip undefined `U`).

    Returns RAW symbol names; see `parse_msvc_map`.
    """
    out: dict[str, int] = {}
    pat = re.compile(r"^([0-9A-Fa-f]+)\s+([A-Za-z?])\s+(\S+)")
    with open(nm_path, encoding="utf-8", errors="replace") as f:
        for line in f:
            m = pat.match(line.strip())
            if not m or m.group(2) == "U":
                continue
            out.setdefault(m.group(3), int(m.group(1), 16))
    return out


def write_manifest(
    path: str,
    raw_symbols: dict[str, int],
    wanted: list[str],
    aliases: dict[str, list[str]] | None = None,
) -> None:
    # Normalized lookup (first raw spelling wins); aliases resolve against
    # RAW names so toolchain-decorated forms (`??_7Circle@@6B@`,
    # `_ZTV6Circle`) match without going through underscore-stripping.
    symbols: dict[str, int] = {}
    for raw, va in raw_symbols.items():
        symbols.setdefault(demangle_symbol(raw), va)
    manifest: dict[str, str] = {}
    missing: list[str] = []
    for w in wanted:
        if w in symbols:
            manifest[w] = hex(symbols[w])
        else:
            missing.append(w)
    for alias, raws in (aliases or {}).items():
        hit = next((r for r in raws if r in raw_symbols), None)
        if hit is None:
            missing.append(f"{alias} (one of {'/'.join(raws)})")
        else:
            manifest[alias] = hex(raw_symbols[hit])
    if missing:
        raise SystemExit(
            f"ERROR: {path}: {len(missing)} wanted symbols missing from the "
            f"built binary: {missing}\n"
            f"(the optimizer may have discarded them — check they are called "
            f"from main and marked NOINLINE)"
        )
    with open(path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
        f.write("\n")
    print(f"wrote {path} ({len(manifest)} symbols)", flush=True)


def build_msvc(out: str) -> None:
    if shutil.which("cl") is None or shutil.which("link") is None:
        raise SystemExit(
            "ERROR: cl/link not on PATH — run from an x86 VS dev prompt "
            "(vcvarsall x86) or use ilammy/msvc-dev-cmd with arch: x86"
        )
    # (stem, src, wanted, aliases, cl_flags, link_flags)
    variants = [
        (
            "c_callgraph",
            C_SRC,
            C_SYMBOLS,
            None,
            ["/O2"],
            ["/INCREMENTAL:NO"],
        ),
        # Unoptimized: EBP frames, no inlining, naive codegen — the closest
        # feasible proxy for a weak/old optimizer. /INCREMENTAL:NO keeps this
        # build thunk-free so it isolates optimization-shape coverage.
        (
            "c_callgraph_od",
            C_SRC,
            C_SYMBOLS,
            None,
            ["/Od"],
            ["/INCREMENTAL:NO"],
        ),
        # Debug + incremental linking: every function call routes through an
        # ILT `JMP real_fn` thunk — the old-debug-build shape (2005-era
        # binaries are full of these). Exercises `resolve_thunk` and the
        # diff's thunk-tolerant wide set on real output. PDB/ILK/EXP land
        # next to the exe (gitignored via target/).
        (
            "c_callgraph_dbg",
            C_SRC,
            C_SYMBOLS,
            None,
            ["/Od", "/Zi"],
            ["/INCREMENTAL", "/DEBUG"],
        ),
        (
            "cpp_callgraph",
            CPP_SRC,
            CPP_SYMBOLS,
            VTABLE_ALIASES,
            ["/O2"],
            ["/INCREMENTAL:NO"],
        ),
    ]
    for stem, src, wanted, aliases, cflags, lflags in variants:
        obj = os.path.join(out, stem + ".obj")
        exe = os.path.join(out, stem + ".exe")
        map_path = os.path.join(out, stem + ".map")
        manifest = os.path.join(out, stem + "_addrs.json")
        run(
            # /MD (dynamic CRT): printf resolves through the IAT, which the
            # iat_calls tests pin. Default /MT links the CRT statically, so
            # main would show no import edges at all.
            ["cl", "/nologo", "/GS-", "/MD", "/W3", "/c", src, "/Fo" + obj]
            + cflags,
            cwd=out,
        )
        run(
            [
                "link",
                "/nologo",
                "/MACHINE:X86",
                "/SUBSYSTEM:CONSOLE",
                "/MAP:" + map_path,
                "/OUT:" + exe,
                obj,
            ]
            + lflags,
            cwd=out,
        )
        write_manifest(manifest, parse_msvc_map(map_path), wanted, aliases)


def build_mingw(out: str) -> None:
    for cc, nm, stem, src, wanted, aliases, opt in (
        (
            "i686-w64-mingw32-gcc",
            "i686-w64-mingw32-nm",
            "c_callgraph",
            C_SRC,
            C_SYMBOLS,
            None,
            "-O2",
        ),
        # Unoptimized twin of the MSVC /Od build (weak-optimizer shapes on
        # the GNU side). No incremental-linking equivalent exists for GNU
        # ld, so the ILT-thunk variant stays MSVC-only.
        (
            "i686-w64-mingw32-gcc",
            "i686-w64-mingw32-nm",
            "c_callgraph_od",
            C_SRC,
            C_SYMBOLS,
            None,
            "-O0",
        ),
        (
            "i686-w64-mingw32-g++",
            "i686-w64-mingw32-nm",
            "cpp_callgraph",
            CPP_SRC,
            CPP_SYMBOLS,
            VTABLE_ALIASES,
            "-O2",
        ),
    ):
        if shutil.which(cc) is None:
            raise SystemExit(
                f"ERROR: {cc} not found — install gcc-mingw-w64-i686 "
                f"(and g++-mingw-w64-i686 for the C++ fixture)"
            )
        exe = os.path.join(out, stem + ".exe")
        map_path = os.path.join(out, stem + ".map")
        nm_path = os.path.join(out, stem + ".nm")
        manifest = os.path.join(out, stem + "_addrs.json")
        run(
            [
                cc,
                opt,
                "-fno-stack-protector",
                "-o",
                exe,
                src,
                "-Wl,-Map," + map_path,
            ],
            cwd=out,
        )
        if shutil.which(nm) is None:
            raise SystemExit(f"ERROR: {nm} not found")
        with open(nm_path, "w", encoding="utf-8") as f:
            subprocess.run([nm, "-n", exe], cwd=out, check=True, stdout=f)
        write_manifest(manifest, parse_nm(nm_path), wanted, aliases)


def build_dos(out: str) -> bool:
    """Build the DOS4GW LE fixture with Open Watcom, if available.

    Returns True when built, False when `owcc` is not on PATH (Watcom is
    CI-only via open-watcom/setup-watcom; local MSVC/MinGW builds skip DOS
    with a note). No address manifest: the dos_le_integration tests discover
    functions by shape, so wlink map parsing is unnecessary.
    """
    if shutil.which("owcc") is None:
        print("note: owcc not on PATH — skipping DOS4GW fixture", flush=True)
        return False
    exe = os.path.join(out, "dos_callgraph.exe")
    # No optimization flags: wcc386 does not inline without -oe, so every
    # call edge in dos/callgraph.c survives as a real CALL.
    run(["owcc", "-bdos4g", "-o", exe, DOS_SRC], cwd=out)
    print(f"built DOS4GW LE fixture: {exe}", flush=True)
    return True


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--out",
        default=os.path.join(HERE, "..", "..", "target", "fixtures"),
        help="output dir for .exe + _addrs.json (default: <repo>/target/fixtures)",
    )
    ap.add_argument(
        "--toolchain",
        choices=["auto", "msvc", "mingw"],
        default="auto",
        help="force a toolchain (default: msvc on Windows, mingw elsewhere)",
    )
    args = ap.parse_args()
    out = os.path.abspath(args.out)
    os.makedirs(out, exist_ok=True)
    tc = args.toolchain
    if tc == "auto":
        tc = "msvc" if os.name == "nt" else "mingw"
    print(f"toolchain={tc} out={out} src_c={C_SRC}", flush=True)
    if tc == "msvc":
        build_msvc(out)
    else:
        build_mingw(out)
    # DOS4GW LE via Open Watcom when present (CI ubuntu job); skipped
    # elsewhere — the dos_le_integration tests skip gracefully without it.
    build_dos(out)
    print("fixtures OK:", sorted(os.listdir(out)), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())

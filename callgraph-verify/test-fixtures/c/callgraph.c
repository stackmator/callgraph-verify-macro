// callgraph.c — real C fixture for the callgraph-verify integration tests.
//
// Compiled by CI (MSVC `cl` on Windows, `i686-w64-mingw32-gcc` on Linux)
// to a 32-bit PE and verified by `callgraph-verify/tests/c_cpp_integration.rs`
// via the address manifest that `build_fixtures.py` extracts from the linker
// map (MSVC) or `nm` (MinGW).
//
// Every function below is NOINLINE + externally linked + reachable from
// `main`, so `/O2` (MSVC) and `-O2` (GCC) must preserve the exact call edges
// the tests pin. If you add a function, call it from `main` (else the linker
// may discard it) and add its name to the manifest list in
// `build_fixtures.py`.

#include <stdio.h>

#if defined(_MSC_VER)
#define NOINLINE __declspec(noinline)
#else
#define NOINLINE __attribute__((noinline))
#endif

// --- leaf functions: no calls at all ---------------------------------------

NOINLINE int leaf_add(int a, int b) {
    return a + b;
}

NOINLINE int leaf_const(void) {
    return 123;
}

NOINLINE int inc_fn(int x) {
    return x + 1;
}

// --- a caller with exactly two direct callees, on different branches -------
// The verifier follows both sides of the conditional, so the binary call set
// of `branch_caller` is exactly { leaf_add, leaf_const }.

NOINLINE int branch_caller(int x) {
    if (x > 100) {
        return leaf_add(x, 1);
    }
    return leaf_const() + x;
}

// --- a caller of a caller (one direct call) --------------------------------

NOINLINE int parent_fn(int x) {
    return branch_caller(x) * 2;
}

// --- a loop: the CFG fingerprint must see at least one back-edge -----------

NOINLINE int loop_sum(int n) {
    int s = 0;
    for (int i = 1; i <= n; i++) {
        s += i;
    }
    return s;
}

// --- nested loops: two natural back-edges (inner + outer) ------------------
// This is the macro's E016 CFG firing threshold (`loops >= 2`), pinned here
// on real compiler output instead of only hand-written bytes (e016_cfg.rs).

NOINLINE int nested_sum(int n, int m) {
    int s = 0;
    for (int i = 0; i < n; i++) {
        for (int j = 0; j < m; j++) {
            s += i + j;
        }
    }
    return s;
}

// --- long if-chain: 12 conditionals, the third E016 prong -------------------
// `conditionals >= 12` with a straight-line body fires E016; pin the INPUT
// (conditional count) on real output — nothing covered it before. Constants
// are deliberately irregular with non-identity returns: dense 0..N ranges
// returning N let MSVC fold the tail into a range check (11 branches for
// 12 ifs), and dense ranges risk jump-table lowering instead of compares.

NOINLINE int decision_chain(int x) {
    if (x == 3) return 30;
    if (x == 17) return -4;
    if (x == 42) return 7;
    if (x == 99) return 1000;
    if (x == 101) return -991;
    if (x == 1009) return 5;
    if (x == -7) return 77;
    if (x == 65536) return 1;
    if (x == -100000) return 2;
    if (x == 1234567) return 3;
    if (x == (-2147483647 - 1)) return 4;
    if (x == 2147483647) return 5;
    if (x == 555) return 6;
    if (x == 777) return 7;
    return -1;
}

// --- dense switch: 8 cases with call bodies lower to control flow ---------
// First coverage of the fingerprint's `switch_cases` prong: dense ranges
// lower to `JMP [table+idx*4]` (MSVC always; GCC when bodies are
// non-trivial), which `follow_jump_table` must resolve to >= 3 case entries.
// Each case calls `leaf_add` with distinct args (never executed — the
// fixture binaries are only parsed): calls can't be predicated away, so the
// switch must survive as control flow on both toolchains. If a toolchain
// emits a compare chain instead of a table, the test accepts that too
// (conditionals prong) — but branchless mush fails it.

NOINLINE int classify(int v) {
    switch (v) {
        case 0: return leaf_add(100, 0);
        case 1: return leaf_add(101, 1);
        case 2: return leaf_add(102, 2);
        case 3: return leaf_add(103, 3);
        case 4: return leaf_add(104, 4);
        case 5: return leaf_add(105, 5);
        case 6: return leaf_add(106, 6);
        case 7: return leaf_add(107, 7);
        default: return -1;
    }
}

// --- a global: `read_global`/`write_global` must reference `g_counter` -----

int g_counter = 0;

NOINLINE int read_global(void) {
    return g_counter;
}

NOINLINE void write_global(int v) {
    g_counter = v;
}

// --- inlining ground truth: tiny_sum is inlined at /O2, called at /Od ----
// `tiny_sum` reads two globals, so its footprint has the >= 2 distinct
// in-image references the inlining rule requires. `uses_tiny` calls it
// twice. At /O2 the calls are inlined (no CALL in uses_tiny) while a
// standalone copy is still emitted (address taken into `g_sum_fn` +
// external linkage, no /GL) — so the /O2-vs-/Od differential below has a
// REAL optimizer inlining event with a resolvable callee VA. At /Od the
// calls are real. Deliberately NO noinline/inline markers: the point is
// what the optimizer does on its own. (Placed after the globals it reads.)

int g_k2 = 7;

int tiny_sum(void) {
    return g_counter + g_k2;
}

typedef int (*sum_fn)(void);

sum_fn g_sum_fn = 0;

NOINLINE int uses_tiny(int x) {
    return tiny_sum() + tiny_sum() + x;
}

// --- struct fields: offsets 0 (`x`) and 4 (`y`) -----------------------------

struct Point {
    int x;
    int y;
    int z;
};

NOINLINE int field_read(struct Point *p) {
    return p->y; // offset 4
}

// NOTE: offset 0 (`p->x`) is deliberately not asserted anywhere: a bare
// `[reg]` dereference is indistinguishable from a field access, so the
// verifier does not harvest disp == 0. Pin the nonzero stored offsets.
NOINLINE void field_write(struct Point *p, int v) {
    p->y = v;     // offset 4
    p->z = v + 1; // offset 8
}

// --- indirect call through a function pointer -------------------------------

typedef int (*int_fn)(int x);

NOINLINE int apply_twice(int_fn f, int x) {
    return f(f(x)); // one indirect call site
}

NOINLINE int use_apply(int x) {
    return apply_twice(inc_fn, x);
}

// --- entry point: keeps every function above alive for the linker -----------

int main(void) {
    struct Point pt;
    pt.x = 1;
    pt.y = 2;
    write_global(10);
    int total = 0;
    total += branch_caller(200); // takes the leaf_add side
    total += branch_caller(7);   // takes the leaf_const side
    total += parent_fn(5);
    total += loop_sum(10);
    total += nested_sum(10, 10);
    total += classify(3);
    total += classify(99);
    total += decision_chain(5);
    total += decision_chain(99);
    g_sum_fn = tiny_sum;
    total += uses_tiny(3);
    total += g_sum_fn();
    total += read_global();
    total += field_read(&pt);
    // Opaque arg (not a constant): a constant here invites constprop
    // cloning (`field_write.constprop`), orphaning the manifest VA.
    field_write(&pt, total);
    total += pt.x;
    total += use_apply(41);
    printf("%d\n", total);
    return 0;
}

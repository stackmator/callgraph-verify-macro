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

// --- dense switch: 8 consecutive cases lower to a jump table ---------------
// First coverage of the fingerprint's `switch_cases` prong: both toolchains
// emit `JMP [table+idx*4]` for this shape, which `follow_jump_table` must
// resolve to >= 3 case entries.

NOINLINE int classify(int v) {
    switch (v) {
        case 0: return 10;
        case 1: return 11;
        case 2: return 12;
        case 3: return 13;
        case 4: return 14;
        case 5: return 15;
        case 6: return 16;
        case 7: return 17;
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
    total += read_global();
    total += field_read(&pt);
    field_write(&pt, 9);
    total += pt.x;
    total += use_apply(41);
    printf("%d\n", total);
    return 0;
}

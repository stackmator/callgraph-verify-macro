/* dos_callgraph.c — real DOS4GW fixture for the callgraph-verify LE path. */
/*
 * Compiled by CI with Open Watcom (`owcc -bdos4g`, no optimization flags)
 * to a 32-bit DOS/4GW Linear Executable and verified by
 * `callgraph-verify/tests/dos_le_integration.rs`.
 *
 * This exercises `Pe::parse_le` + the disassembler over genuine Watcom
 * codegen (startup code, register-based fastcall-ish helpers, real loop
 * back-edges) instead of FALL.EXE, which cannot be checked into the repo.
 *
 * Constraints (Watcom wcc386 + DOS/4GW target):
 *   - C89-style code (declarations at block tops). No CRT beyond stdio.
 *   - No NOINLINE pragma: wcc386 does not inline without `-oe`, and the
 *     CI build passes no optimization flags, so every call edge below
 *     survives. Do NOT add -ot/-oe to the build command.
 *   - No symbol manifest: wlink map parsing is not worth the fragility.
 *     The tests discover functions by shape (callers, leaves, loops), so
 *     keep at least one of each: `branch_caller` (2 callees), `leaf_const`
 *     (leaf), `loop_sum` (loop back-edge).
 *   - LE fixups are NOT applied by the parser yet (see pe.rs): absolute
 *     facts (globals, immediates, IAT) are best-effort on LE. Only pin
 *     call edges, indirect counts, and CFG shape here.
 */

#include <stdio.h>

int leaf_add(int a, int b) {
    return a + b;
}

int leaf_const(void) {
    return 123;
}

int inc_fn(int x) {
    return x + 1;
}

int branch_caller(int x) {
    if (x > 100) {
        return leaf_add(x, 1);
    }
    return leaf_const() + x;
}

int parent_fn(int x) {
    return branch_caller(x) * 2;
}

int loop_sum(int n) {
    int s;
    int i;
    s = 0;
    for (i = 1; i <= n; i++) {
        s += i;
    }
    return s;
}

int nested_sum(int n, int m) {
    int s;
    int i;
    int j;
    s = 0;
    for (i = 0; i < n; i++) {
        for (j = 0; j < m; j++) {
            s += i + j;
        }
    }
    return s;
}

int decision_chain(int x) {
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

int classify(int v) {    switch (v) {
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

int g_counter = 0;

int read_global(void) {
    return g_counter;
}void write_global(int v) {
    g_counter = v;
}

/* Parity with the C fixture's inlining pair (Watcom builds -od only, so
 * both stay real calls here; the /O2-vs-/Od differential is PE-only). */
int g_k2 = 7;

int tiny_sum(void) {
    return g_counter + g_k2;
}

typedef int (*sum_fn)(void);

sum_fn g_sum_fn = 0;

int uses_tiny(int x) {
    return tiny_sum() + tiny_sum() + x;
}

struct Point {
    int x;
    int y;
};

int field_read(struct Point *p) {
    return p->y;
}

void field_write(struct Point *p, int v) {
    p->x = v;
}

typedef int (*int_fn)(int x);

int apply_twice(int_fn f, int x) {
    return f(f(x));
}

int use_apply(int x) {
    return apply_twice(inc_fn, x);
}

int main(void) {
    struct Point pt;
    int total;
    pt.x = 1;
    pt.y = 2;
    write_global(10);
    total = 0;
    total += branch_caller(200);
    total += branch_caller(7);
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
    field_write(&pt, total);
    /* Same liveness shape as the C fixture: y/z are read back so the
     * stores are never dead (GCC would DCE a dead-storing call even
     * through noinline; Watcom -od keeps it either way). */
    total += pt.x + pt.y + pt.z;
    total += use_apply(41);
    printf("%d\n", total);
    return 0;
}

// callgraph.cpp — real C++ fixture for the callgraph-verify integration tests.
//
// Same build story as the C fixture (see `c/callgraph.c` header): compiled by
// CI to a 32-bit PE, addresses resolved via `build_fixtures.py` into a JSON
// manifest. Only the `extern "C"` wrappers have stable symbol names across
// MSVC and Itanium mangling, so only those go in the manifest; the methods
// themselves are exercised structurally (thiscall field access, virtual
// dispatch) through the wrappers.
//
// Like the C fixture: NOINLINE + external linkage + reachable from `main`, so
// `/O2` / `-O2` must preserve the call edges the tests pin.

#include <cstdio>

#if defined(_MSC_VER)
#define NOINLINE __declspec(noinline)
#else
#define NOINLINE __attribute__((noinline))
#endif

// --- free functions ---------------------------------------------------------

extern "C" NOINLINE int cpp_leaf_fn(int x) {
    return x * 3 + 1;
}

// --- a small class: methods take the hidden `this` (ECX on 32-bit thiscall) --

struct Counter {
    int tag;
    int value;
    NOINLINE int get() const {
        return value; // field offset 4 off `this`
    }
    NOINLINE void bump(int d) {
        value += d;
    }
};

extern "C" NOINLINE int cpp_counter_fn(int start, int delta) {
    Counter c;
    c.tag = 7;
    c.value = start;
    c.bump(delta);
    return c.get();
}

// Direct field read through an object POINTER: `c->value` compiles to
// `MOV EAX,[ECX+4]` (thiscall), which the verifier harvests as field
// offset 4. (A stack-resident `Counter` like the one inside
// `cpp_counter_fn` uses ESP-relative slots, which are locals by design and
// never harvested — so the pointer form is pinned here instead.)
extern "C" NOINLINE int cpp_field_fn(Counter *c) {
    return c->value; // field offset 4 off `this`
}

extern "C" NOINLINE int cpp_caller_fn(int x) {
    int a = cpp_leaf_fn(x);
    int b = cpp_counter_fn(x, 2);
    return a + b;
}

// --- virtual dispatch: `use_virtual` must reach `kind()` only indirectly ----

struct Shape {
    virtual int kind() const = 0;
    virtual int sides() const = 0;
    virtual ~Shape() {}
};

struct Circle : Shape {
    int radius;
    explicit Circle(int r) : radius(r) {}
    // Reads the member through `this` (offset 4): the shape `reg_params`
    // must recognize as thiscall, and the field harvester as offset 4.
    // Behavior is unchanged (radius is always > 0 at every call site).
    int kind() const override {
        return radius > 0 ? 1 : 0;
    }
    int sides() const override {
        return 0;
    }
};

struct Square : Shape {
    int edge;
    explicit Square(int e) : edge(e) {}
    int kind() const override {
        return 2;
    }
    int sides() const override {
        return 4;
    }
};

extern "C" NOINLINE int cpp_use_virtual_fn(const Shape *s) {
    return s->kind(); // CALL [reg+slot]: indirect, never a direct call
}

extern "C" NOINLINE int cpp_shapes_fn(void) {
    Circle c(5);
    Square q(3);
    return cpp_use_virtual_fn(&c) * 10 + cpp_use_virtual_fn(&q);
}

int main() {
    int total = 0;
    total += cpp_caller_fn(21);
    total += cpp_counter_fn(100, 23);
    total += cpp_shapes_fn();
    Circle c(9);
    total += cpp_use_virtual_fn(&c);
    Counter fc;
    fc.tag = 1;
    fc.value = 11;
    total += cpp_field_fn(&fc);
    printf("%d\n", total);
    return 0;
}

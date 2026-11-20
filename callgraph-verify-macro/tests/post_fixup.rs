//! Tests for the compile-time LE-07 address marker.
//!
//! The authoritative oracle is the FALL.EXE fixup table: the record at
//! location 0x1ec64 holds pre 0x53f and the loader writes 0x17053f.
//! With TARGET_EXE set (the normal rebuild build) the macro must validate
//! and emit the runtime value; without it the macro is a documented no-op.

use callgraph_verify_macro::post_fixup;

#[test]
fn post_fixup_validates_and_translates() {
    let value: u32 = post_fixup!(0x53f, 0x1ec64);
    if std::env::var("TARGET_EXE").is_ok() {
        assert_eq!(value, 0x17053f, "LE-07 record at 0x1ec64 must translate");
    } else {
        assert_eq!(value, 0x53f, "no-TARGET_EXE mode is the identity");
    }
}

#[test]
fn post_fixup_second_record() {
    // 0x6c20 -> 0x176c20 at fixup location 0x84b6e.
    let value: u32 = post_fixup!(0x6c20, 0x84b6e);
    if std::env::var("TARGET_EXE").is_ok() {
        assert_eq!(value, 0x176c20);
    } else {
        assert_eq!(value, 0x6c20);
    }
}

#![no_std]
#![no_main]

use core::panic::PanicInfo;

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn helper_one() -> u32 {
    42
}

#[no_mangle]
pub extern "C" fn helper_two(a: u32, b: u32) -> u32 {
    a + b
}

#[no_mangle]
pub extern "system" fn WinMain(
    _hinstance: isize,
    _hprevinstance: isize,
    _lpcmdline: *const u8,
    _ncmdshow: i32,
) -> i32 {
    // your code
    0
}

#[no_mangle]
pub extern "C" fn helper_three() {
    // no return
}

#[no_mangle]
pub extern "C" fn target_function(x: u32) -> u32 {
    let a = helper_one();
    let b = helper_two(x, 10);
    helper_three();
    a + b
}

#[no_mangle]
pub extern "C" fn leaf_function() -> u32 {
    123
}

#[no_mangle]
pub extern "C" fn caller_of_leaf() -> u32 {
    leaf_function()
}

#[no_mangle]
pub extern "C" fn indirect_caller(fp: extern "C" fn() -> u32) -> u32 {
    fp()
}

// A function reached ONLY through the vtable below — never directly called. Used by
// `test_has_direct_branch_target_vtable_only` to verify the macro's VTABLE-ONLY DISPATCH
// warning fires: `has_direct_branch_target` must return false even though `referenced_addrs`
// includes this address (it's stored as a dword in the vtable).
#[no_mangle]
pub extern "C" fn vtable_only_method(self_ptr: *mut u32) -> u32 {
    unsafe { *self_ptr }
}

// The vtable is a static array of fn pointers. Stored in .rdata; the dword at index 0
// is the VA of `vtable_only_method`. Because it's `static` it ends up in .rdata; the
// compiler may or may not zero-pad other slots — that's fine, we only check slot 0.
#[no_mangle]
pub static VTABLE: [extern "C" fn(*mut u32) -> u32; 2] =
    [vtable_only_method, vtable_only_method];
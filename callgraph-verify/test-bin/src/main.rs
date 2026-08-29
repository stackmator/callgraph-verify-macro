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
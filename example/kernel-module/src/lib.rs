#![feature(global_asm)]

global_asm!(r#"
    .section .rcore-lkm
    .incbin "lkm_info.txt"
"#);

extern crate mock_kernel;

#[no_mangle]
extern "C" fn init_module() {
	println!("kernel module running");
	println!("calling kernel function");
	let x = mock_kernel::add(1, 2);
	println!("add(1, 2) = {}", x);
}

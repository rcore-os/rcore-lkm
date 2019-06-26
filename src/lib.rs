#![no_std]
#![feature(alloc)]

#[macro_use]
extern crate alloc;
#[macro_use]
extern crate log;

pub mod const_reloc;
pub mod manager;
pub mod structs;

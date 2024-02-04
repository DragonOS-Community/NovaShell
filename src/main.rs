#![allow(non_snake_case)]
#![feature(core_intrinsics)]

extern crate libc;

#[macro_use]
extern crate lazy_static;

#[macro_use]
extern crate num_derive;

mod shell;

mod keycode;

mod env;

use env::Env;
use shell::Shell;

fn main() {
    Env::read_env();
    let mut shell = Shell::new();
    shell.exec();
    return;
}

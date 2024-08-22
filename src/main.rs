#![allow(non_snake_case)]
#![allow(internal_features)]
#![feature(core_intrinsics)]

extern crate libc;

#[macro_use]
extern crate num_derive;

mod shell;

mod keycode;

mod env;

use env::Env;
use shell::Shell;

fn main() {
    Env::init();
    let mut shell = Shell::new();
    shell.exec();
    return;
}

#![allow(non_snake_case)]

extern crate libc;

#[macro_use]
extern crate num_derive;

mod shell;

mod keycode;

mod env;

mod parser;

use env::EnvManager;
use shell::Shell;

fn main() {
    EnvManager::init();
    let mut shell = Shell::new();
    shell.exec();
    return;
}

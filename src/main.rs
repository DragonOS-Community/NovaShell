extern crate libc;

#[macro_use]
extern crate lazy_static;

use std::{
    collections::HashMap,
    fs::File,
    io::{Read, Write},
    path::Path,
    string::String,
    vec::Vec,
};

pub const ROOT_PATH: &str = "/";

mod shell;

pub mod special_keycode {
    pub const LF: u8 = b'\n';
    pub const CR: u8 = b'\r';
    pub const DL: u8 = b'\x7f';
    pub const BS: u8 = b'\x08';
    pub const SPACE: u8 = b' ';
    pub const TAB: u8 = b'\t';

    pub const UP: u8 = 72;
    pub const DOWN: u8 = 80;
    pub const LEFT: u8 = 75;
    pub const RIGHT: u8 = 77;
}

struct Env(std::collections::HashMap<String, String>);

lazy_static! {
    static ref ENV: std::sync::Mutex<Env> = std::sync::Mutex::new(Env(HashMap::new()));
}

impl Env {
    fn init_env() {
        let mut file = File::create("/etc/profile").unwrap();
        file.write_all("PATH=/bin:/usr/bin:/usr/local/bin\n".as_bytes())
            .unwrap();
        file.write_all("PWD=/\n".as_bytes()).unwrap();
    }

    fn read_env() {
        let env = &mut ENV.lock().unwrap().0;
        let mut file = File::open("/etc/profile").unwrap();
        let mut buf: Vec<u8> = Vec::new();
        file.read_to_end(&mut buf).unwrap();
        for (name, value) in String::from_utf8(buf)
            .unwrap()
            .split('\n')
            .filter_map(|str| {
                let v = str.split('=').collect::<Vec<&str>>();
                if v.len() == 2 && !v.contains(&"") {
                    Some((*v.get(0).unwrap(), *v.get(1).unwrap()))
                } else {
                    None
                }
            })
            .collect::<Vec<(&str, &str)>>()
        {
            env.insert(String::from(name), String::from(value));
        }
    }

    fn get(key: &String) -> Option<String> {
        let env = &mut ENV.lock().unwrap().0;
        env.get(key).map(|value| value.clone())
    }

    fn insert(key: String, value: String) {
        ENV.lock().unwrap().0.insert(key, value);
    }

    fn path() -> Vec<String> {
        let env = &ENV.lock().unwrap().0;
        let paths = env.get("PATH").unwrap();
        paths
            .split(':')
            .filter_map(|str| {
                let path = String::from(str);
                if Path::new(&path).is_dir() {
                    Some(path)
                } else {
                    None
                }
            })
            .collect::<Vec<String>>()
    }
}

fn main() {
    Env::init_env();
    Env::read_env();
    let mut shell = shell::Shell::new();
    shell.exec();
    return;
}

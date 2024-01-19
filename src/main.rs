#![allow(non_snake_case)]
#![feature(core_intrinsics)]

mod shell;

use lazy_static::lazy_static;
use num_enum::TryFromPrimitive;
use std::{
    collections::HashMap,
    fs::File,
    io::{Read, Write},
    path::Path,
    string::String,
    sync::Mutex,
    vec::Vec,
};

use shell::Shell;

pub const ROOT_PATH: &str = "/";
pub const ENV_FILE_PATH: &str = "/etc/profile";

#[repr(u8)]
#[derive(Debug, Clone, TryFromPrimitive)]
#[allow(dead_code)]
pub enum SpecialKeycode {
    LF = b'\n',
    CR = b'\r',
    Delete = b'\x7f',
    BackSpace = b'\x08',
    Tab = b'\t',

    FunctionKey = 0xE0,
    PauseBreak = 0xE1,

    Up = 0x48,
    Down = 0x50,
    Left = 0x4B,
    Right = 0x4D,

    Home = 0x47,
    End = 0x4F,
}

impl Into<u8> for SpecialKeycode {
    fn into(self) -> u8 {
        self as u8
    }
}

struct Env(HashMap<String, String>);

lazy_static! {
    static ref ENV: Mutex<Env> = Mutex::new(Env(HashMap::new()));
}

impl Env {
    /// 初始化环境变量文件
    fn init_envfile() {
        let mut file = File::create(ENV_FILE_PATH).unwrap();
        file.write_all("PATH=/bin:/usr/bin:/usr/local/bin\n".as_bytes())
            .unwrap();
        file.write_all("PWD=/\n".as_bytes()).unwrap();
    }

    /// 读取环境变量文件
    /// 如果文件不存在则创建
    fn read_env() {
        let mut env = ENV.lock().unwrap();
        if !Path::new(ENV_FILE_PATH).exists() {
            Env::init_envfile();
        }
        let mut file = File::open(ENV_FILE_PATH).unwrap();
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
            env.0.insert(String::from(name), String::from(value));
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
    Env::read_env();
    let mut shell = Shell::new();
    shell.exec();
    return;
}

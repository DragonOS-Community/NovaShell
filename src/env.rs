use std::{
    collections::HashMap,
    fs::File,
    io::{Read, Write},
    path::Path,
};

pub const ROOT_PATH: &str = "/";
pub const ENV_FILE_PATH: &str = "/etc/profile";

pub struct Env(std::collections::HashMap<String, String>);

lazy_static! {
    static ref ENV: std::sync::Mutex<Env> = std::sync::Mutex::new(Env(HashMap::new()));
}

impl Env {
    /// 初始化环境变量文件
    pub fn init_envfile() {
        let mut file = File::create(ENV_FILE_PATH).unwrap();
        file.write_all("PATH=/bin:/usr/bin:/usr/local/bin\n".as_bytes())
            .unwrap();
        file.write_all("PWD=/\n".as_bytes()).unwrap();
    }

    /// 读取环境变量文件
    /// 如果文件不存在则创建
    pub fn read_env() {
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

    pub fn get(key: &String) -> Option<String> {
        let env = &mut ENV.lock().unwrap().0;
        env.get(key).map(|value| value.clone())
    }

    pub fn insert(key: String, value: String) {
        ENV.lock().unwrap().0.insert(key, value);
    }

    pub fn path() -> Vec<String> {
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

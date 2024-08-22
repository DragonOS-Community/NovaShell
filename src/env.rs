use std::fmt;
use std::ops::{Deref, DerefMut};
use std::{
    collections::HashMap,
    fs::File,
    io::{Read, Write},
    path::Path,
};

pub const ROOT_PATH: &str = "/";
pub const ENV_FILE_PATH: &str = "/etc/profile";

#[derive(Clone, Debug)]
pub struct EnvEntry {
    /// 环境变量的名称
    name: String,
    /// 环境变量值的原始字符串，多个值之间使用':'分隔
    origin: String,
    /// 值分割后的集合
    collection: Vec<String>,
}

impl EnvEntry {
    pub fn new(env: String) -> Option<EnvEntry> {
        let split_result = env.split('=').collect::<Vec<&str>>();
        if split_result.len() != 2 || split_result.contains(&"") {
            return None;
        }

        let name = split_result.get(0).unwrap().to_string();
        let origin = split_result.get(1).unwrap().to_string();

        let collection = origin
            .split(':')
            .filter_map(|str| {
                let path = String::from(str);
                if Path::new(&path).is_dir() {
                    Some(path)
                } else {
                    None
                }
            })
            .collect::<Vec<String>>();

        Some(EnvEntry {
            name,
            origin,
            collection,
        })
    }

    #[allow(dead_code)]
    pub fn name(&self) -> &String {
        &self.name
    }

    pub fn origin(&self) -> &String {
        &self.origin
    }

    #[allow(dead_code)]
    pub fn collection(&self) -> &Vec<String> {
        &self.collection
    }
}

impl fmt::Display for EnvEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}={}", self.name, self.origin)
    }
}

pub struct Env(HashMap<String, EnvEntry>);

static mut ENV: Option<Env> = None;

impl Deref for Env {
    type Target = HashMap<String, EnvEntry>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Env {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Env {
    pub fn init() {
        // unsafe { ENV = Some(std::sync::Mutex::new(Env(HashMap::new()))) };
        unsafe { ENV = Some(Env(HashMap::new())) };
        Self::read_env();
    }

    pub fn env() -> &'static mut Env {
        unsafe { ENV.as_mut().unwrap() }
    }

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
        let env = unsafe { ENV.as_mut().unwrap() };

        if !Path::new(ENV_FILE_PATH).exists() {
            Env::init_envfile();
        }
        let mut file = File::open(ENV_FILE_PATH).unwrap();
        let mut buf: Vec<u8> = Vec::new();
        file.read_to_end(&mut buf).unwrap();

        for str in String::from_utf8(buf).unwrap().split('\n') {
            if let Some(entry) = EnvEntry::new(str.to_string()) {
                env.insert(entry.name.clone(), entry);
            }
        }
    }

    pub fn get(key: &String) -> Option<&EnvEntry> {
        let env = unsafe { ENV.as_ref().unwrap() };
        env.0.get(key)
    }

    pub fn insert(key: String, value: String) {
        if let Some(entry) = EnvEntry::new(value) {
            Self::env().insert(key, entry);
        }
    }

    pub fn path() -> Vec<String> {
        let env = Self::env();
        env.get("PATH").unwrap().collection.clone()
        // paths
        //     .split(':')
        //     .filter_map(|str| {
        //         let path = String::from(str);
        //         if Path::new(&path).is_dir() {
        //             Some(path)
        //         } else {
        //             None
        //         }
        //     })
        //     .collect::<Vec<String>>()
    }

    pub fn current_dir() -> String {
        std::env::current_dir()
            .expect("Error getting current directory")
            .to_str()
            .unwrap()
            .to_string()
    }

    /// 从环境变量搜索路径，返回第一个匹配的绝对路径
    pub fn search_path_from_env(path: &String) -> Option<String> {
        let mut absolute_path = String::new();
        if !path.contains('/') {
            let mut dir_collection = Env::path();
            dir_collection.insert(0, Self::current_dir());
            for dir in dir_collection {
                let possible_path = format!("{}/{}", dir, path);
                if Path::new(&possible_path).is_file() {
                    absolute_path = possible_path;
                    break;
                }
            }
            if absolute_path.is_empty() {
                return None;
            } else {
                return Some(absolute_path);
            }
        } else if Path::new(path).exists() {
            return Some(path.clone());
        } else {
            return None;
        }
    }
}

use std::{
    fs::File,
    io::{Read, Write},
    path::Path,
};

pub const ROOT_PATH: &str = "/";

pub struct EnvManager;

impl EnvManager {
    pub const ENV_FILE_PATH: &str = "/etc/profile";

    /// 初始化环境变量相关信息
    pub fn init() {
        Self::read_env();
    }

    /// 初始化环境变量文件
    pub fn init_envfile() {
        let mut file = File::create(Self::ENV_FILE_PATH).unwrap();
        file.write_all("PATH=/bin:/usr/bin:/usr/local/bin\n".as_bytes())
            .unwrap();
        file.write_all("PWD=/\n".as_bytes()).unwrap();
    }

    /// 读取环境变量文件
    /// 如果文件不存在则创建
    pub fn read_env() {
        if !Path::new(Self::ENV_FILE_PATH).exists() {
            Self::init_envfile();
        }

        let mut file = File::open(Self::ENV_FILE_PATH).unwrap();
        let mut buf: Vec<u8> = Vec::new();
        file.read_to_end(&mut buf).unwrap();

        for str in String::from_utf8(buf).unwrap().split('\n') {
            if let Some(index) = str.find('=') {
                std::env::set_var(&str[..index], &str[index + 1..]);
            }
        }
    }

    pub fn current_dir() -> String {
        std::env::current_dir()
            .expect("Error getting current directory")
            .to_str()
            .unwrap()
            .to_string()
    }
}

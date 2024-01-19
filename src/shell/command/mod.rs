use help::Help;
use libc::fork;
use path_clean::PathClean;
use regex::{Captures, Regex};
use std::intrinsics::unlikely;
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::{
    format,
    fs::{self, File, OpenOptions},
    io::Write,
    path::Path,
    print, println,
    string::String,
    vec::Vec,
};

use crate::shell::Shell;
use crate::ROOT_PATH;
use crate::{Env, ENV_FILE_PATH};

mod help;

#[derive(Debug, PartialEq, Eq, Clone)]
enum CommandType {
    InternalCommand(BuildInCmd),
    ExternalCommand(String),
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Command {
    args: Vec<String>,
    cmd_type: CommandType,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum CommandError {
    CommandNotFound(String),
    InvalidArgument(String),
    WrongArgumentCount(usize),
    EnvironmentVariableNotFound(String),
    PathNotFound(String),
    FileNotFound(String),
    DirectoryNotFound(String),
    NotDirectory(String),
    NotFile(String),
}

impl CommandError {
    pub fn handle(e: CommandError) {
        match e {
            CommandError::CommandNotFound(command) => {
                println!("cannot find command: {}", command)
            }
            CommandError::InvalidArgument(argument) => {
                println!("invalid argument: {}", argument)
            }
            CommandError::WrongArgumentCount(count) => {
                println!("argument count incorrect: {}", count)
            }
            CommandError::EnvironmentVariableNotFound(env) => {
                println!("environment variable not found: {}", env);
            }
            CommandError::PathNotFound(path) => {
                println!("cannot found file or dirctory: {}", path)
            }
            CommandError::FileNotFound(path) => {
                println!("cannot found file: {}", path)
            }
            CommandError::DirectoryNotFound(path) => {
                println!("cannot found dirctory: {}", path)
            }
            CommandError::NotDirectory(path) => {
                println!("path is not a dirctory: {}", path)
            }
            CommandError::NotFile(path) => {
                println!("path is not a file: {}", path)
            }
        };
    }
}

impl Command {
    fn new(name: String, args: Vec<String>) -> Result<Command, CommandError> {
        for BuildInCmd(cmd) in BuildInCmd::BUILD_IN_CMD {
            if name == *cmd {
                return Ok(Command {
                    args,
                    cmd_type: CommandType::InternalCommand(BuildInCmd(cmd)),
                });
            }
        }

        return Ok(Command {
            args,
            cmd_type: CommandType::ExternalCommand(name),
        });
    }

    fn from_string(str: String) -> Result<Command, CommandError> {
        let regex: Regex = Regex::new(r#"([^\s'"]|("[^"]*"|'[^']*'))+"#).unwrap();
        let hay = str.clone();
        let mut iter = regex
            .captures_iter(hay.as_str())
            .map(|c| String::from(c.get(0).unwrap().as_str()));
        // let mut iter = str.split_ascii_whitespace();
        let name = iter.next().unwrap();
        let re: Regex = Regex::new(r"\$[\w_]+").unwrap();
        let replacement = |caps: &Captures| -> String {
            match Env::get(&String::from(&caps[0][1..])) {
                Some(value) => value,
                None => String::from(&caps[0]),
            }
        };
        let mut args: Vec<String> = Vec::new();
        for arg in iter.collect::<Vec<String>>().iter() {
            let arg = re.replace_all(arg.as_str(), &replacement).to_string();
            match re.captures(arg.as_str()) {
                Some(caps) => {
                    return Err(CommandError::EnvironmentVariableNotFound(String::from(
                        caps.get(0).unwrap().as_str(),
                    )))
                }
                None => args.push(arg),
            }
        }
        let cmd = Command::new(name, args);
        return cmd;
    }

    pub fn from_strings(str: String) -> Vec<Command> {
        str.split(';')
            .filter_map(|s| match Command::from_string(String::from(s)) {
                Ok(s) => Some(s),
                Err(e) => {
                    CommandError::handle(e);
                    None
                }
            })
            .collect::<Vec<Command>>()
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct BuildInCmd(pub &'static str);

impl BuildInCmd {
    pub const BUILD_IN_CMD: &[BuildInCmd] = &[
        BuildInCmd("cd"),
        BuildInCmd("ls"),
        BuildInCmd("cat"),
        BuildInCmd("touch"),
        BuildInCmd("mkdir"),
        BuildInCmd("rm"),
        BuildInCmd("rmdir"),
        BuildInCmd("pwd"),
        BuildInCmd("cp"),
        BuildInCmd("exec"),
        BuildInCmd("echo"),
        BuildInCmd("reboot"),
        BuildInCmd("free"),
        BuildInCmd("kill"),
        BuildInCmd("help"),
        BuildInCmd("export"),
        BuildInCmd("env"),
        BuildInCmd("compgen"),
        BuildInCmd("complete"),
    ];
}

impl Shell {
    pub fn exec_internal_command(cmd: &str, args: &Vec<String>) -> Result<(), CommandError> {
        match cmd {
            "cd" => Self::shell_cmd_cd(args),
            "ls" => Self::shell_cmd_ls(args),
            "cat" => Self::shell_cmd_cat(args),
            "touch" => Self::shell_cmd_touch(args),
            "mkdir" => Self::shell_cmd_mkdir(args),
            "rm" => Self::shell_cmd_rm(args),
            "rmdir" => Self::shell_cmd_rmdir(args),
            "pwd" => Self::shell_cmd_pwd(args),
            "cp" => Self::shell_cmd_cp(args),
            "exec" => Self::shell_cmd_exec(args),
            "echo" => Self::shell_cmd_echo(args),
            "reboot" => Self::shell_cmd_reboot(args),
            "free" => Self::shell_cmd_free(args),
            "kill" => Self::shell_cmd_kill(args),
            "help" => Self::shell_cmd_help(args),
            "export" => Self::shell_cmd_export(args),
            "env" => Self::shell_cmd_env(args),
            "compgen" => Self::shell_cmd_compgen(args),
            "complete" => Self::shell_cmd_complete(args),

            _ => Err(CommandError::CommandNotFound(String::from(cmd))),
        }
    }

    pub fn exec_external_command(path: String, args: &Vec<String>) {
        let mut full_args = args.clone();
        full_args.insert(0, path.clone());
        Self::shell_cmd_exec(&full_args).unwrap_or_else(|e| {
            let err = match e {
                CommandError::FileNotFound(rp) => CommandError::CommandNotFound(rp),
                _ => e,
            };
            CommandError::handle(err);
        })
    }

    pub fn exec_command(command: &Command) {
        match &command.cmd_type {
            CommandType::ExternalCommand(path) => {
                Self::exec_external_command(path.to_string(), &command.args);
            }

            CommandType::InternalCommand(BuildInCmd(cmd)) => {
                match Self::exec_internal_command(cmd, &command.args) {
                    Ok(_) => {}
                    Err(e) => CommandError::handle(e),
                }
                if command.args.contains(&String::from("--help")) {
                    Help::shell_help(cmd);
                }
            }
        }
    }

    fn shell_cmd_cd(args: &Vec<String>) -> Result<(), CommandError> {
        let path = match args.len() {
            0 => String::from(ROOT_PATH),
            1 => Self::is_dir(args.get(0).unwrap())?,
            _ => return Err(CommandError::WrongArgumentCount(args.len())),
        };
        // println!("{}", path);
        Self::chdir(&path);
        Ok(())
    }

    fn shell_cmd_ls(args: &Vec<String>) -> Result<(), CommandError> {
        let path = match args.len() {
            0 => Self::current_dir(),
            1 => Self::is_dir(args.get(0).unwrap())?,
            _ => return Err(CommandError::WrongArgumentCount(args.len())),
        };
        let dir = match fs::read_dir(Path::new(&path)) {
            Ok(readdir) => readdir,
            Err(_) => return Err(CommandError::InvalidArgument(path)),
        };

        for entry in dir {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_dir() {
                crate::shell::Printer::print_color(
                    entry.file_name().as_bytes(),
                    0x000088ff,
                    0x00000000,
                );
                print!("    ");
            } else {
                print!("{}    ", entry.file_name().into_string().unwrap());
            }
        }
        println!();
        Ok(())
    }

    fn shell_cmd_cat(args: &Vec<String>) -> Result<(), CommandError> {
        if args.len() <= 0 {
            return Err(CommandError::WrongArgumentCount(args.len()));
        }
        let path = Self::is_file(args.get(0).unwrap())?;
        let mut buf: Vec<u8> = Vec::new();

        File::open(path).unwrap().read_to_end(&mut buf).unwrap();
        if args.len() == 1 {
            println!("{}", String::from_utf8(buf.clone()).unwrap());
        }
        //TODO: 这部分应该放在`Shell`中，所有指令公用
        else if args.len() == 3 {
            let mut target_path = args.get(2).unwrap().clone();
            match Self::is_file(&target_path) {
                Ok(str) => target_path = str,
                Err(e) => return Err(e),
            }

            if args[1] == ">" {
                match OpenOptions::new().write(true).open(target_path) {
                    Ok(mut file) => {
                        file.write_all(&buf).unwrap();
                    }
                    Err(e) => print!("{e}"),
                }
            } else if args[1] == ">>" {
                match OpenOptions::new().append(true).open(target_path) {
                    Ok(mut file) => {
                        file.write_all(&buf).unwrap();
                    }
                    Err(e) => print!("{e}"),
                }
            }
        }
        Ok(())
    }

    fn shell_cmd_touch(args: &Vec<String>) -> Result<(), CommandError> {
        if unlikely(args.len() != 1) {
            return Err(CommandError::WrongArgumentCount(args.len()));
        }
        let path = args.get(0).unwrap();

        //路径中提取目录和文件名
        let index = path.rfind('/').unwrap_or(0);
        let dir = &path[..index];
        let file_name = &path[index..];

        //判断文件所在目录是否存在
        let str = Self::is_dir(&dir.to_string())?;
        //判断文件是否存在，存在时不操作,不存在时创建文件
        let abs_path = format!("{}/{}", str, file_name);
        if !Path::new(&abs_path).exists() {
            File::create(&abs_path).unwrap();
        }
        Ok(())
    }

    fn shell_cmd_mkdir(args: &Vec<String>) -> Result<(), CommandError> {
        if unlikely(args.len() != 1) {
            return Err(CommandError::WrongArgumentCount(args.len()));
        }
        let path = args.get(0).unwrap();
        if let Err(e) = fs::create_dir_all(path) {
            print!("{e}")
        }
        Ok(())
    }

    fn shell_cmd_rm(args: &Vec<String>) -> Result<(), CommandError> {
        if unlikely(args.len() != 1) {
            return Err(CommandError::WrongArgumentCount(args.len()));
        }
        let path = Self::is_file(args.get(0).unwrap())?;
        let path_cstr = std::ffi::CString::new(path).unwrap();
        unsafe {
            libc::syscall(libc::SYS_unlinkat, 0, path_cstr.as_ptr(), 0, 0, 0, 0);
        }
        Ok(())
    }

    fn shell_cmd_rmdir(args: &Vec<String>) -> Result<(), CommandError> {
        if unlikely(args.len() != 1) {
            return Err(CommandError::WrongArgumentCount(args.len()));
        }
        let path = Self::is_dir(args.get(0).unwrap())?;
        let path_cstr = std::ffi::CString::new(path).unwrap();
        unsafe { libc::unlinkat(0, path_cstr.as_ptr(), libc::AT_REMOVEDIR) };
        Ok(())
    }

    fn shell_cmd_pwd(args: &Vec<String>) -> Result<(), CommandError> {
        if unlikely(args.len() != 0) {
            return Err(CommandError::WrongArgumentCount(args.len()));
        }
        println!("{}", Self::current_dir());
        Ok(())
    }

    fn shell_cmd_cp(args: &Vec<String>) -> Result<(), CommandError> {
        if args.len() == 2 {
            let mut src_path = args.get(0).unwrap().clone();
            let mut target_path = args.get(1).unwrap().clone();

            match Self::is_file(&src_path) {
                Ok(str) => src_path = str,
                Err(e) => return Err(e),
            }

            match Self::is_file_or_dir(&target_path) {
                Ok(str) => target_path = str,
                Err(e) => {
                    let prefix = &target_path[..target_path.rfind('/').unwrap_or(0)];
                    if !Path::new(prefix).is_dir() {
                        return Err(e);
                    }
                }
            }

            if Path::new(&src_path).is_dir() {
                let name = &src_path[src_path.rfind('/').unwrap_or(0)..];
                target_path = format!("{}/{}", target_path, name);
            }

            let mut src_file = File::open(&src_path).unwrap();
            let mut target_file = File::create(target_path).unwrap();
            let mut buf: Vec<u8> = Vec::new();
            src_file.read_to_end(&mut buf).unwrap();
            target_file.write_all(&buf).unwrap();
            return Ok(());
        }
        return Err(CommandError::WrongArgumentCount(args.len()));
    }

    pub fn shell_cmd_exec(args: &Vec<String>) -> Result<(), CommandError> {
        if unlikely(args.len() <= 0) {
            return Err(CommandError::WrongArgumentCount(args.len()));
        }
        let path = args.get(0).unwrap();
        //在环境变量中搜索
        //TODO: 放在一个函数里来实现
        let mut real_path = String::new();
        if !path.contains('/') {
            let mut dir_collection = Env::path();
            dir_collection.insert(0, Self::current_dir());
            for dir in dir_collection {
                let possible_path = format!("{}/{}", dir, path);
                if Path::new(&possible_path).is_file() {
                    real_path = possible_path;
                    break;
                }
            }
            if real_path.is_empty() {
                return Err(CommandError::FileNotFound(path.clone()));
            }
        } else {
            real_path = Self::is_file(path)?;
        }

        let mut args = args.clone();
        // 如果文件不存在，返回错误
        if !Path::new(&real_path).is_file() {
            // println!("{}: command not found", real_path);
            return Err(CommandError::FileNotFound(real_path.clone()));
        }

        let pid: libc::pid_t = unsafe { fork() };

        let name = &real_path[real_path.rfind('/').map(|pos| pos + 1).unwrap_or(0)..];
        *args.get_mut(0).unwrap() = name.to_string();
        let mut retval = 0;
        if pid == 0 {
            let path_cstr = std::ffi::CString::new(real_path).unwrap();
            let args_cstr = args
                .iter()
                .map(|str| std::ffi::CString::new(str.as_str()).unwrap())
                .collect::<Vec<std::ffi::CString>>();
            let mut args_ptr = args_cstr
                .iter()
                .map(|c_str| c_str.as_ptr())
                .collect::<Vec<*const i8>>();
            args_ptr.push(std::ptr::null());
            let argv = args_ptr.as_ptr();

            unsafe {
                libc::execv(path_cstr.as_ptr(), argv);
            }
        } else {
            if args.last().unwrap() != &"&" {
                unsafe { libc::waitpid(pid, &mut retval as *mut i32, 0) };
            } else {
                println!("[1] {}", pid);
            }
        }
        return Ok(());
    }

    fn shell_cmd_echo(args: &Vec<String>) -> Result<(), CommandError> {
        if args.len() > 0 {
            let str = args.get(0).unwrap();
            if args.len() == 1 {
                println!("{str}");
            }

            //TODO: 和`cat`中的一样，应放在`Shell`中
            if args.len() == 3 {
                let mut target_path = args.get(2).unwrap().clone();
                match Self::is_file(&target_path) {
                    Ok(str) => target_path = str,
                    Err(e) => return Err(e),
                }
                if args[1] == ">" {
                    match OpenOptions::new().write(true).open(target_path) {
                        Ok(mut file) => {
                            file.write_all(str.as_bytes()).unwrap();
                        }
                        Err(e) => print!("{e}"),
                    }
                } else if args[1] == ">>" {
                    match OpenOptions::new().append(true).open(target_path) {
                        Ok(mut file) => {
                            file.write_all(str.as_bytes()).unwrap();
                        }
                        Err(e) => print!("{e}"),
                    }
                }
            }
            return Ok(());
        }
        return Err(CommandError::WrongArgumentCount(args.len()));
    }

    fn shell_cmd_reboot(args: &Vec<String>) -> Result<(), CommandError> {
        if args.len() == 0 {
            unsafe { libc::syscall(libc::SYS_reboot, 0, 0, 0, 0, 0, 0) };
            return Ok(());
        } else {
            return Err(CommandError::WrongArgumentCount(args.len()));
        }
    }

    fn shell_cmd_free(args: &Vec<String>) -> Result<(), CommandError> {
        if args.len() == 1 && args.get(0).unwrap() != "-m" {
            return Err(CommandError::InvalidArgument(
                args.get(0).unwrap().to_string(),
            ));
        }

        struct Mstat {
            total: u64,      // 计算机的总内存数量大小
            used: u64,       // 已使用的内存大小
            free: u64,       // 空闲物理页所占的内存大小
            shared: u64,     // 共享的内存大小
            cache_used: u64, // 位于slab缓冲区中的已使用的内存大小
            cache_free: u64, // 位于slab缓冲区中的空闲的内存大小
            available: u64,  // 系统总空闲内存大小（包括kmalloc缓冲区）
        }

        let mut mst = Mstat {
            total: 0,
            used: 0,
            free: 0,
            shared: 0,
            cache_used: 0,
            cache_free: 0,
            available: 0,
        };

        let mut info_file = File::open("/proc/meminfo").unwrap();
        let mut buf: Vec<u8> = Vec::new();
        info_file.read_to_end(&mut buf).unwrap();
        let str = String::from_utf8(buf).unwrap();
        let info = str
            .split(&['\n', '\t', ' '])
            .filter_map(|str| str.parse::<u64>().ok())
            .collect::<Vec<u64>>();
        mst.total = *info.get(0).unwrap();
        mst.free = *info.get(1).unwrap();
        mst.used = mst.total - mst.free;

        print!("\ttotal\t\tused\t\tfree\t\tshared\t\tcache_used\tcache_free\tavailable\n");
        print!("Mem:\t");

        if args.len() == 0 {
            print!(
                "{}\t\t{}\t\t{}\t\t{}\t\t{}\t\t{}\t\t{}\n",
                mst.total,
                mst.used,
                mst.free,
                mst.shared,
                mst.cache_used,
                mst.cache_free,
                mst.available
            );
        } else {
            print!(
                "{}\t\t{}\t\t{}\t\t{}\t\t{}\t\t{}\n",
                mst.total >> 10,
                mst.used >> 10,
                mst.free >> 10,
                mst.shared >> 10,
                mst.cache_used >> 10,
                mst.available >> 10
            );
        }
        Ok(())
    }

    fn shell_cmd_kill(args: &Vec<String>) -> Result<(), CommandError> {
        if unlikely(args.len() != 1) {
            return Err(CommandError::WrongArgumentCount(args.len()));
        }

        let pid = match args.get(0).unwrap().parse::<i32>() {
            Ok(x) => x,
            Err(_) => {
                return Err(CommandError::InvalidArgument(
                    args.get(0).unwrap().to_string(),
                ))
            }
        };
        unsafe {
            libc::kill(pid, libc::SIGTERM);
        }
        Ok(())
    }

    fn shell_cmd_help(args: &Vec<String>) -> Result<(), CommandError> {
        if args.len() == 0 {
            for BuildInCmd(cmd) in BuildInCmd::BUILD_IN_CMD {
                Help::shell_help(cmd)
            }
            return Ok(());
        }
        return Err(CommandError::WrongArgumentCount(args.len()));
    }

    fn shell_cmd_export(args: &Vec<String>) -> Result<(), CommandError> {
        if args.len() == 1 {
            let pair = args.get(0).unwrap().split('=').collect::<Vec<&str>>();

            if pair.len() == 2 && !pair.contains(&"") {
                let name = pair.get(0).unwrap().to_string();
                let value = pair.get(1).unwrap().to_string();
                Env::insert(name, value);
                return Ok(());
            } else {
                return Err(CommandError::InvalidArgument(args.get(0).unwrap().clone()));
            }
        }
        return Err(CommandError::WrongArgumentCount(args.len()));
    }

    fn shell_cmd_env(args: &Vec<String>) -> Result<(), CommandError> {
        if args.len() == 0 {
            let mut file = File::open(ENV_FILE_PATH).unwrap();
            let mut buf: Vec<u8> = Vec::new();
            file.read_to_end(&mut buf).unwrap();
            println!("{}", String::from_utf8(buf).unwrap());
            return Ok(());
        } else {
            return Err(CommandError::InvalidArgument(args.get(0).unwrap().clone()));
        }
    }

    fn shell_cmd_compgen(_args: &Vec<String>) -> Result<(), CommandError> {
        //TODO
        Ok(())
    }

    fn shell_cmd_complete(_args: &Vec<String>) -> Result<(), CommandError> {
        //TODO
        Ok(())
    }

    fn path_format(path: &String) -> Result<String, CommandError> {
        let mut abs_path = path.clone();
        if !path.starts_with('/') {
            abs_path = format!("{}/{}", Self::current_dir(), path);
        }
        let path = Path::new(&abs_path).clean();
        let mut fmt_path = path.to_str().unwrap().to_string();
        let replacement = |_caps: &regex::Captures| -> String { String::from("/") };
        let re = regex::Regex::new(r"\/{2,}").unwrap();
        fmt_path = re.replace_all(fmt_path.as_str(), replacement).to_string();
        return Ok(fmt_path);
    }

    fn is_file(path_str: &String) -> Result<String, CommandError> {
        match Self::path_format(path_str) {
            Ok(path_str) => {
                let path = Path::new(&path_str);
                if !path.is_file() {
                    return Err(CommandError::NotFile(path_str.clone()));
                };
                Ok(path_str)
            }
            Err(_) => Err(CommandError::FileNotFound(path_str.clone())),
        }
    }

    fn is_dir(path_str: &String) -> Result<String, CommandError> {
        match Self::path_format(path_str) {
            Ok(path_str) => {
                // println!("{}", path_str);
                let path = Path::new(&path_str);
                // println!("{:?}", path);
                if !path.is_dir() {
                    return Err(CommandError::NotDirectory(path_str.clone()));
                };
                Ok(path_str)
            }
            Err(_) => Err(CommandError::DirectoryNotFound(path_str.clone())),
        }
    }

    fn is_file_or_dir(path_str: &String) -> Result<String, CommandError> {
        match Self::path_format(path_str) {
            Ok(path_str) => Ok(path_str),
            Err(_) => Err(CommandError::PathNotFound(path_str.clone())),
        }
    }
}

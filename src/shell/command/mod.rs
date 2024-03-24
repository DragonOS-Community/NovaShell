use colored::Colorize;
use help::Help;
use path_clean::PathClean;
use regex::{Captures, Regex};
use std::intrinsics::unlikely;
use std::io::Read;
use std::{
    format,
    fs::{self, File, OpenOptions},
    io::Write,
    path::Path,
    print, println,
    string::String,
    vec::Vec,
};

use crate::env::{Env, ENV_FILE_PATH, ROOT_PATH};
use crate::shell::Shell;

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
    UnclosedQuotation(usize),
    UnableGetArg,
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
            CommandError::UnclosedQuotation(index) => {
                println!("command exists unclosed quotation at index: {}", index)
            }
            CommandError::UnableGetArg => {
                println!("unable to get argument")
            }
        }
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

    fn parse_command_into_fragments(str: String) -> Result<Vec<String>, usize> {
        let iter = str.chars();
        let mut fragments: Vec<String> = Vec::new();
        let mut stack: String = String::with_capacity(str.len());
        let mut left_quote: char = ' ';
        let mut left_quote_index: usize = 0;
        for (index, ch) in iter.enumerate() {
            //存在未闭合的左引号，此时除能够配对的引号外，任何字符都加入栈中
            if left_quote != ' ' {
                if ch == left_quote {
                    left_quote = ' ';
                } else {
                    stack.push(ch);
                }
            } else {
                //不存在未闭合的左引号
                if ch == '\'' || ch == '\"' {
                    //字符为引号，记录下来
                    left_quote = ch;
                    left_quote_index = index;
                } else if ch == ' ' {
                    if !stack.is_empty() {
                        //字符为空格且栈中不为空，该空格视作命令段之间的分割线
                        //将栈中字符作为一个命令段加入集合，之后重置栈
                        fragments.push(stack.to_string());
                        stack.clear();
                    }
                } else {
                    //其他字符都作为普通字符加入栈中
                    stack.push(ch);
                }
            }
        }
        //结束时如果栈不为空
        if !stack.is_empty() {
            if left_quote == ' ' {
                //不存在未闭合的引号，将栈中剩余内容作为命令段加入集合
                fragments.push(stack.to_string());
            } else {
                //存在未闭合的引号，返回此引号的下标
                return Err(left_quote_index);
            }
        }
        Ok(fragments)
    }

    fn from_string(str: String) -> Result<Command, CommandError> {
        let iter = Self::parse_command_into_fragments(str);
        if let Err(index) = iter {
            return Err(CommandError::UnclosedQuotation(index));
        }
        let mut iter = iter.unwrap().into_iter();

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
        let mut commands = Vec::new();
        let segments: Vec<&str> = str.split(';').collect();
        for segment in segments {
            if segment.trim().is_empty() {
                continue;
            } else {
                match Command::from_string(String::from(segment)) {
                    Ok(s) => commands.push(s),
                    Err(e) => {
                        CommandError::handle(e);
                    }
                }
            }
        }

        commands
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct BuildInCmd(pub &'static str);

impl BuildInCmd {
    pub const BUILD_IN_CMD: &[BuildInCmd] = &[
        BuildInCmd("cd"),
        BuildInCmd("exec"),
        BuildInCmd("reboot"),
        BuildInCmd("free"),
        BuildInCmd("help"),
        BuildInCmd("export"),
        BuildInCmd("compgen"),
        BuildInCmd("complete"),
    ];
}

impl Shell {
    pub fn exec_internal_command(
        &mut self,
        cmd: &str,
        args: &Vec<String>,
    ) -> Result<(), CommandError> {
        match cmd {
            "cd" => self.shell_cmd_cd(args),
            "exec" => self.shell_cmd_exec(args),
            "reboot" => self.shell_cmd_reboot(args),
            "free" => self.shell_cmd_free(args),
            "help" => self.shell_cmd_help(args),
            "export" => self.shell_cmd_export(args),
            "compgen" => self.shell_cmd_compgen(args),
            "complete" => self.shell_cmd_complete(args),

            _ => Err(CommandError::CommandNotFound(String::from(cmd))),
        }
    }

    pub fn exec_external_command(&mut self, path: String, args: &Vec<String>) {
        let mut full_args = args.clone();
        full_args.insert(0, path.clone());
        self.shell_cmd_exec(&full_args).unwrap_or_else(|e| {
            let err = match e {
                CommandError::FileNotFound(rp) => CommandError::CommandNotFound(rp),
                _ => e,
            };
            CommandError::handle(err);
        })
    }

    pub fn exec_command(&mut self, command: &Command) {
        match &command.cmd_type {
            CommandType::ExternalCommand(path) => {
                self.exec_external_command(path.to_string(), &command.args);
            }

            CommandType::InternalCommand(BuildInCmd(cmd)) => {
                match self.exec_internal_command(cmd, &command.args) {
                    Ok(_) => {}
                    Err(e) => CommandError::handle(e),
                }
                if command.args.contains(&String::from("--help")) {
                    Help::shell_help(cmd);
                }
            }
        }
    }

    fn shell_cmd_cd(&mut self, args: &Vec<String>) -> Result<(), CommandError> {
        let path = match args.len() {
            0 => String::from(ROOT_PATH),
            1 => self.is_dir(args.get(0).unwrap())?,
            _ => return Err(CommandError::WrongArgumentCount(args.len())),
        };
        self.chdir(&path);
        Ok(())
    }

    pub fn shell_cmd_exec(&self, args: &Vec<String>) -> Result<(), CommandError> {
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
            match self.is_file(path) {
                Ok(path) => real_path = path,
                Err(e) => return Err(e),
            }
        }

        let mut args = args.clone();
        // 如果文件不存在，返回错误
        if !Path::new(&real_path).is_file() {
            // println!("{}: command not found", real_path);
            return Err(CommandError::FileNotFound(real_path.clone()));
        }

        let pid: libc::pid_t = unsafe {
            libc::syscall(libc::SYS_fork, 0, 0, 0, 0, 0, 0)
                .try_into()
                .unwrap()
        };

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

    fn shell_cmd_reboot(&self, args: &Vec<String>) -> Result<(), CommandError> {
        if args.len() == 0 {
            unsafe { libc::syscall(libc::SYS_reboot, 0, 0, 0, 0, 0, 0) };
            return Ok(());
        } else {
            return Err(CommandError::WrongArgumentCount(args.len()));
        }
    }

    fn shell_cmd_free(&self, args: &Vec<String>) -> Result<(), CommandError> {
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

    fn shell_cmd_help(&self, args: &Vec<String>) -> Result<(), CommandError> {
        if args.len() == 0 {
            for BuildInCmd(cmd) in BuildInCmd::BUILD_IN_CMD {
                Help::shell_help(cmd)
            }
            return Ok(());
        }
        return Err(CommandError::WrongArgumentCount(args.len()));
    }

    fn shell_cmd_export(&self, args: &Vec<String>) -> Result<(), CommandError> {
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

    fn shell_cmd_compgen(&self, _args: &Vec<String>) -> Result<(), CommandError> {
        //TODO
        Ok(())
    }

    fn shell_cmd_complete(&self, _args: &Vec<String>) -> Result<(), CommandError> {
        //TODO
        Ok(())
    }

    fn path_format(&self, path: &String) -> Result<String, CommandError> {
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

    fn is_file(&self, path_str: &String) -> Result<String, CommandError> {
        match self.path_format(path_str) {
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

    fn is_dir(&self, path_str: &String) -> Result<String, CommandError> {
        match self.path_format(path_str) {
            Ok(path_str) => {
                let path = Path::new(&path_str);
                if !path.is_dir() {
                    return Err(CommandError::NotDirectory(path_str.clone()));
                };
                Ok(path_str)
            }
            Err(_) => Err(CommandError::DirectoryNotFound(path_str.clone())),
        }
    }

    fn is_file_or_dir(&self, path_str: &String) -> Result<String, CommandError> {
        match self.path_format(path_str) {
            Ok(path_str) => Ok(path_str),
            Err(_) => Err(CommandError::PathNotFound(path_str.clone())),
        }
    }
}

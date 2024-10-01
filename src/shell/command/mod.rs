use help::Help;
use path_clean::PathClean;
use regex::{Captures, Regex};
use std::{format, fs::File, io::Read, path::Path, print, println};

use crate::env::{Env, ROOT_PATH};
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
    run_backend: bool,
}

#[allow(dead_code)]
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
    EmptyCommand,
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
            CommandError::EmptyCommand => println!("try to construct an empty command"),
        }
    }
}

impl Command {
    fn new(name: String, args: Vec<String>, run_backend: bool) -> Result<Command, CommandError> {
        for BuildInCmd(cmd) in BuildInCmd::BUILD_IN_CMD {
            if name == *cmd {
                return Ok(Command {
                    args,
                    cmd_type: CommandType::InternalCommand(BuildInCmd(cmd)),
                    run_backend,
                });
            }
        }

        return Ok(Command {
            args,
            cmd_type: CommandType::ExternalCommand(name),
            run_backend,
        });
    }

    pub fn parse(str: String) -> Result<Vec<Command>, CommandError> {
        let iter = str.chars();
        let mut fragments: Vec<String> = Vec::new();
        let mut stack: String = String::with_capacity(str.len());
        let mut left_quote: char = ' ';
        let mut left_quote_index: usize = 0;
        let mut commands: Vec<Command> = Vec::new();
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
                } else if ch == ' ' && !stack.is_empty() {
                    //字符为空格且栈中不为空，该空格视作命令段之间的分割线
                    //将栈中字符作为一个命令段加入集合，之后重置栈
                    fragments.push(stack.to_string());
                    stack.clear();
                } else if ch == ';' || ch == '&' {
                    // ;和&视作命令之间的分隔，且&标志命令后台运行
                    // 使用命令段构造一条命令
                    if !stack.is_empty() {
                        fragments.push(stack.to_string());
                        stack.clear();
                    }
                    if !fragments.is_empty() {
                        match Self::build_command_from_fragments(&fragments, ch == '&') {
                            Ok(command) => commands.push(command),
                            Err(e) => return Err(e),
                        }
                    }

                    fragments.clear();
                } else {
                    //其他字符都作为普通字符加入栈中
                    stack.push(ch);
                }
            }
        }
        //结束时如果栈不为空
        if !stack.is_empty() {
            if left_quote == ' ' {
                //不存在未闭合的引号，将栈中剩余内容作为命令段加入集合，并构造命令
                fragments.push(stack.to_string());
                match Self::build_command_from_fragments(&fragments, false) {
                    Ok(command) => commands.push(command),
                    Err(e) => return Err(e),
                }
            } else {
                //存在未闭合的引号，返回此引号的下标
                return Err(CommandError::UnclosedQuotation(left_quote_index));
            }
        }
        Ok(commands)
    }

    fn build_command_from_fragments(
        fragments: &Vec<String>,
        run_backend: bool,
    ) -> Result<Command, CommandError> {
        if fragments.len() == 0 {
            return Err(CommandError::EmptyCommand);
        }

        let mut iter = fragments.into_iter();

        let name = iter.next().unwrap();
        let re: Regex = Regex::new(r"\$[\w_]+").unwrap();
        let replacement = |caps: &Captures| -> String {
            match Env::get(&String::from(&caps[0][1..])) {
                Some(entry) => entry.origin().clone(),
                None => String::from(&caps[0]),
            }
        };
        let mut args: Vec<String> = Vec::new();
        for arg in iter.collect::<Vec<&String>>().iter() {
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
        Command::new(name.clone(), args, run_backend)
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct BuildInCmd(pub &'static str);

impl BuildInCmd {
    pub const BUILD_IN_CMD: &'static [BuildInCmd] = &[
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

    pub fn exec_command(&mut self, mut command: Command) {
        if command.run_backend {
            command.args.push("&".to_string());
        }

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

    pub fn shell_cmd_exec(&mut self, args: &Vec<String>) -> Result<(), CommandError> {
        if args.len() <= 0 {
            return Err(CommandError::WrongArgumentCount(args.len()));
        }

        let path = args.get(0).unwrap();
        let real_path = match Env::search_path_from_env(path) {
            Some(str) => str,
            None => return Err(CommandError::FileNotFound(path.clone())),
        };

        // 如果文件不存在，返回错误
        if !Path::new(&real_path).is_file() {
            // println!("{}: command not found", real_path);
            return Err(CommandError::NotFile(real_path.clone()));
        }

        let mut args = args.split_first().unwrap().1;
        let run_backend = if let Some(last) = args.last() {
            if last == "&" {
                args = &args[..args.len() - 1];
                true
            } else {
                false
            }
        } else {
            false
        };

        crossterm::terminal::disable_raw_mode().expect("failed to disable raw mode");

        let mut child = std::process::Command::new(real_path)
            .args(args)
            .current_dir(Env::current_dir())
            .envs(Env::get_all())
            .spawn()
            .expect("Failed to execute command");

        if !run_backend {
            unsafe {
                libc::tcsetpgrp(libc::STDIN_FILENO, child.id() as i32);
                let _ = child.wait();
                libc::tcsetpgrp(libc::STDIN_FILENO, std::process::id() as i32);
            };
        } else {
            self.add_backend_task(child);
        }

        crossterm::terminal::enable_raw_mode().expect("failed to enable raw mode");
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
            abs_path = format!("{}/{}", Env::current_dir(), path);
        }
        let path = Path::new(&abs_path).clean();
        let mut fmt_path = path.to_str().unwrap().to_string();
        let replacement = |_caps: &regex::Captures| -> String { String::from("/") };
        let re = regex::Regex::new(r"\/{2,}").unwrap();
        fmt_path = re.replace_all(fmt_path.as_str(), replacement).to_string();
        return Ok(fmt_path);
    }

    #[allow(dead_code)]
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

    #[allow(dead_code)]
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

    #[allow(dead_code)]
    fn is_file_or_dir(&self, path_str: &String) -> Result<String, CommandError> {
        match self.path_format(path_str) {
            Ok(path_str) => Ok(path_str),
            Err(_) => Err(CommandError::PathNotFound(path_str.clone())),
        }
    }
}

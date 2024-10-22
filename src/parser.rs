use std::{
    collections::HashMap,
    io::ErrorKind,
    os::fd::{AsRawFd, FromRawFd},
    process::{Child, ChildStdout, Stdio},
    sync::{Arc, Mutex},
};

use regex::Regex;

use crate::env::EnvManager;

#[derive(Debug)]
pub enum Token {
    Word(String),   // 普通的命令或选项
    Symbol(String), // 特殊符号
}

#[derive(Debug, Clone)]
pub enum CommandType {
    Simple, // 简单命令
    Redirect {
        target: RedirectTarget,
        mode: RedirectMode,
    }, // 重定向命令
    Pipe,   // 管道命令
}

#[derive(Debug, Clone, PartialEq, Eq, Copy)]
pub enum ConnectType {
    Simple, // 普通连接
    And,    // 与连接
    Or,     // 或连接
}

#[derive(Debug, Clone)]
pub struct Command {
    name: String,
    args: Vec<String>,
    cmd_type: CommandType,
    conn_type: ConnectType,
}

impl Command {
    pub fn new(
        name: &String,
        args: &[String],
        cmd_type: CommandType,
        conn_type: ConnectType,
    ) -> Command {
        Self {
            name: name.clone(),
            args: args.to_vec(),
            cmd_type,
            conn_type,
        }
    }

    pub fn execute(&self) {}
}

#[derive(Debug, Clone)]
pub enum RedirectTarget {
    File(String),
    FileDiscriptor(i32),
}

impl RedirectTarget {
    pub fn from_string(str: &String) -> Option<RedirectTarget> {
        if str.starts_with("&") {
            if let Ok(fd) = str.split_at(1).1.parse::<i32>() {
                Some(RedirectTarget::FileDiscriptor(fd))
            } else {
                None
            }
        } else {
            Some(RedirectTarget::File(str.clone()))
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum RedirectMode {
    Overwrite,
    Append,
}

impl RedirectMode {
    pub fn from_string(str: &String) -> Option<RedirectMode> {
        match str.as_str() {
            ">" => Some(RedirectMode::Overwrite),
            ">>" => Some(RedirectMode::Append),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub enum ParseError {
    UnexpectedInput(String),
    UnsupportedToken(String),
    UnexpectedToken(String),
}

impl ParseError {
    pub fn handle(&self) {
        match self {
            ParseError::UnexpectedInput(str) => eprintln!("Unexpected input: \"{str}\""),
            ParseError::UnsupportedToken(str) => eprintln!("Unsupported token: \"{str}\""),
            ParseError::UnexpectedToken(str) => eprintln!("Unexpected token: \"{str}\""),
        }
    }
}

pub struct Parser;

impl Parser {
    fn parse_env(str: &str) -> String {
        std::env::var(str).unwrap_or(String::new())
    }

    fn lexer(input: &str) -> Result<Vec<Token>, ParseError> {
        let mut tokens = Vec::new();

        // 匹配环境变量的正则表达式
        let env_token = Regex::new(r#"\$\{(\w[\w\d_]*)\}"#).unwrap();

        // 使用具体的符号组合来匹配
        let regex_token =
            Regex::new(r#"([^'";|&$\s]+)|(["'].*?["'])|(&&|\|\||<<|>>|[<>|&;])"#).unwrap();

        // 预先替换"${}"包围的环境变量
        let remaining_input = env_token
            .replace_all(input, |captures: &regex::Captures| {
                Self::parse_env(&captures[1])
            })
            .into_owned();

        let mut remaining_input = remaining_input.trim();

        while !remaining_input.is_empty() {
            if let Some(mat) = regex_token.find(remaining_input) {
                let token_str = mat.as_str();
                if token_str.starts_with('"') || token_str.starts_with('\'') {
                    tokens.push(Token::Word(token_str[1..token_str.len() - 1].to_string()));
                } else if token_str.starts_with('$') {
                    tokens.push(Token::Word(Self::parse_env(&token_str[1..])));
                } else if token_str == ">>"
                    || token_str == ">"
                    || token_str == "<<"
                    || token_str == "<"
                    || token_str == "|"
                    || token_str == "&"
                    || token_str == ";"
                    || token_str == "&&"
                    || token_str == "||"
                {
                    if token_str == "<" || token_str == "<<" {
                        return Err(ParseError::UnsupportedToken(token_str.to_string()));
                    }
                    tokens.push(Token::Symbol(token_str.to_string()));
                } else {
                    tokens.push(Token::Word(token_str.to_string()));
                }

                remaining_input = &remaining_input[mat.end()..].trim();
            } else {
                return Err(ParseError::UnexpectedInput(remaining_input.to_string()));
            }
        }
        Ok(tokens)
    }

    fn parser(tokens: Vec<Token>) -> Result<Vec<Pipeline>, ParseError> {
        let mut commands = Vec::new();
        let mut current_command: Vec<String> = Vec::new();
        let mut pipelines = Vec::new();
        let mut redirect_object: (Option<RedirectMode>, Option<RedirectTarget>) = (None, None);

        for token in tokens {
            match token {
                Token::Word(ref word) => {
                    if let (Some(_), None) = redirect_object {
                        redirect_object.1 = RedirectTarget::from_string(word);
                    } else {
                        current_command.push(word.to_string());
                    }
                }

                Token::Symbol(symbol) => {
                    match symbol.as_str() {
                        ">" | ">>" => {
                            // 重定向符号不能重复出现
                            if redirect_object.0.is_some() {
                                return Err(ParseError::UnexpectedToken(symbol));
                            } else {
                                redirect_object.0 = RedirectMode::from_string(&symbol);
                            }
                        }
                        "|" | "&" | "||" | "&&" | ";" => {
                            if let Some((name, args)) = current_command.split_first() {
                                let mut cmd_type =
                                    if let (Some(mode), Some(ref target)) = redirect_object {
                                        CommandType::Redirect {
                                            target: target.clone(),
                                            mode,
                                        }
                                    } else {
                                        CommandType::Simple
                                    };

                                let conn_type = match symbol.as_str() {
                                    "|" => {
                                        // 重定向优先级高于管道
                                        if let CommandType::Simple = cmd_type {
                                            cmd_type = CommandType::Pipe;
                                        }
                                        ConnectType::Simple
                                    }
                                    "&" | ";" => ConnectType::Simple,
                                    "||" => ConnectType::Or,
                                    "&&" => ConnectType::And,
                                    _ => todo!(),
                                };

                                commands.push(Command::new(name, args, cmd_type, conn_type));
                                current_command.clear();

                                if symbol == "&" {
                                    pipelines.push(Pipeline::new(&commands, true));
                                    commands.clear();
                                }
                            } else {
                                // 这些符号之前必须有word作为命令被分隔，否则这些符号是没有意义的
                                return Err(ParseError::UnexpectedToken(symbol));
                            }
                        }
                        _ => todo!(),
                    }
                }
            }
        }

        // 处理最后一个命令
        if let Some((name, args)) = current_command.split_first() {
            commands.push(Command::new(
                name,
                args,
                if let (Some(mode), Some(ref target)) = redirect_object {
                    CommandType::Redirect {
                        target: target.clone(),
                        mode,
                    }
                } else {
                    CommandType::Simple
                },
                ConnectType::Simple,
            ));
        }

        if !commands.is_empty() {
            pipelines.push(Pipeline::new(&commands, false));
        }

        Ok(pipelines)
    }

    pub fn parse(input: &str) -> Result<Vec<Pipeline>, ParseError> {
        // 解析输入并生成token列表
        let tokens = Self::lexer(input)?;
        // println!("tokens: {tokens:?}");

        // 解析 tokens 生成命令流水线
        Self::parser(tokens)
    }
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct ExecuteError {
    name: String,
    err_type: ExecuteErrorType,
}

impl ExecuteError {
    pub fn handle(&self, prompt: Option<String>) {
        if let Some(prompt) = prompt {
            eprint!("{}: ", prompt);
        }
        eprint!("{}: ", self.name);
        match &self.err_type {
            ExecuteErrorType::CommandNotFound => eprintln!("Command not found"),
            ExecuteErrorType::FileNotFound(file) => eprintln!("Not a file or directory: {}", file),
            ExecuteErrorType::NotDir(ref path) => eprintln!("Not a Directory: {path}"),
            ExecuteErrorType::NotFile(ref path) => eprintln!("Not a File: {path}"),
            ExecuteErrorType::PermissionDenied(ref file) => eprintln!("File open denied: {file}"),
            ExecuteErrorType::ExecuteFailed => eprintln!("Command execute failed"),
            ExecuteErrorType::ExitWithCode(exit_code) => {
                eprintln!("Command exit with code: {}", exit_code)
            }
            ExecuteErrorType::ProcessTerminated => eprintln!("Process terminated"),
            ExecuteErrorType::FileOpenFailed(file) => {
                eprintln!("File open failed: {}", file.clone())
            }
            ExecuteErrorType::TooManyArguments => eprintln!("Too many arguments"),
            ExecuteErrorType::TooFewArguments => eprintln!("Too few arguments"),
            ExecuteErrorType::InvalidArgument(arg) => eprintln!("Invalid argument: {}", arg),
        }
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub enum ExecuteErrorType {
    CommandNotFound,
    FileNotFound(String),
    NotDir(String),
    NotFile(String),
    PermissionDenied(String),
    ExecuteFailed,
    ProcessTerminated,
    ExitWithCode(i32),
    FileOpenFailed(String),
    TooManyArguments,
    TooFewArguments,
    InvalidArgument(String),
}

pub enum RedirectStdout {
    Stdout(Option<ChildStdout>),
    RawPipe(i32),
}

impl RedirectStdout {
    pub fn as_raw_fd(&mut self) -> i32 {
        match self {
            RedirectStdout::Stdout(child_stdout) => child_stdout.take().unwrap().as_raw_fd(),
            RedirectStdout::RawPipe(fd) => *fd,
        }
    }

    pub fn as_std(&mut self) -> Stdio {
        match self {
            RedirectStdout::Stdout(child_stdout) => Stdio::from(child_stdout.take().unwrap()),
            RedirectStdout::RawPipe(fd) => unsafe { Stdio::from_raw_fd(*fd) },
        }
    }
}

impl From<i32> for RedirectStdout {
    fn from(value: i32) -> Self {
        RedirectStdout::RawPipe(value)
    }
}

impl From<Option<ChildStdout>> for RedirectStdout {
    fn from(mut value: Option<ChildStdout>) -> Self {
        RedirectStdout::Stdout(value.take())
    }
}

#[derive(Debug)]
pub struct Pipeline {
    commands: Vec<Command>, // 存储一系列命令
    backend: bool,
}

type CommandMap = HashMap<String, fn(&Vec<String>) -> Result<(), ExecuteErrorType>>;

impl Pipeline {
    pub fn new(commands: &Vec<Command>, backend: bool) -> Pipeline {
        Self {
            commands: commands.to_vec(),
            backend,
        }
    }

    pub fn execute(&self, internal_commands: Option<Arc<Mutex<CommandMap>>>) -> Vec<Child> {
        // 前一个命令是否为管道输出
        let mut stdout: Option<RedirectStdout> = None;
        // 提前推断下条命令的布尔值，为None代表下条命令需要运行
        let mut result_next: Option<bool> = None;
        let mut children: Vec<Child> = Vec::new();
        let mut err: Option<ExecuteErrorType> = None;

        for cmd in self.commands.iter() {
            if let Some(result) = result_next {
                // 如果前面已经推导出本条命令的布尔值，则本条命令不需要执行，并继续推断下条命令
                if (result && cmd.conn_type == ConnectType::And)
                    || (!result && cmd.conn_type == ConnectType::Or)
                {
                    // 如果true遇到||或false遇到&&，则下条命令的布尔值相同
                    // 如果true遇到&&或false遇到||，继承中断，设为None以执行后续命令
                    result_next = None;
                }
                continue;
            }

            let mut internal = false;
            if let Some(ref map) = internal_commands {
                let map = map.lock().unwrap();
                if let Some(f) = map.get(&cmd.name) {
                    // 找到内部命令，优先执行，设置标记
                    internal = true;

                    // child_fd
                    let child_fd = if self.backend {
                        unsafe { libc::fork() }
                    } else {
                        0
                    };

                    // 为子进程或前台运行
                    if child_fd == 0 {
                        let mut old_stdin: Option<i32> = None;
                        let mut old_stdout: Option<i32> = None;

                        // 如果上条命令为管道，将标准输入重定向
                        if let Some(mut redirect_stdout) = stdout {
                            unsafe {
                                old_stdin = Some(libc::dup(libc::STDIN_FILENO));
                                libc::dup2(redirect_stdout.as_raw_fd(), libc::STDIN_FILENO);
                                stdout = None;
                            }
                        }

                        // 根据命令类型重定向标准输出
                        match cmd.cmd_type {
                            CommandType::Simple => {}
                            CommandType::Pipe => unsafe {
                                let mut pipe: [i32; 2] = [0; 2];
                                libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC);
                                stdout = Some(RedirectStdout::from(pipe[0]));

                                old_stdout = Some(libc::dup(libc::STDOUT_FILENO));

                                libc::dup2(pipe[1], libc::STDOUT_FILENO);
                            },
                            CommandType::Redirect {
                                ref target,
                                ref mode,
                            } => unsafe {
                                let mut pipe: [i32; 2] = [0; 2];
                                libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC);
                                stdout = Some(RedirectStdout::from(pipe[0]));

                                old_stdout = Some(libc::dup(libc::STDOUT_FILENO));

                                let append = match mode {
                                    RedirectMode::Overwrite => false,
                                    RedirectMode::Append => true,
                                };

                                match target {
                                    RedirectTarget::File(file) => {
                                        match std::fs::OpenOptions::new()
                                            .write(true)
                                            .append(append)
                                            .create(true)
                                            .open(file)
                                        {
                                            Ok(file) => {
                                                libc::dup2(file.as_raw_fd(), libc::STDIN_FILENO);
                                            }

                                            Err(_) => {
                                                err = Some(ExecuteErrorType::FileOpenFailed(
                                                    file.clone(),
                                                ));
                                            }
                                        };
                                    }
                                    RedirectTarget::FileDiscriptor(fd) => {
                                        libc::dup2(*fd, libc::STDIN_FILENO);
                                    }
                                }
                            },
                        }

                        // 如果之前没有出错，执行命令
                        if err.is_none() {
                            match f(&cmd.args) {
                                Ok(_) => err = None,
                                Err(err_type) => err = Some(err_type),
                            }
                        }

                        // 还原标准输出
                        unsafe {
                            if let Some(old_stdin) = old_stdin {
                                libc::dup2(old_stdin, libc::STDIN_FILENO);
                            }

                            if let Some(old_stdout) = old_stdout {
                                libc::dup2(old_stdout, libc::STDOUT_FILENO);
                            }
                        }
                    } else if child_fd < 0 {
                        err = Some(ExecuteErrorType::ExecuteFailed)
                    }

                    // 后台命令且当前进程为父进程
                    if self.backend && !child_fd == 0 {
                        err = match unsafe { libc::waitpid(child_fd, std::ptr::null_mut(), 0) } {
                            -1 => Some(ExecuteErrorType::ExecuteFailed),
                            _ => None,
                        }
                    }
                }
            };

            // 没找到执行内部命令的标记，尝试作为外部命令执行
            if !internal {
                let path = if cmd.name.contains('/') {
                    // 为路径，获取规范的绝对路径
                    if let Ok(path) = std::fs::canonicalize(&cmd.name) {
                        if path.is_file() {
                            Ok(path)
                        } else {
                            // 路径不为文件，返回错误
                            Err(ExecuteErrorType::NotFile(cmd.name.clone()))
                        }
                    } else {
                        Err(ExecuteErrorType::CommandNotFound)
                    }
                } else {
                    // 不为路径，从环境变量中查找命令
                    which::which(&cmd.name).map_err(|_| ExecuteErrorType::CommandNotFound)
                };

                // println!("path: {:?}", path);

                match path {
                    Err(e) => err = Some(e),
                    Ok(real_path) => {
                        let mut child_command = std::process::Command::new(real_path);
                        child_command.args(cmd.args.clone());
                        child_command.current_dir(EnvManager::current_dir());
                        if stdout.is_some() {
                            child_command.stdin(stdout.take().unwrap().as_std());
                        }

                        match &cmd.cmd_type {
                            CommandType::Simple => {}
                            CommandType::Redirect { target, mode } => {
                                let append = match mode {
                                    RedirectMode::Overwrite => false,
                                    RedirectMode::Append => true,
                                };
                                match target {
                                    RedirectTarget::File(file) => {
                                        match std::fs::OpenOptions::new()
                                            .write(true)
                                            .append(append)
                                            .create(true)
                                            .open(file)
                                        {
                                            Ok(file) => {
                                                child_command.stdout(file);
                                            }
                                            Err(_) => {
                                                err = Some(ExecuteErrorType::FileOpenFailed(
                                                    file.clone(),
                                                ));
                                            }
                                        };
                                    }
                                    RedirectTarget::FileDiscriptor(fd) => {
                                        child_command.stdout(unsafe { Stdio::from_raw_fd(*fd) });
                                    }
                                }
                            }
                            CommandType::Pipe => {
                                // 标准输出重定向到管道
                                child_command.stdout(Stdio::piped());
                            }
                        }

                        if err.is_none() {
                            match child_command.spawn() {
                                Ok(mut child) => {
                                    // 如果为管道命令，记录下来
                                    if let CommandType::Pipe = cmd.cmd_type {
                                        stdout = Some(RedirectStdout::Stdout(child.stdout.take()));
                                    }

                                    // println!("exec command: {child_command:#?}");

                                    match child.wait() {
                                        Ok(exit_status) => match exit_status.code() {
                                            Some(exit_code) => {
                                                if exit_code != 0 {
                                                    err = Some(ExecuteErrorType::ExitWithCode(
                                                        exit_code,
                                                    ));
                                                }
                                            }
                                            None => err = Some(ExecuteErrorType::ProcessTerminated),
                                        },
                                        Err(_) => err = Some(ExecuteErrorType::ExecuteFailed),
                                    };

                                    children.push(child);
                                }

                                Err(e) => match e.kind() {
                                    ErrorKind::PermissionDenied => {
                                        err = Some(ExecuteErrorType::PermissionDenied(
                                            cmd.name.clone(),
                                        ))
                                    }
                                    _ => eprintln!("Error occurred: {}", e.kind()),
                                },
                            }
                        }
                    }
                }
            }

            // 预计算下条命令的结果
            result_next = match err {
                Some(ref e) => {
                    ExecuteError {
                        name: cmd.name.clone(),
                        err_type: e.clone(),
                    }
                    .handle(if internal {
                        Some("internal command".to_string())
                    } else {
                        None
                    });
                    if cmd.conn_type == ConnectType::And {
                        Some(false)
                    } else {
                        None
                    }
                }
                None => {
                    if cmd.conn_type == ConnectType::Or {
                        Some(true)
                    } else {
                        None
                    }
                }
            }
        }

        children
    }

    pub fn backend(&self) -> bool {
        self.backend
    }
}

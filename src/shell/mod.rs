use std::{
    cell::RefCell,
    collections::HashMap,
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader, Read, Write},
    ops::Deref,
    path::Path,
    print,
    process::Child,
    rc::Rc,
};

use crate::keycode::{FunctionKeySuffix, SpecialKeycode};

use colored::Colorize;
use command::{BuildInCmd, Command, CommandError};
use printer::Printer;

mod printer;

pub mod command;

const DEFAULT_HISTORY_COMMANDS_PATH: &str = "/history_commands.txt";

#[allow(dead_code)]
pub struct Shell {
    history_commands: Vec<Rc<RefCell<Vec<u8>>>>,
    history_path: String,
    printer: Printer,
    backend_task: HashMap<usize, Child>,
    window_size: Option<WindowSize>,
}

impl Shell {
    pub fn new() -> Shell {
        let mut shell = Shell {
            history_commands: Vec::new(),
            history_path: DEFAULT_HISTORY_COMMANDS_PATH.to_string(),
            printer: Printer::new(&Rc::new(RefCell::new(Vec::new()))),
            backend_task: HashMap::new(),
            window_size: WindowSize::new(),
        };
        shell.read_commands();
        shell
    }

    pub fn chdir(&mut self, new_dir: &String) {
        let path = Path::new(&new_dir);
        if let Err(e) = std::env::set_current_dir(&path) {
            eprintln!("Error changing directory: {}", e);
        }
    }

    pub fn exec(&mut self) {
        // 开启终端raw模式
        crossterm::terminal::enable_raw_mode().expect("failed to enable raw mode");

        // 循环读取一行
        loop {
            self.printer.init_before_readline();
            // 读取一行
            if self.readline() == 0 {
                println!();
                break;
            }

            let command_bytes = self.printer.buf.borrow().clone();

            // 如果命令不以空格开头且不跟上一条命令相同，这条命令会被记录
            if !command_bytes.is_empty()
                && !command_bytes.starts_with(&[b' '])
                && command_bytes
                    != self
                        .history_commands
                        .last()
                        .unwrap_or(&Rc::new(RefCell::new(Vec::new())))
                        .borrow()
                        .clone()
            {
                self.history_commands
                    .push(Rc::new(RefCell::new(command_bytes.clone())));
                self.write_commands(&command_bytes);
            };

            // 命令不为空，执行命令
            if !command_bytes.iter().all(|&byte| byte == b' ') {
                self.exec_commands_in_line(&command_bytes);
            }
            self.detect_task_done();
        }
    }

    fn exec_commands_in_line(&mut self, command_bytes: &Vec<u8>) {
        match Command::parse(String::from_utf8(command_bytes.clone()).unwrap()) {
            Ok(commands) => commands
                .into_iter()
                .for_each(|command| self.exec_command(command)),
            Err(e) => CommandError::handle(e),
        }
    }

    pub fn read_commands(&mut self) {
        let mut history = Vec::new();
        for line in BufReader::new(match File::open(&self.history_path) {
            Ok(file) => file,
            Err(_) => File::create(&self.history_path).unwrap(),
        })
        .lines()
        {
            match line {
                Ok(s) => history.push(Rc::new(RefCell::new(s.into_bytes()))),
                Err(_) => {
                    break;
                }
            }
        }
        self.history_commands = history;
    }

    fn write_commands(&self, command_bytes: &Vec<u8>) {
        let mut file = OpenOptions::new()
            .append(true)
            .open(self.history_path.as_str())
            .unwrap();
        file.write_all(&command_bytes)
            .expect("failed to write history command");
        file.write_all(&[SpecialKeycode::LF.into()]).unwrap();
    }

    fn read_char() -> u8 {
        let mut buf: [u8; 1] = [0];
        loop {
            if std::io::stdin().read(&mut buf).is_ok() {
                return buf[0];
            }
        }
    }

    fn readline(&mut self) -> usize {
        let mut stdout = std::io::stdout();
        self.history_commands.push(Rc::clone(&self.printer.buf));
        let mut command_index = self.history_commands.len() - 1;
        loop {
            let key = Self::read_char();
            if let Ok(special_key) = SpecialKeycode::try_from(key) {
                match special_key {
                    SpecialKeycode::FunctionKeyPrefix => {
                        let key = Self::read_char();
                        let function_key = FunctionKeySuffix::try_from(key).unwrap();
                        match function_key {
                            FunctionKeySuffix::Up => {
                                if command_index > 0 {
                                    command_index -= 1;
                                    self.printer.change_line(
                                        self.history_commands.get(command_index).unwrap(),
                                    );
                                }
                            }

                            FunctionKeySuffix::Down => {
                                if command_index < self.history_commands.len() - 1 {
                                    command_index += 1;
                                    self.printer.change_line(
                                        self.history_commands.get(command_index).unwrap(),
                                    );
                                }
                            }

                            FunctionKeySuffix::Left => {
                                if self.printer.cursor > 0 {
                                    self.printer.cursor_left(1);
                                }
                            }

                            FunctionKeySuffix::Right => {
                                if self.printer.cursor < self.printer.buf.borrow().len() {
                                    self.printer.cursor_right(1);
                                }
                            }

                            FunctionKeySuffix::Home => {
                                self.printer.home();
                            }

                            FunctionKeySuffix::End => {
                                self.printer.end();
                            }
                        }
                    }

                    SpecialKeycode::LF | SpecialKeycode::CR => {
                        println!();
                        self.history_commands.pop();
                        return 1;
                    }

                    SpecialKeycode::BackSpace => {
                        self.printer.backspace();
                    }

                    SpecialKeycode::Delete => {
                        self.printer.delete(1);
                    }

                    SpecialKeycode::Tab => {
                        let mut buf = self.printer.buf.deref().borrow().clone();
                        buf.truncate(self.printer.cursor);
                        let str = String::from_utf8(buf.clone()).unwrap();
                        if buf.len() == 0 || buf.iter().all(|byte| *byte == b' ') {
                            continue;
                        }

                        let iter = str.chars();
                        let mut fragments: Vec<String> = Vec::new();
                        let mut stack: String = String::with_capacity(str.len());
                        let mut left_quote: char = ' ';
                        for ch in iter {
                            //存在未闭合的左引号，此时包括空格的任何字符都加入栈中，直到匹配到右引号
                            if left_quote != ' ' {
                                if ch == left_quote {
                                    left_quote = ' ';
                                }
                                stack.push(ch);
                            } else {
                                //不存在未闭合的左引号
                                if ch == '\'' || ch == '\"' {
                                    //字符为引号，记录下来
                                    left_quote = ch;
                                    stack.push(ch);
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
                            fragments.push(stack.to_string());
                        } else {
                            //结束时如果栈为空，说明光标左边的字符不属于任何命令片段，无法进行补全
                            return 1;
                        }

                        let mut target_fragment = fragments.last().unwrap().clone();
                        target_fragment = target_fragment.replace("\'", "").replace("\"", "");

                        let (prefix, candidates) = if fragments.len() < 2 {
                            //补全命令
                            complete_command(&target_fragment)
                        } else {
                            //补全参数
                            complete_path(&target_fragment)
                        };

                        match candidates.len() {
                            1 => {
                                let old_fragment = fragments.last().unwrap();
                                let candidate = candidates.last().unwrap();
                                self.printer.cursor_left(old_fragment.len());
                                self.printer.delete(old_fragment.len());
                                self.printer
                                    .insert(format!("{}{}", prefix, candidate).as_bytes());
                            }
                            2.. => {
                                self.printer.end();
                                println!();
                                for candidate in candidates {
                                    print!(
                                        "{}\t",
                                        if candidate.ends_with('/') {
                                            candidate.truecolor(0x00, 0x88, 0xff)
                                        } else {
                                            candidate.white()
                                        }
                                    );
                                }
                                println!();
                                self.printer.print_prompt();
                                print!(
                                    "{}",
                                    String::from_utf8(self.printer.buf.borrow().to_vec()).unwrap()
                                );
                            }
                            _ => {}
                        }
                    }

                    _ => {}
                }
            } else {
                match key {
                    1..=31 => {}
                    c => {
                        self.printer.insert(&[c]);
                        // String::from_utf8("abdsdf".as_bytes().to_vec()).unwrap();
                    }
                }
            }
            stdout.flush().unwrap();
        }
    }

    fn add_backend_task(&mut self, child: Child) {
        let mut job_id = 1;
        while self.backend_task.contains_key(&job_id) {
            job_id += 1;
        }

        println!("[{}] {}", job_id, child.id());
        self.backend_task.insert(job_id, child);
    }

    fn detect_task_done(&mut self) {
        self.backend_task.retain(|job_id, task| {
            if let Ok(Some(status)) = task.try_wait() {
                println!("[{}] done with status: {}", job_id, status);
                false
            } else {
                true
            }
        })
    }
}

#[allow(dead_code)]
struct WindowSize {
    row: usize,
    col: usize,
}

impl WindowSize {
    pub fn new() -> Option<Self> {
        let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
        if unsafe {
            libc::ioctl(
                libc::STDOUT_FILENO,
                libc::TIOCGWINSZ,
                &mut ws as *mut libc::winsize,
            )
        } == -1
        {
            None
        } else {
            Some(Self {
                row: ws.ws_row.into(),
                col: ws.ws_col.into(),
            })
        }
    }
}

// 测试终端颜色显示效果
#[allow(dead_code)]
pub fn _print_color_example() {
    let example = "abcdefghijklmnopqrstuvwxyz";
    println!("{}", example.bright_black());
    println!("{}", example.bright_blue());
    println!("{}", example.bright_cyan());
    println!("{}", example.bright_green());
    println!("{}", example.bright_magenta());
    println!("{}", example.bright_purple());
    println!("{}", example.bright_red());
    println!("{}", example.bright_white());
    println!("{}", example.bright_yellow());
    println!("{}", example.black());
    println!("{}", example.blue());
    println!("{}", example.cyan());
    println!("{}", example.green());
    println!("{}", example.magenta());
    println!("{}", example.purple());
    println!("{}", example.red());
    println!("{}", example.white());
    println!("{}", example.yellow());
}

pub fn complete_command(command: &str) -> (&str, Vec<String>) {
    let mut candidates: Vec<String> = Vec::new();
    for BuildInCmd(cmd) in BuildInCmd::BUILD_IN_CMD {
        if cmd.starts_with(command) {
            candidates.push(String::from(*cmd));
        }
    }
    ("", candidates)
}

pub fn complete_path(incomplete_path: &str) -> (&str, Vec<String>) {
    let mut candidates: Vec<String> = Vec::new();
    let mut dir = "";
    let incomplete_name: &str;
    if let Some(index) = incomplete_path.rfind('/') {
        dir = &incomplete_path[..=index];
        incomplete_name = &incomplete_path[index + 1..];
    } else {
        incomplete_name = incomplete_path;
    }
    if let Ok(read_dir) = fs::read_dir(if dir.is_empty() { "." } else { dir }) {
        // if incomplete_name == "" {
        //     for entry in read_dir {
        //         let entry = entry.unwrap();
        //         let mut file_name = entry.file_name().into_string().unwrap();
        //         if entry.file_type().unwrap().is_dir() {
        //             file_name.push('/');
        //         }
        //         candidates.push(file_name);
        //     }
        // } else {
        for entry in read_dir {
            let entry = entry.unwrap();
            let mut file_name = entry.file_name().into_string().unwrap();
            if file_name.starts_with(incomplete_name) {
                if file_name.contains(' ') {
                    file_name = format!("\'{}\'", file_name);
                }
                if entry.file_type().unwrap().is_dir() {
                    file_name.push('/');
                }
                candidates.push(file_name);
            }
        }
        // }
    }

    return (dir, candidates);
}

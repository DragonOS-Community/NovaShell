use core::fmt;
use std::{
    cell::RefCell,
    fs::{self, File, OpenOptions},
    io::{self, stdout, BufRead, BufReader, Read, Write},
    ops::Deref,
    path::Path,
    print,
    rc::Rc,
    string::String,
    vec::Vec,
};

use crate::keycode::{FunctionKeySuffix, SpecialKeycode};

use colored::Colorize;
use command::{BuildInCmd, Command};

pub mod command;

pub struct Prompt {
    user_name: String,
    computer_name: String,
    path: String,
}

impl Prompt {
    pub fn len(&self) -> usize {
        format!("{}@{}:{}$ ", self.user_name, self.computer_name, self.path).len()
    }

    pub fn update_path(&mut self) {
        self.path = std::env::current_dir()
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
    }
}

impl fmt::Display for Prompt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{}$ ",
            format!("{}@{}", self.user_name, self.computer_name).bright_green(),
            self.path.bright_cyan()
        )
    }
}

pub struct Shell {
    history_commands: Vec<Rc<RefCell<Vec<u8>>>>,
    history_path: String,
    printer: Printer,
}

impl Shell {
    pub fn new() -> Shell {
        let mut shell = Shell {
            history_commands: Vec::new(),
            history_path: "history_commands.txt".to_string(),
            printer: Printer::new(&Rc::new(RefCell::new(Vec::new()))),
        };
        shell.read_commands();
        shell
    }

    pub fn current_dir() -> String {
        std::env::current_dir()
            .expect("Error getting current directory")
            .to_str()
            .unwrap()
            .to_string()
    }

    pub fn chdir(&mut self, new_dir: &String) {
        let path = Path::new(&new_dir);
        if let Err(e) = std::env::set_current_dir(&path) {
            eprintln!("Error changing directory: {}", e);
        }
    }

    pub fn exec(&mut self) {
        crossterm::terminal::enable_raw_mode().expect("failed to enable raw mode");
        loop {
            self.printer.init_before_readline();
            if self.readline() == 0 {
                println!();
                break;
            }
            let command_bytes = self.printer.buf.borrow().clone();
            if !command_bytes.starts_with(&[b' '])
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
                self.write_commands();
            };
            if !command_bytes.iter().all(|&byte| byte == b' ') {
                self.exec_commands_in_line(&command_bytes);
            }
        }
    }

    fn exec_commands_in_line(&mut self, command_bytes: &Vec<u8>) {
        let commands = Command::from_strings(String::from_utf8(command_bytes.clone()).unwrap());
        commands
            .iter()
            .for_each(|command| self.exec_command(command));
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

    fn write_commands(&self) {
        let mut file = OpenOptions::new()
            .write(true).truncate(true)
            .open("history_commands.txt")
            .unwrap();
        for command_line in &self.history_commands {
            file.write_all(&command_line.borrow()[..]).unwrap();
            file.write_all(&[SpecialKeycode::LF.into()]).unwrap();
        }
    }

    fn read_char() -> u8 {
        let mut buf: [u8; 1] = [0];
        std::io::stdin().read(&mut buf).expect("read char error");
        buf[0]
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
                                self.printer.cursor_left();
                            }

                            FunctionKeySuffix::Right => {
                                self.printer.cursor_right();
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
                            return 1;
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
                                self.printer.cursor -= old_fragment.len();
                                self.printer.flush_cursor();
                                self.printer.delete(old_fragment.len());
                                self.printer
                                    .insert(format!("{}{}", prefix, candidate).as_bytes());
                            }
                            2.. => {
                                let old_cursor = self.printer.cursor;
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
                                Printer::print(&self.printer.buf.deref().borrow());
                                self.printer.cursor = old_cursor;
                                self.printer.flush_cursor();
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
                    }
                }
            }
            stdout.flush().unwrap();
        }
    }
}

struct Printer {
    prompt: Prompt,
    buf: Rc<RefCell<Vec<u8>>>,
    cursor: usize,
}

impl Printer {
    fn new(bytes: &Rc<RefCell<Vec<u8>>>) -> Self {
        let len = bytes.deref().borrow().len();
        Printer {
            prompt: Prompt {
                computer_name: "DragonOS".to_string(),
                user_name: "root".to_string(),
                path: std::env::current_dir()
                    .expect("Error getting current directory")
                    .to_str()
                    .unwrap()
                    .to_string(),
            },
            buf: Rc::clone(bytes),
            cursor: len,
        }
    }

    fn init_before_readline(&mut self) {
        self.buf = Rc::new(RefCell::new(Vec::new()));
        self.prompt.update_path();
        self.print_prompt();
        self.cursor = 0;
        self.flush_cursor();
    }

    fn print_prompt(&self) {
        print!("{}", self.prompt);
        stdout().flush().unwrap();
    }

    //在光标处插入字符串
    fn insert(&mut self, bytes: &[u8]) {
        let mut buf = self.buf.deref().borrow_mut();
        // self.delete_to_cursor(buf.len() - cursor);
        // print!("{}"," ".repeat(buf.len() - cursor));
        Printer::print(bytes);
        Printer::print(&buf[self.cursor..]);
        buf.splice(self.cursor..self.cursor, bytes.iter().cloned());
        self.cursor += bytes.len();
        self.flush_cursor();
        stdout().flush().unwrap();
    }

    //删除下标为[cursor,cursor + len)的字符，光标位置不变
    fn delete(&self, len: usize) {
        let cursor = self.cursor;
        let mut buf = self.buf.deref().borrow_mut();
        if cursor + len - 1 < buf.len() {
            Printer::print(&buf[cursor + len..]);
            print!("{}", " ".repeat(len));
            self.flush_cursor();
            buf.drain(cursor..cursor + len);
            stdout().flush().unwrap();
        }
    }

    fn backspace(&mut self) {
        if self.cursor > 0 {
            crossterm::execute!(io::stdout(), crossterm::cursor::MoveLeft(1)).unwrap();
            self.cursor -= 1;
            self.flush_cursor();
            self.delete(1);
        }
    }

    fn flush_cursor(&self) {
        crossterm::execute!(
            io::stdout(),
            crossterm::cursor::MoveToColumn((self.cursor + self.prompt.len()) as u16)
        )
        .unwrap();
    }

    fn cursor_left(&mut self) {
        if self.cursor > 0 {
            crossterm::execute!(io::stdout(), crossterm::cursor::MoveLeft(1)).unwrap();
            self.cursor -= 1;
        }
    }

    fn cursor_right(&mut self) {
        let buf = self.buf.deref().borrow();
        if self.cursor < buf.len() {
            crossterm::execute!(io::stdout(), crossterm::cursor::MoveRight(1)).unwrap();
            self.cursor += 1;
        }
    }

    fn home(&mut self) {
        self.cursor = 0;
        self.flush_cursor();
    }

    fn end(&mut self) {
        self.cursor = self.buf.deref().borrow().len();
        self.flush_cursor();
    }

    fn change_line(&mut self, new_buf: &Rc<RefCell<Vec<u8>>>) {
        let old_buf_borrow = self.buf.deref().borrow();
        let new_buf_borrow = new_buf.deref().borrow();
        self.cursor = 0;
        self.flush_cursor();
        Printer::print(&new_buf_borrow[..]);
        self.cursor = new_buf_borrow.len();
        if new_buf_borrow.len() < old_buf_borrow.len() {
            print!(
                "{}",
                " ".repeat(old_buf_borrow.len() - new_buf_borrow.len())
            );
            self.flush_cursor();
        }
        drop(old_buf_borrow);
        drop(new_buf_borrow);
        self.buf = Rc::clone(new_buf);
        stdout().flush().unwrap();
    }

    fn print(bytes: &[u8]) {
        print!("{}", String::from_utf8(bytes.to_vec()).unwrap());
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

use libc::syscall;
use std::{
    fs::{self, File, OpenOptions},
    io::{self, BufRead, BufReader, Read, Write},
    print,
    string::String,
    vec::Vec,
};

use crate::{special_keycode::*, Env};

use command::{BuildInCmd, Command};

pub mod command;

pub struct Shell {
    history_commands: Vec<Vec<u8>>,
    executed_commands: Vec<Vec<u8>>,
    current_dir: String,
}

impl Shell {
    pub fn new() -> Shell {
        let mut shell = Shell {
            history_commands: Vec::new(),
            executed_commands: Vec::new(),
            current_dir: String::from("/"),
        };
        shell.read_commands();
        shell
    }

    pub fn current_dir(&self) -> String {
        self.current_dir.clone()
    }

    pub fn set_current_dir(&mut self, new_dir: String) {
        self.current_dir = new_dir;
        Env::insert(String::from("PWD"), self.current_dir());
    }

    pub fn exec(&mut self) {
        let mut buf: Vec<u8>;
        loop {
            buf = Vec::new();
            buf.push(b' ');
            self.history_commands.push(buf);
            Printer::print_prompt(&self.current_dir);
            if self.readline(0) == 0 {
                Printer::print(&[CR, LF]);
                break;
            }
            let command_bytes = self.history_commands.last().unwrap().clone();
            self.exec_command_in_bytes(&command_bytes);
        }
        self.write_commands();
    }

    fn exec_command_in_bytes(&mut self, command_bytes: &Vec<u8>) {
        let commands = Command::from_strings(String::from_utf8(command_bytes.clone()).unwrap());
        commands
            .iter()
            .for_each(|command| self.exec_command(command));
    }

    fn read_commands(&mut self) {
        for line in BufReader::new(match File::open("history_commands.txt") {
            Ok(file) => file,
            Err(_) => File::create("history_commands.txt").unwrap(),
        })
        .lines()
        {
            match line {
                Ok(s) => self.history_commands.push(s.into_bytes()),
                Err(_) => {
                    break;
                }
            }
        }
    }

    fn write_commands(&self) {
        let mut file = OpenOptions::new()
            .append(true)
            .open("history_commands.txt")
            .unwrap();
        for command_line in &self.executed_commands {
            file.write_all(&command_line[..]).unwrap();
            file.write_all(&[LF]).unwrap();
        }
    }

    fn readline(&mut self, fd: usize) -> usize {
        let mut stdin = std::io::stdin();
        let mut stdout = std::io::stdout();
        let prompt: String = self.current_dir.clone();
        let history_commands = &mut self.history_commands;
        let len = history_commands.len() - 1;
        let mut key: [u8; 1] = [0];
        let mut command_index = len;
        let mut buf = history_commands.get_mut(command_index).unwrap();
        let mut cursor = 0;

        Printer::print_cursor(b' ');
        stdout.flush().unwrap();
        loop {
            let mut c: libc::c_uchar = 0;
            unsafe {
                let p = &mut c as *mut libc::c_uchar as *mut libc::c_void;
                libc::read(0, p, 1);
                key[0] = c;
            }
            // if stdin.read(&mut key).ok() != Some(1) {
            //     continue;
            // }
            if key[0] == 224 {
                stdin.read(&mut key).unwrap();
                if key[0] == b'\x1b' {
                    panic!();
                }
                if key[0] == UP || key[0] == DOWN {
                    Printer::delete_from_index(0, buf.len());

                    match key[0] {
                        UP => {
                            if command_index > 0 {
                                command_index -= 1;
                            }
                        }

                        DOWN => {
                            if command_index < len {
                                command_index += 1;
                            }
                        }

                        _ => {}
                    }
                    buf = history_commands.get_mut(command_index).unwrap();
                    Printer::print(&buf[..buf.len() - 1]);
                    cursor = buf.len() - 1;
                    Printer::print_cursor(b' ');
                }

                if key[0] == LEFT || key[0] == RIGHT {
                    match key[0] {
                        LEFT => {
                            if cursor > 0 {
                                Printer::set_cursor(buf, cursor, cursor - 1);
                                cursor -= 1;
                            }
                        }

                        RIGHT => {
                            if cursor < buf.len() - 1 {
                                Printer::set_cursor(buf, cursor, cursor + 1);
                                cursor += 1;
                            }
                        }

                        _ => {}
                    }
                }
            } else {
                if key[0] == TAB && buf.len() > 1 && buf[cursor - 1] != b' ' {
                    let command: String = String::from_utf8(buf[..cursor].to_vec()).unwrap();
                    let mut command_frag = command.split_ascii_whitespace().collect::<Vec<_>>();
                    let incomplete_frag = command_frag.pop().unwrap();
                    let mut incomplete_len: usize = incomplete_frag.len();
                    let candidates = match command_frag.len() {
                        0 => Printer::complete_command(incomplete_frag),
                        1.. => {
                            if let Some(index) = incomplete_frag.rfind('/') {
                                incomplete_len = incomplete_frag.len() - index - 1;
                            } else {
                                incomplete_len = incomplete_frag.len();
                            }
                            Printer::complete_path(incomplete_frag)
                        }
                        _ => Vec::new(),
                    };
                    match candidates.len() {
                        1 => {
                            let complete_part = candidates[0][incomplete_len..].as_bytes();

                            Printer::delete_from_index(cursor, buf.len());

                            // stdout.write_all(complete_part).unwrap();
                            Printer::print(complete_part);

                            Printer::print_cursor(buf[cursor]);
                            Printer::print(&buf[cursor + 1..]);

                            buf.splice(cursor..cursor, complete_part.iter().cloned());
                            cursor += candidates[0].len() - incomplete_len;
                        }
                        2.. => {
                            Printer::delete_from_index(cursor, buf.len());
                            Printer::print(&buf[cursor..buf.len()]);
                            Printer::print(&[CR, LF]);
                            for candidate in candidates {
                                print!("{candidate}    ");
                            }
                            Printer::print(&[CR, LF]);
                            Printer::print_prompt(&prompt);
                            Printer::print(&buf[..buf.len() - 1]);
                            Printer::print_cursor(b' ');
                        }
                        _ => {}
                    }
                }

                match key[0] {
                    CR | LF => {
                        if cursor > 0 {
                            Printer::set_cursor(buf, cursor, buf.len());
                            Printer::print(&[CR, LF]);
                            let mut command = buf.clone();
                            buf = history_commands.get_mut(len).unwrap();
                            buf.clear();
                            buf.append(&mut command);

                            return 1;
                        }
                    }
                    BS | DL => {
                        if cursor > 0 {
                            Printer::delete_from_index(cursor, buf.len());
                            cursor -= 1;
                            buf.remove(cursor);
                            // stdout.write_all(&[BS]).unwrap();
                            Printer::print(&[BS]);
                            Printer::print_cursor(buf[cursor]);
                            Printer::print(&buf[cursor + 1..]);
                        }
                    }
                    1..=31 => {}
                    c => {
                        Printer::delete_from_index(cursor, buf.len());
                        Printer::print(&[c]);
                        buf.insert(cursor, c);
                        cursor += 1;
                        Printer::print_cursor(buf[cursor]);
                        Printer::print(&buf[cursor + 1..]);
                    }
                }
            }
            stdout.flush().unwrap();
        }
    }
}

struct Printer;

impl Printer {
    fn print_prompt(current_dir: &String) {
        io::stdout().flush().unwrap();
        unsafe {
            syscall(100000, "[DragonOS]:\0".as_ptr(), 0x0000ff90, 0x00000000);

            syscall(
                100000,
                format!("{}\0", current_dir).as_ptr(),
                0x000088ff,
                0x00000000,
            );
            print!("$ ");
        }
    }

    fn print_cursor(c: u8) {
        Self::print_color(&[c], 0x00000000, 0x00ffffff);
    }

    fn delete_from_index(index: usize, length: usize) {
        for _i in 0..length - index {
            Printer::print(&[BS, SPACE, BS]);
        }
    }

    fn print(bytes: &[u8]) {
        print!("{}", String::from_utf8(bytes.to_vec()).unwrap());
    }

    fn print_color(bytes: &[u8], front_color: usize, background_color: usize) {
        std::io::stdout().flush().unwrap();
        let cstr = std::ffi::CString::new(bytes).unwrap();
        unsafe {
            dsc::syscall!(SYS_PUT_STRING, cstr.as_ptr(), front_color, background_color);
        }
    }

    fn set_cursor(buf: &mut Vec<u8>, old_index: usize, new_index: usize) {
        if new_index < buf.len() {
            let index = std::cmp::min(old_index, new_index);
            Printer::delete_from_index(index, buf.len());
            Printer::print(&buf[index..new_index]);
            Printer::print_cursor(buf[new_index]);
            Printer::print(&buf[new_index + 1..]);
        } else {
            Printer::delete_from_index(old_index, buf.len());
            Printer::print(&buf[old_index..]);
        }
    }

    fn complete_command(command: &str) -> Vec<String> {
        let mut candidates: Vec<String> = Vec::new();
        for BuildInCmd(cmd) in BuildInCmd::BUILD_IN_CMD {
            if cmd.starts_with(command) {
                candidates.push(String::from(*cmd));
            }
        }
        candidates
    }

    fn complete_path(path: &str) -> Vec<String> {
        let mut candidates: Vec<String> = Vec::new();
        let dir: &str;
        let incomplete_name: &str;
        if let Some(index) = path.rfind('/') {
            dir = &path[..=index];
            if index < path.len() {
                incomplete_name = &path[index + 1..];
            } else {
                incomplete_name = "";
            }
        } else {
            dir = ".";
            incomplete_name = &path[..];
        }
        match fs::read_dir(dir) {
            Ok(read_dir) => {
                if incomplete_name == "" {
                    for entry in read_dir {
                        let entry = entry.unwrap();
                        let mut file_name = entry.file_name().into_string().unwrap();
                        if entry.file_type().unwrap().is_dir() {
                            file_name.push('/');
                        }
                        candidates.push(file_name);
                    }
                } else {
                    for entry in read_dir {
                        let entry = entry.unwrap();
                        let mut file_name = entry.file_name().into_string().unwrap();
                        if file_name.starts_with(incomplete_name) {
                            if entry.file_type().unwrap().is_dir() {
                                file_name.push('/');
                            }
                            candidates.push(file_name);
                        }
                    }
                }
            }

            Err(_) => {}
        }
        return candidates;
    }
}

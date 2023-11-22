use libc::syscall;
use std::{
    fs::{self, File, OpenOptions},
    io::{self, BufRead, BufReader, Read, Write},
    print,
    string::String,
    vec::Vec,
};

use crate::{Env, SpecialKeycode};

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

    pub fn set_current_dir(&mut self, new_dir: &String) {
        self.current_dir = new_dir.clone();
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
                println!();
                break;
            }
            let command_bytes = self.history_commands.last().unwrap().clone();
            let mut temp = command_bytes.clone();
            temp.retain(|byte| *byte != b' ');
            if temp.len() == 0 {
                self.history_commands.pop().unwrap();
            } else {
                self.executed_commands.push(command_bytes.clone());
                self.exec_command_in_bytes(&command_bytes);
            }
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
            file.write_all(&[SpecialKeycode::LF.into()]).unwrap();
        }
    }

    fn read_char(byte: &mut u8) {
        let mut c: libc::c_uchar = 0;
        unsafe {
            let p = &mut c as *mut libc::c_uchar as *mut libc::c_void;
            libc::read(0, p, 1);
        }
        *byte = c;
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
            Self::read_char(&mut key[0]);
            // if stdin.read(&mut key).ok() != Some(1) {
            //     continue;
            // }
            if let Ok(special_key) = SpecialKeycode::try_from(key[0]) {
                match special_key {
                    SpecialKeycode::FunctionKey => {
                        Self::read_char(&mut key[0]);
                        let special_key = SpecialKeycode::try_from(key[0]).unwrap();
                        match special_key {
                            SpecialKeycode::Up => {
                                if command_index > 0 {
                                    command_index -= 1;
                                }
                                let old_length = buf.len();
                                buf = history_commands.get_mut(command_index).unwrap();
                                Printer::replace(&buf, old_length);
                                cursor = buf.len() - 1;
                            }

                            SpecialKeycode::Down => {
                                if command_index < len {
                                    command_index += 1;
                                }
                                let old_length = buf.len();
                                buf = history_commands.get_mut(command_index).unwrap();
                                Printer::replace(&buf, old_length);
                                cursor = buf.len() - 1;
                            }

                            SpecialKeycode::Left => {
                                if cursor > 0 {
                                    Printer::set_cursor(buf, cursor, cursor - 1);
                                    cursor -= 1;
                                }
                            }

                            SpecialKeycode::Right => {
                                if cursor < buf.len() - 1 {
                                    Printer::set_cursor(buf, cursor, cursor + 1);
                                    cursor += 1;
                                }
                            }

                            SpecialKeycode::Home => {
                                Printer::set_cursor(buf, cursor, 0);
                            }

                            SpecialKeycode::End => {
                                Printer::set_cursor(buf, cursor, buf.len());
                            }

                            _ => {}
                        }
                    }

                    SpecialKeycode::LF | SpecialKeycode::CR => {
                        if cursor > 0 {
                            Printer::set_cursor(buf, cursor, buf.len());
                            println!();
                            let mut command = buf.clone();
                            buf = history_commands.get_mut(len).unwrap();
                            buf.clear();
                            buf.append(&mut command);

                            return 1;
                        }
                    }

                    SpecialKeycode::BackSpace => {
                        if cursor > 0 {
                            Printer::delete_to_cursor(cursor, 1, buf);
                            buf.remove(cursor - 1);
                            cursor -= 1;
                        }
                    }

                    SpecialKeycode::Delete => {
                        if cursor < buf.len() - 1 {
                            Printer::delete(cursor, buf);
                            buf.remove(cursor);
                        }
                    }

                    SpecialKeycode::Tab => {
                        if buf.len() > 1 && buf[cursor - 1] != b' ' {
                            let command: String =
                                String::from_utf8(buf[..cursor].to_vec()).unwrap();
                            let mut command_frag =
                                command.split_ascii_whitespace().collect::<Vec<_>>();
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
                                    println!();
                                    for candidate in candidates {
                                        print!("{candidate}    ");
                                    }
                                    println!();
                                    Printer::print_prompt(&prompt);
                                    Printer::print(&buf[..buf.len() - 1]);
                                    Printer::print_cursor(b' ');
                                }
                                _ => {}
                            }
                        }
                    }

                    _ => todo!(),
                }
            } else {
                match key[0] {
                    1..=31 => {}
                    c => {
                        Printer::insert(cursor, &[c], buf);
                        buf.insert(cursor, c);
                        cursor += 1;
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
        Self::print_color("[DragonOS]:".as_bytes(), 0x0000ff90, 0x00000000);
        Self::print_color(current_dir.as_bytes(), 0x000088ff, 0x00000000);
        print!("$ ");
    }

    fn print_cursor(c: u8) {
        Self::print_color(&[c], 0x00000000, 0x00ffffff);
    }

    fn delete_from_index(index: usize, length: usize) {
        for _i in 0..length - index {
            Printer::print(&[
                SpecialKeycode::BackSpace.into(),
                b' ',
                SpecialKeycode::BackSpace.into(),
            ]);
        }
    }

    fn insert(cursor: usize, bytes: &[u8], buf: &Vec<u8>) {
        Printer::delete_from_index(cursor, buf.len());
        Printer::print(bytes);
        Printer::print_cursor(buf[cursor]);
        Printer::print(&buf[cursor + 1..]);
    }

    fn delete(cursor: usize, buf: &Vec<u8>) {
        if cursor < buf.len() - 1 {
            Printer::delete_from_index(cursor, buf.len());
            Printer::print_cursor(buf[cursor + 1]);
            Printer::print(&buf[cursor + 2..]);
        }
    }

    fn delete_to_cursor(cursor: usize, length: usize, buf: &Vec<u8>) {
        if cursor > 0 {
            Printer::delete_from_index(cursor - length, buf.len());
            Printer::print_cursor(buf[cursor]);
            Printer::print(&buf[cursor + 1..]);
        }
    }

    fn replace(bytes: &[u8], old_length: usize) {
        Printer::delete_from_index(0, old_length);
        Printer::print(&bytes[0..bytes.len() - 1]);
        Printer::print_cursor(b' ');
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

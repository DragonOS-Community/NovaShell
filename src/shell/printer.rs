use std::{
    cell::RefCell,
    fmt,
    io::{self, stdout, Write},
    ops::Deref,
    print,
    rc::Rc,
};

use colored::Colorize;

pub struct Printer {
    /// 提示语
    pub prompt: Prompt,
    /// 缓存区，记录当前显示的内容
    pub buf: Rc<RefCell<Vec<u8>>>,
    /// 光标位置（不包括提示语）
    pub cursor: usize,
}

impl Printer {
    pub fn new(bytes: &Rc<RefCell<Vec<u8>>>) -> Self {
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
            cursor: 0,
        }
    }

    /// 读取输入前初始化信息
    pub fn init_before_readline(&mut self) {
        self.buf = Rc::new(RefCell::new(Vec::new()));
        self.prompt.update_path();
        self.print_prompt();
        self.cursor = 0;
    }

    pub fn print_prompt(&self) {
        print!("{}", self.prompt);
        stdout().flush().unwrap();
    }

    /// 在光标处插入字符串
    pub fn insert(&mut self, bytes: &[u8]) {
        // 记录光标距离末尾的长度，用于后续光标复位
        let len_to_end = self.buf.deref().borrow().len() - self.cursor;

        // 在buf中插入内容
        let mut buf = self.buf.deref().borrow_mut();
        buf.splice(self.cursor..self.cursor, bytes.iter().cloned());

        // 打印cursor后面的内容，此时屏幕光标在末尾
        print!(
            "{}",
            String::from_utf8(buf[self.cursor..].to_vec()).unwrap()
        );

        // 移回光标
        if len_to_end > 0 {
            crossterm::execute!(
                io::stdout(),
                crossterm::cursor::MoveLeft(len_to_end.try_into().unwrap())
            )
            .unwrap();
        }
        self.cursor += bytes.len();

        stdout().flush().unwrap();
    }

    /// 删除下标为[cursor,cursor + len)的字符，光标位置不变
    pub fn delete(&mut self, len: usize) {
        let cursor = self.cursor;
        let buf_len = self.buf.deref().borrow().len();

        // 判断最大下标是否越界
        if cursor + len - 1 < buf_len {
            // 在buf中删除内容
            self.buf.deref().borrow_mut().drain(cursor..cursor + len);

            // 直接打印删除范围之后的内容
            print!(
                "{}",
                String::from_utf8(self.buf.deref().borrow()[self.cursor..].to_vec()).unwrap()
            );

            // 打印len个空格覆盖遗留的内容，此时屏幕光标下标恰好为原buf长度
            print!("{}", " ".repeat(len));

            // 屏幕光标移回原位
            crossterm::execute!(
                io::stdout(),
                crossterm::cursor::MoveLeft((buf_len - cursor).try_into().unwrap())
            )
            .unwrap();
            stdout().flush().unwrap();
        }
    }

    pub fn backspace(&mut self) {
        if self.cursor > 0 {
            self.cursor_left(1);
            self.delete(1);
        }
    }

    pub fn cursor_left(&mut self, len: usize) {
        if self.cursor > 0 {
            crossterm::execute!(
                io::stdout(),
                crossterm::cursor::MoveLeft(len.try_into().unwrap())
            )
            .unwrap();
            self.cursor -= len;
        }
    }

    pub fn cursor_right(&mut self, len: usize) {
        let buf = self.buf.deref().borrow();
        if self.cursor < buf.len() {
            crossterm::execute!(
                io::stdout(),
                crossterm::cursor::MoveRight(len.try_into().unwrap())
            )
            .unwrap();
            self.cursor += len;
        }
    }

    pub fn home(&mut self) {
        self.cursor_left(self.cursor);
    }

    pub fn end(&mut self) {
        let buf_len = self.buf.deref().borrow().len();
        self.cursor_right(buf_len - self.cursor);
    }

    /// 将命令行的内容修改为新的内容
    pub fn change_line(&mut self, new_buf: &Rc<RefCell<Vec<u8>>>) {
        // 移动到开头
        self.home();

        // 打印新的字符串
        print!(
            "{}",
            String::from_utf8(new_buf.deref().borrow()[..].to_vec()).unwrap()
        );

        // 如果新字符串长度比旧的短，后面会有残留，用空格覆盖
        let old_buf_len = self.buf.deref().borrow().len();
        let new_buf_len = new_buf.deref().borrow().len();
        if new_buf_len < old_buf_len {
            let remain_len = old_buf_len - new_buf_len;
            print!("{}", " ".repeat(remain_len));
            crossterm::execute!(
                io::stdout(),
                crossterm::cursor::MoveLeft(remain_len.try_into().unwrap())
            )
            .unwrap();
        }

        self.cursor = new_buf_len;
        self.buf = Rc::clone(new_buf);
        stdout().flush().unwrap();
    }
}

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

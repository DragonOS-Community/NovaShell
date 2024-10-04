use std::{collections::HashMap, sync::Mutex};

type HelpMap = HashMap<String, fn() -> ()>;

macro_rules! help {
    ($cmd:expr,$func:expr) => {
        ($cmd.to_string(), $func as fn() -> ())
    };
}

static mut HELP_MAP: Option<Mutex<HelpMap>> = None;

#[derive(Debug)]
pub struct Helper;

impl Helper {
    pub unsafe fn help() {
        let map = HELP_MAP.as_ref().unwrap().lock().unwrap();
        for (name, func) in map.iter() {
            print!("{name}:",);
            func();
        }
    }

    pub unsafe fn init() {
        HELP_MAP = Some(Mutex::new(HelpMap::new()));
        let mut map = HELP_MAP.as_ref().unwrap().lock().unwrap();

        let mut insert = |tuple: (String, fn() -> ())| map.insert(tuple.0, tuple.1);

        insert(help!("cd", Self::shell_help_cd));
        insert(help!("exec", Self::shell_help_exec));
    }

    fn shell_help_cd() {
        println!("Usage: cd [directory]");
    }

    fn shell_help_exec() {
        println!("exec: exec file");
    }
}

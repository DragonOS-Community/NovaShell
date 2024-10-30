use help::Helper;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::{fs::File, io::Read, print};

use crate::env::{EnvManager, ROOT_PATH};
use crate::parser::ExecuteErrorType;

mod help;

macro_rules! build {
    ($cmd:expr,$func:expr) => {
        (
            $cmd.to_string(),
            $func as fn(&Vec<String>) -> Result<(), ExecuteErrorType>,
        )
    };
}

type CommandMap = HashMap<String, fn(&Vec<String>) -> Result<(), ExecuteErrorType>>;

static mut BUILD_IN_CMD: Option<Arc<Mutex<CommandMap>>> = None;
#[derive(Debug)]
pub struct BuildInCmd;

impl BuildInCmd {
    // pub const BUILD_IN_CMD: &'static [BuildInCmd] = &[
    // BuildInCmd("cd"),
    // BuildInCmd("exec"),
    // BuildInCmd("reboot"),
    // BuildInCmd("free"),
    // BuildInCmd("help"),
    // BuildInCmd("export"),
    // BuildInCmd("compgen"),
    // BuildInCmd("complete"),
    // ];

    pub fn map() -> Option<Arc<Mutex<CommandMap>>> {
        unsafe { BUILD_IN_CMD.clone() }
    }

    pub unsafe fn init() {
        BUILD_IN_CMD = Some(Arc::new(Mutex::new(CommandMap::new())));
        let mut map = BUILD_IN_CMD.as_ref().unwrap().lock().unwrap();
        let mut insert = |tuple: (String, fn(&Vec<String>) -> Result<(), ExecuteErrorType>)| {
            map.insert(tuple.0, tuple.1)
        };

        insert(build!("cd", Self::shell_cmd_cd));
        insert(build!("exec", Self::shell_cmd_exec));
        insert(build!("reboot", Self::shell_cmd_reboot));
        insert(build!("help", Self::shell_cmd_help));
        insert(build!("free", Self::shell_cmd_free));
        insert(build!("export", Self::shell_cmd_export));
    }

    pub fn shell_cmd_cd(args: &Vec<String>) -> Result<(), ExecuteErrorType> {
        let path = match args.len() {
            0 => String::from(ROOT_PATH),
            1 => match std::fs::canonicalize(args.get(0).unwrap()) {
                Ok(path) => {
                    if !path.is_dir() {
                        return Err(ExecuteErrorType::NotDir(path.to_str().unwrap().to_string()));
                    }
                    path.to_str().unwrap().to_string()
                }
                Err(_) => return Err(ExecuteErrorType::FileNotFound(args.get(0).unwrap().clone())),
            },
            _ => return Err(ExecuteErrorType::TooManyArguments),
        };
        if let Err(_) = std::env::set_current_dir(&path) {
            return Err(ExecuteErrorType::ExecuteFailed);
        }
        Ok(())
    }

    pub fn shell_cmd_exec(args: &Vec<String>) -> Result<(), ExecuteErrorType> {
        if let Some((name, args)) = args.split_first() {
            let real_path = if name.contains('/') {
                // 为路径，获取规范的绝对路径
                if let Ok(path) = std::fs::canonicalize(name) {
                    if path.is_file() {
                        Ok(path)
                    } else {
                        // 路径不为文件，返回错误
                        Err(ExecuteErrorType::NotFile(name.clone()))
                    }
                } else {
                    Err(ExecuteErrorType::CommandNotFound)
                }
            } else {
                // 不为路径，从环境变量中查找命令
                which::which(name).map_err(|_| ExecuteErrorType::CommandNotFound)
            }?;

            let pgrp = unsafe { libc::tcgetpgrp(libc::STDIN_FILENO) };

            // 如果当前终端的前台进程等于当前进程，则设置前台进程
            let run_foreground = if pgrp >= 0 {
                if pgrp as u32 == std::process::id() {
                    true
                } else {
                    false
                }
            } else {
                false
            };

            let mut err: Option<ExecuteErrorType> = None;

            match std::process::Command::new(real_path)
                .args(args)
                .current_dir(EnvManager::current_dir())
                .spawn()
            {
                Ok(mut child) => {
                    if run_foreground {
                        unsafe { libc::tcsetpgrp(libc::STDIN_FILENO, child.id() as i32) };
                    }

                    match child.wait() {
                        Ok(exit_status) => match exit_status.code() {
                            Some(exit_code) => {
                                if exit_code != 0 {
                                    err = Some(ExecuteErrorType::ExitWithCode(exit_code));
                                }
                            }
                            None => err = Some(ExecuteErrorType::ProcessTerminated),
                        },
                        Err(_) => err = Some(ExecuteErrorType::ExecuteFailed),
                    }

                    if run_foreground {
                        unsafe { libc::tcsetpgrp(libc::STDIN_FILENO, std::process::id() as i32) };
                    }
                }
                Err(_) => todo!(),
            };
            return if let Some(err) = err {
                Err(err)
            } else {
                Ok(())
            };
        } else {
            return Err(ExecuteErrorType::TooFewArguments);
        }
    }

    fn shell_cmd_reboot(args: &Vec<String>) -> Result<(), ExecuteErrorType> {
        if args.len() == 0 {
            unsafe { libc::syscall(libc::SYS_reboot, 0, 0, 0, 0, 0, 0) };
            return Ok(());
        } else {
            return Err(ExecuteErrorType::TooManyArguments);
        }
    }

    fn shell_cmd_free(args: &Vec<String>) -> Result<(), ExecuteErrorType> {
        if args.len() == 1 && args.get(0).unwrap() != "-m" {
            return Err(ExecuteErrorType::InvalidArgument(
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

    fn shell_cmd_help(args: &Vec<String>) -> Result<(), ExecuteErrorType> {
        if args.len() == 0 {
            unsafe { Helper::help() };
            return Ok(());
        }
        return Err(ExecuteErrorType::TooManyArguments);
    }

    fn shell_cmd_export(args: &Vec<String>) -> Result<(), ExecuteErrorType> {
        if args.len() == 1 {
            let pair = args.get(0).unwrap().split('=').collect::<Vec<&str>>();

            if pair.len() == 2 && !pair.contains(&"") {
                let name = pair.get(0).unwrap().to_string();
                let value = pair.get(1).unwrap().to_string();
                std::env::set_var(name, value);
                return Ok(());
            } else {
                return Err(ExecuteErrorType::InvalidArgument(
                    args.get(0).unwrap().clone(),
                ));
            }
        }
        return Err(ExecuteErrorType::TooManyArguments);
    }
}

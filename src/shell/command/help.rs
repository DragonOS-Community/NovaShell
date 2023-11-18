pub struct Help {}

impl Help {
    pub fn shell_help(cmd: &str) {
        match cmd {
            "cd" => Self::shell_help_cd(),
            "ls" => Self::shell_help_ls(),
            "cat" => Self::shell_help_cat(),
            "touch" => Self::shell_help_touch(),
            "mkdir" => Self::shell_help_mkdir(),
            "rm" => Self::shell_help_rm(),
            "rmdir" => Self::shell_help_rmdir(),
            "pwd" => Self::shell_help_pwd(),
            "cp" => Self::shell_help_cp(),
            "exec" => Self::shell_help_exec(),
            "echo" => Self::shell_help_echo(),
            "reboot" => Self::shell_help_reboot(),
            "compgen" => Self::shell_help_compgen(),
            "complete" => Self::shell_help_complete(),

            _ => {}
        };
    }

    fn shell_help_cd() {
        println!("Usage: cd [directory]");
    }

    fn shell_help_ls() {}

    fn shell_help_cat() {
        println!("cat: cat file");
    }

    fn shell_help_touch() {
        println!("touch: touch file");
    }

    fn shell_help_mkdir() {
        println!("mkdir: mkdir directory");
    }

    fn shell_help_rm() {
        println!("rm: rm file");
    }

    fn shell_help_rmdir() {
        println!("rmdir: rmdir directory");
    }

    fn shell_help_pwd() {}

    fn shell_help_cp() {
        println!("cp: cp file file | directory");
    }

    fn shell_help_exec() {
        println!("exec: exec file");
    }

    fn shell_help_echo() {
        println!("echo: echo string");
    }

    fn shell_help_reboot() {}

    fn shell_help_compgen() {}

    fn shell_help_complete() {}
}

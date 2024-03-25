pub struct Help {}

impl Help {
    pub fn shell_help(cmd: &str) {
        match cmd {
            "cd" => Self::shell_help_cd(),
            "exec" => Self::shell_help_exec(),
            "reboot" => Self::shell_help_reboot(),
            "compgen" => Self::shell_help_compgen(),
            "complete" => Self::shell_help_complete(),

            _ => {}
        };
    }

    fn shell_help_cd() {
        println!("Usage: cd [directory]");
    }

    fn shell_help_exec() {
        println!("exec: exec file");
    }

    fn shell_help_reboot() {}

    fn shell_help_compgen() {}

    fn shell_help_complete() {}
}

use std::process::Child;

use anyhow::Context;
use clap::{Parser, Subcommand};
use log::{error, info};
use nix::{
    sys::{
        ptrace, signal,
        wait::{self, WaitStatus, waitpid},
    },
    unistd::Pid,
};
use rustyline::DefaultEditor;

pub struct Debugger {
    process: Pid,
}

#[derive(Parser, Debug)]
#[command(name = "", disable_help_flag = true, disable_version_flag = true)]
struct Command {
    #[command(subcommand)]
    cmds: SubCommands,
}

#[derive(Subcommand, Debug)]
enum SubCommands {
    #[command(alias = "q")]
    Quit,
    #[command(alias = "c")]
    Continue,
}

impl Debugger {
    pub fn new(process: Pid) -> Self {
        Self { process }
    }
    pub fn run(&mut self) -> anyhow::Result<()> {
        let pid = self.process;
        info!("Started debugging process: {}", pid);
        let mut rl = DefaultEditor::new()?;
        let path = ".rgdb_history";
        rl.set_helper(Some(()));
        rl.load_history(path).ok();
        // wait for trap, caused by traceme
        assert_eq!(
            self.wait4()?,
            WaitStatus::Stopped(self.process, signal::Signal::SIGTRAP)
        );

        let res = ptrace::read(self.process, 0x10427079c as usize as _)?;
        println!("{res}");

        loop {
            match rl.readline("gdb> ") {
                Ok(input) => {
                    let line = input.trim();
                    if line.is_empty() {
                        continue;
                    }
                    rl.add_history_entry(line)?;
                    let args = shlex::split(line).unwrap_or_default();
                    if args.is_empty() {
                        continue;
                    }
                    let argv = std::iter::once("command").chain(args.iter().map(String::as_str));
                    match Command::try_parse_from(argv) {
                        Ok(cmd) => match cmd.cmds {
                            SubCommands::Quit => break,
                            SubCommands::Continue => self.cont()?,
                        },
                        Err(e) => {
                            error!("cmd parse failed, {e}");
                            // eprintln!("cmd parse failed, {e}")
                        }
                    }
                }
                Err(_) => todo!(),
            }
        }
        rl.save_history(path)?;
        Ok(())
    }

    fn cont(&self) -> anyhow::Result<()> {
        info!("continue");
        ptrace::cont(self.process, None).context("failed to continue process")?;
        let res = self.wait4()?;
        info!("process received signal {:?}", res);
        Ok(())
    }

    fn wait4(&self) -> anyhow::Result<WaitStatus> {
        info!("wait");
        waitpid(self.process, None).context("failed to wait")
    }

    fn brk(&self) -> anyhow::Result<()> {
        todo!("break");
        let res = ptrace::read(self.process, 0x101010 as _)?;
        println!("{res}");
        Ok(())
    }
}

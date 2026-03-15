use std::ffi::CString;
mod debugger;
use clap::Parser;
use log::{Log, info};
use nix::{
    sys::ptrace,
    unistd::{ForkResult, execvp, fork},
};

#[derive(Parser, Debug)]
#[command(version, about, long_about=None)]
struct Args {
    program: String,
    args: Vec<String>,
}

struct Logger;
impl Log for Logger {
    fn enabled(&self, _metadata: &log::Metadata) -> bool {
        true
    }
    fn flush(&self) {}
    fn log(&self, record: &log::Record) {
        println!(
            "{}: {}@{} {}",
            record.level(),
            record.line().unwrap_or_default(),
            record.file().unwrap_or_default(),
            record.args(),
        )
    }
}

static LOGGER: Logger = Logger;

fn main() -> anyhow::Result<()> {
    let prog = Args::parse();
    log::set_logger(&LOGGER).map_err(|e| std::io::Error::other(e.to_string()))?;
    log::set_max_level(log::LevelFilter::Info);
    log::info!("args {prog:?}");
    let prog_path = prog.program.clone();
    let pn = CString::new(prog.program)?;
    let mut args = vec![pn.clone()];
    args.append(
        &mut prog
            .args
            .into_iter()
            .map(|e| CString::new(e))
            .collect::<Result<Vec<_>, _>>()?,
    );

    // let sub_process = Command::new(prog.program).args(prog.args).spawn()?;
    let pid = match unsafe { fork()? } {
        ForkResult::Child => {
            ptrace::traceme()?;

            /*
            The operation

            ptrace(PTRACE_TRACEME, 0, 0, 0);

            turns the calling thread into a tracee.  The thread continues to
            run (doesn't enter ptrace-stop).  A common practice is to follow
            the PTRACE_TRACEME with

            raise(SIGSTOP); */

            info!("args {:?}", args);
            execvp(&pn, &args)?;
            unreachable!();
        }
        ForkResult::Parent { child } => child,
    };
    let mut debugger = debugger::Debugger::new(pid, prog_path)?;

    debugger.run()
}

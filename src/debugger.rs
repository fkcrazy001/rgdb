use std::{collections::HashMap, fs, path::PathBuf};

use anyhow::Context;
use clap::{Parser, Subcommand};
use gimli::{Dwarf, EndianSlice, RunTimeEndian};
use log::{error, info};
use nix::{
    sys::{
        ptrace, signal,
        wait::{WaitStatus, waitpid},
    },
    unistd::Pid,
};
use object::{Object, ObjectSection};
use rustyline::DefaultEditor;

pub struct Debugger {
    process: Pid,
    breakpoints: HashMap<usize, i64>,
    dwarf: Option<Dwarf<EndianSlice<'static, RunTimeEndian>>>,
    load_address: usize,
    // Store the loaded ELF data to keep the 'static lifetime for EndianSlice
    _elf_data: Vec<u8>,
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
    #[command(alias = "b")]
    Break { location: String },
    #[command(alias = "reg")]
    Register {
        #[command(subcommand)]
        cmd: RegisterCommand,
    },
    #[command(alias = "mem")]
    Memory {
        #[command(subcommand)]
        cmd: MemoryCommand,
    },
    #[command(alias = "si")]
    StepInstruction,
    #[command(alias = "s")]
    Step,
    #[command(alias = "n")]
    Next,
    #[command(alias = "fin")]
    Finish,
}

#[derive(Subcommand, Debug)]
enum RegisterCommand {
    Read {
        reg: String,
    },
    Write {
        reg: String,
        #[arg(value_parser = parse_hex_u64)]
        value: u64,
    },
    Dump,
}

#[derive(Subcommand, Debug)]
enum MemoryCommand {
    Read {
        #[arg(value_parser = parse_hex_usize)]
        address: usize,
    },
    Write {
        #[arg(value_parser = parse_hex_usize)]
        address: usize,
        #[arg(value_parser = parse_hex_i64)]
        value: i64,
    },
}

fn parse_hex_usize(s: &str) -> Result<usize, String> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    usize::from_str_radix(s, 16).map_err(|e| e.to_string())
}

fn parse_hex_u64(s: &str) -> Result<u64, String> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    u64::from_str_radix(s, 16).map_err(|e| e.to_string())
}

fn parse_hex_i64(s: &str) -> Result<i64, String> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    i64::from_str_radix(s, 16).map_err(|e| e.to_string())
}

#[derive(Debug)]
struct SourceLocation {
    file: String,
    line: u64,
    column: u64,
}

impl Debugger {
    pub fn new(process: Pid, program_path: String) -> anyhow::Result<Self> {
        let (dwarf, elf_data) = Self::load_debug_info(&program_path)?;
        Ok(Self {
            process,
            breakpoints: HashMap::new(),
            dwarf,
            load_address: 0, // Will be updated after exec
            _elf_data: elf_data,
        })
    }

    fn update_load_address(&mut self) -> anyhow::Result<()> {
        let maps = fs::read_to_string(format!("/proc/{}/maps", self.process.as_raw()))?;
        if let Some(line) = maps.lines().next() {
            let addr_str = line.split('-').next().context("failed to parse maps")?;
            self.load_address = usize::from_str_radix(addr_str, 16)?;
            info!("updated load address to 0x{:x}", self.load_address);
        }
        Ok(())
    }

    fn load_debug_info(
        path: &str,
    ) -> anyhow::Result<(Option<Dwarf<EndianSlice<'static, RunTimeEndian>>>, Vec<u8>)> {
        let path = PathBuf::from(path);
        let data = fs::read(&path).context(format!("failed to read ELF file at {:?}", path))?;

        // 尝试从 ELF 本身加载
        if let Ok((dwarf, data)) = Self::parse_dwarf(data) {
            if dwarf.units().count() > 0 {
                return Ok((Some(dwarf), data));
            }
        }

        // 检查分离的调试信息文件 (e.g., .debug)
        let mut debug_path = path.clone();
        debug_path.set_extension("debug");
        if debug_path.exists() {
            info!("found split debug info at {:?}", debug_path);
            let data = fs::read(&debug_path)?;
            if let Ok((dwarf, data)) = Self::parse_dwarf(data) {
                return Ok((Some(dwarf), data));
            }
        }

        // 检查 /usr/lib/debug/ 路径 (简化版)
        let mut system_debug_path = PathBuf::from("/usr/lib/debug");
        if let Some(abs_path) = path.canonicalize().ok() {
            system_debug_path.push(abs_path.strip_prefix("/").unwrap_or(&abs_path));
            if system_debug_path.exists() {
                info!("found system debug info at {:?}", system_debug_path);
                let data = fs::read(&system_debug_path)?;
                if let Ok((dwarf, data)) = Self::parse_dwarf(data) {
                    return Ok((Some(dwarf), data));
                }
            }
        }

        info!("no debug info found for {:?}", path);
        Ok((None, Vec::new()))
    }

    fn parse_dwarf(
        data: Vec<u8>,
    ) -> anyhow::Result<(Dwarf<EndianSlice<'static, RunTimeEndian>>, Vec<u8>)> {
        let data = Box::leak(data.into_boxed_slice());
        let obj = object::File::parse(&*data).context("failed to parse ELF")?;
        let endian = if obj.is_little_endian() {
            RunTimeEndian::Little
        } else {
            RunTimeEndian::Big
        };

        let load_section =
            |id: gimli::SectionId| -> anyhow::Result<EndianSlice<'static, RunTimeEndian>> {
                let data = obj
                    .section_by_name(id.name())
                    .and_then(|section| section.uncompressed_data().ok())
                    .unwrap_or_else(|| std::borrow::Cow::Borrowed(&[]));
                let leaked_data = Box::leak(data.into_owned().into_boxed_slice());
                Ok(EndianSlice::new(leaked_data, endian))
            };

        let dwarf = Dwarf::load(&load_section)?;
        Ok((dwarf, Vec::new())) // Since we leak, Vec is empty
    }

    pub fn run(&mut self) -> anyhow::Result<()> {
        let pid = self.process;
        info!("Started debugging process: {}", pid);
        let mut rl = DefaultEditor::new()?;
        let path = ".rgdb_history";
        rl.set_helper(Some(()));
        rl.load_history(path).ok();
        // wait for trap, caused by traceme
        let status = self.wait4()?;
        self.handle_wait_status(status)?;

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
                            SubCommands::Break { location } => self.handle_break_cmd(&location)?,
                            SubCommands::Register { cmd } => self.handle_register_cmd(cmd)?,
                            SubCommands::Memory { cmd } => self.handle_memory_cmd(cmd)?,
                            SubCommands::StepInstruction => self.step_instruction()?,
                            SubCommands::Step => self.step_source()?,
                            SubCommands::Next => self.next_source()?,
                            SubCommands::Finish => self.finish()?,
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

    fn cont(&mut self) -> anyhow::Result<()> {
        info!("continue");
        let pc = self.get_pc()?;
        // Check if we are at a breakpoint (on x86_64, RIP is PC+1 after trap)
        #[cfg(target_arch = "x86_64")]
        let breakpoint_addr = (pc - 1) as usize;
        #[cfg(target_arch = "aarch64")]
        let breakpoint_addr = pc as usize;

        if self.breakpoints.contains_key(&breakpoint_addr) {
            info!("stepping over breakpoint at 0x{:x}", breakpoint_addr);
            // 1. Roll back PC if needed (only for x86_64)
            #[cfg(target_arch = "x86_64")]
            self.set_pc(breakpoint_addr as u64)?;

            // 2. Remove breakpoint temporarily
            let original_data = self.breakpoints[&breakpoint_addr];
            ptrace::write(self.process, breakpoint_addr as _, original_data as _)
                .context("failed to restore original instruction")?;

            // 3. Single step
            ptrace::step(self.process, None).context("failed to step")?;
            self.wait4()?;

            // 4. Re-insert breakpoint
            self.set_breakpoint(breakpoint_addr)?;
        }

        ptrace::cont(self.process, None).context("failed to continue process")?;
        let res = self.wait4()?;
        self.handle_wait_status(res)?;
        Ok(())
    }

    fn handle_wait_status(&mut self, status: WaitStatus) -> anyhow::Result<()> {
        if let Err(e) = self.update_load_address() {
            error!("failed to update load address: {}", e);
        }
        match status {
            WaitStatus::Stopped(_, sig) => {
                let pc = self.get_pc()?;
                // On x86_64, after a breakpoint trap, RIP is at address + 1
                #[cfg(target_arch = "x86_64")]
                let lookup_addr = if sig == signal::Signal::SIGTRAP {
                    pc - 1
                } else {
                    pc
                };
                #[cfg(target_arch = "aarch64")]
                let lookup_addr = pc;

                let mut output = format!("Stopped by signal {:?} at 0x{:x}", sig, pc);
                if let Ok(Some(loc)) = self.lookup_source_location(lookup_addr) {
                    output.push_str(&format!(" [{}:{}:{}]", loc.file, loc.line, loc.column));
                    info!("{}", output);
                    let _ = self.display_source(&loc.file, loc.line, 3);
                } else {
                    info!("{}", output);
                }
            }
            WaitStatus::Exited(_, code) => {
                info!("Process exited with code {}", code);
            }
            WaitStatus::Signaled(_, sig, _) => {
                info!("Process killed by signal {:?}", sig);
            }
            _ => info!("process received status {:?}", status),
        }
        Ok(())
    }

    fn finish(&mut self) -> anyhow::Result<()> {
        let pc = self.get_pc()?;
        #[cfg(target_arch = "x86_64")]
        {
            let regs = ptrace::getregs(self.process)?;
            let ret_addr = ptrace::read(self.process, regs.rsp as _)? as u64;
            info!(
                "setting temporary breakpoint at return address 0x{:x}",
                ret_addr
            );
            self.set_breakpoint(ret_addr as usize)?;
            self.cont()?;
            // TODO: remove temporary breakpoint
        }
        #[cfg(target_arch = "aarch64")]
        {
            let regs = ptrace::getregs(self.process)?;
            let ret_addr = regs.x[30]; // LR
            info!(
                "setting temporary breakpoint at return address 0x{:x}",
                ret_addr
            );
            self.set_breakpoint(ret_addr as usize)?;
            self.cont()?;
        }
        Ok(())
    }

    fn step_source(&mut self) -> anyhow::Result<()> {
        let pc = self.get_pc()?;
        let start_loc = self.lookup_source_location(pc)?;

        loop {
            self.step_instruction()?;
            let new_pc = self.get_pc()?;
            let new_loc = self.lookup_source_location(new_pc)?;

            match (&start_loc, &new_loc) {
                (Some(s), Some(n)) if s.file == n.file && s.line == n.line => continue,
                _ => break,
            }
        }
        Ok(())
    }

    fn next_source(&mut self) -> anyhow::Result<()> {
        // Simplified next: just step for now, properly implementing this requires
        // either an instruction decoder or a deeper understanding of the line table.
        self.step_source()
    }

    fn step_instruction(&mut self) -> anyhow::Result<()> {
        let pc = self.get_pc()?;
        #[cfg(target_arch = "x86_64")]
        let breakpoint_addr = (pc - 1) as usize;
        #[cfg(target_arch = "aarch64")]
        let breakpoint_addr = pc as usize;

        if self.breakpoints.contains_key(&breakpoint_addr) {
            info!("stepping over breakpoint at 0x{:x}", breakpoint_addr);
            #[cfg(target_arch = "x86_64")]
            self.set_pc(breakpoint_addr as u64)?;

            let original_data = self.breakpoints[&breakpoint_addr];
            ptrace::write(self.process, breakpoint_addr as _, original_data as _)?;

            ptrace::step(self.process, None)?;
            self.wait4()?;

            self.set_breakpoint(breakpoint_addr)?;
            // We already did one step, so we are done with si
            let status = self.wait4_no_log()?; // Consume the stop from step if any? No, ptrace::step already stopped.
        // Wait, ptrace::step already results in a SIGTRAP.
        } else {
            ptrace::step(self.process, None)?;
            let status = self.wait4()?;
            self.handle_wait_status(status)?;
        }
        Ok(())
    }

    fn wait4(&self) -> anyhow::Result<WaitStatus> {
        info!("wait");
        waitpid(self.process, None).context("failed to wait")
    }

    fn wait4_no_log(&self) -> anyhow::Result<WaitStatus> {
        waitpid(self.process, None).context("failed to wait")
    }

    fn set_breakpoint(&mut self, address: usize) -> anyhow::Result<()> {
        info!("setting breakpoint at 0x{:x}", address);
        let data = ptrace::read(self.process, address as _).context("failed to read memory")?;
        self.breakpoints.insert(address, data);

        #[cfg(target_arch = "x86_64")]
        let trap_data = (data & !0xFF) | 0xCC;

        #[cfg(target_arch = "aarch64")]
        let trap_data = (data & !0xFFFFFFFF) | 0xd4200000;

        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        compile_error!("Unsupported architecture");

        ptrace::write(self.process, address as _, trap_data as _)
            .context("failed to write trap instruction")?;
        Ok(())
    }

    fn lookup_source_location(&self, addr: u64) -> anyhow::Result<Option<SourceLocation>> {
        let dwarf = match &self.dwarf {
            Some(d) => d,
            None => return Ok(None),
        };

        // For PIE, we need to subtract the load address to get the offset
        // For non-PIE, load_address should be what's in the ELF header, but usually 0 is fine if we use offsets.
        // Actually, let's just try both absolute and relative if needed, but better to be precise.
        let offset = if addr >= self.load_address as u64 {
            addr - self.load_address as u64
        } else {
            addr
        };
        info!(
            "looking up source location for addr 0x{:x} (offset 0x{:x}, load_address 0x{:x})",
            addr, offset, self.load_address
        );

        let mut iter = dwarf.units();
        while let Some(header) = iter.next()? {
            let unit = dwarf.unit(header)?;
            if let Some(ref line_program) = unit.line_program {
                let mut rows = line_program.clone().rows();
                while let Some((_, row)) = rows.next_row()? {
                    // Check both absolute and relative
                    if row.address() == offset || row.address() == addr {
                        let file_index = row.file_index();
                        let file = line_program
                            .header()
                            .file(file_index)
                            .and_then(|f| {
                                let mut path = PathBuf::new();
                                if let Some(dir) = f.directory(line_program.header()) {
                                    if let Ok(dir_str) = dwarf.attr_string(&unit, dir) {
                                        path.push(dir_str.to_string_lossy().into_owned());
                                    }
                                }
                                if let Ok(name) = dwarf.attr_string(&unit, f.path_name()) {
                                    path.push(name.to_string_lossy().into_owned());
                                }
                                Some(path.to_string_lossy().into_owned())
                            })
                            .unwrap_or_else(|| "unknown".into());

                        return Ok(Some(SourceLocation {
                            file,
                            line: row.line().map(|l| l.get()).unwrap_or(0),
                            column: match row.column() {
                                gimli::ColumnType::Column(c) => c.get(),
                                gimli::ColumnType::LeftEdge => 0,
                            },
                        }));
                    }
                }
            }
        }
        Ok(None)
    }

    fn display_source(&self, file_path: &str, line: u64, context_lines: u64) -> anyhow::Result<()> {
        let file = match fs::read_to_string(file_path) {
            Ok(f) => f,
            Err(_) => {
                // Try relative path from current directory
                let mut rel_path = PathBuf::from(".");
                rel_path.push(file_path);
                fs::read_to_string(rel_path)
                    .context(format!("failed to read source file {}", file_path))?
            }
        };

        let start_line = if line > context_lines {
            line - context_lines
        } else {
            1
        };
        let end_line = line + context_lines;

        for (idx, content) in file.lines().enumerate() {
            let current_line = (idx + 1) as u64;
            if current_line >= start_line && current_line <= end_line {
                let prefix = if current_line == line { "=> " } else { "   " };
                println!("{}{:4} {}", prefix, current_line, content);
            }
        }
        Ok(())
    }

    fn handle_break_cmd(&mut self, location: &str) -> anyhow::Result<()> {
        if let Ok(addr) = parse_hex_usize(location) {
            self.set_breakpoint(addr)?;
        } else if location.contains(':') {
            let parts: Vec<&str> = location.split(':').collect();
            if parts.len() == 2 {
                let file = parts[0];
                if let Ok(line) = parts[1].parse::<u64>() {
                    if let Some(addr) = self.lookup_line_address(file, line)? {
                        self.set_breakpoint(addr as usize)?;
                    } else {
                        error!("could not find address for {}:{}", file, line);
                    }
                }
            }
        } else {
            if let Some(addr) = self.lookup_function_address(location)? {
                self.set_breakpoint(addr as usize)?;
            } else {
                error!("could not find function {}", location);
            }
        }
        Ok(())
    }

    fn lookup_function_address(&self, name: &str) -> anyhow::Result<Option<u64>> {
        let dwarf = match &self.dwarf {
            Some(d) => d,
            None => return Ok(None),
        };

        let mut iter = dwarf.units();
        while let Some(header) = iter.next()? {
            let unit = dwarf.unit(header)?;
            let mut entries = unit.entries();
            while let Some((_, entry)) = entries.next_dfs()? {
                if entry.tag() == gimli::DW_TAG_subprogram {
                    if let Some(attr) = entry.attr_value(gimli::DW_AT_name)? {
                        if let Ok(attr_name) = dwarf.attr_string(&unit, attr) {
                            if attr_name.to_string_lossy() == name {
                                if let Some(attr_low_pc) = entry.attr_value(gimli::DW_AT_low_pc)? {
                                    if let gimli::AttributeValue::Addr(addr) = attr_low_pc {
                                        return Ok(Some(addr + self.load_address as u64));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        Ok(None)
    }

    fn lookup_line_address(&self, file: &str, line: u64) -> anyhow::Result<Option<u64>> {
        let dwarf = match &self.dwarf {
            Some(d) => d,
            None => return Ok(None),
        };

        let mut iter = dwarf.units();
        while let Some(header) = iter.next()? {
            let unit = dwarf.unit(header)?;
            if let Some(ref line_program) = unit.line_program {
                let mut rows = line_program.clone().rows();
                while let Some((_, row)) = rows.next_row()? {
                    if let Some(row_line) = row.line() {
                        if row_line.get() == line {
                            if let Some(file_index) = row.file_index() {
                                if let Some(f) = line_program.header().file(file_index) {
                                    if let Ok(name) = dwarf.attr_string(&unit, f.path_name()) {
                                        if name.to_string_lossy().ends_with(file) {
                                            return Ok(Some(
                                                row.address() + self.load_address as u64,
                                            ));
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        Ok(None)
    }

    fn lookup_symbol(&self, _name: &str) -> anyhow::Result<Option<u64>> {
        // ELF symbol table lookup can be added here
        // For now, focus on DWARF source mapping
        Ok(None)
    }

    fn get_pc(&self) -> anyhow::Result<u64> {
        #[cfg(target_arch = "x86_64")]
        {
            let regs = ptrace::getregs(self.process)?;
            Ok(regs.rip)
        }
        #[cfg(target_arch = "aarch64")]
        {
            let mut regs = ptrace::getregs(self.process)?;
            Ok(regs.pc)
        }
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        compile_error!("Unsupported architecture");
    }

    fn set_pc(&self, pc: u64) -> anyhow::Result<()> {
        #[cfg(target_arch = "x86_64")]
        {
            let mut regs = ptrace::getregs(self.process)?;
            regs.rip = pc;
            ptrace::setregs(self.process, regs)?;
            Ok(())
        }
        #[cfg(target_arch = "aarch64")]
        {
            let mut regs = ptrace::getregs(self.process)?;
            regs.pc = pc;
            ptrace::setregs(self.process, regs)?;
            Ok(())
        }
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        compile_error!("Unsupported architecture");
    }

    fn handle_register_cmd(&self, cmd: RegisterCommand) -> anyhow::Result<()> {
        match cmd {
            RegisterCommand::Read { reg } => {
                let val = self.get_register_value(&reg)?;
                println!("{}: 0x{:x}", reg, val);
            }
            RegisterCommand::Write { reg, value } => {
                self.set_register_value(&reg, value)?;
                println!("Set {} to 0x{:x}", reg, value);
            }
            RegisterCommand::Dump => {
                self.dump_registers()?;
            }
        }
        Ok(())
    }

    fn handle_memory_cmd(&self, cmd: MemoryCommand) -> anyhow::Result<()> {
        match cmd {
            MemoryCommand::Read { address } => {
                let val = ptrace::read(self.process, address as _)?;
                println!("0x{:x}: 0x{:x}", address, val);
            }
            MemoryCommand::Write { address, value } => {
                ptrace::write(self.process, address as _, value as _)?;
                println!("Wrote 0x{:x} to 0x{:x}", value, address);
            }
        }
        Ok(())
    }

    #[cfg(target_arch = "x86_64")]
    fn get_register_value(&self, reg_name: &str) -> anyhow::Result<u64> {
        let regs = ptrace::getregs(self.process)?;
        match reg_name.to_lowercase().as_str() {
            "rax" => Ok(regs.rax),
            "rbx" => Ok(regs.rbx),
            "rcx" => Ok(regs.rcx),
            "rdx" => Ok(regs.rdx),
            "rdi" => Ok(regs.rdi),
            "rsi" => Ok(regs.rsi),
            "rbp" => Ok(regs.rbp),
            "rsp" => Ok(regs.rsp),
            "r8" => Ok(regs.r8),
            "r9" => Ok(regs.r9),
            "r10" => Ok(regs.r10),
            "r11" => Ok(regs.r11),
            "r12" => Ok(regs.r12),
            "r13" => Ok(regs.r13),
            "r14" => Ok(regs.r14),
            "r15" => Ok(regs.r15),
            "rip" => Ok(regs.rip),
            "eflags" | "rflags" => Ok(regs.eflags),
            _ => Err(anyhow::anyhow!("Unknown register: {}", reg_name)),
        }
    }

    #[cfg(target_arch = "x86_64")]
    fn set_register_value(&self, reg_name: &str, value: u64) -> anyhow::Result<()> {
        let mut regs = ptrace::getregs(self.process)?;
        match reg_name.to_lowercase().as_str() {
            "rax" => regs.rax = value,
            "rbx" => regs.rbx = value,
            "rcx" => regs.rcx = value,
            "rdx" => regs.rdx = value,
            "rdi" => regs.rdi = value,
            "rsi" => regs.rsi = value,
            "rbp" => regs.rbp = value,
            "rsp" => regs.rsp = value,
            "r8" => regs.r8 = value,
            "r9" => regs.r9 = value,
            "r10" => regs.r10 = value,
            "r11" => regs.r11 = value,
            "r12" => regs.r12 = value,
            "r13" => regs.r13 = value,
            "r14" => regs.r14 = value,
            "r15" => regs.r15 = value,
            "rip" => regs.rip = value,
            "eflags" | "rflags" => regs.eflags = value,
            _ => return Err(anyhow::anyhow!("Unknown register: {}", reg_name)),
        }
        ptrace::setregs(self.process, regs)?;
        Ok(())
    }

    #[cfg(target_arch = "x86_64")]
    fn dump_registers(&self) -> anyhow::Result<()> {
        let regs = ptrace::getregs(self.process)?;
        println!(
            "rax: 0x{:016x} rbx: 0x{:016x} rcx: 0x{:016x}",
            regs.rax, regs.rbx, regs.rcx
        );
        println!(
            "rdx: 0x{:016x} rsi: 0x{:016x} rdi: 0x{:016x}",
            regs.rdx, regs.rsi, regs.rdi
        );
        println!(
            "rbp: 0x{:016x} rsp: 0x{:016x} r8:  0x{:016x}",
            regs.rbp, regs.rsp, regs.r8
        );
        println!(
            "r9:  0x{:016x} r10: 0x{:016x} r11: 0x{:016x}",
            regs.r9, regs.r10, regs.r11
        );
        println!(
            "r12: 0x{:016x} r13: 0x{:016x} r14: 0x{:016x}",
            regs.r12, regs.r13, regs.r14
        );
        println!(
            "r15: 0x{:016x} rip: 0x{:016x} eflags: 0x{:08x}",
            regs.r15, regs.rip, regs.eflags
        );
        Ok(())
    }

    // AArch64 placeholders
    #[cfg(target_arch = "aarch64")]
    fn get_register_value(&self, _reg_name: &str) -> anyhow::Result<u64> {
        todo!("get_register_value for aarch64")
    }
    #[cfg(target_arch = "aarch64")]
    fn set_register_value(&self, _reg_name: &str, _value: u64) -> anyhow::Result<()> {
        todo!("set_register_value for aarch64")
    }
    #[cfg(target_arch = "aarch64")]
    fn dump_registers(&self) -> anyhow::Result<()> {
        todo!("dump_registers for aarch64")
    }
}

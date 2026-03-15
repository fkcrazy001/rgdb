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
use object::{Object, ObjectSection, ObjectSymbol};
use rustyline::DefaultEditor;

pub struct Debugger {
    process: Pid,
    breakpoints: HashMap<usize, Breakpoint>,
    dwarf: Option<Dwarf<EndianSlice<'static, RunTimeEndian>>>,
    load_address: usize,
    is_pie: bool,
    symbols: HashMap<String, u64>,
    inferior_exited: bool,
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
    #[command(alias = "bt")]
    Backtrace,
    #[command(alias = "p")]
    Print { name: String },
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

#[derive(Clone, Copy, Debug)]
struct BreakpointPatch {
    base: usize,
    mask: u64,
    orig: u64,
    trap: u64,
}

#[derive(Clone, Copy, Debug)]
struct Breakpoint {
    patch: BreakpointPatch,
    temporary: bool,
}

impl Debugger {
    fn base_address(&self) -> u64 {
        if self.is_pie {
            self.load_address as u64
        } else {
            0
        }
    }

    fn runtime_to_offset(&self, addr: u64) -> u64 {
        let base = self.base_address();
        if self.is_pie && addr >= base {
            addr - base
        } else {
            addr
        }
    }

    fn offset_to_runtime(&self, offset: u64) -> u64 {
        offset + self.base_address()
    }

    pub fn new(process: Pid, program_path: String) -> anyhow::Result<Self> {
        let dwarf = Self::load_debug_info(&program_path)?;
        let symbols = Self::load_symbols(&program_path)?;
        let is_pie = Self::detect_pie(&program_path)?;
        Ok(Self {
            process,
            breakpoints: HashMap::new(),
            dwarf,
            load_address: 0, // Will be updated after exec
            is_pie,
            symbols,
            inferior_exited: false,
        })
    }

    fn detect_pie(path: &str) -> anyhow::Result<bool> {
        let header =
            fs::read(path).with_context(|| format!("failed to read ELF file at {}", path))?;
        if header.len() < 0x20 {
            return Ok(false);
        }
        if &header[0..4] != b"\x7fELF" {
            return Ok(false);
        }
        let endian = header[5];
        let e_type_bytes = &header[16..18];
        let e_type = match endian {
            1 => u16::from_le_bytes([e_type_bytes[0], e_type_bytes[1]]),
            2 => u16::from_be_bytes([e_type_bytes[0], e_type_bytes[1]]),
            _ => return Ok(false),
        };
        // ET_DYN (3) usually indicates PIE for executables built as position independent
        Ok(e_type == 3)
    }

    fn load_symbols(path: &str) -> anyhow::Result<HashMap<String, u64>> {
        let data = fs::read(path)?;
        let obj = object::File::parse(&*data)?;
        let mut symbols = HashMap::new();
        for symbol in obj.symbols() {
            if let Ok(name) = symbol.name() {
                symbols.insert(name.to_string(), symbol.address());
            }
        }
        Ok(symbols)
    }

    fn update_load_address(&mut self) -> anyhow::Result<()> {
        if !self.is_pie {
            self.load_address = 0;
            return Ok(());
        }
        let maps = fs::read_to_string(format!("/proc/{}/maps", self.process.as_raw()))
            .with_context(|| format!("failed to read /proc/{}/maps", self.process.as_raw()))?;
        if let Some(line) = maps.lines().next() {
            let addr_str = line.split('-').next().context("failed to parse maps")?;
            self.load_address = usize::from_str_radix(addr_str, 16)?;
            info!("updated load address to 0x{:x}", self.load_address);
        }
        Ok(())
    }

    fn load_debug_info(
        path: &str,
    ) -> anyhow::Result<Option<Dwarf<EndianSlice<'static, RunTimeEndian>>>> {
        let path = PathBuf::from(path);
        let data = fs::read(&path).context(format!("failed to read ELF file at {:?}", path))?;

        // 尝试从 ELF 本身加载
        if let Ok(dwarf) = Self::parse_dwarf(data) {
            if dwarf.units().count() > 0 {
                return Ok(Some(dwarf));
            }
        }

        // 检查分离的调试信息文件 (e.g., .debug)
        let mut debug_path = path.clone();
        debug_path.set_extension("debug");
        if debug_path.exists() {
            info!("found split debug info at {:?}", debug_path);
            let data = fs::read(&debug_path)?;
            if let Ok(dwarf) = Self::parse_dwarf(data) {
                return Ok(Some(dwarf));
            }
        }

        // 检查 /usr/lib/debug/ 路径 (简化版)
        let mut system_debug_path = PathBuf::from("/usr/lib/debug");
        if let Some(abs_path) = path.canonicalize().ok() {
            system_debug_path.push(abs_path.strip_prefix("/").unwrap_or(&abs_path));
            if system_debug_path.exists() {
                info!("found system debug info at {:?}", system_debug_path);
                let data = fs::read(&system_debug_path)?;
                if let Ok(dwarf) = Self::parse_dwarf(data) {
                    return Ok(Some(dwarf));
                }
            }
        }

        info!("no debug info found for {:?}", path);
        Ok(None)
    }

    fn parse_dwarf(data: Vec<u8>) -> anyhow::Result<Dwarf<EndianSlice<'static, RunTimeEndian>>> {
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
        Ok(dwarf)
    }

    pub fn run(&mut self) -> anyhow::Result<()> {
        let pid = self.process;
        info!("Started debugging process: {}", pid);
        let mut rl = DefaultEditor::new()?;
        let path = ".rgdb_history";
        rl.load_history(path).ok();
        // wait for trap, caused by traceme
        let status = self.wait4()?;
        self.handle_wait_status(status)?;
        if self.inferior_exited {
            return Ok(());
        }

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
                            SubCommands::Backtrace => self.backtrace()?,
                            SubCommands::Print { name } => self.print_variable(&name)?,
                        },
                        Err(e) => {
                            error!("cmd parse failed, {e}");
                            // eprintln!("cmd parse failed, {e}")
                        }
                    }
                    if self.inferior_exited {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        let _ = rl.save_history(path);
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

            self.disable_breakpoint(breakpoint_addr)?;

            // 3. Single step
            ptrace::step(self.process, None).context("failed to step")?;
            self.wait4()?;

            if self
                .breakpoints
                .get(&breakpoint_addr)
                .is_some_and(|bp| bp.temporary)
            {
                self.breakpoints.remove(&breakpoint_addr);
            } else {
                self.enable_breakpoint(breakpoint_addr)?;
            }
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
                self.inferior_exited = true;
            }
            WaitStatus::Signaled(_, sig, _) => {
                info!("Process killed by signal {:?}", sig);
                self.inferior_exited = true;
            }
            _ => info!("process received status {:?}", status),
        }
        Ok(())
    }

    fn print_variable(&self, name: &str) -> anyhow::Result<()> {
        let pc = self.get_pc()?;
        let offset = self.runtime_to_offset(pc);

        let dwarf = match &self.dwarf {
            Some(d) => d,
            None => {
                error!("no debug info");
                return Ok(());
            }
        };

        let mut iter = dwarf.units();
        while let Some(header) = iter.next()? {
            let unit = dwarf.unit(header)?;
            let mut entries = unit.entries();
            let mut current_subprogram = None;

            while let Some(entry) = entries.next_dfs()? {
                if entry.tag() == gimli::DW_TAG_subprogram {
                    let mut low_pc = 0;
                    let mut high_pc = 0;
                    for attr in entry.attrs() {
                        match attr.name() {
                            gimli::DW_AT_low_pc => {
                                if let gimli::AttributeValue::Addr(addr) = attr.value() {
                                    low_pc = addr;
                                }
                            }
                            gimli::DW_AT_high_pc => match attr.value() {
                                gimli::AttributeValue::Udata(size) => high_pc = low_pc + size,
                                gimli::AttributeValue::Addr(addr) => high_pc = addr,
                                _ => {}
                            },
                            _ => {}
                        }
                    }

                    if offset >= low_pc && offset < high_pc {
                        current_subprogram = Some(entry.offset());
                    }
                }

                if let Some(_sub_offset) = current_subprogram {
                    if entry.tag() == gimli::DW_TAG_variable
                        || entry.tag() == gimli::DW_TAG_formal_parameter
                    {
                        let mut name_match = false;
                        let mut location = None;
                        let mut ty = None;

                        for attr in entry.attrs() {
                            match attr.name() {
                                gimli::DW_AT_name => {
                                    if let Ok(attr_name) = dwarf.attr_string(&unit, attr.value()) {
                                        if attr_name.to_string_lossy() == name {
                                            name_match = true;
                                        }
                                    }
                                }
                                gimli::DW_AT_location => {
                                    location = attr.value().exprloc_value();
                                }
                                gimli::DW_AT_type => {
                                    if let gimli::AttributeValue::UnitRef(o) = attr.value() {
                                        ty = Some(o);
                                    }
                                }
                                _ => {}
                            }
                        }

                        if name_match {
                            if let Some(expr) = location {
                                let expr: gimli::Expression<EndianSlice<RunTimeEndian>> = expr;
                                let size = ty
                                    .and_then(|t| self.resolve_type_size(&unit, t).ok().flatten())
                                    .unwrap_or(8);
                                self.evaluate_location_expr(&unit, expr, size)?;
                                return Ok(());
                            }
                        }
                    }
                }
            }
        }
        error!("variable {} not found in current scope", name);
        Ok(())
    }

    fn evaluate_location_expr(
        &self,
        unit: &gimli::Unit<EndianSlice<RunTimeEndian>, usize>,
        expr: gimli::Expression<EndianSlice<RunTimeEndian>>,
        size: u64,
    ) -> anyhow::Result<()> {
        let mut ops = expr.operations(unit.encoding());
        let op = match ops.next()? {
            Some(o) => o,
            None => {
                error!("empty location expression");
                return Ok(());
            }
        };

        match op {
            gimli::Operation::FrameOffset { offset } => {
                let cfa = self.get_cfa()?;
                let addr = (cfa as i64).wrapping_add(offset) as u64;
                let bytes = self.read_memory_bytes(addr, size as usize)?;
                println!("{}", self.format_scalar(&bytes));
            }
            gimli::Operation::Register { register } => {
                let val = self.get_register_value_by_number(register.0)?;
                println!("0x{:x}", val);
            }
            gimli::Operation::Address { address } => {
                let bytes = self.read_memory_bytes(address, size as usize)?;
                println!("{}", self.format_scalar(&bytes));
            }
            _ => {
                error!("unsupported variable location");
            }
        }
        Ok(())
    }

    fn resolve_type_size(
        &self,
        unit: &gimli::Unit<EndianSlice<RunTimeEndian>, usize>,
        mut ty: gimli::UnitOffset<usize>,
    ) -> anyhow::Result<Option<u64>> {
        for _ in 0..16 {
            let mut entries = unit.entries();
            while let Some(entry) = entries.next_dfs()? {
                if entry.offset() != ty {
                    continue;
                }

                if let Some(gimli::AttributeValue::Udata(size)) =
                    entry.attr_value(gimli::DW_AT_byte_size)
                {
                    return Ok(Some(size));
                }
                if let Some(next) = entry.attr_value(gimli::DW_AT_type) {
                    if let gimli::AttributeValue::UnitRef(o) = next {
                        ty = o;
                        break;
                    }
                    return Ok(None);
                }
                return Ok(None);
            }
        }
        Ok(None)
    }

    fn get_cfa(&self) -> anyhow::Result<u64> {
        #[cfg(target_arch = "x86_64")]
        {
            let regs = ptrace::getregs(self.process)?;
            Ok(regs.rbp.wrapping_add(16))
        }
        #[cfg(target_arch = "aarch64")]
        {
            let regs = ptrace::getregs(self.process)?;
            Ok(regs.x[29].wrapping_add(16))
        }
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        compile_error!("Unsupported architecture");
    }

    fn read_memory_bytes(&self, address: u64, size: usize) -> anyhow::Result<Vec<u8>> {
        let mut out = vec![0u8; size];
        let mut i = 0usize;
        while i < size {
            let word = ptrace::read(self.process, (address as usize + i) as _)? as u64;
            let bytes = word.to_ne_bytes();
            let take = (size - i).min(bytes.len());
            out[i..i + take].copy_from_slice(&bytes[..take]);
            i += take;
        }
        Ok(out)
    }

    fn format_scalar(&self, bytes: &[u8]) -> String {
        match bytes.len() {
            1 => format!("0x{:x}", bytes[0]),
            2 => format!("0x{:x}", u16::from_ne_bytes([bytes[0], bytes[1]])),
            4 => format!(
                "0x{:x}",
                u32::from_ne_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
            ),
            _ => {
                let mut buf = [0u8; 8];
                let take = bytes.len().min(8);
                buf[..take].copy_from_slice(&bytes[..take]);
                format!("0x{:x}", u64::from_ne_bytes(buf))
            }
        }
    }

    fn get_register_value_by_number(&self, reg_num: u16) -> anyhow::Result<u64> {
        #[cfg(target_arch = "x86_64")]
        {
            let regs = ptrace::getregs(self.process)?;
            // DWARF register numbers for x86_64: rax=0, rdx=1, rcx=2, rbx=3, rsp=7, rbp=6, etc.
            match reg_num {
                0 => Ok(regs.rax),
                1 => Ok(regs.rdx),
                2 => Ok(regs.rcx),
                3 => Ok(regs.rbx),
                4 => Ok(regs.rsi),
                5 => Ok(regs.rdi),
                6 => Ok(regs.rbp),
                7 => Ok(regs.rsp),
                8 => Ok(regs.r8),
                9 => Ok(regs.r9),
                10 => Ok(regs.r10),
                11 => Ok(regs.r11),
                12 => Ok(regs.r12),
                13 => Ok(regs.r13),
                14 => Ok(regs.r14),
                15 => Ok(regs.r15),
                16 => Ok(regs.rip),
                _ => Err(anyhow::anyhow!("unsupported register number {}", reg_num)),
            }
        }
        #[cfg(target_arch = "aarch64")]
        {
            let regs = ptrace::getregs(self.process)?;
            if reg_num < 31 {
                Ok(regs.x[reg_num as usize])
            } else if reg_num == 31 {
                Ok(regs.sp)
            } else if reg_num == 32 {
                Ok(regs.pc)
            } else {
                Err(anyhow::anyhow!("unsupported register number {}", reg_num))
            }
        }
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        compile_error!("Unsupported architecture");
    }

    fn backtrace(&self) -> anyhow::Result<()> {
        let mut pc = self.get_pc()?;
        #[cfg(target_arch = "x86_64")]
        {
            let bp = pc.saturating_sub(1) as usize;
            if self.breakpoints.contains_key(&bp) {
                pc = pc.saturating_sub(1);
            }
        }
        #[cfg(target_arch = "x86_64")]
        let mut fp = ptrace::getregs(self.process)?.rbp;
        #[cfg(target_arch = "aarch64")]
        let mut fp = ptrace::getregs(self.process)?.x[29];

        let mut frame_num = 0;
        loop {
            let mut func_info = String::new();
            if let Ok(Some((name, start))) = self.lookup_function_name(pc) {
                let delta = pc.saturating_sub(start);
                func_info = format!(" in {}+0x{:x}", name, delta);
            }

            let mut line_info = String::new();
            if let Ok(Some(loc)) = self.lookup_source_location(pc) {
                line_info = format!(" at {}:{}:{}", loc.file, loc.line, loc.column);
            }
            println!("#{} 0x{:016x}{}{}", frame_num, pc, func_info, line_info);

            if fp == 0 {
                break;
            }

            // Follow frame pointer
            match ptrace::read(self.process, (fp + 8) as _) {
                Ok(ret_addr) => pc = ret_addr as u64,
                Err(_) => break,
            }
            match ptrace::read(self.process, fp as _) {
                Ok(next_fp) => fp = next_fp as u64,
                Err(_) => break,
            }

            frame_num += 1;
            if frame_num > 50 {
                break;
            }
        }
        Ok(())
    }

    fn lookup_function_name(&self, addr: u64) -> anyhow::Result<Option<(String, u64)>> {
        let dwarf = match &self.dwarf {
            Some(d) => d,
            None => return Ok(None),
        };

        let base = self.base_address();
        let offset = self.runtime_to_offset(addr);

        let mut iter = dwarf.units();
        while let Some(header) = iter.next()? {
            let unit = dwarf.unit(header)?;
            let mut entries = unit.entries();
            while let Some(entry) = entries.next_dfs()? {
                if entry.tag() != gimli::DW_TAG_subprogram {
                    continue;
                }
                let mut low_pc = None;
                let mut high_pc = None;
                let mut name = None;
                for attr in entry.attrs() {
                    match attr.name() {
                        gimli::DW_AT_low_pc => {
                            if let gimli::AttributeValue::Addr(a) = attr.value() {
                                low_pc = Some(a);
                            }
                        }
                        gimli::DW_AT_high_pc => match attr.value() {
                            gimli::AttributeValue::Udata(size) => {
                                if let Some(low) = low_pc {
                                    high_pc = Some(low + size);
                                }
                            }
                            gimli::AttributeValue::Addr(a) => {
                                high_pc = Some(a);
                            }
                            _ => {}
                        },
                        gimli::DW_AT_name => {
                            if let Ok(s) = dwarf.attr_string(&unit, attr.value()) {
                                name = Some(s.to_string_lossy().into_owned());
                            }
                        }
                        _ => {}
                    }
                }
                let (Some(low), Some(high), Some(n)) = (low_pc, high_pc, name) else {
                    continue;
                };
                if offset >= low && offset < high {
                    return Ok(Some((n, low + base)));
                }
            }
        }

        let max_sym = self.symbols.values().copied().max().unwrap_or(0);
        if max_sym > 0 && offset > max_sym.saturating_add(0x10000) {
            return Ok(None);
        }

        let mut best: Option<(String, u64)> = None;
        for (n, sym_addr) in &self.symbols {
            if *sym_addr <= offset {
                best = match best {
                    Some((_, baddr)) if baddr >= *sym_addr => Some((n.clone(), baddr)),
                    _ => Some((n.clone(), *sym_addr)),
                };
            }
        }
        Ok(best.map(|(n, a)| (n, a + base)))
    }

    fn finish(&mut self) -> anyhow::Result<()> {
        let _pc = self.get_pc()?;
        #[cfg(target_arch = "x86_64")]
        {
            let regs = ptrace::getregs(self.process)?;
            let ret_addr = ptrace::read(self.process, regs.rsp as _)? as u64;
            info!(
                "setting temporary breakpoint at return address 0x{:x}",
                ret_addr
            );
            self.set_temp_breakpoint(ret_addr as usize)?;
            self.cont()?;
        }
        #[cfg(target_arch = "aarch64")]
        {
            let regs = ptrace::getregs(self.process)?;
            let ret_addr = regs.x[30]; // LR
            info!(
                "setting temporary breakpoint at return address 0x{:x}",
                ret_addr
            );
            self.set_temp_breakpoint(ret_addr as usize)?;
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
        let pc = self.get_pc()?;
        #[cfg(target_arch = "x86_64")]
        let lookup_pc = pc
            .checked_sub(1)
            .filter(|p| self.breakpoints.contains_key(&(*p as usize)))
            .unwrap_or(pc);
        #[cfg(target_arch = "aarch64")]
        let lookup_pc = pc;

        let loc = match self.lookup_source_location(lookup_pc)? {
            Some(l) => l,
            None => return self.step_source(),
        };

        let pc_offset = self.runtime_to_offset(lookup_pc);

        let next_offset = match self.lookup_next_line_offset(&loc.file, loc.line, pc_offset)? {
            Some(a) => a,
            None => return self.cont(),
        };

        self.set_temp_breakpoint(self.offset_to_runtime(next_offset) as usize)?;
        self.cont()
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

            self.disable_breakpoint(breakpoint_addr)?;

            ptrace::step(self.process, None)?;
            let status = self.wait4()?;
            self.handle_wait_status(status)?;

            if self
                .breakpoints
                .get(&breakpoint_addr)
                .is_some_and(|bp| bp.temporary)
            {
                self.breakpoints.remove(&breakpoint_addr);
            } else {
                self.enable_breakpoint(breakpoint_addr)?;
            }
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

    fn set_breakpoint(&mut self, address: usize) -> anyhow::Result<()> {
        info!("setting breakpoint at 0x{:x}", address);
        self.insert_breakpoint(address, false)
    }

    fn set_temp_breakpoint(&mut self, address: usize) -> anyhow::Result<()> {
        info!("setting breakpoint at 0x{:x}", address);
        self.insert_breakpoint(address, true)
    }

    fn insert_breakpoint(&mut self, address: usize, temporary: bool) -> anyhow::Result<()> {
        if let Some(existing) = self.breakpoints.get_mut(&address) {
            existing.temporary &= temporary;
            return Ok(());
        }

        let base = address & !0x7;
        let shift = ((address - base) * 8) as u32;
        let word = ptrace::read(self.process, base as _).context("failed to read memory")? as u64;

        #[cfg(target_arch = "x86_64")]
        let (mask, trap) = (0xffu64 << shift, 0xccu64 << shift);
        #[cfg(target_arch = "aarch64")]
        let (mask, trap) = (0xffff_ffffu64 << shift, 0xd420_0000u64 << shift);
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        compile_error!("Unsupported architecture");

        let orig = word & mask;
        let patched = (word & !mask) | trap;
        ptrace::write(self.process, base as _, patched as _).context("failed to write memory")?;
        self.breakpoints.insert(
            address,
            Breakpoint {
                patch: BreakpointPatch {
                    base,
                    mask,
                    orig,
                    trap,
                },
                temporary,
            },
        );
        Ok(())
    }

    fn disable_breakpoint(&mut self, address: usize) -> anyhow::Result<()> {
        let Some(patch) = self.breakpoints.get(&address).map(|b| b.patch) else {
            return Ok(());
        };
        let word =
            ptrace::read(self.process, patch.base as _).context("failed to read memory")? as u64;
        let restored = (word & !patch.mask) | patch.orig;
        ptrace::write(self.process, patch.base as _, restored as _)
            .context("failed to write memory")?;
        Ok(())
    }

    fn enable_breakpoint(&mut self, address: usize) -> anyhow::Result<()> {
        let Some(patch) = self.breakpoints.get(&address).map(|b| b.patch) else {
            return Ok(());
        };
        let word =
            ptrace::read(self.process, patch.base as _).context("failed to read memory")? as u64;
        let patched = (word & !patch.mask) | patch.trap;
        ptrace::write(self.process, patch.base as _, patched as _)
            .context("failed to write memory")?;
        Ok(())
    }

    fn lookup_next_line_offset(
        &self,
        file: &str,
        line: u64,
        current_offset: u64,
    ) -> anyhow::Result<Option<u64>> {
        let dwarf = match &self.dwarf {
            Some(d) => d,
            None => return Ok(None),
        };

        let target_basename = PathBuf::from(file)
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| file.to_string());

        let mut best: Option<u64> = None;
        let mut iter = dwarf.units();
        while let Some(header) = iter.next()? {
            let unit = dwarf.unit(header)?;
            if let Some(ref line_program) = unit.line_program {
                let mut rows = line_program.clone().rows();
                while let Some((_, row)) = rows.next_row()? {
                    let addr = row.address();
                    if addr <= current_offset {
                        continue;
                    }
                    if !row.is_stmt() {
                        continue;
                    }
                    let row_line = match row.line() {
                        Some(l) => l.get(),
                        None => continue,
                    };
                    if row_line <= line {
                        continue;
                    }
                    let file_index = row.file_index();
                    let row_file = line_program
                        .header()
                        .file(file_index)
                        .and_then(|f| dwarf.attr_string(&unit, f.path_name()).ok())
                        .map(|s| s.to_string_lossy().into_owned())
                        .unwrap_or_default();
                    if !row_file.ends_with(&target_basename) && row_file != file {
                        continue;
                    }
                    best = match best {
                        Some(b) if b <= addr => Some(b),
                        _ => Some(addr),
                    };
                }
            }
        }
        Ok(best)
    }

    fn lookup_source_location(&self, addr: u64) -> anyhow::Result<Option<SourceLocation>> {
        let dwarf = match &self.dwarf {
            Some(d) => d,
            None => return Ok(None),
        };

        let offset = self.runtime_to_offset(addr);
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
                    if row.address() == offset || (!self.is_pie && row.address() == addr) {
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
            } else if let Some(addr) = self.lookup_symbol(location)? {
                self.set_breakpoint(addr as usize)?;
            } else {
                error!("could not find function or symbol {}", location);
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
            while let Some(entry) = entries.next_dfs()? {
                if entry.tag() == gimli::DW_TAG_subprogram {
                    let mut name_match = false;
                    let mut low_pc = None;

                    for attr in entry.attrs() {
                        match attr.name() {
                            gimli::DW_AT_name => {
                                if let Ok(attr_name) = dwarf.attr_string(&unit, attr.value()) {
                                    if attr_name.to_string_lossy() == name {
                                        name_match = true;
                                    }
                                }
                            }
                            gimli::DW_AT_low_pc => {
                                if let gimli::AttributeValue::Addr(addr) = attr.value() {
                                    low_pc = Some(addr);
                                }
                            }
                            _ => {}
                        }
                    }

                    if name_match {
                        if let Some(addr) = low_pc {
                            let runtime_low_pc = self.offset_to_runtime(addr);
                            if let Some(loc) = self.lookup_source_location(runtime_low_pc)? {
                                if let Some(next) =
                                    self.lookup_next_line_offset(&loc.file, loc.line, addr)?
                                {
                                    return Ok(Some(self.offset_to_runtime(next)));
                                }
                            }
                            return Ok(Some(runtime_low_pc));
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
                            let file_index = row.file_index();
                            if let Some(f) = line_program.header().file(file_index) {
                                if let Ok(name) = dwarf.attr_string(&unit, f.path_name()) {
                                    if name.to_string_lossy().ends_with(file) {
                                        return Ok(Some(self.offset_to_runtime(row.address())));
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

    fn lookup_symbol(&self, name: &str) -> anyhow::Result<Option<u64>> {
        if let Some(addr) = self.symbols.get(name) {
            return Ok(Some(self.offset_to_runtime(*addr)));
        }
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

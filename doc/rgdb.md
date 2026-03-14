# rgdb

A gdb write in Rust,  Inspired By https://tartanllama.xyz/posts/writing-a-linux-debugger/setup/ .

## GOALS: 

从文章中继承，后续看情况会不会新增

- Launch, halt, and continue execution
- Set breakpoints on
  - Memory addresses
  - Source code lines
  - Function entry
- Read and write registers and memory
- Single stepping
  - si
  - s
  - finish
  - n
- Print current source location
- Print backtrace
- Print values of simple variables

and more todo:
- Remote debugging
- Shared library and dynamic loading support
- Expression evaluation
- Multi-threaded debugging support


## SETUP

文章中说需要解析一下命令行参数和DWARF调试信息，原文中使用了  Linenoise 和 libelfin。 
Rust中的话就用 clap 和 gimli 好了，都是主流库，而且在MAC上也有支持，所以进行这个开发会更方便。

- 启动: 先不支持 attach 到 pid

通过下面这种方式启动，那么启动阶段要先创建一下子进程，在子进程中来通过 ptrace 系统调用来让自己停下来先，等着父进程来调试自己。

`rgdb $PROCESS <$ARGS>`

通过封装好的 command::new 这种函数，直接来启动子进程会导致子进程可能退出了，而父进程都没有机会去控制它。

所以这里不能用这个函数，必须使用 nix 库的函数，手动 fork 和 execv 子进程, 然后在这中间插入 SIGTRAP 信号，让子进程停下来先。
```rust
    // let sub_process = Command::new(prog.program).args(prog.args).spawn()?;
    let pid = match unsafe { fork()? } {
        ForkResult::Child => {
            ptrace::traceme()?;
            // traceme on some platform, like macos, doesn't send a signal
            unsafe { raise(SIGTRAP) };
            execv(&pn, &args)?;
            unreachable!();
        }
        ForkResult::Parent { child } => child,
    };
```

- 设计 debugger

设计一个 debugger， 这个 debugger 首先要能够

1. 接收用户输入
2. 操作子进程

对于处理用户输入，gdb有搜索和自动补全的功能，rust有 rustyline 可以很方便的解决这个问题。

然后需要把这些输入一个个翻译为对应的subcommand, 然后执行对应的动作。

## SUBCOMMAND 实现

### continue

很简单，就是通过 ptrace::cont 来通知内核(可以带上一个信号)。

关于系统调用具体干了什么，可以查看 [syscall专栏](syscall.md)。

### break point

有软件 break point 和 硬件 break point。

- 软件 break point

想法是这样的： 当break一个代码地址时，把这儿的指令改掉，比如说 改成 `int 3`(x86-64)上，这样执行到这儿就会陷入中断，linux 会执行 SIGTRAP 的逻辑。 这样父进程就能收到消息了。


- 硬件 break point

硬件断点利用处理器提供的调试寄存器来实现，不需要修改目标程序的指令。这在调试只读内存（如 ROM）或者设置数据断点（Watchpoint）时非常有用。

实现思路：
1. **x86-64**: 使用 `DR0`-`DR3` 调试寄存器存储断点地址，并通过 `DR7` 调试控制寄存器来启用它们。在 Linux 中，可以通过 `ptrace(PTRACE_POKEUSER, ...)` 来设置这些寄存器，偏移量通常由 `libc` 或 `nix` 提供。
2. **AArch64**: 使用 `DBGBVR<n>_EL1` (Breakpoint Value Registers) 和 `DBGBCR<n>_EL1` (Breakpoint Control Registers)。在 Linux 中，通常通过 `ptrace(PTRACE_SETREGSET, ...)` 配合 `NT_ARM_HW_BREAK` 寄存器集类型来配置。

限制：
- 硬件断点的数量有限（x86 通常为 4 个，ARM 通常为 2-16 个）。
- 设置硬件断点不涉及内存修改，因此不会破坏指令缓存。

### register

为了观察和修改程序的状态，我们需要读写 CPU 寄存器的能力。

在 Linux 上，我们可以通过 `ptrace(PTRACE_GETREGS, ...)` 一次性获取所有的通用寄存器。
- 对于 **x86_64**，这会返回 `user_regs_struct`，包含了 `rax`, `rbx`, `rip`, `rsp` 等。
- 对于 **AArch64**，通常使用 `PTRACE_GETREGSET` 并指定 `NT_PRSTATUS` 来获取寄存器信息。

一旦获取了寄存器结构体，我们就可以：
1. **read**: 打印指定寄存器的值，或者打印全部寄存器。
2. **write**: 修改指定寄存器的值，然后通过 `PTRACE_SETREGS` 写回。

### memory

除了寄存器，观察进程内存也至关重要。

1. **read**: 使用 `ptrace(PTRACE_PEEKDATA, ...)` 读取指定地址的内存。由于这个系统调用每次只读取一个字（word），我们需要循环调用来读取大块内存。
2. **write**: 使用 `ptrace(PTRACE_POKEDATA, ...)` 向指定地址写入数据。这同样是按字操作的。在写入断点（软件断点）时，我们实际上就是在进行内存写入。

## ELF and DWARF (Step 4)

为了让调试器理解源代码，我们需要解析二进制文件中的调试信息。

### ELF 解析
使用 `object` 库来解析 ELF 文件结构。主要用于查找符号表（Symbol Table）以及定位 DWARF 相关的 Section（如 `.debug_info`, `.debug_line`）。

### DWARF 解析
使用 `gimli` 库来处理 DWARF 格式。
1. **行表 (Line Table)**: 用于机器码地址与源代码行号之间的映射。
2. **编译单元 (Compilation Units)**: 调试信息的顶层结构。
3. **加载地址处理**: 对于 PIE (Position Independent Executables)，调试信息中的地址是相对偏移。我们需要通过 `/proc/<pid>/maps` 获取进程的加载基址，并将绝对地址转换为相对偏移后再进行 DWARF 查找。

### 调试信息查找路径
为了与 GDB 行为一致，`rgdb` 会按以下顺序查找调试信息：
1. 二进制文件自身的 Section。
2. 同目录下的 `.debug` 文件。
3. 系统全局调试路径 `/usr/lib/debug/`。
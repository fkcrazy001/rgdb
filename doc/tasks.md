# rgdb 开发任务路线图 (10 步挑战)

本路线图基于 [Writing a Linux Debugger](https://tartanllama.xyz/posts/writing-a-linux-debugger/setup/) 系列教程。

## 任务列表

| 步骤 | 任务名称 | 描述 | 状态 |
| :--- | :--- | :--- | :--- |
| 1 | **Setup** | 进程派生 (`fork`/`execvp`)、`ptrace(PTRACE_TRACEME)` | ✅ 完成 |
| 2 | **Breakpoints** | 地址断点实现 (`int 3`) | ✅ 完成 |
| 3 | **Registers & Memory** | 寄存器与内存读写、Step Over Breakpoint | ✅ 完成 |
| 4 | **Elves and Dwarves** | 解析 ELF/DWARF 调试信息 (使用 `gimli`) | 🏗️ 进行中 |
| 5 | **Source and Signals** | 信号处理、显示源代码上下文 | ⏳ 待办 |
| 6 | **Source-Level Stepping** | 实现源码级单步执行 (`si`, `s`, `n`, `finish`) | ⏳ 待办 |
| 7 | **Source-Level Breakpoints** | 实现基于函数名和 `文件:行号` 的断点 | ⏳ 待办 |
| 8 | **Stack Unwinding** | 实现函数调用栈回溯 (`backtrace`) | ⏳ 待办 |
| 9 | **Handling Variables** | 读取并打印源代码变量值 | ⏳ 待办 |
| 10 | **Advanced Topics** | 表达式求值、远程调试、多线程支持等 | ⏳ 待办 |

## 当前执行步骤：Step 4 - Elves and Dwarves

### 目标
让 `rgdb` 能够理解二进制文件的结构和调试符号。通过解析 `.debug_info` 和 `.debug_line` 段，将机器码地址映射回源代码位置。

### 关键点
- 使用 `gimli` 库解析 ELF 文件。
- 提取编译单元 (Compilation Units)。
- 解析行表 (Line Tables) 以进行地址/行号映射。
- 查找符号表 (Symbol Table)。

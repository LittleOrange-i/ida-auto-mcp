# IDA Auto MCP

[English](#english) | [中文](#中文)

---

## English

Headless IDA Pro MCP server that enables AI agents to **automatically** open, analyze, and query multiple binary files — no manual IDA GUI interaction required.

### Why This Project?

IDA Auto MCP is a small MCP server built directly on IDA's headless `idalib` library. The AI agent opens binaries itself with `open_binary` (no IDA window, no plugin to start) and can track several of them as sessions, switching between them as it works, which helps with programs made of an executable and several DLLs. Only the active database is open at a time: switching saves and closes it, then reopens the other one.

It is not the only headless option: [ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp) also ships an idalib-based server with multi-binary support, and [ida-mcp-rs](https://github.com/blacktop/ida-mcp-rs) is a headless server written in Rust. IDA Auto MCP aims to stay small and easy to audit: a single Python process, no third-party dependencies besides IDA's own `idapro` package, and an implicit active session so tools don't take a database argument.

### Key Features

- **Fully Automatic** — AI agents call `open_binary("path/to/file.dll")` to start analysis, no human in the loop
- **Multi-Binary Sessions** — Track several binaries as sessions and switch between them (only one database is open at a time; switching saves it and reopens the other one without re-running analysis)
- **Headless** — Uses `idalib` (IDA as a library), no GUI needed
- **55 Analysis Tools** — Decompile, disassemble, xrefs, strings, imports, types, search, rename, patching, and more
- **Read-Only by Default** — Tools that modify the database or run arbitrary code are off until you enable them
- **MCP Standard** — Works with Claude Desktop, Claude Code, and any MCP-compatible client
- **Stdio + HTTP** — Stdio transport for MCP clients, token-protected HTTP for debugging

### Prerequisites

1. **IDA Pro 9.0+** (with valid license), tested with IDA 9.3 and 9.5. On IDA 9.5 the server uses the address-based APIs that replace the ones 9.5 deprecates (`get_func`, `getseg`, the `func_t`-based frame functions), so it prints no `DeprecationWarning`; earlier versions keep using the original APIs.
2. **idapro Python package** — shipped with IDA Pro:
   ```bash
   pip install "<IDA_INSTALL_DIR>/idalib/python/idapro-<version>-py3-none-any.whl"
   ```
   The file name depends on the IDA release, for example `idapro-0.0.7-py3-none-any.whl` in IDA 9.3 and `idapro-0.0.10-py3-none-any.whl` in IDA 9.5. After upgrading IDA, install the wheel from the new installation and point `IDADIR` (or `--ida-dir`) at it.
3. **IDADIR** — set via environment variable or `--ida-dir` flag

### Installation

```bash
git clone https://github.com/mufeng05/ida-auto-mcp.git
cd ida-auto-mcp
pip install -e .
```

### Quick Start

#### Codex (`~/.codex/config.toml`)

Codex reads MCP server settings from `~/.codex/config.toml` (or from
`.codex/config.toml` in a trusted project). Add:

```toml
[mcp_servers.ida-auto-mcp]
command = "python"
args = ["-m", "ida_auto_mcp"]
startup_timeout_sec = 30
tool_timeout_sec = 600

[mcp_servers.ida-auto-mcp.env]
IDADIR = "C:/Program Files/IDA Pro"
```

You can register the same server with the Codex CLI instead:

```bash
codex mcp add ida-auto-mcp --env "IDADIR=C:/Program Files/IDA Pro" -- python -m ida_auto_mcp
codex mcp list
```

Replace the IDA path with the installation path on your machine. If Codex
cannot find `python`, set `command` to the Python executable's absolute path,
for example `C:/Python310/python.exe`. Start a new Codex session after changing
the configuration; restart the desktop app or IDE extension when using those
clients. See the [Codex MCP documentation](https://developers.openai.com/codex/mcp/)
for additional configuration options.

#### Claude Code (`~/.claude.json`)

```json
{
  "mcpServers": {
    "ida": {
      "command": "python",
      "args": ["-m", "ida_auto_mcp", "--ida-dir", "C:/Program Files/IDA Pro"],
      "env": {
        "IDADIR": "C:/Program Files/IDA Pro"
      }
    }
  }
}
```

#### Claude Desktop (`claude_desktop_config.json`)

```json
{
  "mcpServers": {
    "ida": {
      "command": "python",
      "args": ["-m", "ida_auto_mcp", "--ida-dir", "C:/Program Files/IDA Pro"],
      "env": {
        "IDADIR": "C:/Program Files/IDA Pro"
      }
    }
  }
}
```

#### Command Line

```bash
# Start server (stdio mode, default; read-only tools only)
python -m ida_auto_mcp

# Pre-load a binary on startup
python -m ida_auto_mcp C:/samples/target.exe

# Also enable the tools that modify the database, and run_script
python -m ida_auto_mcp --allow-write --allow-script

# HTTP mode for debugging (prints a bearer token on startup)
python -m ida_auto_mcp --transport http --port 8765

# Verbose logging
python -m ida_auto_mcp -v
```

### Permissions

By default the server only exposes tools that read the database. Two flags enable the rest:

| Flag | Enables |
|------|---------|
| `--allow-write` | Tools that modify the IDA database or save it to disk: `save_database`, `rename_address`, `set_comment`, `append_comment`, `set_function_type`, `declare_type`, `apply_type`, `enum_upsert`, `infer_types`, `declare_stack_var`, `delete_stack_var`, `define_function`, `define_code`, `undefine_code`, `patch_bytes`, `patch_asm` |
| `--allow-script` | `run_script`, which executes arbitrary Python with the server's privileges |

Add the flags to `args` in your MCP client configuration, for example `"args": ["-m", "ida_auto_mcp", "--allow-write"]`. Disabled tools are not listed, and calling one returns an error that names the flag. As IDA always does, opening a binary still creates database files next to it, and closing or switching sessions saves them.

Keep both flags off while analyzing untrusted samples: strings and names inside a binary can carry prompt-injection text aimed at the agent.

### Tools (55 total)

Tools marked *(write)* need `--allow-write`; *(script)* needs `--allow-script`.

#### Session
| Tool | Description |
|------|-------------|
| `open_binary` | Open a binary for analysis (auto-analysis included) |
| `close_binary` | Close a session |
| `switch_binary` | Switch active session |
| `list_sessions` | List all open sessions |
| `get_current_session` | Get active session info |

#### Database
| Tool | Description |
|------|-------------|
| `get_database_info` | Binary metadata (filename, arch, imagebase, MD5, SHA256, file size) |
| `wait_analysis` | Wait for auto-analysis to complete |
| `save_database` | Save IDA database to disk *(write)* |

#### Analysis
| Tool | Description |
|------|-------------|
| `list_functions` | List/filter functions with pagination |
| `get_function_info` | Detailed function info (prototype, size) |
| `decompile_function` | Hex-Rays decompilation to C pseudocode |
| `disassemble_function` | Assembly disassembly |
| `get_xrefs_to` | Cross-references TO an address |
| `get_xrefs_from` | Cross-references FROM an address |
| `export_function` | Export function as C header or full decompiled code |

#### Data
| Tool | Description |
|------|-------------|
| `list_strings` | Strings in the binary; IDA 9.5 synthetic strings, which exist only in the code, are marked `synthetic` |
| `search_strings` | Regex search in strings |
| `list_imports` | Imported functions by module |
| `list_exports` | Exported symbols |
| `list_segments` | Memory segments/sections |
| `list_entrypoints` | List binary entry points |
| `get_globals` | List global variables |

#### Control Flow
| Tool | Description |
|------|-------------|
| `get_callers` | Find all functions that call a given function |
| `get_callees` | Find all functions called by a given function |
| `get_callgraph` | Build call graph with depth control (BFS) |
| `get_basic_blocks` | Get CFG basic blocks with type/successor/predecessor info |
| `get_address_info` | Resolve address to segment/function/symbol context |
| `find_paths` | Find control-flow paths between two addresses in the same function |
| `trace_data_flow` | BFS data flow tracing via xrefs (forward/backward) |

#### Types & Structs
| Tool | Description |
|------|-------------|
| `list_structs` | List structs/unions in the database |
| `get_struct_info` | Get struct details with all member fields |
| `list_local_types` | List all local types (structs, enums, typedefs) with filtering |
| `type_inspect` | Inspect a named type in detail (size, kind, declaration, members) |
| `declare_type` | Declare C type definition in local type library *(write)* |
| `apply_type` | Apply type to address (function, global, etc.) *(write)* |
| `enum_upsert` | Create or extend an enum type, optionally a bitmask enum (idempotent) *(write)* |
| `infer_types` | Auto-infer and apply type at address (Hex-Rays/heuristic) *(write)* |
| `xrefs_to_field` | Get cross-references to a specific struct field member |
| `get_stack_frame` | Get stack frame layout (locals, args); each member's `fp_offset` (frame-pointer-relative) is the offset the stack variable tools take |
| `declare_stack_var` | Create or rename the stack variable at an `fp_offset` *(write)* |
| `delete_stack_var` | Delete the stack variable at an `fp_offset` from a function frame *(write)* |

#### Code Definition
| Tool | Description |
|------|-------------|
| `define_function` | Define a function at an address *(write)* |
| `define_code` | Convert bytes to code instructions *(write)* |
| `undefine_code` | Undefine items back to raw bytes *(write)* |

#### Search
| Tool | Description |
|------|-------------|
| `search_bytes` | Byte pattern search with wildcards (`48 89 5C ?? 57`) |
| `find_insns` | Find instructions matching mnemonic/operand pattern (regex) |

#### Modify
| Tool | Description |
|------|-------------|
| `rename_address` | Rename function/address (auto-invalidates decompiler cache) *(write)* |
| `set_comment` | Set disassembly comment *(write)* |
| `append_comment` | Append comment without overwriting (auto-dedup) *(write)* |
| `set_function_type` | Set function prototype (auto-invalidates decompiler cache) *(write)* |
| `patch_bytes` | Patch bytes at an address (binary patching) *(write)* |
| `patch_asm` | Assemble instruction and patch at address *(write)* |

#### Memory Reading
| Tool | Description |
|------|-------------|
| `read_bytes` | Read raw bytes at address |
| `get_string_at` | Read null-terminated string at address |

#### Script
| Tool | Description |
|------|-------------|
| `run_script` | Execute arbitrary IDAPython code *(script)* |

### Multi-Binary Workflow Example

```
User: Analyze main.exe and its plugin.dll

AI: open_binary("C:/samples/main.exe")        → Opens & analyzes main.exe
AI: list_functions(filter_str="*LoadPlugin*")  → Finds LoadPlugin function
AI: decompile_function("LoadPlugin")           → Gets pseudocode
AI: open_binary("C:/samples/plugin.dll")       → Opens plugin.dll (new session)
AI: list_exports()                             → Lists DLL exports
AI: decompile_function("PluginInit")           → Decompiles export
AI: switch_binary("<main.exe session id>")     → Switches back to main.exe
AI: get_xrefs_to("0x401000")                  → Checks cross-references
```

### Architecture

```
ida_auto_mcp/
├── server.py        # CLI entry point, idapro initialization
├── mcp_server.py    # MCP protocol implementation (stdio + HTTP)
├── _registry.py     # Global McpServer instance + tool decorators
├── session.py       # Multi-binary session management via idalib
└── tools.py         # 55 IDA analysis tools
```

Tests for tool permissions and the HTTP checks need no IDA installation:

```bash
python -m unittest discover -s tests -v
```

### Security

- **HTTP transport** is meant for local debugging. It listens on 127.0.0.1, and every POST to `/mcp` needs `Authorization: Bearer <token>`. A random token is printed at startup; when you register the server in a client, set your own in the `IDA_AUTO_MCP_TOKEN` environment variable instead, because the random one changes on every start. Requests whose `Host` or `Origin` is not a loopback address are rejected, which blocks DNS rebinding and calls from web pages on other sites. `--host` changes this: bound to a specific address, the server also accepts that address as `Host` and `Origin`; bound to all interfaces (`0.0.0.0`), it accepts any `Host` and relies on the token alone. Either way it prints a warning, because the traffic is not encrypted. With Claude Code, for example: `claude mcp add --transport http ida http://127.0.0.1:8765/mcp --header "Authorization: Bearer <token>"`.
- **Untrusted samples:** analyze malware only inside an isolated VM. Everything the tools return from a sample (strings, names, decompiled code) is untrusted input to your agent.
- **Intended use:** software you own or are authorized to analyze, such as malware triage, vulnerability research and auditing your own builds and firmware. Don't use it to circumvent software licensing.
- Report vulnerabilities as described in [SECURITY.md](SECURITY.md).

### Acknowledgements

- The MCP protocol layer (`mcp_server.py`) is adapted from [zeromcp](https://github.com/mrexodia/zeromcp) by Duncan Ogilvie (MIT License); see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
- Many tool names and features follow [ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp).
- The control-flow, struct and patching tools were first modeled on [ida-mcp-rs](https://github.com/blacktop/ida-mcp-rs).

### License

MIT, see [LICENSE](LICENSE). IDA Pro itself requires a valid license.

---

## 中文

无界面 IDA Pro MCP 服务器，让 AI 智能体**自动**打开、分析和查询多个二进制文件——无需手动操作 IDA GUI。

### 为什么做这个项目？

IDA Auto MCP 是直接基于 IDA 无头分析库 `idalib` 的小型 MCP 服务器。AI 智能体自己调用 `open_binary` 打开二进制文件（不需要打开 IDA 界面，也不用启动插件），还可以把多个文件记录为会话并在它们之间切换，适合分析由一个主程序和多个 DLL 组成的软件。同一时刻只打开一个数据库：切换时会保存并关闭当前数据库，再重新打开目标数据库。

它不是唯一的无头方案：[ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp) 同样提供基于 idalib、支持多文件的服务器，[ida-mcp-rs](https://github.com/blacktop/ida-mcp-rs) 是用 Rust 写的无头服务器。IDA Auto MCP 的目标是保持小巧、便于审计：单个 Python 进程，除 IDA 自带的 `idapro` 包外没有第三方依赖，并采用隐式的当前会话，调用工具时不需要传数据库参数。

### 核心特性

- **全自动** — AI 直接调用 `open_binary("path/to/file.dll")` 即可开始分析，无需人工干预
- **多文件会话** — 可将多个文件记录为会话并自由切换（同一时刻只打开一个数据库，切换时保存当前数据库并重新打开目标数据库，不会重新分析）
- **无需 GUI** — 使用 `idalib`（IDA 库模式），不需要打开 IDA 界面
- **55 个分析工具** — 反编译、反汇编、交叉引用、字符串、导入表、类型系统、搜索、重命名、补丁等
- **默认只读** — 会修改数据库或执行任意代码的工具默认关闭，需要显式开启
- **MCP 标准协议** — 支持 Claude Desktop、Claude Code 及所有 MCP 兼容客户端
- **双传输模式** — stdio 模式用于 MCP 客户端，带令牌认证的 HTTP 模式用于调试

### 前置要求

1. **IDA Pro 9.0+**（需要有效许可证），已在 IDA 9.3 和 9.5 上测试。在 IDA 9.5 上，服务器改用基于地址的新接口，替代 9.5 弃用的接口（`get_func`、`getseg`、基于 `func_t` 的栈帧函数等），因此不会输出 `DeprecationWarning`；更早的版本继续使用原有接口。
2. **idapro Python 包** — IDA Pro 安装目录自带：
   ```bash
   pip install "<IDA安装目录>/idalib/python/idapro-<版本>-py3-none-any.whl"
   ```
   文件名随 IDA 版本而变，例如 IDA 9.3 中为 `idapro-0.0.7-py3-none-any.whl`，IDA 9.5 中为 `idapro-0.0.10-py3-none-any.whl`。升级 IDA 后，请安装新安装目录中的 wheel，并把 `IDADIR`（或 `--ida-dir`）指向新的安装目录。
3. **IDADIR** — 通过环境变量或 `--ida-dir` 参数设置 IDA 安装路径

### 安装

```bash
git clone https://github.com/mufeng05/ida-auto-mcp.git
cd ida-auto-mcp
pip install -e .
```

### 快速开始

#### Codex 配置 (`~/.codex/config.toml`)

Codex 从 `~/.codex/config.toml` 读取 MCP 服务器配置；也可以在受信任的项目中使用
项目级 `.codex/config.toml`。添加以下内容：

```toml
[mcp_servers.ida-auto-mcp]
command = "python"
args = ["-m", "ida_auto_mcp"]
startup_timeout_sec = 30
tool_timeout_sec = 600

[mcp_servers.ida-auto-mcp.env]
IDADIR = "C:/Program Files/IDA Pro"
```

也可以使用 Codex CLI 注册相同的服务器：

```bash
codex mcp add ida-auto-mcp --env "IDADIR=C:/Program Files/IDA Pro" -- python -m ida_auto_mcp
codex mcp list
```

请将 IDA 路径替换为本机的实际安装路径。如果 Codex 找不到 `python`，请将
`command` 改为 Python 可执行文件的绝对路径，例如 `C:/Python310/python.exe`。
修改配置后请新建 Codex 会话；使用桌面应用或 IDE 扩展时，请重启对应客户端。
更多配置选项请参阅 [Codex MCP 官方文档](https://developers.openai.com/codex/mcp/)。

#### Claude Code 配置 (`~/.claude.json`)

```json
{
  "mcpServers": {
    "ida": {
      "command": "python",
      "args": ["-m", "ida_auto_mcp", "--ida-dir", "C:/Program Files/IDA Pro"],
      "env": {
        "IDADIR": "C:/Program Files/IDA Pro"
      }
    }
  }
}
```

#### Claude Desktop 配置 (`claude_desktop_config.json`)

```json
{
  "mcpServers": {
    "ida": {
      "command": "python",
      "args": ["-m", "ida_auto_mcp", "--ida-dir", "C:/Program Files/IDA Pro"],
      "env": {
        "IDADIR": "C:/Program Files/IDA Pro"
      }
    }
  }
}
```

#### 命令行使用

```bash
# 启动服务器（stdio 模式，默认；只提供只读工具）
python -m ida_auto_mcp

# 启动时预加载一个文件
python -m ida_auto_mcp C:/samples/target.exe

# 同时开启修改数据库的工具和 run_script
python -m ida_auto_mcp --allow-write --allow-script

# HTTP 模式（调试用，启动时会打印 Bearer 令牌）
python -m ida_auto_mcp --transport http --port 8765

# 详细日志
python -m ida_auto_mcp -v
```

### 权限

默认只提供读取数据库的工具，其余工具需要用参数开启：

| 参数 | 开启的工具 |
|------|------------|
| `--allow-write` | 修改 IDA 数据库或将其保存到磁盘的工具：`save_database`、`rename_address`、`set_comment`、`append_comment`、`set_function_type`、`declare_type`、`apply_type`、`enum_upsert`、`infer_types`、`declare_stack_var`、`delete_stack_var`、`define_function`、`define_code`、`undefine_code`、`patch_bytes`、`patch_asm` |
| `--allow-script` | `run_script`，以服务器进程的权限执行任意 Python 代码 |

在 MCP 客户端配置的 `args` 中加上这些参数即可，例如 `"args": ["-m", "ida_auto_mcp", "--allow-write"]`。未开启的工具不会出现在工具列表中，调用时会返回错误并提示所需的参数。与 IDA 平常的行为一样，打开二进制文件时仍会在文件旁边生成数据库文件，关闭或切换会话时也会保存这些文件。

分析不可信样本时请保持这两个参数关闭：二进制中的字符串和名称可能藏有针对 AI 智能体的提示注入内容。

### 工具列表（共 55 个）

标注 *（写入）* 的工具需要 `--allow-write`；标注 *（脚本）* 的需要 `--allow-script`。

#### 会话管理
| 工具 | 说明 |
|------|------|
| `open_binary` | 打开二进制文件进行分析（含自动分析） |
| `close_binary` | 关闭分析会话 |
| `switch_binary` | 切换到其他会话 |
| `list_sessions` | 列出所有打开的会话 |
| `get_current_session` | 获取当前活跃会话信息 |

#### 数据库操作
| 工具 | 说明 |
|------|------|
| `get_database_info` | 获取二进制文件元数据（文件名、架构、基址、MD5、SHA256、文件大小） |
| `wait_analysis` | 等待自动分析完成 |
| `save_database` | 保存 IDA 数据库到磁盘 *（写入）* |

#### 分析功能
| 工具 | 说明 |
|------|------|
| `list_functions` | 列出/过滤函数（支持分页） |
| `get_function_info` | 获取函数详细信息（原型、大小） |
| `decompile_function` | Hex-Rays 反编译为 C 伪代码 |
| `disassemble_function` | 反汇编 |
| `get_xrefs_to` | 获取到某地址的交叉引用 |
| `get_xrefs_from` | 获取从某地址出发的交叉引用 |
| `export_function` | 导出函数为 C 头文件或完整反编译代码 |

#### 数据查询
| 工具 | 说明 |
|------|------|
| `list_strings` | 列出二进制中的字符串；IDA 9.5 中仅存在于代码里的合成字符串会标记为 `synthetic` |
| `search_strings` | 正则搜索字符串 |
| `list_imports` | 列出导入函数（按模块） |
| `list_exports` | 列出导出符号 |
| `list_segments` | 列出内存段/节 |
| `list_entrypoints` | 列出二进制入口点 |
| `get_globals` | 列出全局变量 |

#### 控制流分析
| 工具 | 说明 |
|------|------|
| `get_callers` | 查找调用指定函数的所有函数 |
| `get_callees` | 查找指定函数调用的所有函数 |
| `get_callgraph` | 构建调用图（BFS，支持深度控制） |
| `get_basic_blocks` | 获取函数基本块（含块类型/后继/前驱） |
| `get_address_info` | 解析地址所属的段/函数/符号 |
| `find_paths` | 在函数内查找两个地址间的控制流路径 |
| `trace_data_flow` | 沿交叉引用 BFS 追踪数据流（前向/后向） |

#### 类型与结构体
| 工具 | 说明 |
|------|------|
| `list_structs` | 列出数据库中的结构体/联合体 |
| `get_struct_info` | 获取结构体详细信息（含所有字段） |
| `list_local_types` | 列出所有本地类型（结构体、枚举、typedef）|
| `type_inspect` | 按名称查看类型详情（大小/类型/声明/成员） |
| `declare_type` | 声明 C 类型定义到本地类型库 *（写入）* |
| `apply_type` | 将类型应用到地址（函数、全局变量等） *（写入）* |
| `enum_upsert` | 创建或扩展枚举类型，可选位掩码枚举（幂等操作） *（写入）* |
| `infer_types` | 自动推断并应用地址处的类型（Hex-Rays/启发式） *（写入）* |
| `xrefs_to_field` | 获取结构体特定字段的交叉引用 |
| `get_stack_frame` | 获取函数栈帧布局；每个成员的 `fp_offset`（相对帧指针的偏移）就是栈变量工具使用的偏移 |
| `declare_stack_var` | 在指定 `fp_offset` 处创建或重命名栈变量 *（写入）* |
| `delete_stack_var` | 删除函数栈帧中指定 `fp_offset` 处的栈变量 *（写入）* |

#### 代码定义
| 工具 | 说明 |
|------|------|
| `define_function` | 在指定地址定义函数 *（写入）* |
| `define_code` | 将字节转换为代码指令 *（写入）* |
| `undefine_code` | 取消定义，恢复为原始字节 *（写入）* |

#### 搜索
| 工具 | 说明 |
|------|------|
| `search_bytes` | 字节模式搜索（支持通配符，如 `48 89 5C ?? 57`） |
| `find_insns` | 按助记符/操作数模式搜索指令（支持正则） |

#### 修改
| 工具 | 说明 |
|------|------|
| `rename_address` | 重命名函数/地址（自动刷新反编译缓存） *（写入）* |
| `set_comment` | 设置反汇编注释 *（写入）* |
| `append_comment` | 追加注释（不覆盖已有注释，自动去重） *（写入）* |
| `set_function_type` | 设置函数原型（自动刷新反编译缓存） *（写入）* |
| `patch_bytes` | 在指定地址写入字节（二进制补丁） *（写入）* |
| `patch_asm` | 汇编指令并写入到指定地址 *（写入）* |

#### 内存读取
| 工具 | 说明 |
|------|------|
| `read_bytes` | 读取指定地址的原始字节 |
| `get_string_at` | 读取指定地址的以 null 结尾的字符串 |

#### 脚本
| 工具 | 说明 |
|------|------|
| `run_script` | 执行 IDAPython 脚本 *（脚本）* |

### 多文件分析示例

```
用户：分析 main.exe 和它的 plugin.dll

AI: open_binary("C:/samples/main.exe")        → 打开并分析 main.exe
AI: list_functions(filter_str="*LoadPlugin*")  → 查找 LoadPlugin 函数
AI: decompile_function("LoadPlugin")           → 反编译
AI: open_binary("C:/samples/plugin.dll")       → 打开 plugin.dll（新会话）
AI: list_exports()                             → 查看 DLL 导出
AI: decompile_function("PluginInit")           → 反编译导出函数
AI: switch_binary("<main.exe 的会话 ID>")      → 切回 main.exe
AI: get_xrefs_to("0x401000")                  → 查看交叉引用
```

### 项目结构

```
ida_auto_mcp/
├── server.py        # 命令行入口，idapro 初始化
├── mcp_server.py    # MCP 协议实现（stdio + HTTP 传输）
├── _registry.py     # 全局 McpServer 实例 + 工具装饰器
├── session.py       # 多文件会话管理（基于 idalib）
└── tools.py         # 55 个 IDA 分析工具
```

工具权限和 HTTP 检查的测试不需要安装 IDA：

```bash
python -m unittest discover -s tests -v
```

### 安全

- **HTTP 传输**仅用于本机调试。它监听 127.0.0.1，每个发往 `/mcp` 的 POST 请求都必须带 `Authorization: Bearer <令牌>`。启动时会打印一个随机令牌；在客户端中注册服务器时，请改用环境变量 `IDA_AUTO_MCP_TOKEN` 指定固定令牌，因为随机令牌每次启动都会变。`Host` 或 `Origin` 不是本机回环地址的请求会被拒绝，以防御 DNS 重绑定和其他网站页面发起的请求。`--host` 会改变这一规则：绑定到某个具体地址时，该地址也会被接受为 `Host` 和 `Origin`；绑定到所有网卡（`0.0.0.0`）时，接受任意 `Host`，只靠令牌把关。这两种情况都会打印警告，因为流量没有加密。以 Claude Code 为例：`claude mcp add --transport http ida http://127.0.0.1:8765/mcp --header "Authorization: Bearer <令牌>"`。
- **不可信样本**：恶意软件只在隔离的虚拟机中分析。工具从样本中返回的一切内容（字符串、名称、反编译代码）对 AI 智能体来说都是不可信输入。
- **用途**：分析你拥有或获得授权分析的软件，例如恶意样本分析、漏洞研究、审计自己构建的程序和固件。请勿用于绕过软件授权。
- 发现漏洞请按 [SECURITY.md](SECURITY.md) 中的方式报告。

### 致谢

- MCP 协议层（`mcp_server.py`）改编自 Duncan Ogilvie 的 [zeromcp](https://github.com/mrexodia/zeromcp)（MIT 许可证），详见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。
- 许多工具的命名和功能参考了 [ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp)。
- 控制流、结构体和补丁类工具最初参考 [ida-mcp-rs](https://github.com/blacktop/ida-mcp-rs) 实现。

### 许可

MIT，详见 [LICENSE](LICENSE)。IDA Pro 本身需要有效的许可证。

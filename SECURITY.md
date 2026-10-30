# Security Policy

[English](#english) | [中文](#中文)

---

## English

### Security contact

This project is maintained by [@mufeng05](https://github.com/mufeng05), who is also its security contact. Please report vulnerabilities privately as described below, not in public issues, pull requests or discussions.

### Reporting a vulnerability

Use GitHub private vulnerability reporting: open the [Security](https://github.com/mufeng05/ida-auto-mcp/security) tab and click **Report a vulnerability**, or go to <https://github.com/mufeng05/ida-auto-mcp/security/advisories/new>.

Please include:

- the ida-auto-mcp commit, IDA Pro version, operating system and Python version
- the transport (stdio or HTTP) and the MCP client you use
- steps to reproduce, a proof of concept if you have one, and the impact

I will acknowledge your report as soon as I can, keep you informed while it is confirmed and fixed, and agree on a disclosure date with you. After a fix is available I will publish a GitHub Security Advisory and credit you, unless you prefer not to be named.

### Supported versions

There are no tagged releases. Security fixes go to the latest commit on `master`. Please check that the issue still reproduces there.

### Scope

In scope:

- the MCP server and its stdio and HTTP transports, including the HTTP bearer-token, `Host` and `Origin` checks
- any way for someone other than the MCP client you configured to reach the server or call its tools
- tools that are off by default being listed or callable without `--allow-write` / `--allow-script`
- tools that write files or modify the IDA database doing more than they document
- `open_binary`'s loader options reaching IDA as anything but the processor, file type, base address and entry point switches, for example to run a script

Not vulnerabilities:

- Once you start the server with `--allow-write` or `--allow-script`, the MCP client you configured can use those tools, and `run_script` executes arbitrary IDAPython by design. A configured client being able to do what the enabled tools do is expected.
- Strings, names and decompiled code returned from an analysed binary come from the sample itself and should be treated as untrusted. Guarding the AI agent against prompt injection hidden in samples is up to the MCP client.
- Bugs in IDA Pro, idalib or the Hex-Rays decompiler, including crashes on malformed binaries; please report those to [Hex-Rays](https://hex-rays.com/).

---

## 中文

### 安全联系人

本项目的维护者兼安全联系人是 [@mufeng05](https://github.com/mufeng05)。发现安全漏洞请按下面的方式私下报告，不要发在公开的 Issue、Pull Request 或 Discussion 里。

### 报告漏洞

请使用 GitHub 私密漏洞报告：打开仓库的 [Security](https://github.com/mufeng05/ida-auto-mcp/security) 页签，点击 **Report a vulnerability**，或直接访问 <https://github.com/mufeng05/ida-auto-mcp/security/advisories/new>。

请尽量提供：

- ida-auto-mcp 的 commit、IDA Pro 版本、操作系统和 Python 版本
- 使用的传输方式（stdio 或 HTTP）和 MCP 客户端
- 复现步骤、PoC（如有）以及影响

我会尽快确认收到报告，在确认和修复期间同步进展，并与你商定公开时间。修复发布后，我会发布 GitHub 安全公告（Security Advisory）并致谢报告者，除非你希望匿名。

### 支持的版本

本项目没有打标签的发布版本。安全修复只进入 `master` 分支的最新提交，报告前请先确认问题在最新提交上仍能复现。

### 范围

属于本项目的范围：

- MCP 服务器本身及其 stdio、HTTP 两种传输方式，包括 HTTP 的 Bearer 令牌、`Host` 和 `Origin` 校验
- 除你配置的 MCP 客户端之外，其他任何人能够访问服务器或调用其工具的途径
- 默认关闭的工具在未使用 `--allow-write` / `--allow-script` 时仍能被列出或调用
- 会写文件或修改 IDA 数据库的工具做了超出其文档说明的事
- `open_binary` 的加载选项传给 IDA 的内容超出处理器、文件类型、基址和入口点这几个开关，例如借此运行脚本

不属于漏洞：

- 用 `--allow-write` 或 `--allow-script` 启动服务器后，你配置的 MCP 客户端就可以使用这些工具，`run_script` 按设计就会执行任意 IDAPython。已配置的客户端能做到已开启的工具本来就能做的事，属于预期行为。
- 从被分析二进制中返回的字符串、名称和反编译代码都来自样本本身，应视为不可信。防范样本中暗藏的提示注入攻击 AI 代理，由 MCP 客户端负责。
- IDA Pro、idalib 或 Hex-Rays 反编译器自身的问题（包括解析畸形二进制时崩溃），请向 [Hex-Rays](https://hex-rays.com/) 报告。

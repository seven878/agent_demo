# my-agent

本地终端编程助手：你描述需求，它读代码、改代码、跑命令；每个任务结束后自动建分支、提交，并向 GitHub 提 PR。

## 安装与启动
```bash
pip install openai          # 需要 Python 3.11+
export DEEPSEEK_API_KEY=你的DeepSeek_API_Key        # Windows: set DEEPSEEK_API_KEY=你的key
export GITHUB_TOKEN=你的GitHub令牌     # 需有 Pull requests: write 权限；不设置则只在本地提交
cp agent.toml.example agent.toml     # 按需改模型名
cd 你的项目目录 && python /path/to/agent.py
```
项目需是 git 仓库，且已关联 GitHub 远程（`origin`），本机 git 能推送（SSH 或凭据管理器）；`GITHUB_TOKEN` 负责通过 API 创建 PR。
在项目根目录放一个 `AGENT.md` 可写入项目约定，agent 每次启动都会读取。

## 命令
`/undo` 撤销上一个任务（回到上一分支并删除该任务分支） · `/clear` 清空对话 · `/exit` 退出 · `Ctrl+C` 中断当前任务

## 工作方式
- 全自动：工作目录内的读写、命令不再确认。
- 每个任务（你输入的一条需求）= 一个分支 `agent/时间戳` + 一次提交 + 一个 PR。默认 PR 依次叠加（指向上一个任务分支），按顺序合并即可。
- 日志在 `.agent/log.jsonl`（已自动加入 git 排除）。

## 安全机制与局限
已做：文件工具限制在工作目录（含符号链接）；`.env`、密钥文件拒绝读写且不会被提交；子进程环境里不含任何 KEY/TOKEN 变量；
拦截 sudo、手动 git push/commit/checkout、`curl | sh`、删除 .git、打印环境变量、访问目录外路径等；命令 60 秒超时、输出截断；最多 25 步，连续 3 次相同调用会被叫停。

**注意：命令拦截是字符串启发式检查，不是沙箱。** 模型若通过脚本内部（如 `python -c`、先写脚本再运行）做坏事，是拦不住的。
真正的隔离需要 Docker（需求 R10，尚未实现）。建议只在有 git 备份的项目里使用，并先在 GitHub 上审阅 PR 再合并。

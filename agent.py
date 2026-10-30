#!/usr/bin/env python3
"""my-agent：本地终端编程助手。

- 全自动：工作目录内的读写/命令不再逐条确认
- 安全：路径限制、危险命令拦截、密钥不入环境/日志、超时与输出截断、步数上限
- 每个任务结束后：自动建分支 -> 提交 -> 推送 -> 向 GitHub 提 PR
"""
from __future__ import annotations

import argparse
import difflib
import fnmatch
import json
import locale
import os
import platform
import re
import shlex
import signal
import subprocess
import sys
import time
import tomllib
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

import requests

# ============================================================ 配置
DEFAULTS = {
    "model": {
        "name": "deepseek-flash",
        "base_url": "https://api.deepseek.com",
        "api_key_env": "DEEPSEEK_API_KEY",
        "stream": True,
        "timeout": 120,
        "retries": 3,
    },
    "agent": {
        "max_steps": 25,
        "command_timeout": 60,
        "output_limit": 4000,
        "max_context_chars": 120000,
    },
    "github": {
        "enabled": True,
        "remote": "origin",
        "base_branch": "",  # stack=false 时 PR 的目标分支；留空则用启动时所在分支
        "token_env": "GITHUB_TOKEN",
        "stack": True,  # True：PR 目标是上一个任务分支（改动互不重叠）
    },
}


def load_config(path: str | None) -> dict:
    cfg = {k: dict(v) for k, v in DEFAULTS.items()}
    candidates = [path] if path else [Path.cwd() / "agent.toml", Path(__file__).parent / "agent.toml"]
    for p in candidates:
        if p and Path(p).is_file():
            with open(p, "rb") as f:
                user = tomllib.load(f)
            for sec, vals in user.items():
                cfg.setdefault(sec, {}).update(vals)
            break
    return cfg


# ============================================================ 终端输出
def _c(t: str, code: str) -> str:
    return f"\033[{code}m{t}\033[0m" if sys.stdout.isatty() else t


dim = lambda t: _c(t, "2")
red = lambda t: _c(t, "31")
green = lambda t: _c(t, "32")
yellow = lambda t: _c(t, "33")
cyan = lambda t: _c(t, "36")

# ============================================================ 密钥与敏感文件
SECRET_ENV = re.compile(r"(KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL)", re.I)
SECRET_SUFFIX = {".pem", ".key", ".p12", ".pfx", ".ppk"}
SECRET_NAMES = {".netrc", "id_rsa", "id_ed25519", "id_ecdsa", "credentials", ".pypirc", ".npmrc"}
ENV_OK = {".env.example", ".env.sample", ".env.template"}


def redact(s: str) -> str:
    for k, v in os.environ.items():
        if SECRET_ENV.search(k) and len(v) >= 8:
            s = s.replace(v, "***")
    return s


def scrubbed_env() -> dict:
    """给子进程用的环境变量：去掉所有疑似密钥的变量。"""
    return {k: v for k, v in os.environ.items() if not SECRET_ENV.search(k)}


def is_secret_path(rel: Path) -> bool:
    n = rel.name.lower()
    if n == ".env" or (n.startswith(".env.") and n not in ENV_OK):
        return True
    return n in SECRET_NAMES or rel.suffix.lower() in SECRET_SUFFIX or ".ssh" in [x.lower() for x in rel.parts]


# ============================================================ 路径与命令安全
class ToolError(Exception):
    pass


def inside(p: Path, root: Path) -> bool:
    try:
        p.relative_to(root)
        return True
    except ValueError:
        return False


class Workspace:
    def __init__(self, root: str | Path):
        self.root = Path(os.path.realpath(root))

    def resolve(self, p: str | None, write: bool = False) -> Path:
        raw = Path(os.path.expanduser(str(p or ".")))
        full = Path(os.path.realpath(raw if raw.is_absolute() else self.root / raw))
        if not inside(full, self.root):
            raise ToolError(f"路径超出工作目录，已拒绝：{p}")
        rel = full.relative_to(self.root)
        if is_secret_path(rel):
            raise ToolError(f"拒绝访问敏感文件：{rel.name}")
        if write and (".git" in rel.parts or ".agent" in rel.parts):
            raise ToolError("不允许写入 .git / .agent 目录")
        return full

    def rel(self, p: Path) -> str:
        return str(p.relative_to(self.root)) or "."


DENY = [
    (r"\bsudo\b", "不允许提权"),
    (r"\bgit\s+(-\S+\s+)*(push|commit|checkout|switch|branch|reset|rebase|merge|stash|clean|tag|remote|config|filter-branch|gc|reflog)\b",
     "分支/提交/推送由 agent 的 PR 流程统一处理（git status/diff/log/add 可用）"),
    (r"(curl|wget|iwr|Invoke-WebRequest)[^\n]*\|\s*(sh|bash|zsh|python\d?|iex|Invoke-Expression)\b",
     "不允许下载后直接执行"),
    (r"\b(mkfs\S*|fdisk|parted|diskpart)\b|\bdd\b[^\n;|&]*\bof=/dev/", "不允许磁盘操作"),
    (r":\(\)\s*\{", "疑似 fork 炸弹"),
    (r"\b(shutdown|reboot|halt|poweroff)\b", "不允许关机/重启"),
    (r"\bformat\s+[a-zA-Z]:", "不允许格式化磁盘"),
    (r"(^|[;&|]\s*)(env|printenv|set|export)\s*($|[;&|>])", "不允许打印环境变量"),
    (r"\$\{?\w*(KEY|TOKEN|SECRET|PASSWORD)\w*|%\w*(KEY|TOKEN|SECRET|PASSWORD)\w*%", "不允许引用密钥变量"),
    (r"\.ssh\b|\.env\b(?!\.(example|sample|template))|\bid_rsa\b|\.netrc|\.pem\b", "不允许访问敏感文件"),
    (r"\b(rm|rmdir|rd|del)\b[^\n;|&]*\.git(\s|/|\\|$)", "不允许删除 .git"),
    (r"\brm\b[^\n;|&]*\s(\.|\./|\*|\./\*|\.\*)(\s|$)", "不允许删除整个工作目录内容"),
]
SAFE_ABS = [Path(p) for p in
            ("/usr", "/bin", "/sbin", "/lib", "/lib64", "/opt", "/dev/null", "/dev/stdout", "/dev/stderr")]
SAFE_ABS += [Path(os.path.realpath(p)) for p in (sys.prefix, sys.base_prefix)]  # 仅供“执行”系统程序/解释器；删改类命令不适用
DESTRUCTIVE = re.compile(r"\b(rm|rmdir|rd|del|mv|move|chmod|chown|truncate|shred)\b", re.I)


def _pathlike(t: str) -> bool:
    return (
            bool(re.match(r"^(/|~|\.\.?(/|\\|$)|[A-Za-z]:[\\/])", t))
            or "$HOME" in t
            or "%USERPROFILE%" in t.upper()
            or re.search(r"(^|[\\/])\.\.([\\/]|$)", t) is not None
    )


def check_command(cmd: str, root: Path) -> str | None:
    """返回拦截原因；None 表示放行。注意这是启发式检查，不是沙箱。"""
    for pat, reason in DENY:
        if re.search(pat, cmd, re.I):
            return reason
    try:
        tokens = shlex.split(cmd, posix=(os.name != "nt"))
    except ValueError:
        tokens = cmd.split()
    for tok in tokens:
        t = tok.strip("'\"")
        if t.startswith("-") and "=" in t:
            t = t.split("=", 1)[1].strip("'\"")
        if not t or t.startswith("-") or not _pathlike(t):
            continue
        if os.name == "nt" and re.fullmatch(r"/[A-Za-z?]+", t):
            continue  # cmd 的开关，如 /s /b
        p = Path(os.path.expandvars(os.path.expanduser(t)))
        p = Path(os.path.realpath(p if p.is_absolute() else root / p))
        if inside(p, root) or (not DESTRUCTIVE.search(cmd) and any(inside(p, a) for a in SAFE_ABS)):
            continue
        if t.startswith("/") and len(p.parts) > 1 and not os.path.exists(os.path.join(p.parts[0], p.parts[1])):
            continue  # 形如 sed 的 /pattern/ 参数，不是真实路径
        return f"涉及工作目录之外的路径：{tok}"
    return None


# ============================================================ 文件读写辅助
IGNORE = {".git", ".agent", "node_modules", "__pycache__", ".venv", "venv", ".idea", ".vscode", "dist", "build"}
READ_LIMIT = 12000


def decode_text(data: bytes) -> tuple[str, str]:
    for enc in ("utf-8-sig", "gb18030"):  # NC/老文件常见 GBK
        try:
            return data.decode(enc), enc
        except UnicodeDecodeError:
            pass
    return data.decode("utf-8", errors="replace"), "utf-8"


def load_text(p: Path) -> tuple[str, str, bool]:
    text, enc = decode_text(p.read_bytes())
    crlf = "\r\n" in text
    return text.replace("\r\n", "\n"), ("utf-8" if enc == "utf-8-sig" else enc), crlf


def save_text(p: Path, text: str, enc: str, crlf: bool) -> None:
    if crlf:
        text = text.replace("\n", "\r\n")
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(text.encode(enc))


def show_diff(rel: str, old: str, new: str) -> None:
    d = list(difflib.unified_diff(old.splitlines(), new.splitlines(), f"a/{rel}", f"b/{rel}", lineterm="", n=2))
    for line in d[:60]:
        print("  " + (green(line) if line.startswith("+") else red(line) if line.startswith("-") else dim(line)))
    if len(d) > 60:
        print(dim(f"  ... 另有 {len(d) - 60} 行 diff 未显示"))


def kill_tree(proc: subprocess.Popen) -> None:
    try:
        if os.name == "nt":
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)], capture_output=True)
        else:
            os.killpg(proc.pid, signal.SIGKILL)
    except Exception:
        proc.kill()


def create_pull_request(repo_owner, repo_name, title, head_branch, base_branch="main", body=""):
    """
    在指定仓库创建 Pull Request。
    head_branch 格式：如果是同仓库分支，填分支名；如果是 fork，填 "用户名:分支名"。
    """
    pat = os.environ.get("GITHUB_PAT")  # 从环境变量读取你的 PAT
    url = f"https://api.github.com/repos/{repo_owner}/{repo_name}/pulls"
    headers = {
        "Authorization": f"Bearer {pat}",
        "Accept": "application/vnd.github+json"
    }
    data = {
        "title": title,
        "head": head_branch,
        "base": base_branch,
        "body": body
    }
    resp = requests.post(url, json=data, headers=headers)
    return resp.json()  # 返回结果给 Agent


# ============================================================ 工具
TOOLS = [
    {"type": "function", "function": {
        "name": "read_file", "description": "读取文本文件，可按行范围读取（行号从 1 开始）",
        "parameters": {"type": "object", "properties": {
            "path": {"type": "string"}, "start_line": {"type": "integer"}, "end_line": {"type": "integer"}},
                       "required": ["path"]}}},
    {"type": "function", "function": {
        "name": "write_file", "description": "创建或整体覆盖文件。小改动请用 edit_file",
        "parameters": {"type": "object", "properties": {
            "path": {"type": "string"}, "content": {"type": "string"}}, "required": ["path", "content"]}}},
    {"type": "function", "function": {
        "name": "edit_file",
        "description": "把文件中唯一出现的 old_str 替换为 new_str（old_str 要包含足够上下文以保证唯一）",
        "parameters": {"type": "object", "properties": {
            "path": {"type": "string"}, "old_str": {"type": "string"}, "new_str": {"type": "string"},
            "replace_all": {"type": "boolean"}}, "required": ["path", "old_str", "new_str"]}}},
    {"type": "function", "function": {
        "name": "list_dir", "description": "列出目录结构（默认 2 层，自动忽略 .git/node_modules 等）",
        "parameters": {"type": "object", "properties": {
            "path": {"type": "string"}, "depth": {"type": "integer"}}}}},
    {"type": "function", "function": {
        "name": "search_text", "description": "用正则在文件中搜索文本，返回 文件:行号: 内容",
        "parameters": {"type": "object", "properties": {
            "pattern": {"type": "string"}, "path": {"type": "string"},
            "glob": {"type": "string", "description": "文件名匹配，如 *.py"}}, "required": ["pattern"]}}},
    {"type": "function", "function": {
        "name": "run_command",
        "description": "在工作目录执行 shell 命令（非交互，有超时）。用于运行测试、脚本、git status/diff 等",
        "parameters": {"type": "object", "properties": {"command": {"type": "string"}}, "required": ["command"]}}},
    {
        "type": "function",
        "function": {
            "name": "create_pull_request",
            "description": "在 GitHub 仓库中创建一个 Pull Request",
            "parameters": {
                "type": "object",
                "properties": {
                    "repo_owner": {"type": "string", "description": "仓库所有者"},
                    "repo_name": {"type": "string", "description": "仓库名"},
                    "title": {"type": "string", "description": "PR 标题"},
                    "head_branch": {"type": "string",
                                    "description": "包含更改的分支名，若来自 fork 则格式为 owner:branch"},
                    "base_branch": {"type": "string", "description": "目标分支，默认 main"}
                },
                "required": ["repo_owner", "repo_name", "title", "head_branch"]
            }
        }
    }
]


class Tools:
    def __init__(self, ws: Workspace, cfg: dict):
        self.ws, self.cfg = ws, cfg

    def call(self, name: str, args: dict) -> str:
        fn = getattr(self, "t_" + name, None)
        if fn is None:
            return f"错误：未知工具 {name}"
        try:
            return fn(**args)
        except ToolError as e:
            return f"错误：{e}"
        except TypeError as e:
            return f"错误：参数不正确（{e}）"
        except OSError as e:
            return f"错误：{e}"

    def t_read_file(self, path, start_line=1, end_line=None):
        p = self.ws.resolve(path)
        if not p.is_file():
            raise ToolError("文件不存在或不是文件")
        data = p.read_bytes()
        if len(data) > 20_000_000:
            raise ToolError("文件超过 20MB")
        if b"\0" in data[:2048]:
            raise ToolError("看起来是二进制文件，无法读取")
        lines = decode_text(data)[0].splitlines()
        n = len(lines)
        s = max(1, int(start_line or 1))
        e = min(n, int(end_line)) if end_line else n
        out, used, last = [], 0, s - 1
        for i in range(s - 1, e):
            if used + len(lines[i]) + 1 > READ_LIMIT and out:
                break
            out.append(lines[i])
            used += len(lines[i]) + 1
            last = i + 1
        head = f"[{self.ws.rel(p)} 共 {n} 行，显示 {s}-{last}" + ("，已截断，请用 start_line 继续]" if last < e else "]")
        return head + "\n" + "\n".join(out)

    def t_write_file(self, path, content):
        p = self.ws.resolve(path, write=True)
        if p.is_dir():
            raise ToolError("目标是目录")
        if len(content) > 1_000_000:
            raise ToolError("内容超过 1MB")
        old, enc, crlf = (load_text(p) if p.exists() else ("", "utf-8", False))
        save_text(p, content, enc, crlf)
        show_diff(self.ws.rel(p), old, content)
        return f"已写入 {self.ws.rel(p)}（{len(content.splitlines())} 行）"

    def t_edit_file(self, path, old_str, new_str, replace_all=False):
        p = self.ws.resolve(path, write=True)
        if not p.is_file():
            raise ToolError("文件不存在")
        if not old_str:
            raise ToolError("old_str 不能为空")
        text, enc, crlf = load_text(p)
        cnt = text.count(old_str)
        if cnt == 0:
            raise ToolError("没找到 old_str，请先 read_file 确认原文（注意空白与缩进）")
        if cnt > 1 and not replace_all:
            raise ToolError(f"old_str 出现 {cnt} 次，请加入更多上下文使其唯一，或设置 replace_all=true")
        new = text.replace(old_str, new_str) if replace_all else text.replace(old_str, new_str, 1)
        save_text(p, new, enc, crlf)
        show_diff(self.ws.rel(p), text, new)
        return f"已修改 {self.ws.rel(p)}（替换 {cnt if replace_all else 1} 处）"

    def t_list_dir(self, path=".", depth=2):
        root = self.ws.resolve(path)
        if not root.is_dir():
            raise ToolError("不是目录")
        depth, out = max(1, min(int(depth or 2), 5)), []

        def walk(d: Path, lvl: int):
            try:
                entries = sorted(d.iterdir(), key=lambda e: (e.is_file(), e.name.lower()))
            except OSError:
                return
            for e in entries:
                if len(out) >= 300:
                    return
                if e.name in IGNORE or is_secret_path(Path(e.name)):
                    continue
                if e.is_dir() and not e.is_symlink():
                    out.append("  " * lvl + e.name + "/")
                    if lvl + 1 < depth:
                        walk(e, lvl + 1)
                else:
                    out.append("  " * lvl + e.name)

        walk(root, 0)
        return "\n".join(out) + ("\n...(已截断)" if len(out) >= 300 else "") if out else "(空目录)"

    def t_search_text(self, pattern, path=".", glob="*"):
        try:
            rx = re.compile(pattern, re.I)
        except re.error as e:
            raise ToolError(f"正则不合法：{e}")
        root = self.ws.resolve(path)
        files = [root] if root.is_file() else (
            Path(dp) / f
            for dp, dns, fns in os.walk(root)
            for _ in [dns.__setitem__(slice(None), [d for d in dns if d not in IGNORE])]
            for f in fns
        )
        hits = []
        for f in files:
            if not fnmatch.fnmatch(f.name, glob or "*"):
                continue
            real = Path(os.path.realpath(f))
            if not inside(real, self.ws.root) or is_secret_path(real.relative_to(self.ws.root)):
                continue
            try:
                if real.stat().st_size > 1_000_000:
                    continue
                data = real.read_bytes()
            except OSError:
                continue
            if b"\0" in data[:2048]:
                continue
            for i, line in enumerate(decode_text(data)[0].splitlines(), 1):
                if rx.search(line):
                    hits.append(f"{self.ws.rel(real)}:{i}: {line.strip()[:200]}")
                    if len(hits) >= 100:
                        return "\n".join(hits) + "\n...(仅显示前 100 条)"
        return "\n".join(hits) or "没有匹配"

    def t_run_command(self, command):
        reason = check_command(command, self.ws.root)
        if reason:
            raise ToolError(f"命令被拦截：{reason}")
        limit, tmo = self.cfg["agent"]["output_limit"], self.cfg["agent"]["command_timeout"]
        kw = {"start_new_session": True} if os.name != "nt" else {}
        proc = subprocess.Popen(command, shell=True, cwd=self.ws.root, stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=scrubbed_env(), **kw)
        timed_out = False
        try:
            raw, _ = proc.communicate(timeout=tmo)
        except subprocess.TimeoutExpired:
            kill_tree(proc)
            timed_out = True
            try:
                raw, _ = proc.communicate(timeout=5)
            except Exception:
                raw = b""
        except BaseException:
            kill_tree(proc)
            raise
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            text = raw.decode(locale.getpreferredencoding(False), errors="replace")
        if len(text) > limit:
            text = f"...(前面省略 {len(text) - limit} 字符)\n" + text[-limit:]
        tail = f"\n[超时 {tmo}s，已终止]" if timed_out else f"\n[退出码 {proc.returncode}]"
        return redact(text) + tail


# ============================================================ 模型调用
class ModelError(Exception):
    pass


@dataclass
class Reply:
    content: str = ""
    tool_calls: list = field(default_factory=list)  # [{"id","name","args"}]
    reasoning: str = ""


class Model:
    def __init__(self, cfg: dict):
        self.cfg = cfg["model"]
        try:
            import openai
            from openai import OpenAI
        except ImportError:
            raise ModelError("缺少依赖：请先运行 pip install openai")
        self.openai = openai
        key = os.environ.get(self.cfg["api_key_env"])
        if not key:
            raise ModelError(f"没有找到 API key：请设置环境变量 {self.cfg['api_key_env']}")
        self.client = OpenAI(base_url=self.cfg["base_url"], api_key=key, timeout=self.cfg["timeout"], max_retries=0)

    def chat(self, messages: list) -> Reply:
        o, retries = self.openai, self.cfg["retries"]
        for attempt in range(retries + 1):
            try:
                return self._once(messages)
            except (o.AuthenticationError, o.PermissionDeniedError):
                raise ModelError(f"API key 无效或没有权限，请检查环境变量 {self.cfg['api_key_env']}")
            except o.NotFoundError:
                raise ModelError(f"找不到模型 {self.cfg['name']}，请检查配置里的模型名和 base_url")
            except o.BadRequestError as e:
                raise ModelError(
                    f"服务端拒绝了请求(400)：{redact(str(e))[:300]}\n可能该模型不支持工具调用，或对话过长（可输入 /clear）")
            except (o.RateLimitError, o.APITimeoutError, o.APIConnectionError, o.InternalServerError) as e:
                why = {"RateLimitError": "触发限流", "APITimeoutError": "等待超时",
                       "APIConnectionError": "网络连接失败"}.get(
                    type(e).__name__, "服务端错误")
                if attempt == retries:
                    raise ModelError(f"{why}，已重试 {retries} 次仍失败。检查网络/代理，或稍后再试。")
                wait = min(2 ** attempt * 2, 30)
                print(yellow(f"\n{why}，{wait}s 后重试（{attempt + 1}/{retries}）"))
                time.sleep(wait)
            except o.APIStatusError as e:
                raise ModelError(f"服务端返回 {e.status_code}：{redact(str(e))[:300]}")

    def _once(self, messages: list) -> Reply:
        params = dict(model=self.cfg["name"], messages=messages, tools=TOOLS)
        print(dim("⏳ 等待模型响应…"), end="\r", flush=True)
        if not self.cfg["stream"]:
            m = self.client.chat.completions.create(**params).choices[0].message
            print(" " * 30, end="\r")
            if m.content:
                print(m.content)
            calls = [{"id": t.id, "name": t.function.name, "args": t.function.arguments or "{}"} for t in
                     (m.tool_calls or [])]
            return Reply(m.content or "", calls, getattr(m, "reasoning_content", None) or "")
        text, reasoning, calls, started, thinking = [], [], {}, False, False
        for chunk in self.client.chat.completions.create(**params, stream=True):
            if not chunk.choices:
                continue
            d = chunk.choices[0].delta
            if not started:
                print(" " * 30, end="\r")
                started = True
            r = getattr(d, "reasoning_content", None)
            if r:
                reasoning.append(r)
                if not thinking:
                    print(dim("💭 思考中…"), flush=True)
                    thinking = True
            if d.content:
                print(d.content, end="", flush=True)
                text.append(d.content)
            for tc in d.tool_calls or []:
                slot = calls.setdefault(tc.index, {"id": "", "name": "", "args": ""})
                if tc.id:
                    slot["id"] = tc.id
                if tc.function:
                    slot["name"] += tc.function.name or ""
                    slot["args"] += tc.function.arguments or ""
        if text:
            print()
        out = []
        for i, k in enumerate(sorted(calls)):
            c = calls[k]
            out.append({"id": c["id"] or f"call_{int(time.time())}_{i}", "name": c["name"], "args": c["args"] or "{}"})
        return Reply("".join(text), out, "".join(reasoning))


# ============================================================ git / GitHub
class GitError(Exception):
    pass


class Git:
    def __init__(self, root: Path):
        self.root = root

    def run(self, *args, timeout=60) -> str:
        r = subprocess.run(["git", "-c", "core.quotepath=false", *args], cwd=self.root, capture_output=True,
                           text=True, encoding="utf-8", errors="replace", timeout=timeout,
                           env={**os.environ, "GIT_TERMINAL_PROMPT": "0"})
        if r.returncode:
            raise GitError(redact((r.stderr or r.stdout).strip()))
        return r.stdout.strip()

    def exists(self, branch: str) -> bool:
        try:
            self.run("rev-parse", "--verify", "-q", "refs/heads/" + branch)
            return True
        except GitError:
            return False

    def is_repo(self) -> bool:
        try:
            return self.run("rev-parse", "--is-inside-work-tree") == "true"
        except (GitError, FileNotFoundError):
            return False


def parse_github(url: str):
    m = re.search(r"(?:github\.com[:/])([^/]+)/([^/]+?)(?:\.git)?/?$", url, re.I)
    return (m.group(1), m.group(2)) if m else None


def create_pr(owner, repo, token, title, head, base, body) -> str:
    data = json.dumps({"title": title, "head": head, "base": base, "body": body}).encode()
    req = urllib.request.Request(f"https://api.github.com/repos/{owner}/{repo}/pulls", data=data, method="POST",
                                 headers={"Accept": "application/vnd.github+json",
                                          "Authorization": f"Bearer {token}",
                                          "X-GitHub-Api-Version": "2022-11-28",
                                          "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            res = json.load(r)
    except urllib.error.HTTPError as e:
        raise GitError(f"GitHub 返回 {e.code}：{redact(e.read().decode('utf-8', 'replace'))[:300]}")
    except urllib.error.URLError as e:
        raise GitError(f"无法连接 GitHub：{e.reason}")
    return res.get("html_url", "")


# ============================================================ Agent
class Log:
    def __init__(self, root: Path):
        self.path = root / ".agent" / "log.jsonl"
        try:
            self.path.parent.mkdir(exist_ok=True)
        except OSError:
            pass

    def write(self, **kw):
        kw["ts"] = time.strftime("%F %T")
        try:
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(redact(json.dumps(kw, ensure_ascii=False)) + "\n")
        except OSError:
            pass


def system_prompt(root: Path, cfg: dict) -> str:
    s = f"""你是运行在用户终端里的编程助手。工作目录：{root}（系统：{platform.system()}）。
你通过工具读写文件、运行命令来完成用户需求。规则：
1. 多步骤任务先用 2-5 行说明计划，再动手；简单任务直接做。
2. 先读相关文件再修改；小改动用 edit_file，不要整文件重写；改完尽量运行测试或脚本验证。
3. 路径用相对路径，只能访问工作目录；不要访问 .env、密钥文件，不要打印环境变量。
4. 不要执行 git commit/push/checkout 等；任务结束后系统会自动提交到新分支并创建 PR。
5. 命令必须非交互，{cfg['agent']['command_timeout']} 秒超时；耗时任务请拆开。
6. 完成后用简短文字总结：做了什么、改了哪些文件、如何验证。用户用什么语言，你就用什么语言回答。"""
    md = root / "AGENT.md"
    if md.is_file():
        s += "\n\n项目约定（来自 AGENT.md）：\n" + decode_text(md.read_bytes())[0][:4000]
    return s


def compact(messages: list, limit: int, keep: int = 12) -> None:
    """上下文过长时，把较早的工具输出替换成占位符。"""
    if sum(len(m.get("content") or "") for m in messages) <= limit:
        return
    for m in messages[:-keep]:
        if m["role"] == "tool" and len(m["content"]) > 200:
            m["content"] = "[较早的工具输出已省略以节省上下文]"


def fmt_args(args: dict) -> str:
    return " ".join(f"{k}={str(v).replace(chr(10), ' ')[:60]!r}" for k, v in args.items())


class Agent:
    def __init__(self, cfg: dict, root, model=None, no_pr: bool = False):
        self.cfg = cfg
        self.ws = Workspace(root)
        self.model = model or Model(cfg)
        self.tools = Tools(self.ws, cfg)
        self.log = Log(self.ws.root)
        self.git = Git(self.ws.root)
        self.use_git = self.git.is_repo()
        self.pr_on = cfg["github"]["enabled"] and not no_pr
        self.messages = [{"role": "system", "content": system_prompt(self.ws.root, cfg)}]
        self.undo_stack: list[dict] = []
        self.start_branch = ""
        if self.use_git:
            try:
                self.start_branch = self.git.run("rev-parse", "--abbrev-ref", "HEAD")
                excl = self.ws.root / self.git.run("rev-parse", "--git-path", "info/exclude")
                if ".agent/" not in (excl.read_text(encoding="utf-8") if excl.exists() else ""):
                    excl.parent.mkdir(parents=True, exist_ok=True)
                    with open(excl, "a", encoding="utf-8") as f:
                        f.write("\n.agent/\n")
            except (GitError, OSError):
                pass

    def dirty(self) -> bool:
        return self.use_git and bool(self.git.run("status", "--porcelain"))

    # ---------------------------------------------------- 任务循环
    def run_task(self, request: str) -> None:
        max_steps = self.cfg["agent"]["max_steps"]
        snap = len(self.messages)
        self.messages.append({"role": "user", "content": request})
        summary, recent = "", []
        try:
            for _ in range(max_steps):
                compact(self.messages, self.cfg["agent"]["max_context_chars"])
                reply = self.model.chat(self.messages)
                msg = {"role": "assistant", "content": reply.content}
                if reply.reasoning:
                    msg["reasoning_content"] = reply.reasoning
                if reply.tool_calls:
                    msg["tool_calls"] = [{"id": t["id"], "type": "function",
                                          "function": {"name": t["name"], "arguments": t["args"]}} for t in
                                         reply.tool_calls]
                self.messages.append(msg)
                if not reply.tool_calls:
                    summary = reply.content
                    break
                for tc in reply.tool_calls:
                    self.messages.append(
                        {"role": "tool", "tool_call_id": tc["id"], "content": self.exec_tool(tc, recent)})
            else:
                print(yellow(f"\n已达到最大步数 {max_steps}，任务暂停；输入“继续”可接着做。"))
                summary = "(达到最大步数，任务可能未完成)"
        except KeyboardInterrupt:
            del self.messages[snap:]
            self.messages.append(
                {"role": "user", "content": "[系统提示] 上一个任务被用户中断，已完成的文件改动仍保留在磁盘上。"})
            print(yellow("\n已中断当前任务（文件改动保留，未提交 PR）。"))
            return
        except ModelError as e:
            print(red("\n" + str(e)))
            print(dim("已完成的步骤保留，修复问题后输入“继续”即可接着做。"))
            return
        self.finish_task(request, summary)

    def exec_tool(self, tc: dict, recent: list) -> str:
        name, raw = tc["name"], tc["args"] or "{}"
        try:
            args = json.loads(raw)
            if not isinstance(args, dict):
                raise ValueError
        except ValueError:
            result, args = "错误：参数不是合法的 JSON 对象，请重新调用", {}
        else:
            print(dim("→ ") + cyan(name) + dim(" " + fmt_args(args)))
            recent.append((name, raw))
            if recent[-3:] == [(name, raw)] * 3:
                result = "错误：你已连续 3 次用相同参数调用同一工具，请换个方法，或直接向用户说明情况"
            else:
                result = self.tools.call(name, args)
        if result.startswith("错误："):
            print(red("  ✗ " + result[:200]))
        elif name == "run_command":
            print(dim("\n".join("  " + ln for ln in result.splitlines()[:12])))
        self.log.write(tool=name, args=json.dumps(args, ensure_ascii=False)[:500], ok=not result.startswith("错误："),
                       result_len=len(result))
        return redact(result)

    # ---------------------------------------------------- 提交 + PR
    def finish_task(self, request: str, summary: str) -> None:
        if not self.use_git:
            return
        g = self.git
        try:
            if not g.run("status", "--porcelain"):
                print(dim("\n本次没有文件改动，不提 PR。"))
                return
            prev = g.run("rev-parse", "--abbrev-ref", "HEAD")
            if prev == "HEAD":
                print(yellow("\n当前是游离 HEAD，跳过自动提交。"))
                return
            base_name, n = time.strftime("agent/%Y%m%d-%H%M%S"), 1
            branch = base_name
            while g.exists(branch):
                n += 1
                branch = f"{base_name}-{n}"
            title = "[agent] " + " ".join(request.split())[:60]
            g.run("checkout", "-b", branch)
            g.run("add", "-A")
            for f in g.run("diff", "--cached", "--name-only").splitlines():
                if is_secret_path(Path(f)):
                    g.run("reset", "-q", "--", f)
                    print(yellow(f"已排除敏感文件：{f}"))
            if not g.run("diff", "--cached", "--name-only"):
                print(yellow("没有可提交的内容。"))
                return
            g.run("commit", "-m", title, "-m", "由 my-agent 自动提交\n\n" + request[:1000])
        except GitError as e:
            print(red(f"\n自动提交失败：{e}"))
            print(dim("若提示缺少用户信息，请先执行 git config user.name / user.email。"))
            return
        print(green(f"\n✔ 已提交到分支 {branch}"))
        entry = {"branch": branch, "prev": prev, "msgs": len(self.messages) - self._task_len(request), "pushed": False}
        self.undo_stack.append(entry)
        if self.pr_on:
            self.push_and_pr(entry, title, request, summary)

    def _task_len(self, request: str) -> int:
        for i in range(len(self.messages) - 1, -1, -1):
            if self.messages[i]["role"] == "user" and self.messages[i]["content"] == request:
                return len(self.messages) - i
        return 0

    def push_and_pr(self, entry: dict, title: str, request: str, summary: str) -> None:
        gc, g = self.cfg["github"], self.git
        branch, prev = entry["branch"], entry["prev"]
        try:
            info = parse_github(g.run("remote", "get-url", gc["remote"]))
            if not info:
                print(yellow(f"远程 {gc['remote']} 不是 GitHub 地址，已保留本地分支，未推送。"))
                return
            token = os.environ.get(gc["token_env"])
            if not token:
                print(yellow(f"未设置环境变量 {gc['token_env']}，已保留本地分支，未推送、未提 PR。"))
                return
            g.run("push", "-u", gc["remote"], branch, timeout=120)
            entry["pushed"] = True
            base = prev if gc["stack"] else (gc["base_branch"] or self.start_branch)
            stat = g.run("show", "--stat", "--format=", "HEAD")
            body = f"**需求**\n\n{request}\n\n**agent 总结**\n\n{summary[:3000]}\n\n**改动**\n\n```\n{stat}\n```\n\n> 由 my-agent 自动创建"
            url = create_pr(info[0], info[1], token, title, branch, base, body)
            print(green(f"✔ 已创建 PR（{branch} → {base}）：{url}"))
        except GitError as e:
            print(red(f"推送/创建 PR 失败：{e}"))
            print(dim("分支已在本地保留；检查 GitHub 推送权限和 GITHUB_TOKEN 的 Pull requests 写入权限。"))

    def undo(self) -> None:
        if not self.undo_stack:
            print("没有可撤销的任务。")
            return
        u = self.undo_stack.pop()
        try:
            self.git.run("checkout", u["prev"])
            self.git.run("branch", "-D", u["branch"])
        except GitError as e:
            print(red(f"撤销失败：{e}"))
            self.undo_stack.append(u)
            return
        del self.messages[u["msgs"]:]
        print(green(f"已回到分支 {u['prev']}，并删除本地分支 {u['branch']}。"))
        if u["pushed"]:
            print(yellow("远程分支和 PR 仍在，请到 GitHub 手动关闭。"))


# ============================================================ 命令行界面
HELP = "/help 帮助   /undo 撤销上一个任务的分支   /clear 清空对话   /exit 退出   Ctrl+C 中断当前任务"


def main() -> int:
    if os.name == "nt":
        os.system("")  # 启用 ANSI 颜色
    for s in (sys.stdout, sys.stderr):
        try:
            s.reconfigure(encoding="utf-8")
        except Exception:
            pass
    ap = argparse.ArgumentParser(description="本地终端编程 agent")
    ap.add_argument("--workspace", "-w", default=".", help="工作目录（默认当前目录）")
    ap.add_argument("--config", help="配置文件路径（默认 ./agent.toml）")
    ap.add_argument("--no-pr", action="store_true", help="本次不推送、不提 PR（仍会本地提交）")
    a = ap.parse_args()

    cfg = load_config(a.config)
    root = Path(a.workspace).resolve()
    if not root.is_dir():
        print(red(f"工作目录不存在：{root}"))
        return 1
    try:
        agent = Agent(cfg, root, no_pr=a.no_pr)
    except ModelError as e:
        print(red(str(e)))
        return 1

    print(f"工作目录：{root}\n模型：{cfg['model']['name']}  |  最大步数：{cfg['agent']['max_steps']}  |  "
          f"提 PR：{'开' if agent.use_git and agent.pr_on else '关'}")
    if not agent.use_git:
        print(yellow("⚠ 这里不是 git 仓库：无法回滚，也不会提 PR。建议先 git init 并关联 GitHub 远程。"))
    elif agent.dirty() and input(
            yellow("⚠ 工作区有未提交改动，会被一并提交进第一个 PR。继续？[y/N] ")).strip().lower() != "y":
        return 0
    print(dim(HELP))
    while True:
        try:
            line = input(_c("\n> ", "1;32")).strip()
        except EOFError:
            break
        except KeyboardInterrupt:
            print(dim("\n（输入 /exit 退出）"))
            continue
        if not line:
            continue
        if line in ("/exit", "/quit", "exit", "quit"):
            break
        if line == "/help":
            print(HELP)
        elif line == "/clear":
            agent.messages = agent.messages[:1]
            print("对话已清空。")
        elif line == "/undo":
            agent.undo()
        else:
            agent.run_task(line)
    return 0


if __name__ == "__main__":
    sys.exit(main())

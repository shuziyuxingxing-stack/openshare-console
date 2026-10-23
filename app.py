"""Exposure Console — a local-only controller for safe sharing paths.

This intentionally contains no cloud credentials. It detects what is usable,
starts a read-only local file service, and only invokes a tunnel after the user
has supplied the provider-specific details in the browser and confirmed it.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import secrets
import shutil
import socket
import ssl
import subprocess
import sys
import threading
import time
import urllib.request
import urllib.parse
from urllib.error import HTTPError, URLError
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


ROOT = Path(__file__).resolve().parent
WEB = ROOT / "web"
RUNTIME = ROOT / "runtime"
FILE_SERVER = ROOT / "file_server.py"
RUNTIME.mkdir(exist_ok=True)
CF_HOME = Path.home() / ".cloudflared"
CF_PERSIST = Path(os.environ.get("LOCALAPPDATA", str(Path.home() / "AppData" / "Local"))) / "ExposureConsole" / "cloudflared"
CF_MANIFEST = CF_PERSIST / "managed-tunnels.json"
FRP_TOKEN_STORE = CF_PERSIST / "frp-token.dpapi"
CF_PERSIST.mkdir(parents=True, exist_ok=True)

PROCESS_LOCK = threading.Lock()
PROCESSES: dict[str, subprocess.Popen[bytes]] = {}
PROCESS_META: dict[str, dict[str, Any]] = {}


def powershell(script: str) -> tuple[bool, str]:
    try:
        done = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True,
            text=True,
            timeout=12,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        return done.returncode == 0, done.stdout.strip() or done.stderr.strip()
    except Exception as exc:  # Diagnostics must never prevent the UI loading.
        return False, str(exc)


def command_path(name: str, known_paths: list[str] | None = None) -> str | None:
    found = shutil.which(name)
    if found:
        return found
    for candidate in known_paths or []:
        if Path(candidate).is_file():
            return candidate
    return None


def downloads_directory() -> Path:
    """Return Windows' configured Downloads folder, with a safe fallback."""
    fallback = Path.home() / "Downloads"
    if os.name != "nt":
        return fallback
    try:
        done = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "[Environment]::ExpandEnvironmentVariables((Get-ItemProperty "
                "'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders' "
                "-Name '{374DE290-123F-4565-9164-39C4925E467B}').'"
                "{374DE290-123F-4565-9164-39C4925E467B}')",
            ],
            capture_output=True,
            text=True,
            timeout=5,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        candidate = Path(done.stdout.strip())
        if done.returncode == 0 and candidate.is_dir():
            return candidate
    except Exception:
        pass
    return fallback


def frpc_path() -> str | None:
    """Find frpc on PATH or in the user's extracted FRP download folders."""
    found = command_path("frpc.exe")
    if found:
        return found
    downloads = downloads_directory()
    candidates = [downloads / "frpc.exe"]
    if downloads.is_dir():
        candidates.extend(downloads.glob("frp*/frpc.exe"))
        candidates.extend(downloads.glob("frp*/**/frpc.exe"))
    for candidate in candidates:
        if candidate.is_file():
            return str(candidate)
    return None


def caddy_path() -> str | None:
    """Find Caddy on PATH or in conventional extracted Downloads folders."""
    found = command_path("caddy.exe", [r"C:\Program Files\Caddy\caddy.exe", r"C:\caddy\caddy.exe"])
    if found:
        return found
    downloads = downloads_directory()
    candidates = [downloads / "caddy.exe"]
    if downloads.is_dir():
        candidates.extend(downloads.glob("caddy*/caddy.exe"))
        candidates.extend(downloads.glob("caddy*/**/caddy.exe"))
    for candidate in candidates:
        if candidate.is_file():
            return str(candidate)
    return None


def output_text(value: Any) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value or "")


def dpapi_protect(value: str) -> str:
    """Encrypt a secret for this Windows user without exposing it in arguments."""
    script = (
        "Add-Type -AssemblyName System.Security; "
        "$value = [Console]::In.ReadToEnd(); "
        "if ([string]::IsNullOrWhiteSpace($value)) { exit 2 }; "
        "$bytes = [Text.Encoding]::UTF8.GetBytes($value); "
        "[Convert]::ToBase64String([Security.Cryptography.ProtectedData]::Protect("
        "$bytes, $null, [Security.Cryptography.DataProtectionScope]::CurrentUser))"
    )
    done = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
        input=value,
        capture_output=True,
        text=True,
        timeout=10,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if done.returncode != 0 or not done.stdout.strip():
        raise ValueError("无法使用 Windows 用户加密保存 FRP token。")
    return done.stdout.strip()


def dpapi_unprotect(value: str) -> str:
    script = (
        "Add-Type -AssemblyName System.Security; "
        "$protected = [Console]::In.ReadToEnd(); "
        "$bytes = [Security.Cryptography.ProtectedData]::Unprotect("
        "[Convert]::FromBase64String($protected), $null, "
        "[Security.Cryptography.DataProtectionScope]::CurrentUser); "
        "[Text.Encoding]::UTF8.GetString($bytes)"
    )
    done = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
        input=value,
        capture_output=True,
        text=True,
        timeout=10,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if done.returncode != 0:
        raise ValueError("保存的 FRP token 无法解密；请重新配对。")
    return done.stdout.rstrip("\r\n")


def save_frp_token(token: str) -> None:
    protected = dpapi_protect(token)
    temporary = FRP_TOKEN_STORE.with_suffix(".new")
    temporary.write_text(protected, encoding="utf-8")
    temporary.replace(FRP_TOKEN_STORE)


def load_frp_token() -> str | None:
    if not FRP_TOKEN_STORE.is_file():
        return None
    try:
        token = dpapi_unprotect(FRP_TOKEN_STORE.read_text(encoding="utf-8"))
        return token or None
    except (OSError, ValueError):
        return None


def frp_pair(payload: dict[str, Any]) -> dict[str, str]:
    token = str(payload.get("token") or "")
    if len(token) < 24:
        raise ValueError("FRP token 至少应为 24 个字符。")
    save_frp_token(token)
    return {"message": "FRP token 已为当前 Windows 用户加密保存；之后可留空。"}


def validate_server_host(value: Any) -> str:
    host = str(value or "").strip()
    if not host or len(host) > 253:
        raise ValueError("请填写有效的 VPS IP 或主机名。")
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        if re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?", host):
            return host
    raise ValueError("VPS 地址格式无效。")


def ssh_run(client: Any, command: str, stdin_data: str | None = None, timeout: int = 240) -> str:
    stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
    if stdin_data is not None:
        stdin.write(stdin_data)
        stdin.channel.shutdown_write()
    else:
        stdin.close()
    output = output_text(stdout.read()).strip()
    error = output_text(stderr.read()).strip()
    if stdout.channel.recv_exit_status() != 0:
        # Remote output never includes the SSH password or generated token.
        raise ValueError(error or output or "VPS 执行 FRP 初始化失败。")
    return output


def frp_bootstrap(payload: dict[str, Any]) -> dict[str, str]:
    """Install/configure frps once, then retain only a DPAPI-protected client token."""
    host = validate_server_host(payload.get("serverAddr"))
    password = str(payload.get("sshPassword") or "")
    if not password:
        raise ValueError("首次初始化需要 VPS root 的一次性 SSH 密码。")
    try:
        import paramiko
    except ImportError as exc:
        raise ValueError("当前控制台缺少 SSH 初始化组件。") from exc

    token = secrets.token_urlsafe(32)
    config = (
        "bindPort = 7000\n\n"
        "[transport]\n"
        "tls.force = true\n\n"
        "[auth]\n"
        "method = \"token\"\n"
        f"token = {json.dumps(token)}\n"
    )
    install_script = """set -eu
if ! command -v frps >/dev/null 2>&1; then
  workdir=/tmp/exposure-console-frp-0.71.1
  mkdir -p "$workdir"
  curl -fL --retry 3 --connect-timeout 15 -o "$workdir/frp.tar.gz" https://ghfast.top/https://github.com/fatedier/frp/releases/download/v0.71.1/frp_0.71.1_linux_amd64.tar.gz
  echo '1d9875210972a5d1a62b2dc4c48df45ab0af05d3ca1b5e494a014428259df803  '"$workdir"'/frp.tar.gz' | sha256sum -c -
  mkdir -p "$workdir/extracted"
  tar -xzf "$workdir/frp.tar.gz" -C "$workdir/extracted" --strip-components=1
  install -Dm755 "$workdir/extracted/frps" /usr/local/bin/frps
fi
install -d -m 700 /etc/frp
if [ ! -f /etc/systemd/system/frps.service ]; then
  cat >/etc/systemd/system/frps.service <<'UNIT'
[Unit]
Description=FRP Server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/frps -c /etc/frp/frps.toml
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=true

[Install]
WantedBy=multi-user.target
UNIT
fi
systemctl daemon-reload
"""
    write_config = "cat >/etc/frp/frps.toml && chmod 600 /etc/frp/frps.toml"
    restart_service = "/usr/local/bin/frps verify -c /etc/frp/frps.toml && systemctl enable --now frps && systemctl restart frps && systemctl is-active --quiet frps"
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(hostname=host, username="root", password=password, timeout=15, auth_timeout=15, banner_timeout=15, look_for_keys=False, allow_agent=False)
        ssh_run(client, install_script, timeout=360)
        ssh_run(client, write_config, stdin_data=config)
        ssh_run(client, restart_service)
    except Exception as exc:
        if isinstance(exc, ValueError):
            raise
        raise ValueError("无法通过 SSH 初始化 VPS；请确认 IP、root 密码、22 端口与网络状态。") from exc
    finally:
        client.close()
    save_frp_token(token)
    return {"message": "VPS 已初始化：frps 已启用，新的 token 已加密保存到当前 Windows 用户。后续无需填写 token。"}


def find_tools() -> dict[str, dict[str, Any]]:
    tools = {
        "tailscale": command_path("tailscale.exe", [r"C:\Program Files\Tailscale\tailscale.exe"]),
        "cloudflared": command_path("cloudflared.exe", [r"C:\Program Files (x86)\cloudflared\cloudflared.exe"]),
        "frpc": frpc_path(),
        "caddy": caddy_path(),
    }
    return {name: {"installed": bool(path), "path": path} for name, path in tools.items()}


def json_powershell(script: str) -> Any:
    ok, value = powershell(script)
    if not ok or not value:
        return []
    try:
        parsed = json.loads(value)
        return parsed if isinstance(parsed, list) else [parsed]
    except json.JSONDecodeError:
        return []


def probe() -> dict[str, Any]:
    addresses = json_powershell(
        "Get-NetIPAddress -AddressFamily IPv6 -ErrorAction SilentlyContinue | "
        "Select-Object InterfaceAlias,IPAddress,PrefixLength,AddressState | ConvertTo-Json -Compress"
    )
    routes = json_powershell(
        "Get-NetRoute -AddressFamily IPv6 -DestinationPrefix '::/0' -ErrorAction SilentlyContinue | "
        "Select-Object InterfaceAlias,NextHop,RouteMetric,State | ConvertTo-Json -Compress"
    )
    global_v6: list[dict[str, Any]] = []
    for address in addresses:
        try:
            ip = ipaddress.ip_address(address.get("IPAddress", ""))
            if ip.version == 6 and ip.is_global and address.get("AddressState") in ("Preferred", 4):
                global_v6.append(address)
        except ValueError:
            continue
    tools = find_tools()
    tailnet: dict[str, Any] = {"loggedIn": False, "dnsName": None, "serveConfigured": False, "funnelConfigured": False, "servePort": None, "serveTarget": None}
    if tools["tailscale"]["path"]:
        try:
            done = subprocess.run(
                [str(tools["tailscale"]["path"]), "status", "--json"],
                capture_output=True,
                text=True,
                timeout=8,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            if done.returncode == 0:
                data = json.loads(done.stdout)
                tailnet = {"loggedIn": bool(data.get("BackendState") == "Running"), "dnsName": data.get("Self", {}).get("DNSName"), "serveConfigured": False, "funnelConfigured": False, "servePort": None, "serveTarget": None}
                serve_status = subprocess.run([str(tools["tailscale"]["path"]), "serve", "status"], capture_output=True, text=True, timeout=8, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
                funnel_status = subprocess.run([str(tools["tailscale"]["path"]), "funnel", "status"], capture_output=True, text=True, timeout=8, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
                tailnet["serveConfigured"] = bool(serve_status.stdout.strip() and "No serve config" not in serve_status.stdout)
                tailnet["funnelConfigured"] = bool(funnel_status.stdout.strip() and "No serve config" not in funnel_status.stdout)
                serve_match = re.search(r"proxy\s+http://(?:127\.0\.0\.1|localhost):(\d+)", serve_status.stdout)
                if serve_match:
                    tailnet["servePort"] = int(serve_match.group(1))
                    tailnet["serveTarget"] = f"127.0.0.1:{serve_match.group(1)}"
        except Exception:
            pass
    return {
        "checkedAt": time.strftime("%Y-%m-%d %H:%M:%S"),
        "ipv6": {
            "globalAddresses": global_v6,
            "defaultRoutes": routes,
            "available": bool(global_v6 and routes),
            "message": "检测到可公网路由的 IPv6。" if global_v6 and routes else "未检测到公网 IPv6 或 IPv6 默认路由；不能使用原生 IPv6 直连。",
        },
        "tools": tools,
        "frp": {"tokenSaved": bool(load_frp_token())},
        "tailscale": tailnet,
        "processes": process_status(),
    }


def process_status() -> list[dict[str, Any]]:
    with PROCESS_LOCK:
        stale = [key for key, proc in PROCESSES.items() if proc.poll() is not None]
        for key in stale:
            config_path = PROCESS_META.get(key, {}).get("configPath")
            if config_path and PROCESS_META.get(key, {}).get("cleanupConfig", True):
                Path(config_path).unlink(missing_ok=True)
            PROCESSES.pop(key, None)
            PROCESS_META.pop(key, None)
        return [{"id": key, **meta} for key, meta in PROCESS_META.items()]


def free_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def validate_directory(value: Any) -> Path:
    path = Path(str(value or "")).expanduser().resolve()
    if not path.is_dir():
        raise ValueError("请选择一个存在的文件夹。")
    return path


def launch(name: str, args: list[str], meta: dict[str, Any], env: dict[str, str] | None = None) -> None:
    with PROCESS_LOCK:
        if name in PROCESSES and PROCESSES[name].poll() is None:
            raise ValueError("此路径已经在运行。请先停止后再重新启动。")
        merged_env = os.environ.copy()
        if env:
            merged_env.update(env)
        proc = subprocess.Popen(
            args,
            cwd=str(ROOT),
            env=merged_env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        PROCESSES[name] = proc
        PROCESS_META[name] = {"pid": proc.pid, "startedAt": time.strftime("%Y-%m-%d %H:%M:%S"), **meta}


USER_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.@-]{0,63}")
FILE_PERMISSIONS = ("read", "modify", "upload", "delete")


def atomic_json_write(path: Path, payload: Any) -> None:
    temporary = path.with_suffix(path.suffix + ".new")
    temporary.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    temporary.replace(path)


def validate_file_user(payload: dict[str, Any]) -> dict[str, Any]:
    user_id = str(payload.get("id") or payload.get("username") or "").strip()
    password = str(payload.get("password") or "")
    if not USER_ID_RE.fullmatch(user_id):
        raise ValueError("用户 ID 仅允许字母、数字、点、下划线、连字符和 @，长度 1–64。")
    if len(password) < 12:
        raise ValueError("每个用户的密码至少需要 12 位。")
    supplied = payload.get("permissions") or {}
    permissions = {permission: bool(supplied.get(permission, False)) for permission in FILE_PERMISSIONS}
    if not permissions["read"]:
        raise ValueError("文件用户至少需要“读取”权限，否则无法使用文件站。")
    return {"id": user_id, "password": password, "permissions": permissions}


def active_file_service() -> tuple[Path, Path]:
    with PROCESS_LOCK:
        proc = PROCESSES.get("file-service")
        meta = PROCESS_META.get("file-service", {})
        if not proc or proc.poll() is not None:
            raise ValueError("请先启动本地文件服务。")
        users_path = Path(str(meta.get("configPath") or ""))
        access_log = Path(str(meta.get("accessLogPath") or ""))
    if not users_path.is_file():
        raise ValueError("当前文件服务没有可管理的用户配置；请重新启动文件服务。")
    return users_path, access_log


def load_file_users() -> tuple[list[dict[str, Any]], Path]:
    users_path, _ = active_file_service()
    try:
        users = json.loads(users_path.read_text(encoding="utf-8")).get("users", [])
    except (OSError, json.JSONDecodeError):
        raise ValueError("读取用户配置失败。")
    return (users if isinstance(users, list) else []), users_path


def file_users() -> dict[str, Any]:
    users, _ = load_file_users()
    return {"users": users, "note": "密码以明文显示，仅在本机控制台和当前文件服务会话中保存。"}


def add_file_user(payload: dict[str, Any]) -> dict[str, str]:
    user = validate_file_user(payload)
    users, users_path = load_file_users()
    if any(item.get("id") == user["id"] for item in users):
        raise ValueError("该用户 ID 已存在。")
    users.append(user)
    atomic_json_write(users_path, {"users": users})
    return {"message": f"已添加用户：{user['id']}。权限立即生效。"}


def update_file_user(payload: dict[str, Any]) -> dict[str, str]:
    user = validate_file_user(payload)
    users, users_path = load_file_users()
    for index, item in enumerate(users):
        if item.get("id") == user["id"]:
            users[index] = user
            atomic_json_write(users_path, {"users": users})
            return {"message": f"已更新用户：{user['id']}。权限立即生效。"}
    raise ValueError("找不到该用户。")


def delete_file_user(payload: dict[str, Any]) -> dict[str, str]:
    user_id = str(payload.get("id") or "").strip()
    users, users_path = load_file_users()
    remaining = [item for item in users if item.get("id") != user_id]
    if len(remaining) == len(users):
        raise ValueError("找不到该用户。")
    if not remaining:
        raise ValueError("不能删除最后一个用户；请至少保留一个可读取的账号。")
    atomic_json_write(users_path, {"users": remaining})
    return {"message": f"已删除用户：{user_id}。该账号的后续请求将被拒绝。"}


def file_access_records() -> dict[str, Any]:
    _, access_log = active_file_service()
    records: list[dict[str, Any]] = []
    try:
        if access_log.is_file():
            for line in access_log.read_text(encoding="utf-8").splitlines()[-500:]:
                try:
                    record = json.loads(line)
                    if isinstance(record, dict):
                        records.append(record)
                except json.JSONDecodeError:
                    continue
    except OSError:
        raise ValueError("读取访问记录失败。")
    return {"records": list(reversed(records))}


def start_file_service(payload: dict[str, Any], bind: str = "127.0.0.1") -> dict[str, Any]:
    directory = validate_directory(payload.get("directory"))
    username = str(payload.get("username") or "share")
    password = str(payload.get("password") or "")
    initial_user = validate_file_user({"id": username, "password": password, "permissions": {"read": True}})
    requested_port = payload.get("port")
    port = int(requested_port) if requested_port else free_loopback_port()
    service_id = "file-service" if bind == "127.0.0.1" else "ipv6-file-service"
    users_path = RUNTIME / f"{service_id}-users.json"
    access_log = RUNTIME / f"{service_id}-access.jsonl"
    atomic_json_write(users_path, {"users": [initial_user]})
    access_log.unlink(missing_ok=True)
    args = [sys.executable, str(FILE_SERVER), "--directory", str(directory), "--port", str(port), "--bind", bind, "--users-path", str(users_path), "--access-log", str(access_log)]
    launch(service_id, args, {"kind": "文件服务（默认只读）", "address": f"http://{'[::]' if bind == '::' else bind}:{port}", "directory": str(directory), "configPath": str(users_path), "accessLogPath": str(access_log)})
    # Give the child process a short chance to bind so an invalid path/port is surfaced early.
    time.sleep(0.25)
    with PROCESS_LOCK:
        proc = PROCESSES[service_id]
        if proc.poll() is not None:
            PROCESSES.pop(service_id, None)
            PROCESS_META.pop(service_id, None)
            raise ValueError("文件服务未能启动，请检查端口和目录权限。")
    return {"serviceId": service_id, "port": port, "localUrl": f"http://127.0.0.1:{port}", "message": "只读文件服务已在本机启动。"}


def stop_service(service_id: str) -> dict[str, str]:
    with PROCESS_LOCK:
        proc = PROCESSES.get(service_id)
        if not proc:
            raise ValueError("找不到正在运行的服务。")
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        PROCESSES.pop(service_id, None)
        meta = PROCESS_META.pop(service_id, {})
        config_path = meta.get("configPath")
        if config_path and meta.get("cleanupConfig", True):
            Path(config_path).unlink(missing_ok=True)
    return {"message": "服务已停止。"}


def require_local_port(payload: dict[str, Any]) -> int:
    port = int(payload.get("localPort") or 0)
    if not 1 <= port <= 65535:
        raise ValueError("请先启动文件服务，或填写一个有效的本地端口。")
    return port


def tailscale_serve(payload: dict[str, Any], public: bool) -> dict[str, str]:
    tool = find_tools()["tailscale"]["path"]
    if not tool:
        raise ValueError("未找到 Tailscale 客户端。")
    port = require_local_port(payload)
    current = subprocess.run([str(tool), "serve", "status"], capture_output=True, text=True, timeout=10, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    current_output = "\n".join(part for part in (current.stdout, current.stderr) if part).strip()
    existing_match = re.search(r"proxy\s+http://(?:127\.0\.0\.1|localhost):(\d+)", current_output)
    existing_port = int(existing_match.group(1)) if existing_match else None
    replace_existing = bool(payload.get("replaceExisting"))
    if current.returncode != 0:
        raise ValueError(current_output or "读取 Tailscale Serve 配置失败。")
    if existing_port and existing_port != port and not replace_existing:
        raise ValueError(f"当前 Serve 正在转发到 127.0.0.1:{existing_port}，但当前文件服务是 127.0.0.1:{port}。请点击“更新 Serve 到当前文件服务”，不要重复创建。")
    if current_output and "No serve config" not in current_output and replace_existing:
        reset = subprocess.run([str(tool), "serve", "reset"], capture_output=True, text=True, timeout=15, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        if reset.returncode != 0:
            reset_output = "\n".join(part for part in (reset.stdout, reset.stderr) if part).strip()
            raise ValueError(reset_output or "无法清理旧的 Tailscale Serve 配置。")
    # Serve config is owned by Tailscale; no sensitive material is stored by this console.
    command = [str(tool), "serve", "--bg", f"http://127.0.0.1:{port}"]
    try:
        done = subprocess.run(command, capture_output=True, text=True, timeout=8, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except subprocess.TimeoutExpired as exc:
        detail = "\n".join(output_text(part) for part in (exc.stdout, exc.stderr)).strip()
        if "Serve is not enabled" in detail:
            raise ValueError(f"Tailscale tailnet 尚未启用 Serve。请先打开管理授权地址：{detail}")
        raise ValueError(f"Tailscale Serve 等待超时。{detail or '请确认客户端正在运行并重试。'}")
    output = "\n".join(output_text(part) for part in (done.stdout, done.stderr) if part).strip()
    if "Serve is not enabled" in output:
        raise ValueError(f"Tailscale tailnet 尚未启用 Serve。请先打开管理授权地址：{output}")
    if done.returncode != 0:
        raise ValueError(output or "Tailscale Serve 配置失败，请确认已登录 tailnet。")
    if public:
        try:
            done = subprocess.run([str(tool), "funnel", "--bg", f"http://127.0.0.1:{port}"], capture_output=True, text=True, timeout=8, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        except subprocess.TimeoutExpired as exc:
            detail = "\n".join(output_text(part) for part in (exc.stdout, exc.stderr)).strip()
            raise ValueError(f"Tailscale Funnel 等待超时。{detail or '请确认 tailnet 管理员已允许 Funnel。'}")
        output = "\n".join(output_text(part) for part in (done.stdout, done.stderr) if part).strip()
        if "Funnel is not enabled" in output:
            raise ValueError(f"Tailscale tailnet 尚未启用 Funnel。请先打开管理授权地址：{output}")
        if done.returncode != 0:
            raise ValueError(output or "Funnel 开启失败。请确认 tailnet 管理员已授权 Funnel。")
    dns_name = str(probe().get("tailscale", {}).get("dnsName") or "").rstrip(".")
    url = f"https://{dns_name}" if dns_name else "请运行 tailscale status 获取设备 DNS 名称"
    return {"message": "Tailscale " + ("Funnel 已开启，链接对互联网公开。" if public else "Serve 已开启，仅 tailnet 成员可访问。"), "url": url, "audience": "互联网访客" if public else "同一 tailnet 的成员"}


def cloudflare_tunnel(payload: dict[str, Any]) -> dict[str, str]:
    tool = find_tools()["cloudflared"]["path"]
    token = str(payload.get("token") or "").strip()
    if not tool:
        raise ValueError("未找到 cloudflared，请先安装 Cloudflare Tunnel 客户端。")
    if not token:
        raise ValueError("需要粘贴 Cloudflare Tunnel token；本控制台不会保存它。")
    port = require_local_port(payload)
    token_path = RUNTIME / "cloudflare-token.txt"
    token_path.write_text(token, encoding="utf-8")
    launch("cloudflare-tunnel", [str(tool), "tunnel", "--no-autoupdate", "run", "--token-file", str(token_path)], {"kind": "Cloudflare Tunnel", "address": f"127.0.0.1:{port}", "configPath": str(token_path)})
    return {"message": "Cloudflare Tunnel 进程已启动。请在 Cloudflare Zero Trust 中把 Public Hostname 指向该 tunnel 与本地服务。"}


def cf_identifier(value: Any, label: str) -> str:
    candidate = str(value or "").strip().lower()
    if not re.fullmatch(r"[a-f0-9]{32}", candidate):
        raise ValueError(f"{label}应为 Cloudflare 控制台中显示的 32 位十六进制 ID。")
    return candidate


def cf_hostname(value: Any) -> str:
    hostname = str(value or "").strip().lower().rstrip(".")
    if len(hostname) > 253 or not re.fullmatch(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", hostname):
        raise ValueError("请填写完整的公开域名，例如 files.example.com。")
    return hostname


class CloudflareTransportError(ValueError):
    """A retryable failure occurred before Cloudflare returned an API result."""


def cf_api(token: str, method: str, path: str, payload: dict[str, Any] | None = None) -> Any:
    """Call Cloudflare without persisting the token; retry safe transient calls."""
    body = json.dumps(payload).encode("utf-8") if payload is not None else None
    method = method.upper()
    # GET/PUT/DELETE are safe to repeat. POST may have succeeded remotely even
    # when its response was reset, so callers reconcile POST results instead.
    attempts = 3 if method in {"GET", "PUT", "DELETE"} else 1
    decoded: dict[str, Any] | None = None
    for attempt in range(attempts):
        request = urllib.request.Request(
            f"https://api.cloudflare.com/client/v4{path}",
            data=body,
            method=method,
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                decoded = json.loads(response.read().decode("utf-8"))
            break
        except HTTPError as exc:
            retryable = exc.code in {408, 429} or 500 <= exc.code <= 599
            if retryable and attempt + 1 < attempts:
                time.sleep(attempt + 1)
                continue
            try:
                error_body = json.loads(exc.read().decode("utf-8"))
                detail = "; ".join(str(item.get("message", "未知错误")) for item in error_body.get("errors", []))
            except Exception:
                detail = f"HTTP {exc.code}"
            raise ValueError(f"Cloudflare API 拒绝了此操作：{detail or f'HTTP {exc.code}'}。") from exc
        except (URLError, TimeoutError, ConnectionResetError, ssl.SSLError, OSError) as exc:
            if attempt + 1 < attempts:
                time.sleep(attempt + 1)
                continue
            detail = exc.reason if isinstance(exc, URLError) else exc
            suffix = f"；已自动重试 {attempts} 次" if attempts > 1 else ""
            raise CloudflareTransportError(f"无法连接 Cloudflare API：{detail}{suffix}。") from exc
    if decoded is None:
        raise CloudflareTransportError("无法连接 Cloudflare API：未收到响应。")
    if not decoded.get("success"):
        detail = "; ".join(str(item.get("message", "未知错误")) for item in decoded.get("errors", []))
        raise ValueError(f"Cloudflare API 操作失败：{detail or '未返回成功结果'}。")
    return decoded.get("result")


def cf_upsert_direct_aaaa(payload: dict[str, Any]) -> dict[str, str]:
    """Create or update one DNS-only AAAA record in a zone visible to the token."""
    token = str(payload.get("apiToken") or "").strip()
    hostname = cf_hostname(payload.get("hostname"))
    raw_address = str(payload.get("ipv6") or "").strip()
    if not token:
        raise ValueError("需要 Cloudflare API Token；它只在本次本机请求中使用，不会保存。")
    try:
        address = ipaddress.ip_address(raw_address)
    except ValueError as exc:
        raise ValueError("请填写合法的 IPv6 地址。") from exc
    if address.version != 6 or not address.is_global:
        raise ValueError("AAAA 记录必须是可公网路由的 IPv6 地址。")

    # A hostname may belong to a parent zone (for example files.example.com
    # belongs to example.com), so locate the most-specific zone the token can
    # read rather than asking the user for an opaque Zone ID.
    labels = hostname.split(".")
    zone: dict[str, Any] | None = None
    for index in range(len(labels) - 1):
        candidate = ".".join(labels[index:])
        found = cf_api(token, "GET", f"/zones?name={urllib.parse.quote(candidate, safe='')}") or []
        zone = next((item for item in found if str(item.get("name", "")).lower() == candidate), None)
        if zone:
            break
    if not zone or not str(zone.get("id") or ""):
        raise ValueError("此 Token 找不到该域名所属的 Cloudflare Zone。请确认域名已托管到此账户，且 Token 具有 Zone:Zone Read 权限。")

    zone_id = str(zone["id"])
    quoted = urllib.parse.quote(hostname, safe="")
    all_records = cf_api(token, "GET", f"/zones/{zone_id}/dns_records?name={quoted}") or []
    cname_records = [record for record in all_records if str(record.get("type", "")).upper() == "CNAME"]
    if cname_records:
        destination = str(cname_records[0].get("content") or "未知目标")
        raise ValueError(f"{hostname} 已存在 CNAME → {destination}。同一主机名不能同时使用 CNAME 与 AAAA；请先删除原发布配置或改用另一个子域名。")
    records = [record for record in all_records if str(record.get("type", "")).upper() == "AAAA"]
    if len(records) > 1:
        raise ValueError("该名称存在多条 AAAA 记录。为避免误删或覆盖，控制台不会自动处理；请先在 Cloudflare 控制台整理为一条。")
    record_payload = {"type": "AAAA", "name": hostname, "content": str(address), "ttl": 1, "proxied": False}
    if records:
        record_id = str(records[0].get("id") or "")
        if not record_id:
            raise ValueError("无法读取现有 AAAA 记录 ID。")
        record = cf_api(token, "PUT", f"/zones/{zone_id}/dns_records/{record_id}", record_payload)
        action = "已更新"
        created_by_console = False
    else:
        try:
            record = cf_api(token, "POST", f"/zones/{zone_id}/dns_records", record_payload)
        except CloudflareTransportError:
            # A POST response can be lost after Cloudflare committed it. Query
            # once and adopt the exact record instead of blindly creating twice.
            confirmed = cf_api(token, "GET", f"/zones/{zone_id}/dns_records?name={quoted}") or []
            matches = [item for item in confirmed if str(item.get("type", "")).upper() == "AAAA" and str(item.get("content", "")) == str(address)]
            if len(matches) != 1:
                raise
            record = matches[0]
        record_id = str(record.get("id") or "")
        if not record_id:
            raise ValueError("Cloudflare 已接受 AAAA 写入，但未返回记录 ID。")
        action = "已创建"
        created_by_console = True
    message = f"{action} DNS-only AAAA 记录：{hostname} → {address}。"
    return {
        "message": message,
        "summary": message,
        "zoneId": zone_id,
        "recordId": record_id,
        "hostname": hostname,
        "content": str(address),
        "recordCreated": created_by_console,
    }


def cf_one_click_tunnel(payload: dict[str, Any]) -> dict[str, str]:
    """Create a remotely-managed tunnel, route one hostname, then run it locally."""
    tool = find_tools()["cloudflared"]["path"]
    api_token = str(payload.get("apiToken") or "").strip()
    if not tool:
        raise ValueError("未找到 cloudflared，请先安装 Cloudflare Tunnel 客户端。")
    if not api_token:
        raise ValueError("需要 Cloudflare API Token；它只在本次本机请求中使用，不会保存。")
    account_id = cf_identifier(payload.get("accountId"), "Account ID")
    zone_id = cf_identifier(payload.get("zoneId"), "Zone ID")
    hostname = cf_hostname(payload.get("hostname"))
    name = str(payload.get("tunnelName") or f"exposure-{hostname.split('.')[0]}").strip()
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_. -]{0,99}", name):
        raise ValueError("Tunnel 名称只能包含字母、数字、空格、点、下划线和连字符，且长度不超过 100。")
    port = require_local_port(payload)
    with PROCESS_LOCK:
        if "cloudflare-tunnel" in PROCESSES and PROCESSES["cloudflare-tunnel"].poll() is None:
            raise ValueError("已有 Cloudflare Tunnel 正在运行。请先停止它，再创建新的 Tunnel。")

    # Validate before mutating Cloudflare, so an expired or incorrectly scoped token
    # cannot leave an unexpected tunnel behind.
    cf_api(api_token, "GET", "/user/tokens/verify")
    created = cf_api(api_token, "POST", f"/accounts/{account_id}/cfd_tunnel", {"name": name, "config_src": "cloudflare"})
    tunnel_id = str(created.get("id") or "")
    runner_token = str(created.get("token") or "")
    if not tunnel_id:
        raise ValueError("Cloudflare 创建 Tunnel 后没有返回 Tunnel ID，请在控制台中检查该 Tunnel。")
    if not runner_token:
        runner_token = str(cf_api(api_token, "GET", f"/accounts/{account_id}/cfd_tunnel/{tunnel_id}/token") or "")
    if not runner_token:
        raise ValueError(f"Tunnel {tunnel_id} 已创建，但未能获取运行 token；请在 Cloudflare 控制台中删除或手动启动它。")

    # Do not silently replace another DNS destination. Reusing the same tunnel CNAME
    # is harmless; any other record is left for the user to resolve deliberately.
    query_name = urllib.parse.quote(hostname, safe="")
    records = cf_api(api_token, "GET", f"/zones/{zone_id}/dns_records?type=CNAME&name={query_name}") or []
    destination = f"{tunnel_id}.cfargotunnel.com"
    if records and str(records[0].get("content", "")).lower().rstrip(".") != destination:
        raise ValueError(f"Tunnel {tunnel_id} 已创建，但 {hostname} 已存在其他 DNS 记录；为避免覆盖，控制台没有改动它。请手动处理后重试或删除这个新 Tunnel。")
    cf_api(api_token, "PUT", f"/accounts/{account_id}/cfd_tunnel/{tunnel_id}/configurations", {"config": {"ingress": [{"hostname": hostname, "service": f"http://127.0.0.1:{port}"}, {"service": "http_status:404"}]}})
    if not records:
        cf_api(api_token, "POST", f"/zones/{zone_id}/dns_records", {"type": "CNAME", "proxied": True, "name": hostname, "content": destination})

    token_path = RUNTIME / "cloudflare-token.txt"
    token_path.write_text(runner_token, encoding="utf-8")
    launch("cloudflare-tunnel", [str(tool), "tunnel", "--no-autoupdate", "run", "--token-file", str(token_path)], {"kind": "Cloudflare Tunnel", "address": hostname, "tunnelId": tunnel_id, "configPath": str(token_path)})
    return {"message": f"Cloudflare Tunnel、入口规则和 DNS 已创建，并正在连接：{hostname}", "url": f"https://{hostname}", "tunnelId": tunnel_id}


def cf_local_auth_state() -> dict[str, Any]:
    tool = find_tools()["cloudflared"]
    with PROCESS_LOCK:
        pending = "cloudflare-login" in PROCESSES and PROCESSES["cloudflare-login"].poll() is None
    return {
        "installed": tool["installed"],
        "authorized": (CF_HOME / "cert.pem").is_file(),
        "pending": pending,
        "certificatePath": str(CF_HOME / "cert.pem"),
    }


def cf_load_manifest() -> list[dict[str, Any]]:
    try:
        items = json.loads(CF_MANIFEST.read_text(encoding="utf-8"))
        return items if isinstance(items, list) else []
    except (FileNotFoundError, json.JSONDecodeError):
        return []


def cf_save_manifest(items: list[dict[str, Any]]) -> None:
    # The manifest is deliberately metadata-only: no API tokens, account certificate,
    # or tunnel credential is copied into it.
    CF_MANIFEST.write_text(json.dumps(items, ensure_ascii=False, indent=2), encoding="utf-8")


def cf_login() -> dict[str, str]:
    tool = find_tools()["cloudflared"]["path"]
    if not tool:
        raise ValueError("未找到 cloudflared，请先安装 Cloudflare Tunnel 客户端。")
    if (CF_HOME / "cert.pem").is_file():
        return {"message": "本机已有 Cloudflare 浏览器授权。若要更换账户或域名权限，请先在 Cloudflare Dashboard 撤销该 Tunnel API Token，再重新授权。"}
    launch("cloudflare-login", [str(tool), "tunnel", "login"], {"kind": "Cloudflare 浏览器授权", "address": "等待浏览器完成授权"})
    return {"message": "已打开 Cloudflare 浏览器授权页。登录后选择一个已托管到 Cloudflare 的域名；完成后回到此页点击“检查授权”。"}


def cf_tunnel_name(value: Any) -> str:
    name = str(value or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_. -]{0,99}", name):
        raise ValueError("Tunnel 名称只能包含字母、数字、空格、点、下划线和连字符，且长度不超过 100。")
    return name


def cf_run(args: list[str], timeout: int = 30) -> str:
    try:
        done = subprocess.run(args, capture_output=True, text=True, timeout=timeout, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except subprocess.TimeoutExpired:
        raise ValueError("cloudflared 命令等待超时，请检查网络或浏览器授权是否已完成。")
    output = "\n".join(part for part in (done.stdout, done.stderr) if part).strip()
    if done.returncode != 0:
        raise ValueError(output or "cloudflared 命令失败。")
    return output


def cf_config_path(tunnel_id: str) -> Path:
    return CF_PERSIST / f"{tunnel_id}.yml"


def cf_write_config(tunnel_id: str, hostname: str, port: int) -> Path:
    credential = CF_HOME / f"{tunnel_id}.json"
    if not credential.is_file():
        raise ValueError("没有找到该 Tunnel 的本机凭据文件；请重新创建 Tunnel，或从原电脑安全地恢复对应凭据。")
    path = cf_config_path(tunnel_id)
    # JSON strings are valid YAML scalars and handle Windows paths safely.
    content = (
        f"tunnel: {tunnel_id}\n"
        f"credentials-file: {json.dumps(str(credential), ensure_ascii=False)}\n"
        "ingress:\n"
        f"  - hostname: {hostname}\n"
        f"    service: http://127.0.0.1:{port}\n"
        "  - service: http_status:404\n"
    )
    path.write_text(content, encoding="utf-8")
    return path


def cf_launch_named_tunnel(tool: str, tunnel_id: str, hostname: str, port: int) -> None:
    config_path = cf_write_config(tunnel_id, hostname, port)
    launch(
        "cloudflare-tunnel",
        [tool, "tunnel", "--no-autoupdate", "--config", str(config_path), "run", tunnel_id],
        {"kind": "Cloudflare Tunnel（已保存）", "address": hostname, "tunnelId": tunnel_id, "configPath": str(config_path), "cleanupConfig": False},
    )


def cf_save_tunnel(tunnel_id: str, name: str, hostname: str, port: int) -> None:
    items = [item for item in cf_load_manifest() if item.get("id") != tunnel_id]
    items.append({"id": tunnel_id, "name": name, "hostname": hostname, "port": port, "configPath": str(cf_config_path(tunnel_id)), "updatedAt": time.strftime("%Y-%m-%d %H:%M:%S")})
    cf_save_manifest(items)


def cf_create_named_tunnel(payload: dict[str, Any]) -> dict[str, str]:
    tool = find_tools()["cloudflared"]["path"]
    if not tool:
        raise ValueError("未找到 cloudflared，请先安装 Cloudflare Tunnel 客户端。")
    if not (CF_HOME / "cert.pem").is_file():
        raise ValueError("尚未完成 Cloudflare 浏览器授权。请先点击“浏览器授权”，选择受管域名后再继续。")
    name = cf_tunnel_name(payload.get("tunnelName"))
    hostname = cf_hostname(payload.get("hostname"))
    port = require_local_port(payload)
    with PROCESS_LOCK:
        if "cloudflare-tunnel" in PROCESSES and PROCESSES["cloudflare-tunnel"].poll() is None:
            raise ValueError("已有 Cloudflare Tunnel 正在运行。请先停止它，再创建新的 Tunnel。")
    output = cf_run([str(tool), "tunnel", "--output", "json", "create", name])
    try:
        tunnel_id = str(json.loads(output).get("id") or "")
    except json.JSONDecodeError:
        match = re.search(r"\b[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\b", output, re.IGNORECASE)
        tunnel_id = match.group(0) if match else ""
    if not tunnel_id:
        raise ValueError("Tunnel 已创建，但无法读取其 ID；请在 Cloudflare Dashboard 中确认后再继续。")
    try:
        cf_run([str(tool), "tunnel", "route", "dns", tunnel_id, hostname])
    except ValueError as exc:
        raise ValueError(f"Tunnel {tunnel_id} 已创建，但 DNS 路由未完成：{exc}。为避免覆盖同名记录，控制台没有继续启动；请处理 DNS 后重试。")
    cf_launch_named_tunnel(str(tool), tunnel_id, hostname, port)
    cf_save_tunnel(tunnel_id, name, hostname, port)
    return {"message": f"已保存并启动 Cloudflare Tunnel：{name}", "url": f"https://{hostname}", "tunnelId": tunnel_id}


def cf_start_saved_tunnel(payload: dict[str, Any]) -> dict[str, str]:
    tunnel_id = str(payload.get("tunnelId") or "").strip().lower()
    if not re.fullmatch(r"[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}", tunnel_id):
        raise ValueError("请选择已保存的 Cloudflare Tunnel。")
    record = next((item for item in cf_load_manifest() if item.get("id") == tunnel_id), None)
    if not record:
        raise ValueError("找不到该 Tunnel 的本地保存记录。")
    tool = find_tools()["cloudflared"]["path"]
    if not tool:
        raise ValueError("未找到 cloudflared。")
    port = require_local_port(payload)
    with PROCESS_LOCK:
        if "cloudflare-tunnel" in PROCESSES and PROCESSES["cloudflare-tunnel"].poll() is None:
            raise ValueError("已有 Cloudflare Tunnel 正在运行。请先停止它，再启动保存的 Tunnel。")
    hostname = cf_hostname(record.get("hostname"))
    cf_launch_named_tunnel(str(tool), tunnel_id, hostname, port)
    cf_save_tunnel(tunnel_id, str(record.get("name") or tunnel_id), hostname, port)
    return {"message": f"已用当前本地端口重新连接保存的 Tunnel：{record.get('name')}", "url": f"https://{hostname}", "tunnelId": tunnel_id}


def frp_tunnel(payload: dict[str, Any]) -> dict[str, str]:
    with PROCESS_LOCK:
        existing = PROCESSES.get("frp")
        if existing and existing.poll() is None:
            raise ValueError("FRP 隧道已经在运行。请先停止它，再更改模式、端口或本地服务。")
    tool = str(payload.get("frpcPath") or "").strip() or find_tools()["frpc"]["path"]
    host = str(payload.get("serverAddr") or "").strip()
    token = str(payload.get("token") or "") or load_frp_token() or ""
    mode = str(payload.get("mode") or "tcp").strip().lower()
    if not tool or not Path(tool).is_file():
        raise ValueError("未找到 frpc.exe。请下载与 VPS 上 frps 同版本的 FRP 客户端后再填写其路径。")
    if not host or not token:
        raise ValueError("FRP 需要 VPS / frps 地址。首次使用请先配对并加密保存 token。")
    if mode != "tcp":
        raise ValueError("此控制台的 FRP 仅支持 IPv4 + 公网端口（TCP）模式。")
    port = require_local_port(payload)
    config_path = RUNTIME / "frpc.runtime.toml"
    def toml_string(value: str) -> str:
        return json.dumps(value, ensure_ascii=False)
    server_port = int(payload.get("serverPort") or 7000)
    if not 1 <= server_port <= 65535:
        raise ValueError("frps 端口必须在 1–65535 之间。")
    common = f'''serverAddr = {toml_string(host)}\nserverPort = {server_port}\nauth.method = "token"\nauth.token = {toml_string(token)}\ntransport.tls.enable = true\n\n[[proxies]]\nname = "exposure-console-files"\nlocalIP = "127.0.0.1"\nlocalPort = {port}\n'''
    remote_port = int(payload.get("remotePort") or 0)
    if not 1 <= remote_port <= 65535:
        raise ValueError("需要填写 VPS 对外开放的公网端口（1–65535）。")
    config = common + f'type = "tcp"\nremotePort = {remote_port}\n'
    address = f"http://{host}:{remote_port}"
    message = f"frpc 已启动。IPv4 + 公网端口入口：{address}。此模式是明文 HTTP；不要传输敏感内容。"
    config_path.write_text(config, encoding="utf-8")
    launch("frp", [str(tool), "-c", str(config_path)], {"kind": "FRP TCP 直通", "address": address, "configPath": str(config_path)})
    return {"message": message, "url": address}


def direct_ipv6(payload: dict[str, Any]) -> dict[str, str]:
    if not probe()["ipv6"]["available"]:
        raise ValueError("当前网络没有可用公网 IPv6，已安全阻止启动。")
    caddy = str(payload.get("caddyPath") or "").strip() or find_tools()["caddy"]["path"]
    domain = str(payload.get("domain") or "").strip()
    if not caddy:
        raise ValueError("原生 IPv6 直连需要 Caddy 为域名配置可信 HTTPS；当前未安装 Caddy。")
    if not domain or "." not in domain:
        raise ValueError("请先将域名 AAAA 记录指向本机公网 IPv6，再填写域名。")
    started = start_file_service(payload, bind="127.0.0.1")
    caddyfile = RUNTIME / "Caddyfile"
    caddyfile.write_text(f"{domain} {{\n    bind ::\n    reverse_proxy 127.0.0.1:{started['port']}\n}}\n", encoding="utf-8")
    try:
        launch("caddy", [str(caddy), "run", "--config", str(caddyfile), "--adapter", "caddyfile"], {"kind": "IPv6 + Caddy HTTPS", "address": domain, "configPath": str(caddyfile)})
    except Exception:
        stop_service(started["serviceId"])
        raise
    return {"message": f"Caddy HTTPS 已启动：{domain}。请确认 AAAA 已指向此机，且 Windows 防火墙允许 Caddy 入站 80/443。"}


def config_templates() -> dict[str, str]:
    return {
        "frps.toml（无域名 TCP）": "bindPort = 7000\nauth.method = \"token\"\nauth.token = \"PASTE_A_LONG_RANDOM_TOKEN\"\ntransport.tls.force = true\n# 同时在 VPS 防火墙/安全组开放 TCP 7000（frpc）和 18080（访客）\n",
        "Caddyfile": "files.example.com {\n    reverse_proxy 127.0.0.1:8080\n}\n",
        "cloudflared-config.yml": "tunnel: YOUR_TUNNEL_UUID\ncredentials-file: /path/to/YOUR_TUNNEL_UUID.json\ningress:\n  - hostname: files.example.com\n    service: http://127.0.0.1:PORT\n  - service: http_status:404\n",
    }


def pick_directory() -> dict[str, str]:
    # This native picker is only opened after an explicit click in the local UI.
    script = (
        "Add-Type -AssemblyName System.Windows.Forms; "
        "$dialog = New-Object System.Windows.Forms.FolderBrowserDialog; "
        "$dialog.Description = '选择要只读分享的文件夹'; "
        "if ($dialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) { $dialog.SelectedPath }"
    )
    try:
        done = subprocess.run(
            ["powershell", "-NoProfile", "-STA", "-Command", script],
            capture_output=True,
            text=True,
            timeout=120,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        selected = done.stdout.strip()
        if done.returncode == 0 and selected:
            return {"path": selected}
        raise ValueError("未选择文件夹。")
    except subprocess.TimeoutExpired:
        raise ValueError("选择文件夹超时。")


class ConsoleHandler(SimpleHTTPRequestHandler):
    server_version = "ExposureConsole/0.1"

    def log_message(self, _format: str, *_args: Any) -> None:
        return  # Keep credentials and local paths out of terminal logs.

    def _json(self, status: int, payload: Any) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _body(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0"))
        if length > 32_768:
            raise ValueError("请求过大。")
        return json.loads(self.rfile.read(length) or b"{}")

    def do_GET(self) -> None:
        if not self._is_local_request():
            self._json(HTTPStatus.FORBIDDEN, {"error": "仅允许本机访问控制台。"})
            return
        parsed = urlparse(self.path)
        if parsed.path == "/api/probe":
            self._json(HTTPStatus.OK, probe())
            return
        if parsed.path == "/api/templates":
            self._json(HTTPStatus.OK, config_templates())
            return
        if parsed.path == "/api/cloudflare/auth":
            self._json(HTTPStatus.OK, cf_local_auth_state())
            return
        if parsed.path == "/api/cloudflare/saved":
            self._json(HTTPStatus.OK, cf_load_manifest())
            return
        if parsed.path == "/api/users":
            self._json(HTTPStatus.OK, file_users())
            return
        if parsed.path == "/api/access-records":
            self._json(HTTPStatus.OK, file_access_records())
            return
        if parsed.path == "/api/processes":
            self._json(HTTPStatus.OK, process_status())
            return
        if parsed.path in {"/", "/index.html"}:
            content = (WEB / "index.html").read_bytes()
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)
            return
        self.send_error(HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:
        if not self._is_local_request():
            self._json(HTTPStatus.FORBIDDEN, {"error": "仅允许本机访问控制台。"})
            return
        try:
            payload = self._body()
            if self.path == "/api/files/start":
                result = start_file_service(payload)
            elif self.path == "/api/users/add":
                result = add_file_user(payload)
            elif self.path == "/api/users/update":
                result = update_file_user(payload)
            elif self.path == "/api/users/delete":
                result = delete_file_user(payload)
            elif self.path == "/api/files/ipv6":
                result = direct_ipv6(payload)
            elif self.path == "/api/tailscale/serve":
                result = tailscale_serve(payload, public=False)
            elif self.path == "/api/tailscale/funnel":
                result = tailscale_serve(payload, public=True)
            elif self.path == "/api/cloudflare/start":
                result = cloudflare_tunnel(payload)
            elif self.path == "/api/cloudflare/provision":
                result = cf_one_click_tunnel(payload)
            elif self.path == "/api/cloudflare/dns-aaaa":
                result = cf_upsert_direct_aaaa(payload)
            elif self.path == "/api/cloudflare/login":
                result = cf_login()
            elif self.path == "/api/cloudflare/named-create":
                result = cf_create_named_tunnel(payload)
            elif self.path == "/api/cloudflare/named-start":
                result = cf_start_saved_tunnel(payload)
            elif self.path == "/api/frp/pair":
                result = frp_pair(payload)
            elif self.path == "/api/frp/bootstrap":
                result = frp_bootstrap(payload)
            elif self.path == "/api/frp/start":
                result = frp_tunnel(payload)
            elif self.path == "/api/files/pick-directory":
                result = pick_directory()
            elif self.path.startswith("/api/stop/"):
                service_id = self.path.removeprefix("/api/stop/")
                if service_id == "tailscale":
                    tool = find_tools()["tailscale"]["path"]
                    if not tool:
                        raise ValueError("未找到 Tailscale 客户端。")
                    subprocess.run([str(tool), "serve", "reset"], capture_output=True, timeout=15, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
                    subprocess.run([str(tool), "funnel", "reset"], capture_output=True, timeout=15, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
                    result = {"message": "Tailscale Serve/Funnel 已重置。"}
                else:
                    result = stop_service(service_id)
            else:
                self._json(HTTPStatus.NOT_FOUND, {"error": "未知操作。"})
                return
            self._json(HTTPStatus.OK, result)
        except (ValueError, json.JSONDecodeError) as exc:
            self._json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
        except Exception:
            self._json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "操作失败。请检查所需客户端、网络状态和输入内容。"})

    def _is_local_request(self) -> bool:
        host = self.headers.get("Host", "").split(":", 1)[0].strip("[]").lower()
        if host not in {"localhost", "127.0.0.1", "::1"}:
            return False
        origin = self.headers.get("Origin")
        return origin is None or origin in {"http://localhost:8765", "http://127.0.0.1:8765", "http://[::1]:8765"}


def main() -> None:
    host, port = "127.0.0.1", 8765
    server = ThreadingHTTPServer((host, port), ConsoleHandler)
    print(f"Exposure Console is running at http://{host}:{port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        with PROCESS_LOCK:
            for proc in PROCESSES.values():
                if proc.poll() is None:
                    proc.terminate()
            for path in RUNTIME.iterdir():
                if path.is_file() and path.name != ".gitkeep":
                    path.unlink(missing_ok=True)


if __name__ == "__main__":
    from control import main as control_main
    control_main()

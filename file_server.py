"""Authenticated, permission-scoped local file service for Exposure Console."""

from __future__ import annotations

import argparse
import base64
import hmac
import html
import io
import json
import socket
import time
import urllib.parse
import uuid
import threading
from collections import defaultdict
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any


PERMISSIONS = ("read", "modify", "rename", "upload", "delete")
AUTH_FAILURES = defaultdict(list)
AUTH_LOCK = threading.Lock()
LOG_LOCK = threading.Lock()
MAX_UPLOAD_BYTES = 1024 * 1024 * 1024


def urlparse_path(path: str) -> str:
    return urllib.parse.urlparse(path).path


class FileHandler(SimpleHTTPRequestHandler):
    directory: str
    users_path: Path
    access_log: Path

    def __init__(self, *args: Any, directory: str, users_path: Path, access_log: Path, **kwargs: Any):
        self.directory = directory
        self.users_path = users_path
        self.access_log = access_log
        self._last_status = 500
        super().__init__(*args, directory=directory, **kwargs)

    def send_response(self, code: int, message: str | None = None) -> None:
        self._last_status = code
        super().send_response(code, message)

    def _users(self) -> list[dict[str, Any]]:
        try:
            if self.users_path.suffix == '.dpapi':
                from storage import read
                data = read(self.users_path, {'users': []})
            else:
                data = json.loads(self.users_path.read_text(encoding="utf-8"))
            users = data.get("users", [])
            return users if isinstance(users, list) else []
        except (OSError, json.JSONDecodeError):
            return []

    def _authenticate(self) -> dict[str, Any] | None:
        supplied = self.headers.get("Authorization", "")
        try:
            kind, encoded = supplied.split(" ", 1)
            raw = base64.b64decode(encoded, validate=True).decode("utf-8")
            username, password = raw.split(":", 1)
        except Exception:
            return None
        if kind.lower() != "basic":
            return None
        for user in self._users():
            if hmac.compare_digest(str(user.get("id", "")), username) and hmac.compare_digest(str(user.get("password", "")), password):
                return user
        return None

    def _can(self, user: dict[str, Any], permission: str) -> bool:
        return bool(user.get("permissions", {}).get(permission, False))

    def _record(self, user: dict[str, Any] | None, action: str) -> None:
        entry = {
            "time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "user": str(user.get("id")) if user else "anonymous",
            "action": action,
            "method": self.command,
            "path": urllib.parse.unquote(urlparse_path(self.path)),
            "status": self._last_status,
            "client": self.client_address[0],
            "requestId": getattr(self, '_request_id', ''),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "durationMs": round((time.monotonic() - getattr(self, '_request_started', time.monotonic())) * 1000),
            "directory": self.directory,
            "userAgent": self.headers.get('User-Agent', '')[:512],
            "host": self.headers.get('Host', '')[:253],
            "contentLength": self.headers.get('Content-Length', '0'),
            "ipSource": 'socket peer; proxy client IP not verified',
            "statusMeaning": HTTPStatus(self._last_status).phrase if self._last_status in HTTPStatus._value2member_map_ else '',
        }
        try:
            with LOG_LOCK:
                if self.access_log.exists() and self.access_log.stat().st_size > 10 * 1024 * 1024:
                    self.access_log.replace(self.access_log.with_suffix('.previous.jsonl'))
                with self.access_log.open("a", encoding="utf-8") as handle:
                    handle.write(json.dumps(entry, ensure_ascii=False) + "\n")
        except OSError:
            pass

    def translate_path(self, path: str) -> str:
        candidate = Path(super().translate_path(path)).resolve()
        root = Path(self.directory).resolve()
        try:
            candidate.relative_to(root)
        except ValueError:
            return str(root / "__blocked_path__")
        return str(candidate)

    def _require_auth(self) -> None:
        self.send_response(HTTPStatus.UNAUTHORIZED)
        self.send_header("WWW-Authenticate", 'Basic realm="Shared files", charset="UTF-8"')
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _forbidden(self) -> None:
        self.send_error(HTTPStatus.FORBIDDEN, "This account is not permitted to perform that action.")

    def _user_for(self, permission: str) -> dict[str, Any] | None:
        self._request_started = time.monotonic()
        self._request_id = uuid.uuid4().hex
        key = self.client_address[0]
        with AUTH_LOCK:
            AUTH_FAILURES[key] = [t for t in AUTH_FAILURES[key] if time.monotonic() - t < 60]
            limited = len(AUTH_FAILURES[key]) >= 10
        if limited:
            self.send_error(429, 'Too many login attempts; retry in 60 seconds.')
            self._record(None, 'login-rate-limit')
            return None
        user = self._authenticate()
        if not user:
            with AUTH_LOCK:
                AUTH_FAILURES[key].append(time.monotonic())
            self._require_auth()
            self._record(None, permission)
            return None
        if not self._can(user, permission):
            self._forbidden()
            self._record(user, permission)
            return None
        return user

    def do_GET(self) -> None:
        if urlparse_path(self.path) == '/.well-known/exposure-health':
            import os
            body = os.environ.get('EXPOSURE_MARKER', '').encode()
            self.send_response(200)
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store')
            self.end_headers()
            self.wfile.write(body)
            return
        user = self._user_for("read")
        if not user:
            return
        try:
            super().do_GET()
        finally:
            self._record(user, "read")

    def do_HEAD(self) -> None:
        user = self._user_for("read")
        if not user:
            return
        try:
            super().do_HEAD()
        finally:
            self._record(user, "read")

    def do_PUT(self) -> None:
        user = self._user_for("upload")
        if not user:
            return
        target = Path(self.translate_path(self.path))
        root = Path(self.directory).resolve()
        try:
            length = int(self.headers.get("Content-Length", "-1"))
        except ValueError:
            length = -1
        if target == root or urlparse_path(self.path).endswith("/") or length < 0 or length > MAX_UPLOAD_BYTES:
            self.send_error(HTTPStatus.BAD_REQUEST, "Provide a file path and a valid upload size up to 1 GiB.")
            self._record(user, "upload")
            return
        if not target.parent.is_dir():
            self.send_error(HTTPStatus.NOT_FOUND, "The target folder does not exist.")
            self._record(user, "upload")
            return
        existed = target.exists()
        if existed and not self._can(user, "modify"):
            self._forbidden()
            self._record(user, "upload-overwrite")
            return
        temporary = target.parent / f".{target.name}.{uuid.uuid4().hex}.uploading"
        try:
            remaining = length
            with temporary.open("xb") as handle:
                while remaining:
                    chunk = self.rfile.read(min(1024 * 1024, remaining))
                    if not chunk:
                        raise OSError("request ended before declared length")
                    handle.write(chunk)
                    remaining -= len(chunk)
            temporary.replace(target)
            self.send_response(HTTPStatus.NO_CONTENT if existed else HTTPStatus.CREATED)
            self.send_header("Content-Length", "0")
            self.end_headers()
        except OSError as exc:
            temporary.unlink(missing_ok=True)
            self.send_error(HTTPStatus.INTERNAL_SERVER_ERROR, str(exc))
        self._record(user, "upload")

    def do_DELETE(self) -> None:
        user = self._user_for("delete")
        if not user:
            return
        target = Path(self.translate_path(self.path))
        root = Path(self.directory).resolve()
        try:
            if target == root:
                raise PermissionError("The shared root cannot be deleted.")
            if target.is_dir():
                target.rmdir()
            else:
                target.unlink()
            self.send_response(HTTPStatus.NO_CONTENT)
            self.send_header("Content-Length", "0")
            self.end_headers()
        except FileNotFoundError:
            self.send_error(HTTPStatus.NOT_FOUND, "File not found.")
        except (OSError, PermissionError) as exc:
            self.send_error(HTTPStatus.CONFLICT, str(exc))
        self._record(user, "delete")

    def do_MOVE(self) -> None:
        user = self._user_for("rename")
        if not user:
            return
        destination = self.headers.get("Destination", "")
        if not destination:
            self.send_error(HTTPStatus.BAD_REQUEST, "Destination header is required.")
            self._record(user, "modify")
            return
        source = Path(self.translate_path(self.path))
        target = Path(self.translate_path(urllib.parse.urlparse(destination).path or destination))
        root = Path(self.directory).resolve()
        try:
            if source == root or target == root or source.parent != target.parent or not source.exists() or target.exists() or not target.parent.is_dir():
                raise OSError("Source/destination is invalid or destination already exists.")
            source.replace(target)
            self.send_response(HTTPStatus.NO_CONTENT)
            self.send_header("Content-Length", "0")
            self.end_headers()
        except OSError as exc:
            self.send_error(HTTPStatus.CONFLICT, str(exc))
        self._record(user, "modify")

    def do_POST(self) -> None:
        self.send_error(HTTPStatus.METHOD_NOT_ALLOWED, "Use PUT to upload or MOVE to rename.")
        self._record(self._authenticate(), "post")

    do_PATCH = do_POST

    def list_directory(self, path: str) -> io.BytesIO | None:
        user = self._authenticate() or {"id": "unknown", "permissions": {}}
        try:
            entries = sorted(Path(path).iterdir(), key=lambda item: (not item.is_dir(), item.name.lower()))
        except OSError:
            self.send_error(HTTPStatus.NOT_FOUND, "No permission to list directory")
            return None
        base = urlparse_path(self.path)
        if not base.endswith("/"):
            base += "/"
        rows: list[str] = []
        if base != "/":
            rows.append('<li><a href="../">../</a></li>')
        for item in entries:
            name = item.name + ("/" if item.is_dir() else "")
            href = urllib.parse.quote(item.name) + ("/" if item.is_dir() else "")
            controls = ""
            if self._can(user, "rename"):
                controls += f'<button class="rename" data-name="{html.escape(item.name, quote=True)}">重命名</button>'
            if not item.is_dir() and self._can(user, "delete"):
                controls += f'<button class="delete" data-name="{html.escape(item.name, quote=True)}">删除</button>'
            rows.append(f'<li><a href="{href}">{html.escape(name)}</a>{controls}</li>')
        upload = '<div class="upload"><input id="upload" type="file" multiple><button id="send">上传文件</button><span id="result"></span></div>' if self._can(user, "upload") else ""
        script = f'''<script>
const base={json.dumps(base)},result=document.getElementById('result')||{{set textContent(v){{alert(v)}}}};
document.getElementById('send')?.addEventListener('click',async()=>{{try{{for(const f of document.getElementById('upload').files){{const r=await fetch(base+encodeURIComponent(f.name),{{method:'PUT',body:f}});if(!r.ok)throw new Error(f.name+' '+r.status)}}location.reload()}}catch(e){{result.textContent='上传失败：'+e.message}}}});
document.querySelectorAll('.delete').forEach(b=>b.onclick=async()=>{{if(confirm('删除 '+b.dataset.name+'？')){{const r=await fetch(base+encodeURIComponent(b.dataset.name),{{method:'DELETE'}});if(r.ok)location.reload();else result.textContent='删除失败：'+r.status}}}});
document.querySelectorAll('.rename').forEach(b=>b.onclick=async()=>{{const n=prompt('新文件名',b.dataset.name);if(n&&n!==b.dataset.name){{const r=await fetch(base+encodeURIComponent(b.dataset.name),{{method:'MOVE',headers:{{Destination:base+encodeURIComponent(n)}}}});if(r.ok)location.reload();else result.textContent='修改失败：'+r.status}}}});
</script>'''
        permissions = ", ".join(key for key in PERMISSIONS if self._can(user, key)) or "无"
        content = f'''<!doctype html><meta charset="utf-8"><title>共享文件</title><style>body{{font:15px system-ui;margin:2rem;max-width:800px}}li{{margin:.55rem 0}}button{{margin-left:.7rem}}.upload{{padding:1rem;background:#eef5ff;border-radius:8px}}#result{{margin-left:.6rem}}</style><h1>共享文件</h1><p>用户：{html.escape(str(user.get('id')))} · 权限：{html.escape(permissions)}</p>{upload}<ul>{''.join(rows)}</ul>{script}'''.encode("utf-8")
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        return io.BytesIO(content)

    def log_message(self, _format: str, *_args: object) -> None:
        return


class IPv6Server(ThreadingHTTPServer):
    address_family = socket.AF_INET6


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--directory", required=True)
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--users-path", required=True)
    parser.add_argument("--access-log", required=True)
    args = parser.parse_args()
    directory = str(Path(args.directory).resolve())
    users_path = Path(args.users_path).resolve()
    access_log = Path(args.access_log).resolve()
    server_class = IPv6Server if args.bind == "::" else ThreadingHTTPServer
    # AF_INET6 is platform-specific (23 on Windows, 10 on Linux).
    server_address = (args.bind, args.port, 0, 0) if args.bind == "::" else (args.bind, args.port)
    server = server_class(server_address, lambda *a, **kw: FileHandler(*a, directory=directory, users_path=users_path, access_log=access_log, **kw))
    server.serve_forever()


if __name__ == "__main__":
    main()

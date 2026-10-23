"""Exposure Console: persistent configuration and observable background workflows."""
import concurrent.futures
import copy
import hashlib
import io
import json
import os
import platform
import re
import secrets
import socket
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.error
import urllib.request
import zipfile
from collections import deque
from http.server import ThreadingHTTPServer
from pathlib import Path

import app as core
import storage

DATA = storage.DATA
CONFIG = DATA / 'settings.dpapi'
USERS = DATA / 'users.dpapi'
ACCESS = DATA / 'access.jsonl'
TASKFILE = DATA / 'tasks.json'
OWNED = DATA / 'routes.dpapi'
TOOLS = DATA / 'tools'
TOOLS.mkdir(exist_ok=True)
LOCK = threading.RLock()
TASKS = {}
TASK_INPUTS = {}
CANCEL = {}
LOGS = deque(maxlen=1000)
SECRETS = set()
DEFAULTS = {'directory': '', 'port': '', 'serverAddr': '', 'sshUser': 'root', 'sshPort': 22, 'serverPort': 7000, 'remotePort': 18080, 'cfMode': 'quick', 'hostname': '', 'tunnelName': 'exposure-files', 'ipv6': '', 'dnsMode': 'manual'}
SECRET_KEYS = {'apiToken', 'sshPassword', 'token'}
ROUTES = {'serve': 'Tailscale Serve', 'funnel': 'Tailscale Funnel', 'cloudflare': 'Cloudflare Tunnel', 'frp': 'VPS + FRP', 'ipv6': 'IPv6 直连'}
PROC_IDS = {'cloudflare': 'cloudflare-tunnel', 'frp': 'frp', 'ipv6': 'caddy'}
RAW_FIND = core.find_tools
NO_WINDOW = getattr(subprocess, 'CREATE_NO_WINDOW', 0)
HTTP = urllib.request.build_opener(urllib.request.ProxyHandler({}))
TOOL_NAMES = {'tailscale': 'tailscale.exe', 'cloudflared': 'cloudflared.exe', 'frpc': 'frpc.exe', 'caddy': 'caddy.exe'}
IPV6_PORT_TEST_API = 'https://api.networktools.dev/v1/port-test'


def settings():
    return {**DEFAULTS, **storage.read(CONFIG, {})}


def redact(value):
    text = str(value)
    for secret in sorted(SECRETS, key=len, reverse=True):
        if len(secret) >= 4:
            text = text.replace(secret, '[凭据已隐藏]')
    return re.sub(r'(?i)(authorization|password|token|secret)([=: ]+)[^\s,]+', r'\1\2[隐藏]', text)


def log(kind, message):
    entry = {'time': time.strftime('%Y-%m-%d %H:%M:%S'), 'kind': kind, 'message': redact(message)}
    with LOCK:
        LOGS.appendleft(entry)
        path = DATA / 'operations.jsonl'
        if path.exists() and path.stat().st_size > 5_000_000:
            path.replace(path.with_suffix('.previous.jsonl'))
        with path.open('a', encoding='utf-8') as f:
            f.write(json.dumps(entry, ensure_ascii=False) + '\n')


def cmd(args, timeout=25):
    try:
        result = subprocess.run(args, capture_output=True, encoding='utf-8', errors='replace', timeout=timeout, creationflags=NO_WINDOW)
    except subprocess.TimeoutExpired as exc:
        detail = core.output_text(exc.stdout) + core.output_text(exc.stderr)
        raise ValueError('操作超时。' + redact(detail[-1500:])) from exc
    text = (result.stdout + '\n' + result.stderr).strip()
    if result.returncode:
        raise ValueError(redact(text[-2000:]) or f'程序退出码 {result.returncode}')
    return text


def find_tools():
    found = RAW_FIND()
    config = settings()
    for name in found:
        paths = [config.get(name + 'Path'), str(TOOLS / (name + '.exe')), found[name]['path']]
        found[name] = {'installed': False, 'path': None}
        for path in paths:
            if path and Path(path).is_file():
                found[name] = {'installed': True, 'path': path}
                break
    return found


core.find_tools = find_tools


def launch(name, args, meta, env=None):
    with core.PROCESS_LOCK:
        if name in core.PROCESSES and core.PROCESSES[name].poll() is None:
            raise ValueError('此入口已在运行，请停止后更新。')
        proc = subprocess.Popen(args, cwd=core.ROOT, env={**os.environ, **(env or {})}, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, creationflags=NO_WINDOW)
        core.PROCESSES[name] = proc
        core.PROCESS_META[name] = {'pid': proc.pid, 'startedAt': time.strftime('%Y-%m-%d %H:%M:%S'), **meta}
    def collect():
        for line in iter(proc.stdout.readline, b''):
            log(name, line.decode('utf-8', errors='replace').rstrip())
        proc.stdout.close()
        log(name, f'进程结束，退出码 {proc.wait()}')
    threading.Thread(target=collect, daemon=True).start()


core.launch = launch


def users():
    value = storage.read(USERS, {'users': []})
    return value['users']


def change_user(p):
    with LOCK:
        items = users()
        uid = str(p.get('id', '')).strip()
        if p.get('delete'):
            if not any(u['id'] == uid for u in items):
                raise ValueError('用户不存在。')
            if len(items) <= 1:
                raise ValueError('请至少保留一个用户。')
            items = [u for u in items if u['id'] != uid]
        else:
            if not core.USER_ID_RE.fullmatch(uid):
                raise ValueError('账号请用 1–64 位字母、数字、点、下划线、@ 或连字符。')
            password = str(p.get('password', ''))
            if not re.fullmatch(r'[0-9]{6}', password):
                raise ValueError('密码必须为六位数字，可包含前导零。')
            permissions = {k: bool(p.get('permissions', {}).get(k)) for k in ('read', 'modify', 'rename', 'upload', 'delete')}
            item = {'id': uid, 'password': password, 'permissions': permissions}
            if not p.get('originalId') and any(u['id'] == uid for u in items):
                raise ValueError('账号已经存在，请编辑原账户或换一个账号。')
            index = next((i for i, u in enumerate(items) if u['id'] == p.get('originalId', uid)), None)
            if index is None:
                items.append(item)
            else:
                if any(u['id'] == uid for i, u in enumerate(items) if i != index):
                    raise ValueError('账号已经存在。')
                items[index] = item
        storage.write(USERS, {'users': items})
    log('用户管理', f'已更新账号 {uid}')
    return {'message': '用户与权限已保存，后续请求立即生效。'}


def local_service(p):
    directory = core.validate_directory(p.get('directory'))
    if not str(p.get('directory', '')).strip():
        raise ValueError('请先选择要分享的文件夹。')
    with core.PROCESS_LOCK:
        existing = core.PROCESSES.get('file-service')
        meta = core.PROCESS_META.get('file-service', {})
        if existing and existing.poll() is None:
            if meta.get('directory') != str(directory) or (p.get('port') and int(p['port']) != meta['port']):
                raise ValueError('文件夹或端口已改变，请先停止当前文件服务。')
            return meta
    if not users():
        storage.write(USERS, {'users': [{'id': 'share', 'password': f'{secrets.randbelow(1000000):06}', 'permissions': {'read': True}}]})
    port = int(p.get('port') or core.free_loopback_port())
    if not 1 <= port <= 65535:
        raise ValueError('本地端口必须为 1–65535。')
    marker = secrets.token_urlsafe(24)
    launch('file-service', [sys.executable, str(core.FILE_SERVER), '--directory', str(directory), '--port', str(port), '--bind', '127.0.0.1', '--users-path', str(USERS), '--access-log', str(ACCESS)], {'kind': '文件服务', 'address': f'http://127.0.0.1:{port}', 'directory': str(directory), 'port': port, 'marker': marker}, {'EXPOSURE_MARKER': marker})
    for _ in range(30):
        try:
            if fetch_marker(f'http://127.0.0.1:{port}') == marker:
                return core.PROCESS_META['file-service']
        except Exception:
            pass
        time.sleep(.1)
    raise ValueError('文件服务未响应健康检查；查看运行日志确认端口是否占用。')


def fetch_marker(url):
    with HTTP.open(url.rstrip('/') + '/.well-known/exposure-health', timeout=5) as r:
        return r.read(1024).decode()


def verification_error(exc):
    message = str(exc)
    if 'getaddrinfo failed' in message.lower() or '11001' in message:
        return '本机 DNS 无法解析分享域名；入口进程仍在运行，但本机回访验证失败。请稍后重试，或从另一网络测试该 URL。'
    return redact(message)


def save_routes(records):
    storage.write(OWNED, records)


def remember(route, **fields):
    records = storage.read(OWNED, {})
    records[route] = {**records.get(route, {}), **fields}
    save_routes(records)


def task_save():
    with LOCK:
        core.atomic_json_write(TASKFILE, list(TASKS.values())[-40:])


class Cancelled(Exception):
    pass


class Job:
    def __init__(self, task):
        self.task = task

    def step(self, title, fn):
        if CANCEL[self.task['id']].is_set():
            raise Cancelled()
        row = {'title': title, 'status': 'running', 'detail': '正在执行', 'started': time.time()}
        with LOCK:
            self.task['steps'].append(row)
            task_save()
        try:
            result = fn()
            detail = result if isinstance(result, str) else result.get('summary', '已完成') if isinstance(result, dict) else '已完成'
            row.update(status='success', detail=redact(detail), elapsed=round(time.time() - row['started'], 1))
            log('操作', title + '：' + row['detail'])
            return result
        except Exception as exc:
            row.update(status='cancelled' if isinstance(exc, Cancelled) else 'failed', detail=redact(str(exc)), elapsed=round(time.time() - row['started'], 1))
            raise
        finally:
            task_save()


def tool_check(name):
    tool = find_tools()[name]
    if not tool['path']:
        raise ValueError(f'未找到 {name}。请点击“一键安装客户端”或在配置页填写路径。')
    flag = 'version' if name in ('tailscale', 'caddy') else '--version'
    version = cmd([tool['path'], flag], timeout=10)
    return f"{tool['path']} · {version.splitlines()[0][:200]}"


def discover_tool_paths(job):
    """Use the existing fast resolver once, then verify each located executable."""
    located = find_tools()
    updated = settings()
    verified = {}
    unverified = {}
    for name in TOOL_NAMES:
        existing = located.get(name, {}).get('path')
        if existing:
            try:
                flag = 'version' if name in ('tailscale', 'caddy') else '--version'
                version = cmd([existing, flag], timeout=10).splitlines()[0][:200]
                updated[name + 'Path'] = existing
                verified[name] = {'path': existing, 'version': version}
            except Exception as exc:
                unverified[name] = {'selectedPath': existing, 'reason': redact(str(exc))}
    storage.write(CONFIG, updated)
    found_summary = ', '.join(name + ': ' + item['path'] + ' · ' + item['version'] for name, item in verified.items())
    missing = [name for name in TOOL_NAMES if name not in verified]
    if missing:
        found_summary += '; 未找到可验证程序: ' + ', '.join(missing)
    if not found_summary:
        found_summary = '未找到可验证客户端。已检查 PATH、配置路径、常见安装位置和既有客户端目录。'
    updated['toolDiscovery'] = {'checkedAt': time.strftime('%Y-%m-%d %H:%M:%S'), 'verified': verified, 'unverified': unverified}
    storage.write(CONFIG, updated)
    return {'verified': verified, 'unverified': unverified, 'missing': missing, 'summary': found_summary}


def visitor_urls():
    owned = storage.read(OWNED, {})
    urls = {}
    for route in ROUTES:
        entry = owned.get(route, {})
        url = entry.get('url')
        if url:
            detail = '发布入口正在运行。' if entry.get('active') else '入口已停止；配置保留，可重新启动。'
        else:
            detail = '暂无访客地址。创建并启动此发布入口后，这里会显示 URL。'
        urls[route] = {'url': url, 'detail': detail, 'active': bool(entry.get('active') and url), 'verification': entry.get('verification', '')}
    return urls


def cf_context(p):
    token = p.get('apiToken', '')
    if not token:
        raise ValueError('请在配置与凭据中填写 Cloudflare API Token。')
    zones = []
    page = 1
    while True:
        batch = core.cf_api(token, 'GET', f'/zones?per_page=50&page={page}') or []
        zones.extend(batch)
        if len(batch) < 50:
            break
        page += 1
        if page > 20:
            raise ValueError('域名超过当前列表上限，请缩小 Token 的 Zone 范围。')
    return zones


def domain_zone(p):
    hostname = core.cf_hostname(p.get('hostname'))
    matches = [z for z in cf_context(p) if hostname == z['name'] or hostname.endswith('.' + z['name'])]
    if not matches:
        raise ValueError('Token 无法管理此域名；请选择授权列表里的域名。')
    return max(matches, key=lambda z: len(z['name']))


def ensure_hostname_available(route, hostname):
    """Prevent two local publication paths from claiming the same DNS owner."""
    for other, record in storage.read(OWNED, {}).items():
        if other == route:
            continue
        claimed = str(record.get('hostname') or '').lower().rstrip('.')
        if claimed == hostname:
            raise ValueError(
                f'{hostname} 已被“{ROUTES.get(other, other)}”发布配置占用。'
                '同一主机名不能同时用于 CNAME Tunnel 与 AAAA 直连；请先删除原发布配置或改用另一个子域名。'
            )


def confirm_ipv6_dns(p, hostname, address, dns_record=None):
    """Verify the authoritative record; treat local resolver lag as propagation."""
    expected = str(core.ipaddress.ip_address(str(address)))
    if dns_record:
        remote = core.cf_api(p['apiToken'], 'GET', f"/zones/{dns_record['zoneId']}/dns_records/{dns_record['recordId']}")
        actual = str(core.ipaddress.ip_address(str(remote.get('content') or '')))
        if str(remote.get('type') or '').upper() != 'AAAA' or actual != expected:
            raise ValueError('Cloudflare 返回的 AAAA 与选定 IPv6 不一致，未继续启动。')
    try:
        answers = {str(core.ipaddress.ip_address(item[4][0])) for item in socket.getaddrinfo(hostname, 443, socket.AF_INET6)}
    except socket.gaierror:
        answers = set()
    if expected in answers:
        return 'Cloudflare 记录与本机 DNS 均已解析到选定 IPv6。' if dns_record else 'AAAA 已解析到选定 IPv6。'
    if dns_record:
        return 'Cloudflare 已确认 AAAA 写入；本机 DNS 缓存尚未更新，不再将其误判为失败。Caddy 会在后台重试证书申请。'
    raise ValueError('本机尚未解析到选定 IPv6。手动添加 AAAA 后，请等待 DNS 生效再重试。')


class IPv6ProbeListener:
    """A dependency-free, short-lived IPv6 TCP listener for the preflight."""

    def __init__(self):
        self.socket = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind(('::', 0))
        self.socket.listen(8)
        self.socket.settimeout(.2)
        self.port = int(self.socket.getsockname()[1])
        self.closed = threading.Event()
        self.thread = threading.Thread(target=self._serve, daemon=True, name='ipv6-inbound-probe')

    def _serve(self):
        while not self.closed.is_set():
            try:
                connection, _ = self.socket.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            with connection:
                try:
                    connection.sendall(b'exposure-ipv6-probe\n')
                except OSError:
                    pass

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *_):
        self.closed.set()
        self.socket.close()
        self.thread.join(timeout=1)


def external_port_status(address, port):
    query = urllib.parse.urlencode({'ip': address, 'port': int(port)})
    request = urllib.request.Request(
        IPV6_PORT_TEST_API + '?' + query,
        headers={'Accept': 'application/json', 'User-Agent': 'ExposureConsole/1.0'},
    )
    last_error = None
    for attempt in range(2):
        try:
            with urllib.request.urlopen(request, timeout=12) as response:
                result = json.load(response)
            if str(result.get('ip') or '') != address or int(result.get('port') or 0) != int(port):
                raise ValueError('外部探测服务返回了不匹配的目标，结果已丢弃。')
            return str(result.get('status') or '').upper(), result
        except (urllib.error.URLError, TimeoutError, ConnectionResetError, OSError) as exc:
            last_error = exc
            if attempt == 0:
                time.sleep(1)
    raise ValueError(f'公网入站检测服务暂时不可用：{last_error}。未写入 DNS，也未启动发布。')


def ipv6_inbound_probe(p):
    info = core.probe()['ipv6']
    if not info['available']:
        raise ValueError(info['message'])
    local_addresses = [
        str(core.ipaddress.ip_address(item['IPAddress']))
        for item in info.get('globalAddresses', [])
        if item.get('IPAddress')
    ]
    requested = str(p.get('ipv6') or '').strip()
    if requested:
        try:
            address = str(core.ipaddress.ip_address(requested))
        except ValueError as exc:
            raise ValueError('请填写本机当前持有的合法公网 IPv6。') from exc
        if address not in local_addresses:
            raise ValueError('填写的 IPv6 不属于本机当前网络接口，未允许外部探测。')
    else:
        address = local_addresses[0] if local_addresses else ''
    if not address:
        raise ValueError('没有找到可用于入站探测的公网 IPv6。')

    try:
        with IPv6ProbeListener() as listener:
            port = listener.port
            status, result = external_port_status(address, port)
    except OSError as exc:
        raise ValueError(f'无法建立临时 IPv6 入站探针：{exc}。未检查 Caddy，也未启动文件服务。') from exc
    if status == 'OPEN':
        return {
            'summary': f'公网节点已成功连接 {address} 的临时 TCP 端口 {port}；IPv6 入站可用。',
            'address': address,
            'port': port,
            'provider': 'networktools.dev',
        }
    if status == 'TIMEOUT':
        raise ValueError(
            f'公网节点连接 {address} 的临时端口 {port} 超时。当前网络、热点或防火墙不允许 IPv6 主动入站；'
            '已停止流程，未写 DNS、未启动文件服务、未申请证书。请改用 Cloudflare Tunnel、Tailscale Funnel 或 FRP。'
        )
    raise ValueError(
        f'公网节点返回 {status or "未知"}。临时监听未能从外部建立连接；'
        '已停止流程，未写 DNS、未启动文件服务、未申请证书。'
    )


def api_tunnels(token, account):
    items = []
    for page in range(1, 21):
        batch = core.cf_api(token, 'GET', f'/accounts/{account}/cfd_tunnel?is_deleted=false&per_page=100&page={page}') or []
        items.extend(batch)
        if len(batch) < 100:
            break
    return items


def browser_tunnels(tool):
    output = cmd([tool, 'tunnel', '--output', 'json', 'list'], timeout=30)
    try:
        value = json.loads(output)
    except ValueError:
        start, end = output.find('['), output.rfind(']')
        if start < 0 or end < start:
            raise ValueError('无法读取 Cloudflare Tunnel 列表，未继续创建，以免名称重复。')
        value = json.loads(output[start:end + 1])
    if not isinstance(value, list):
        raise ValueError('Cloudflare Tunnel 列表格式异常，未继续创建。')
    return value


def cf_start(p):
    port = p['localPort']
    tool = find_tools()['cloudflared']['path']
    if p.get('cfMode') == 'quick':
        if storage.read(OWNED, {}).get('cloudflare', {}).get('tunnelId'):
            raise ValueError('已有固定域名 Tunnel，请先删除其发布配置，再切换临时模式。')
        with LOCK:
            kept = [entry for entry in LOGS if entry['kind'] != 'cloudflare-tunnel']
            LOGS.clear()
            LOGS.extend(kept)
        launch('cloudflare-tunnel', [tool, 'tunnel', '--no-autoupdate', '--url', f'http://127.0.0.1:{port}'], {'kind': 'Cloudflare 临时入口'})
        for _ in range(90):
            with LOCK:
                text = '\n'.join(e['message'] for e in LOGS if e['kind'] == 'cloudflare-tunnel')
            urls = re.findall(r'https://[a-z0-9-]+\.trycloudflare\.com', text)
            if urls:
                return {'url': urls[0], 'mode': 'quick'}
            proc = core.PROCESSES['cloudflare-tunnel']
            if proc.poll() is not None:
                raise ValueError('cloudflared 已退出，请查看运行日志。')
            time.sleep(.5)
        raise ValueError('未取得临时链接，请查看 cloudflared 日志后重试。')
    hostname = core.cf_hostname(p.get('hostname'))
    ensure_hostname_available('cloudflare', hostname)
    tunnel_name = core.cf_tunnel_name(p.get('tunnelName') or f"exposure-{hostname.split('.')[0]}")
    owned = storage.read(OWNED, {}).get('cloudflare', {})
    if owned.get('tunnelId') and (owned.get('hostname') != hostname or owned.get('mode') != p['cfMode'] or owned.get('tunnelName', tunnel_name) != tunnel_name):
        raise ValueError('已有其他 Tunnel 名称、域名或授权方式的命名 Tunnel。请先删除原发布配置，再创建。')
    if p['cfMode'] == 'browser':
        tid = owned.get('tunnelId')
        if not tid:
            duplicates = [item for item in browser_tunnels(tool) if str(item.get('name') or '').casefold() == tunnel_name.casefold()]
            if duplicates:
                raise ValueError(f'Tunnel 名称“{tunnel_name}”已存在。请换一个名称，或删除 Cloudflare 中的同名 Tunnel。')
            output = cmd([tool, 'tunnel', '--output', 'json', 'create', tunnel_name])
            match = re.search(r'\b[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\b', output, re.I)
            if not match:
                raise ValueError('Tunnel 创建结果未返回 ID，请在 Cloudflare 中检查。')
            tid = match.group(0)
            remember('cloudflare', tunnelId=tid, tunnelName=tunnel_name, hostname=hostname, mode='browser')
        try:
            cmd([tool, 'tunnel', 'route', 'dns', tid, hostname])
        except ValueError as exc:
            raise ValueError(
                f'{hostname} 无法绑定到 Tunnel。该主机名可能已有 AAAA、CNAME 或其他 DNS 记录；'
                f'Cloudflare 不允许 CNAME 与其他记录共存。原始错误：{exc}'
            ) from exc
        core.cf_launch_named_tunnel(tool, tid, hostname, port)
        return {'url': 'https://' + hostname, 'tunnelId': tid, 'tunnelName': tunnel_name, 'hostname': hostname, 'mode': 'browser'}
    zone = domain_zone(p)
    token = p['apiToken']
    tid = owned.get('tunnelId')
    account = zone['account']['id']
    quoted = urllib.parse.quote(hostname)
    records = core.cf_api(token, 'GET', f"/zones/{zone['id']}/dns_records?name={quoted}") or []
    if records and not (tid and len(records) == 1 and records[0].get('content') == tid + '.cfargotunnel.com'):
        types = '、'.join(sorted({str(record.get('type') or '未知') for record in records}))
        raise ValueError(f'{hostname} 已存在 {types} 记录，控制台不会覆盖。CNAME Tunnel 不能与 AAAA 或其他记录共存；请选一个空闲子域名。')
    duplicates = [item for item in api_tunnels(token, account) if str(item.get('name') or '').casefold() == tunnel_name.casefold() and str(item.get('id') or '') != str(tid or '')]
    if duplicates:
        raise ValueError(f'Tunnel 名称“{tunnel_name}”已存在。请换一个名称，或删除 Cloudflare 中的同名 Tunnel。')
    if not tid:
        try:
            created = core.cf_api(token, 'POST', f'/accounts/{account}/cfd_tunnel', {'name': tunnel_name, 'config_src': 'cloudflare'})
        except core.CloudflareTransportError:
            time.sleep(1)
            recovered = [item for item in api_tunnels(token, account) if str(item.get('name') or '').casefold() == tunnel_name.casefold()]
            if len(recovered) != 1:
                raise
            created = recovered[0]
        tid = created['id']
        remember('cloudflare', tunnelId=tid, tunnelName=tunnel_name, hostname=hostname, mode='api', accountId=account, zoneId=zone['id'])
    core.cf_api(token, 'PUT', f'/accounts/{account}/cfd_tunnel/{tid}/configurations', {'config': {'ingress': [{'hostname': hostname, 'service': f'http://127.0.0.1:{port}'}, {'service': 'http_status:404'}]}})
    record = records[0] if records else core.cf_api(token, 'POST', f"/zones/{zone['id']}/dns_records", {'type': 'CNAME', 'name': hostname, 'content': tid + '.cfargotunnel.com', 'proxied': True})
    remember('cloudflare', recordId=record['id'])
    runner = core.cf_api(token, 'GET', f'/accounts/{account}/cfd_tunnel/{tid}/token')
    SECRETS.add(runner)
    path = core.RUNTIME / 'cloudflare-token.txt'
    path.write_text(runner, encoding='utf-8')
    launch('cloudflare-tunnel', [tool, 'tunnel', '--no-autoupdate', 'run', '--token-file', str(path)], {'kind': 'Cloudflare 命名入口', 'configPath': str(path)})
    return {'url': 'https://' + hostname, 'mode': 'api', 'tunnelId': tid, 'tunnelName': tunnel_name, 'hostname': hostname, 'accountId': account, 'zoneId': zone['id'], 'recordId': record['id']}


def tail_start(route, p):
    tool = find_tools()['tailscale']['path']
    status = json.loads(cmd([tool, 'status', '--json']))
    if status.get('BackendState') != 'Running':
        raise ValueError('Tailscale 尚未登录，请在客户端登录后重试。')
    config = json.loads(cmd([tool, 'serve', 'status', '--json']) or '{}')
    owned = storage.read(OWNED, {})
    # A prior start may have succeeded before its ownership record was persisted.
    # Adopt only when every existing proxy points at this exact local service.
    if config and not any(owned.get(r, {}).get('active') for r in ('serve', 'funnel')):
        expected = f"http://127.0.0.1:{p['localPort']}"
        targets = tailscale_proxy_targets(config)
        if not targets or any(target.rstrip('/') != expected for target in targets):
            found = ', '.join(targets) if targets else '无法识别的目标'
            raise ValueError(f'设备已有其他 Serve/Funnel 配置（当前转发目标：{found}）。请先检查并停止该入口后重试。')
    for other in ('serve', 'funnel'):
        if owned.get(other, {}).get('active'):
            stop_route(other)
    cmd([tool, route, '--bg', '--https=443', f"http://127.0.0.1:{p['localPort']}"], timeout=35)
    actual = json.loads(cmd([tool, 'serve', 'status', '--json']) or '{}')
    if f"127.0.0.1:{p['localPort']}" not in json.dumps(actual):
        raise ValueError('Tailscale 未确认绑定到当前文件服务。')
    hostname = status.get('Self', {}).get('DNSName', '').rstrip('.')
    return {'url': 'https://' + hostname, 'targetPort': p['localPort']}


def tailscale_proxy_targets(config):
    targets = []
    def visit(value):
        if isinstance(value, dict):
            for key, child in value.items():
                if key.lower() == 'proxy' and isinstance(child, str):
                    targets.append(child)
                visit(child)
        elif isinstance(value, list):
            for child in value:
                visit(child)
    visit(config)
    return targets


def ssh_connect(p):
    import paramiko
    client = paramiko.SSHClient()
    known = DATA / 'known_hosts'
    if known.exists():
        client.load_host_keys(str(known))
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(core.validate_server_host(p.get('serverAddr')), port=int(p.get('sshPort') or 22), username=p.get('sshUser') or 'root', password=p.get('sshPassword') or None, timeout=12, auth_timeout=12, banner_timeout=12, allow_agent=True, look_for_keys=True)
        client.save_host_keys(str(known))
        return client
    except Exception:
        client.close()
        raise ValueError('SSH 连接失败：请检查地址、SSH 端口、用户名、密码/密钥或服务器主机密钥变化。')


def vps_check(p):
    client = ssh_connect(p)
    try:
        return core.ssh_run(client, 'uname -sm; command -v frps; systemctl is-active frps', timeout=20)
    finally:
        client.close()


def bootstrap(p):
    client = ssh_connect(p)
    try:
        who = core.ssh_run(client, 'id -u; uname -sm', timeout=15)
        if not who.startswith('0\n'):
            raise ValueError('自动安装当前需要 root 登录；普通账号请先由管理员配置 frps，再使用 token 配对。')
        if 'Linux x86_64' not in who:
            raise ValueError('当前自动部署支持 Linux x86_64；其他架构请安装对应 frps 后手动配对。')
        exists = core.ssh_run(client, 'if test -f /etc/frp/frps.toml; then echo exists; fi')
        if exists:
            import tomllib
            raw = core.ssh_run(client, 'cat /etc/frp/frps.toml')
            config = tomllib.loads(raw)
            token = config.get('auth', {}).get('token')
            if config.get('auth', {}).get('method') != 'token' or not token:
                raise ValueError('现有 frps 不使用可复用的 token 配对方式，请手动配置。')
            if int(config.get('bindPort', 7000)) != int(p['serverPort']):
                raise ValueError(f"服务器控制端口为 {config.get('bindPort', 7000)}，请修改控制台端口后重试。")
            core.ssh_run(client, 'systemctl is-active --quiet frps')
            core.save_frp_token(token)
            SECRETS.add(token)
            remember('frp', pairedHost=p['serverAddr'], pairedPort=int(p['serverPort']))
            return '已复用 VPS 现有 token，并加密保存；没有轮换服务器密钥。'
    finally:
        client.close()
    # Existing bootstrap is deliberately limited to the supported default deployment.
    if int(p['sshPort']) != 22 or int(p['serverPort']) != 7000:
        raise ValueError('新服务器自动安装目前使用 SSH 22 / frps 7000；请使用默认端口部署或预装 frps。')
    result = core.frp_bootstrap(p)
    remember('frp', pairedHost=p['serverAddr'], pairedPort=int(p['serverPort']))
    return result['message']


def install_tool(name):
    if name not in ('frpc', 'caddy', 'cloudflared'):
        raise ValueError('Tailscale 请通过官方安装程序安装并登录。')
    if platform.machine().lower() not in ('amd64', 'x86_64'):
        raise ValueError('自动安装暂支持 Windows x64，请为当前架构填写客户端路径。')
    repo = {'frpc': 'fatedier/frp', 'caddy': 'caddyserver/caddy', 'cloudflared': 'cloudflare/cloudflared'}[name]
    suffix = '/tags/v0.71.1' if name == 'frpc' else '/latest'
    request = urllib.request.Request('https://api.github.com/repos/' + repo + '/releases' + suffix, headers={'User-Agent': 'ExposureConsole'})
    with urllib.request.urlopen(request, timeout=30) as response:
        release = json.load(response)
    pattern = {'frpc': r'frp_.*_windows_amd64\.zip$', 'caddy': r'caddy_.*_windows_amd64\.zip$', 'cloudflared': r'cloudflared-windows-amd64\.exe$'}[name]
    asset = next((a for a in release['assets'] if re.fullmatch(pattern, a['name'])), None)
    if not asset:
        raise ValueError('官方发布中未找到匹配安装包。')
    with urllib.request.urlopen(asset['browser_download_url'], timeout=90) as response:
        content = response.read(150_000_000)
    digest = asset.get('digest') or ''
    if not digest.startswith('sha256:'):
        raise ValueError('官方 API 未提供 SHA256 校验值，未安装；请手动下载并填写路径。')
    if hashlib.sha256(content).hexdigest() != digest.split(':')[1]:
        raise ValueError('下载校验失败，未安装。')
    if asset['name'].endswith('.zip'):
        with zipfile.ZipFile(io.BytesIO(content)) as archive:
            member = next(n for n in archive.namelist() if Path(n).name == name + '.exe')
            content = archive.read(member)
    (TOOLS / (name + '.exe')).write_bytes(content)
    return tool_check(name)


def stop_route(route):
    record = storage.read(OWNED, {}).get(route, {})
    if route in ('serve', 'funnel'):
        if record.get('active'):
            tool = find_tools()['tailscale']['path']
            actual = cmd([tool, 'serve', 'status', '--json'])
            if f"127.0.0.1:{record.get('targetPort')}" not in actual:
                raise ValueError('Tailscale 配置已被外部修改，未停止其他服务。')
            cmd([tool, route, '--https=443', 'off'])
    elif route in PROC_IDS:
        service_id = PROC_IDS[route]
        if service_id in core.PROCESSES:
            core.stop_service(service_id)
        proc = core.PROCESSES.get(service_id)
        if proc and proc.poll() is None:
            raise ValueError('本控制台启动的入口进程尚未退出，未继续删除。')
    remember(route, active=False)
    return '入口已停止，配置已保留。'


def delete_tunnel_with_retry(delete):
    last_error = None
    for attempt in range(3):
        try:
            return delete()
        except Exception as exc:
            last_error = exc
            message = str(exc).lower()
            active = '1022' in message or 'active connection' in message or 'active connections' in message
            if not active or attempt == 2:
                break
            time.sleep(2 * (attempt + 1))
    if last_error and ('1022' in str(last_error) or 'active connection' in str(last_error).lower()):
        raise ValueError('Cloudflare Tunnel 仍有活跃连接（错误 1022）。已停止本控制台托管的入口并重试 3 次，但没有结束其他 cloudflared 进程；请在 Cloudflare 中确认其他 replica 已停止，等待几分钟后再删除。') from last_error
    raise last_error


def delete_route(route, p):
    stop_route(route)
    records = storage.read(OWNED, {})
    record = records.get(route, {})
    if route == 'cloudflare' and record.get('tunnelId'):
        tid = record['tunnelId']
        if record.get('mode') == 'api':
            token = p.get('apiToken')
            if not token:
                raise ValueError('需要 API Token 才能删除云端 Tunnel。入口已停止，配置保留。')
            if record.get('recordId'):
                path = f"/zones/{record['zoneId']}/dns_records/{record['recordId']}"
                remote = core.cf_api(token, 'GET', path)
                if remote.get('content') != tid + '.cfargotunnel.com':
                    raise ValueError('DNS 已被修改，未删除；请手动确认。')
                core.cf_api(token, 'DELETE', path)
                remember('cloudflare', recordId=None)
            delete_tunnel_with_retry(lambda: core.cf_api(token, 'DELETE', f"/accounts/{record['accountId']}/cfd_tunnel/{tid}"))
        else:
            tool = find_tools()['cloudflared']['path']
            if not tool:
                raise ValueError('未找到 cloudflared，入口已停止，Tunnel 配置仍保留。')
            delete_tunnel_with_retry(lambda: cmd([tool, 'tunnel', 'delete', tid]))
            records.pop(route, None)
            save_routes(records)
            return 'Tunnel 已删除。浏览器授权分支无法自动清理通用 DNS；请在 Cloudflare 删除指向此 Tunnel 的 CNAME。'
    elif route == 'ipv6' and record.get('dnsMode') == 'api' and record.get('recordCreated') and record.get('recordId'):
        token = p.get('apiToken')
        if not token:
            raise ValueError('需要 API Token 才能删除本控制台创建的 AAAA。HTTPS 入口已停止，DNS 配置仍保留。')
        path = f"/zones/{record['zoneId']}/dns_records/{record['recordId']}"
        remote = core.cf_api(token, 'GET', path)
        same_name = str(remote.get('name') or '').lower().rstrip('.') == str(record.get('hostname') or '').lower().rstrip('.')
        same_type = str(remote.get('type') or '').upper() == 'AAAA'
        try:
            same_address = str(core.ipaddress.ip_address(str(remote.get('content') or ''))) == str(core.ipaddress.ip_address(str(record.get('address') or '')))
        except ValueError:
            same_address = False
        if not (same_name and same_type and same_address):
            raise ValueError('AAAA 已被外部修改，未自动删除；请在 Cloudflare 中确认。')
        core.cf_api(token, 'DELETE', path)
    records.pop(route, None)
    save_routes(records)
    return '已删除本控制台的发布配置。共享文件、VPS frps 和手动 DNS 均保留。'


def publish(job, route, p):
    inbound = None
    if route == 'ipv6':
        inbound = job.step('检测公网 IPv6 入站能力', lambda: ipv6_inbound_probe(p))
        p = {**p, 'ipv6': inbound['address']}
    service = job.step('检查并启动文件服务', lambda: local_service(p))
    p = {**p, 'localPort': service['port']}
    tool = {'serve': 'tailscale', 'funnel': 'tailscale', 'cloudflare': 'cloudflared', 'frp': 'frpc', 'ipv6': 'caddy'}[route]
    if not find_tools()[tool]['installed'] and tool != 'tailscale':
        job.step('下载并校验缺少的客户端 ' + tool, lambda: install_tool(tool))
    job.step('检查 ' + tool, lambda: tool_check(tool))
    owned = storage.read(OWNED, {}).get(route, {})
    if route in PROC_IDS and PROC_IDS[route] in core.PROCESSES:
        job.step('停止旧入口以绑定当前服务', lambda: stop_route(route))
    if route in ('serve', 'funnel'):
        result = job.step('建立 Tailscale 入口', lambda: tail_start(route, p))
    elif route == 'cloudflare':
        if p.get('cfMode') == 'browser':
            def authorize():
                cf = find_tools()['cloudflared']['path']
                if not (core.CF_HOME / 'cert.pem').exists():
                    core.cf_login()
                    job.task['steps'][-1].update(status='waiting', detail='请在浏览器登录并授权；本窗口会自动等待结果。')
                    task_save()
                    for _ in range(180):
                        if CANCEL[job.task['id']].is_set():
                            raise Cancelled()
                        if (core.CF_HOME / 'cert.pem').exists():
                            break
                        time.sleep(1)
                return cmd([cf, 'tunnel', 'list'], timeout=30)
            job.step('检查浏览器授权', authorize)
        elif p.get('cfMode') == 'api':
            job.step('读取授权域名', lambda: f"发现 {len(cf_context(p))} 个可读 Zone；写入权限将在创建时验证。")
        result = job.step('创建或复用 Tunnel 并连接', lambda: cf_start(p))
    elif route == 'frp':
        if p.get('token'):
            job.step('加密保存手动配对密钥', lambda: core.frp_pair(p))
            remember('frp', pairedHost=p['serverAddr'], pairedPort=int(p['serverPort']))
        elif p.get('sshPassword'):
            job.step('检查 VPS 并自动配对', lambda: bootstrap(p))
        elif not core.load_frp_token():
            raise ValueError('请填写 VPS SSH 凭据以自动配对，或填写已有 FRP token。')
        paired = storage.read(OWNED, {}).get('frp', {})
        if paired.get('pairedHost') and paired['pairedHost'] != p['serverAddr']:
            raise ValueError('保存的配对凭据属于另一台 VPS，请提供新 VPS 的 SSH 凭据或 token。')
        result = job.step('启动 frpc 并建立端口映射', lambda: core.frp_tunnel(p))
    else:
        address = p['ipv6']
        hostname = core.cf_hostname(p.get('hostname'))
        ensure_hostname_available('ipv6', hostname)
        dns_record = None
        if p.get('dnsMode') == 'api':
            dns_record = job.step('写入 DNS-only AAAA', lambda: core.cf_upsert_direct_aaaa({**p, 'ipv6': address}))
        job.step('确认 DNS 配置与传播状态', lambda: confirm_ipv6_dns(p, hostname, address, dns_record))
        path = core.RUNTIME / 'Caddyfile'
        path.write_text(f'{hostname} {{\n bind ::\n reverse_proxy 127.0.0.1:{service["port"]}\n}}\n', encoding='utf-8')
        def caddy_start():
            binary = find_tools()['caddy']['path']
            cmd([binary, 'validate', '--config', str(path), '--adapter', 'caddyfile'])
            launch('caddy', [binary, 'run', '--config', str(path), '--adapter', 'caddyfile'], {'kind': 'IPv6 HTTPS', 'configPath': str(path)})
            return 'Caddy 已启动；证书申请状态见运行日志。'
        job.step('启动 HTTPS 并申请证书', caddy_start)
        result = {'url': 'https://' + hostname, 'hostname': hostname, 'address': str(address), 'dnsMode': p.get('dnsMode')}
        if dns_record:
            result.update(zoneId=dns_record['zoneId'], recordId=dns_record['recordId'], recordCreated=dns_record['recordCreated'])
    remember(route, **result, active=True)
    job.task['url'] = result['url']
    def verify():
        last = ''
        for _ in range(3):
            if CANCEL[job.task['id']].is_set():
                raise Cancelled()
            try:
                if fetch_marker(result['url']) == service['marker']:
                    return '从本机经分享地址收到当前项目标记。尚未验证独立外部网络。'
                last = '返回内容不匹配当前项目'
            except Exception as exc:
                last = verification_error(exc)
            time.sleep(1)
        raise ValueError('入口进程已启动，但分享链接未验证通过：' + last)
    try:
        job.step('验证链接确实指向当前文件服务', verify)
        job.task['status'] = 'warning'
        job.task['message'] = '分享链接本机回访通过；独立外部网络尚未验证。'
    except Cancelled:
        raise
    except Exception as exc:
        job.task['status'] = 'warning'
        job.task['message'] = str(exc)
    remember(route, verification=job.task['message'])


def execute(task, p):
    job = Job(task)
    action, route = task['action'], task.get('route')
    try:
        if action == 'publish':
            publish(job, route, p)
        elif action == 'files-start':
            job.step('检查目录、账户并启动本地服务', lambda: local_service(p))
        elif action == 'files-stop':
            for r, entry in storage.read(OWNED, {}).items():
                if entry.get('active'):
                    job.step('停止依赖入口：' + ROUTES.get(r, r), lambda r=r: stop_route(r))
            job.step('停止文件服务', lambda: core.stop_service('file-service') if 'file-service' in core.PROCESSES else '文件服务已停止')
        elif action == 'stop':
            job.step('停止入口', lambda: stop_route(route))
        elif action == 'delete':
            job.step('删除发布配置', lambda: delete_route(route, p))
        elif action == 'install':
            job.step('下载、校验并安装 ' + p['tool'], lambda: install_tool(p['tool']))
        elif action == 'bootstrap':
            job.step('检查 VPS、准备 frps 并配对', lambda: bootstrap(p))
        elif action == 'check':
            discovery = job.step('快速检查已知位置并验证客户端程序', lambda: discover_tool_paths(job))
            task['discovery'] = discovery
            for tool in find_tools():
                try:
                    job.step('验证客户端：' + tool, lambda tool=tool: tool_check(tool))
                except Exception:
                    pass
            info = job.step('检查 IPv6 地址和路由', lambda: core.probe()['ipv6'])
            task['steps'][-1]['detail'] = info['message'] + ' 入站可达性尚未验证。'
            if not info['available']:
                task['steps'][-1]['status'] = 'warning'
            if not p.get('apiToken'):
                task['steps'].append({'title': '验证 Cloudflare API 授权', 'status': 'skipped', 'detail': '未填写 API Token；临时 Tunnel 不需要此凭据。'})
            if not (p.get('serverAddr') and p.get('sshPassword')):
                task['steps'].append({'title': '验证 VPS SSH 连接', 'status': 'skipped', 'detail': '未填写完整 SSH 信息，未执行远程验证。'})
            if p.get('apiToken'):
                try:
                    job.step('验证 Cloudflare Token 与域名权限', lambda: f'读取到 {len(cf_context(p))} 个 Zone；写权限尚未执行验证。')
                except Exception:
                    pass
            if p.get('serverAddr') and p.get('sshPassword'):
                try:
                    job.step('检查 VPS 与 frps', lambda: vps_check(p))
                except Exception:
                    pass
            if any(s['status'] in ('failed', 'warning') for s in task['steps']):
                task.update(status='warning', message='检查完成，部分依赖尚未就绪；详情见各步骤。')
        else:
            raise ValueError('未知任务操作。')
        if task['status'] == 'running':
            task.update(status='success', message='操作完成。')
    except Cancelled:
        task.update(status='cancelled', message='任务已取消。已创建的服务或云端资源保留，可在对应线路停止或删除。')
    except Exception as exc:
        task.update(status='failed', message=redact(str(exc)))
        if not task['steps'] or task['steps'][-1]['status'] == 'success':
            task['steps'].append({'title': '检查下一步条件', 'status': 'failed', 'detail': redact(str(exc))})
        log('失败', str(exc))
    finally:
        task['ended'] = time.time()
        task_save()


def start_task(p):
    route = p.get('route')
    if p.get('action') in ('publish', 'stop', 'delete') and route not in ROUTES:
        raise ValueError('请选择有效线路。')
    with LOCK:
        running = next((t for t in TASKS.values() if t['status'] == 'running'), None)
        if running:
            return {'task': running}
        payload = {**settings(), **p}
        for key in SECRET_KEYS:
            if payload.get(key):
                SECRETS.add(payload[key])
        tid = secrets.token_hex(8)
        title = {'publish': '创建 / 启动', 'stop': '停止入口', 'delete': '删除配置', 'check': '检查环境', 'files-start': '启动文件服务', 'files-stop': '停止文件服务与入口', 'install': '安装客户端', 'bootstrap': 'VPS 安装与配对'}.get(p['action'], p['action'])
        task = {'id': tid, 'action': p['action'], 'route': route, 'title': ROUTES.get(route, '控制台') + ' · ' + title, 'status': 'running', 'steps': [], 'started': time.time(), 'message': ''}
        TASKS[tid] = task
        TASK_INPUTS[tid] = payload
        CANCEL[tid] = threading.Event()
        task_save()
        threading.Thread(target=execute, args=(task, payload), daemon=True).start()
        return {'task': copy.deepcopy(task)}


def snapshot():
    config = settings()
    safe = {k: v for k, v in config.items() if k not in SECRET_KEYS}
    safe['savedSecrets'] = {k: bool(config.get(k)) for k in SECRET_KEYS}
    procs = [{k: v for k, v in proc.items() if k != 'marker'} for proc in core.process_status()]
    route_state = storage.read(OWNED, {})
    for route, record in route_state.items():
        if route in PROC_IDS and record.get('active'):
            process = core.PROCESSES.get(PROC_IDS[route])
            if not process or process.poll() is not None:
                record.update(active=False, verification='入口进程未在本次会话运行，请重新启动并验证。')
    records = []
    if ACCESS.exists():
        with ACCESS.open(encoding='utf-8') as f:
            for line in deque(f, maxlen=500):
                try:
                    records.append(json.loads(line))
                except ValueError:
                    pass
    with LOCK:
        return {'settings': safe, 'users': users(), 'processes': procs, 'routes': route_state, 'tasks': copy.deepcopy(list(TASKS.values())[-40:]), 'logs': list(LOGS), 'records': list(reversed(records))}


class Handler(core.ConsoleHandler):
    def do_GET(self):
        if not self._is_local_request():
            return self._json(403, {'error': '仅允许本机访问控制台。'})
        path = urllib.parse.urlparse(self.path).path
        try:
            if path == '/api/v2/state':
                return self._json(200, snapshot())
            if path == '/api/v2/environment':
                return self._json(200, core.probe())
            if path == '/api/v2/urls':
                return self._json(200, visitor_urls())
            if path in ('/control.js', '/control.css'):
                data = (core.WEB / path[1:]).read_bytes()
                self.send_response(200)
                self.send_header('Content-Type', 'application/javascript' if path.endswith('.js') else 'text/css')
                self.send_header('Content-Length', str(len(data)))
                self.end_headers()
                self.wfile.write(data)
                return
            if path.startswith('/api/'):
                return self._json(404, {'error': '请刷新控制台，使用新版接口。'})
            super().do_GET()
        except Exception as exc:
            self._json(400, {'error': redact(str(exc))})

    def do_POST(self):
        if not self._is_local_request():
            return self._json(403, {'error': '仅允许本机访问控制台。'})
        try:
            p = self._body()
            path = self.path
            if path == '/api/v2/settings':
                with LOCK:
                    value = settings()
                    allowed = set(DEFAULTS) | SECRET_KEYS | {t + 'Path' for t in ('tailscale', 'cloudflared', 'caddy', 'frpc')}
                    for k, v in p.items():
                        if k in allowed and (k not in SECRET_KEYS or v):
                            value[k] = v
                            if k in SECRET_KEYS and v:
                                SECRETS.add(v)
                    storage.write(CONFIG, value)
                result = {'message': '配置已保存；凭据使用当前 Windows 用户加密。'}
            elif path == '/api/v2/users':
                result = change_user(p)
            elif path == '/api/v2/pick':
                result = core.pick_directory()
            elif path == '/api/v2/task':
                result = start_task(p)
            elif path == '/api/v2/cancel':
                CANCEL[p['id']].set()
                result = {'message': '已请求取消；正在执行的命令结束或超时后停止后续步骤。'}
            elif path == '/api/v2/retry':
                old = TASK_INPUTS.get(p['id'])
                if not old:
                    raise ValueError('任务来自上次会话，请从线路重新启动。')
                result = start_task({**old, **settings()})
            elif path == '/api/v2/zones':
                result = {'zones': [{'name': z['name'], 'id': z['id']} for z in cf_context(settings())]}
            else:
                raise ValueError('未知操作，请刷新页面。')
            self._json(200, result)
        except Exception as exc:
            self._json(400, {'error': redact(str(exc))})


def main():
    if TASKFILE.exists():
        for task in json.loads(TASKFILE.read_text(encoding='utf-8')):
            if task['status'] == 'running':
                task.update(status='interrupted', message='控制台已重启，请检查现状后重新启动。')
            TASKS[task['id']] = task
    for k in SECRET_KEYS:
        if settings().get(k):
            SECRETS.add(settings()[k])
    previous = DATA / 'operations.jsonl'
    if previous.exists():
        for line in deque(previous.read_text(encoding='utf-8').splitlines(), maxlen=300):
            try:
                LOGS.appendleft(json.loads(line))
            except ValueError:
                pass
    server = ThreadingHTTPServer(('127.0.0.1', 8765), Handler)
    log('控制台', '控制台已启动。历史任务与配置已恢复；线路需重新检查运行状态。')
    print('Exposure Console http://127.0.0.1:8765', flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        for name in list(core.PROCESSES):
            core.stop_service(name)
        server.server_close()


if __name__ == '__main__':
    main()

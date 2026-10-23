# OpenShare Console

[English](README_EN.md)

OpenShare Console 是一个面向 Windows 的本机文件与网站发布控制台。它把文件服务、账号权限、访问记录和多种公网发布方式集中到一个只在本机开放的网页界面，并以逐步任务面板显示每一步的成功、失败和处理建议。

> 项目仍处于早期阶段。向公网发布文件具有安全风险，请先阅读“安全说明”。

## 为什么使用 OpenShare Console

- **一键发布，全流程实现**：从选择文件、启动本地服务，到建立公网入口、生成访客 URL 和验证访问状态，都在同一个控制台中逐步完成。
- **无需复杂配置**：尽量自动发现客户端、复用已有授权并生成连接配置，适合临时分享、演示前来不及部署、远程协作和快速内测等场景。
- **软件本身无任何费用**：OpenShare Console 不收取订阅费或服务费；使用 Tailscale Serve/Funnel、Cloudflare Tunnel 或原生 IPv6 的免费能力时，可以在不购买本项目服务的情况下完成分享。

> OpenShare Console 本身完全免费，但自购 VPS、域名，以及第三方平台超出免费额度后的资源用量，仍可能由对应服务商收费。

## 功能

- 选择共享目录和本地端口，一键启动或停止文件服务，并贯通公网发布全流程。
- 创建六位数字密码的访问账号，并分别授予读取、上传、修改、重命名和删除权限。
- 记录访问时间、账号、来源、浏览器、操作、路径、状态码和耗时。
- 逐步执行、取消、重试和查看历史任务，不把“进程已启动”冒充为“公网已经可访问”。
- 支持五条发布线路：
  - Tailscale Serve：仅供获准加入 tailnet 的访客访问。
  - Tailscale Funnel：生成临时公网 HTTPS 入口。
  - Cloudflare Tunnel：临时随机域名或自定义域名。
  - VPS + FRP：通过自有公网 VPS 的 IPv4 和端口转发。
  - 原生 IPv6：先从公网检测 IPv6 入站能力，再配置 AAAA 与 Caddy HTTPS。
- 快速检测常见安装位置中的 Tailscale、cloudflared、frpc 和 Caddy；不会遍历整块磁盘。
- 使用 Windows DPAPI 加密保存管理凭据。

## 系统要求

- Windows 10/11
- Python 3.11 或更高版本（建议 3.13）
- 可选客户端取决于所选线路：Tailscale、cloudflared、frpc、Caddy
- VPS 自动部署需要 `paramiko`：

```powershell
py -m pip install paramiko
```

## 快速开始

```powershell
git clone https://github.com/shuziyuxingxing-stack/openshare-console.git
cd openshare-console
.\Start-ExposureConsole.ps1
```

或者直接运行：

```powershell
py -3 control.py
```

随后打开 <http://127.0.0.1:8765/>。管理控制台只监听回环地址，不应通过端口映射直接暴露到公网。

运行测试：

```powershell
py -3 -m unittest -v
```

## 发布线路怎么选

| 线路 | 适合场景 | 访客需要安装软件 | 域名 | 主要外部条件 |
|---|---|---:|---:|---|
| Tailscale Serve | 小范围内测 | 是 | 自动分配 | 访客已加入获准访问的 tailnet |
| Tailscale Funnel | 临时公开分享 | 否 | 自动分配 | 管理员允许 Funnel |
| Cloudflare Tunnel | 公网 HTTPS、固定域名 | 否 | 临时模式不需要 | Cloudflare 授权；固定域名已托管到 Cloudflare |
| VPS + FRP | 长期 IPv4 端口入口 | 否 | 不需要 | VPS 运行 frps，安全组和防火墙放行端口 |
| 原生 IPv6 | 不经过中继的直连 | 否，但访客网络需支持 IPv6 | HTTPS 建议需要 | 本机拥有可入站的全球 IPv6，80/443 可达 |

## Cloudflare 授权

固定域名支持两种方式：

1. 浏览器授权：调用 cloudflared 官方登录流程并读取本机授权证书。
2. API Token：建议最小权限为 `Account → Cloudflare Tunnel → Edit`、`Zone → DNS → Edit` 和读取 Zone 所需权限。

控制台不会覆盖指向其他目标的同名 DNS 记录，也会阻止同一主机名同时被 CNAME Tunnel 和 AAAA 直连占用。

## VPS + FRP

首次使用时可提供 VPS 地址和 SSH 凭据，让控制台安装或检查 frps、生成随机配对密钥并通过 DPAPI 保存。也可以连接已经部署好的 frps。访客最终访问类似 `http://203.0.113.10:18080` 的地址。

无域名的 FRP TCP 模式默认是 HTTP，Basic Auth 密码不会获得传输层加密；请勿用于敏感文件。长期使用应在 VPS 上配置 HTTPS 反向代理，或改用 Cloudflare Tunnel。

## IPv6 入站预检

IPv6 线路的第一步会创建一个一次性 TCP 监听端口，并请求独立公网节点连接该端口。只有检测成功后，控制台才会启动文件服务、检查 Caddy、写入 AAAA 和申请证书。探测服务只会收到公网 IPv6 与临时端口，不会收到文件内容或凭据。

## 数据与安全

- 配置、API Token、SSH 密码、FRP 密钥和文件用户密码存放在 `%LOCALAPPDATA%\ExposureConsole\control\`，并由当前 Windows 用户的 DPAPI 加密。
- Cloudflare 运行 Token 和生成的连接器配置可能短暂写入 `runtime/`，正常停止后会清理；该目录已被 Git 忽略。
- 访问日志不记录密码或 Authorization 请求头。
- 文件服务使用 HTTP Basic Auth。只有通过可信 HTTPS 隧道或反向代理发布时，密码传输才受到保护。
- 请不要公开 SMB、RDP、NAS 管理端口或未认证的本地 API。
- 浏览器授权产生的 Cloudflare `cert.pem` 具有管理能力，绝不能提交到仓库或发送给他人。
- 安全问题请参阅 [SECURITY.md](SECURITY.md)。

## 已知限制

- 当前主要面向 Windows；DPAPI 存储在非 Windows 系统上不可用。
- 自动部署 frps 当前针对 Linux x86_64 和 root 管理场景。
- 云厂商安全组、运营商入站过滤和上游网络策略无法仅靠本机程序绕过。
- 本机 DNS 缓存可能晚于权威 DNS 生效，因此 DNS 写入成功和本机回访验证会分开报告。

## 许可证

本仓库当前未附带开源许可证。除非版权所有者另行授权，否则保留所有权利。

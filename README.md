# OpenShare Console

[English](README_EN.md)

OpenShare Console 可以一键将本机文件部署到公网，无需付费，无需任何额外操作和部署，适合小白体质。当你临时需要将网站给朋友浏览、来不及部署到云服务器上时，这个项目是你绝佳的选择。我们设置了五条线路，均一键部署：这意味着在任何线路下，你只需要点击“创建/启动”按钮，你将看到项目的每一步是否成功，约2分钟后，你将收获一条可直接分享给他人查看浏览的公网链接。我们同时还设计了完善的账号和权限管理系统。

##我为什么做这个项目
因为本地部署到公网、或者临时把本地网站分享给他人是日常情景，但是部署到公网的方式繁杂，收钱项目（如pinme）也五花八门，门外汉多半不了解不同方式之间的原理和区别，遑论具体如何操作。我们希望通过一键部署、打通本地云端和cloudflare的方式让部署到公网变得易操作。有了该项目后，我们选择自己青睐的路径一键部署等流程走完（约2分钟）即可，命令行、DNS解析、上云都交给程序自动搞定。

## 为什么使用 OpenShare Console

- **一键发布**：从选择文件、启动本地服务，到建立公网入口、生成访客 URL 和验证访问状态，都在同一个控制台中逐步完成。你将看到这些步骤流水线执行，无需你进行任何操作。
  
- **无需复杂配置**：集成tailscale、cloudflare tunnel、vps frp、IPV6直连等路径，打通本地、云端，我们将为你自动创建环境、配置本地网络、连接云服务器、检测本地路由，你仅需提供必要信息交由程序自动执行即可。适合临时分享、演示前来不及部署、远程协作和快速内测。
  
- **无任何费用**：OpenShare Console 不收取任何费用。
  
- **隐私安全**：所有信息均在你本地。
  
> OpenShare Console 本身完全免费，但如果你选择购买 VPS、域名的路径（可选且非必须），仍可能由对应服务商收费。

## 功能

- 选择共享目录和本地端口，一键启动或停止文件服务，并贯通公网发布全流程。
  
- 创建访问账号和访问密码，并分别授予读取、上传、修改、重命名和删除权限。
  
- 记录访问时间、账号、来源、浏览器、操作、路径、状态码等信息。
  
- 支持五条发布线路：
  
| 线路 | 适合场景 | 访客需要安装软件 | 域名 | 可访问群体
|---|---|---:|---:|---|
| Tailscale Serve | 小范围内测 | 是 | 自动分配 |  tailnet组网内的访客 |
| Tailscale Funnel | 临时公开分享 | 否 | 自动分配 | 所有人|
| Cloudflare Tunnel | 公网 HTTPS、固定域名 | 否 | 临时模式不需要 | 所有人|
| VPS + FRP | 长期 IPv4 端口入口 | 否 | 不需要 |所有人|
| 原生 IPv6 | 不经过中继的直连 | 否，但访客网络需支持 IPv6 | HTTPS 建议需要 | 所有人（前提是主机支持ipv6入站） |
    

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

## Cloudflare 授权

固定域名支持两种方式：

1. 浏览器授权：调用 cloudflared 官方登录流程并读取本机授权证书。
2. API Token授权。

保存到配置栏即可复用。任何授权信息都保存于您的本地。

## VPS + FRP

首次使用时可提供 VPS 地址和 SSH 凭据，控制台将安装或检查 frps、生成随机配对密钥并通过 DPAPI 保存。也可以连接已经部署好的 frps。访客最终访问类似 `http://203.0.113.10:18080` 的地址。

## 数据与安全

- 配置、API Token、SSH 密码、FRP 密钥和文件用户密码由当前 Windows 用户的 DPAPI 加密。
- 运行 Token 和生成的连接器配置会清理。
- 访问日志不记录密码或 Authorization 请求头。
- 安全问题请参阅 [SECURITY.md](SECURITY.md)。


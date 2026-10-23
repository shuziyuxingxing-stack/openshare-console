# OpenShare Console

[中文](README.md)

OpenShare Console lets you publish local files or a local website to the public Internet with one click — no payment, no extra deployment steps, and beginner-friendly. When you need to show a website to a friend or share files temporarily and don't have time to deploy to a cloud server, this is an excellent choice. Five publication routes are available, all deployed with one click: on any route, you only need to click "Create/Start", watch each step succeed, and in about two minutes you'll have a public URL you can share directly. A complete account and permission management system is also included.

## Why I built this project

Publishing local services to the public Internet, or temporarily sharing a local website with others, is a daily scenario — but the available methods are complicated, and paid projects (such as pinme) vary widely. Most non-experts don't understand the principles and differences between methods, let alone how to operate them. We want to make public deployment easy through one-click deployment that connects local, cloud, and Cloudflare. With this project, you choose your preferred route and let the program handle the rest (about 2 minutes) — command line, DNS resolution, and cloud setup are all automated.

## Why use OpenShare Console

- **One-click publishing**: From selecting files, starting the local service, to establishing the public route, generating the visitor URL, and verifying access status, everything happens step by step in the same console. You'll see the pipeline execute without any manual intervention.

- **No complex configuration**: Integrated routes include Tailscale, Cloudflare Tunnel, VPS + FRP, and native IPv6. We automatically create the environment, configure the local network, connect to the cloud server, and detect the local route — you only provide the necessary information and the program does the rest. Suitable for temporary sharing, last-minute demos, remote collaboration, and rapid internal testing.

- **No fees**: OpenShare Console charges no fees.

- **Privacy and security**: All information stays on your local machine.

> OpenShare Console itself is completely free. If you choose to purchase a VPS or domain (optional and not required), the corresponding provider may still charge you.

## Features

- Select a shared directory and local port, start or stop the file service with one click, and complete the entire public publishing workflow.

- Create access accounts and passwords, and grant read, upload, modify, rename, and delete permissions independently.

- Record access time, account, source, browser, operation, path, status code, and duration.

- Run, cancel, retry, and review observable background workflows.

- Five publication routes:

| Route | Best for | Visitor software required | Domain | Accessible to |
|---|---|---:|---:|---|
| Tailscale Serve | Private testing | Yes | Assigned automatically | Visitors within the tailnet |
| Tailscale Funnel | Temporary public sharing | No | Assigned automatically | Everyone |
| Cloudflare Tunnel | Public HTTPS, fixed domain | No | Not required in quick mode | Everyone |
| VPS + FRP | Long-term IPv4 port entry | No | Not required | Everyone |
| Native IPv6 | Direct connection without relay | No, but visitor network must support IPv6 | Recommended for HTTPS | Everyone (provided the host supports IPv6 inbound) |

  **Main external requirements**: Tailscale Serve requires the visitor to belong to an authorized tailnet; VPS + FRP requires frps to be running and VPS firewall/security-group ports to be open; native IPv6 requires a globally routable inbound IPv6 address and reachable ports 80/443.

## Requirements

- Windows 10/11
- Python 3.11 or newer (3.13 recommended)
- Optional route-specific clients: Tailscale, cloudflared, frpc, and Caddy
- `paramiko` for automated VPS setup: `py -m pip install paramiko`

## Quick start

```powershell
git clone https://github.com/shuziyuxingxing-stack/openshare-console.git
cd openshare-console
.\Start-ExposureConsole.ps1
```

Or run `py -3 control.py`, then open <http://127.0.0.1:8765/>. 

Run tests with `py -3 -m unittest -v`.

## Cloudflare authorization

Fixed hostnames support two methods:

1. Browser authorization: use cloudflared's official login flow and read the local authorization certificate.
2. API Token authorization.

Save to the configuration field for reuse. All authorization information is stored on your local machine.

A minimal API Token should include `Account → Cloudflare Tunnel → Edit`, `Zone → DNS → Edit`, and the permissions required to read the target zone.

## VPS + FRP

On first use, you can provide the VPS address and SSH credentials. The console will install or check frps, generate a random shared secret, and save it via DPAPI. You can also connect to an already-deployed frps. Visitors ultimately open an address such as `http://203.0.113.10:18080`.

## IPv6 inbound preflight

The first IPv6 workflow step opens a one-time TCP listener and asks an independent public node to connect to it. The console proceeds to the file service, Caddy, AAAA DNS, and certificate steps only after that connection succeeds. 

## Data and security

- Configuration, API Tokens, SSH passwords, FRP secrets, and file-user passwords are  encrypted with the current Windows user's DPAPI key.
- Cloudflare runner tokens and generated connector files may briefly exist under `runtime/`; normal shutdown removes them and Git ignores the directory.
- Access logs never store passwords or the Authorization header.
- See [SECURITY.md](SECURITY.md) for vulnerability reporting guidance.

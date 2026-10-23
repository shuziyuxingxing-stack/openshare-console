# OpenShare Console

[中文](README.md)

OpenShare Console is a Windows-first local control panel for publishing files or local websites. It combines a file server, per-user permissions, access logs, and several public exposure methods in a browser interface that is only available on the local machine. Every workflow reports its progress step by step instead of treating a started process as proof that the public URL is reachable.

> This project is at an early stage. Publishing local files to the Internet carries security risks; read the Security section first.

## Why OpenShare Console

- **One-click publishing, end to end**: select files, start the local service, establish a public route, obtain the visitor URL, and verify reachability from one guided console.
- **No complex configuration**: the console discovers clients, reuses existing authorization, and generates connector configuration wherever possible. It is designed for temporary sharing, last-minute demos, rapid testing, and situations where there is no time for a traditional deployment.
- **No fee for the software**: OpenShare Console charges no subscription or service fee. Free capabilities offered by Tailscale Serve/Funnel, Cloudflare Tunnel, or native IPv6 can be used without purchasing any OpenShare Console service.

> OpenShare Console itself is completely free. A separately purchased VPS or domain, and third-party usage beyond a provider's free allowance, may still incur charges from that provider.

## Features

- Select a directory and local port, then run the complete local-to-public publishing workflow from one place.
- Create six-digit user passwords and grant read, upload, modify, rename, and delete permissions independently.
- Record access time, account, connection source, browser, operation, path, status code, and duration.
- Run, cancel, retry, and review observable background workflows.
- Five publication routes: Tailscale Serve, Tailscale Funnel, Cloudflare Tunnel, VPS + FRP, and native IPv6.
- Fast discovery of Tailscale, cloudflared, frpc, and Caddy in common locations without scanning the entire disk.
- Windows DPAPI encryption for stored management credentials.

## Requirements

- Windows 10 or 11
- Python 3.11 or newer (3.13 recommended)
- Optional route-specific clients: Tailscale, cloudflared, frpc, and Caddy
- `paramiko` for automated VPS setup: `py -m pip install paramiko`

## Quick start

```powershell
git clone https://github.com/shuziyuxingxing-stack/openshare-console.git
cd openshare-console
.\Start-ExposureConsole.ps1
```

Or run `py -3 control.py`, then open <http://127.0.0.1:8765/>. The management interface only binds to loopback and should never be port-forwarded directly to the Internet.

Run tests with `py -3 -m unittest -v`.

## Choosing a route

| Route | Best for | Visitor software | Domain | Main external requirement |
|---|---|---:|---:|---|
| Tailscale Serve | Private testing | Required | Assigned automatically | Visitor belongs to an authorized tailnet |
| Tailscale Funnel | Temporary public sharing | None | Assigned automatically | Funnel is allowed by the tailnet administrator |
| Cloudflare Tunnel | Public HTTPS and custom hostnames | None | Not required in quick mode | Cloudflare authorization and, for fixed hostnames, a Cloudflare-managed zone |
| VPS + FRP | Persistent IPv4 port entry | None | Not required | frps is running and VPS firewall/security-group ports are open |
| Native IPv6 | Direct access without a relay | None, but IPv6 is required | Recommended for HTTPS | A globally routable inbound IPv6 address and reachable ports 80/443 |

## Cloudflare authorization

Fixed hostnames support either the official cloudflared browser login flow or an API Token. A minimal API Token should include `Account → Cloudflare Tunnel → Edit`, `Zone → DNS → Edit`, and the permissions required to read the target zone.

The console never overwrites an existing DNS record that points elsewhere. It also prevents a hostname from being assigned to both a Tunnel CNAME and a direct IPv6 AAAA record.

## VPS + FRP

The console can connect to a VPS over SSH, install or inspect frps, generate a random shared secret, and protect it with DPAPI. Visitors ultimately open an address such as `http://203.0.113.10:18080`.

The domainless FRP TCP mode uses plain HTTP by default. HTTP Basic Auth credentials are not protected in transit, so this mode is unsuitable for sensitive data. Terminate HTTPS on the VPS or use Cloudflare Tunnel for long-term sharing.

## IPv6 inbound preflight

The first IPv6 workflow step opens a one-time TCP listener and asks an independent public node to connect to it. The console proceeds to the file service, Caddy, AAAA DNS, and certificate steps only after that connection succeeds. The probe receives only the public IPv6 address and temporary port, never credentials or file contents.

## Data and security

- Configuration, API Tokens, SSH passwords, FRP secrets, and file-user passwords are stored under `%LOCALAPPDATA%\ExposureConsole\control\` and encrypted with the current Windows user's DPAPI key.
- Cloudflare runner tokens and generated connector files may briefly exist under `runtime/`; normal shutdown removes them and Git ignores the directory.
- Access logs never store passwords or the Authorization header.
- The file server uses HTTP Basic Auth. Credentials are protected in transit only when the service is published through trusted HTTPS.
- Never expose SMB, RDP, NAS administration ports, or unauthenticated local APIs.
- A Cloudflare `cert.pem` obtained through browser authorization has management privileges and must never be committed or shared.
- See [SECURITY.md](SECURITY.md) for vulnerability reporting guidance.

## Known limitations

- Windows is the primary platform; DPAPI-backed storage is unavailable elsewhere.
- Automated frps setup currently targets Linux x86_64 with root administration.
- The console cannot bypass cloud security groups, carrier inbound filtering, or upstream network policy.
- Local DNS caches may lag behind authoritative DNS, so DNS write success and local URL verification are reported separately.

## License

No open-source license is currently granted. All rights are reserved unless the copyright owner states otherwise.

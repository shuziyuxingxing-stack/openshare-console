# 项目维护须知

- Windows 本机 Python 项目，控制台入口为 `control.py`，监听 `127.0.0.1:8765`；`Start-ExposureConsole.ps1` 是后台启动入口。
- README 的最低 Python 版本为 3.11。不得将启动器写死为 3.13；存在 `py.exe` 不代表已安装某个具体版本。应实际验证解释器，并确认 HTTP 就绪后才打开浏览器。
- Python 命令探测须逐个处理 `Get-Command` 返回的 ApplicationInfo；真实解释器与 WindowsApps 别名同时在 PATH 时可能返回多个结果，不能将其 `.Source` 数组直接传给调用运算符。
- PowerShell 启动器须兼容 Windows PowerShell 5.1，使用 ASCII 内容、UTF-8 无 BOM，避免中文脚本在默认编码下解析错误。子进程保持隐藏，错误应保存在 `%LOCALAPPDATA%\ExposureConsole\control\console.stderr.log`，标准输出保存在同目录 `console.stdout.log`。
- `Start-Process -PassThru` 返回后保留进程句柄；确认 `HasExited` 后调用 `WaitForExit()` 再读取日志和退出码。Windows PowerShell 5.1 未保留句柄时可能得到空的 `ExitCode`。
- 本机 HTTP 健康检查应绕过代理，只检查首页及 `ExposureConsole/` 服务标识。`/api/v2/state` 含账号等本地数据，不得原样输出到诊断日志或聊天。
- 配置和凭据存放在 `%LOCALAPPDATA%\ExposureConsole`，使用 Windows DPAPI；不要覆盖、删除或提交这些文件。`paramiko` 仅为 VPS 自动部署功能的可选依赖，不影响控制台启动。
- 验证启动器时覆盖缺少 3.13、重复运行和进程启动失败的情况；可用 `-NoBrowser` 避免测试弹出浏览器。现有应用测试为 `py -3 -m unittest -v`。
- 2026-10-24：从远程 `main` 的 `4452ab3` 排查，确认旧启动器强制 `py -3.13`、隐藏错误并在 700 毫秒后无条件打开页面，可造成拒绝连接。修改前先核对当前 HEAD 与远程分支，避免基于旧代码覆盖后续更新。

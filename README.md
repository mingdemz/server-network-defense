# 服务器防御系统

纯防御型的本地安全小工具，用 Python 标准库编写，不需要安装额外依赖。
适合在 Windows 或 Linux 服务器上做日常检查：看本机端口和防火墙、分析访问日志、给网站前面加一层限流与特征拦截，以及监控网站目录有没有被改过。

> 这是监控和防护辅助工具，不能替代系统更新、杀毒软件、正规防火墙或云厂商的 WAF。
> 本工具不会破解密码、不会扫描别人的网络，也不会自动修改系统防火墙。

兼容：Windows 10/11（含 Python 3.14）、Linux；需要 Python 3.10 或更高版本。

## 文件说明

| 文件 | 作用 |
| --- | --- |
| `server_defense.py` | 主程序（命令行工具） |
| `defense_policy.json` | 策略配置：限流阈值、高风险端口、敏感路径等 |
| `sample_access.log` | 带正常流量和模拟攻击的示例日志，供练习使用 |
| `README.md` | 本说明 |

## 快速开始

在 PowerShell 或命令提示符中，先进入本目录：

```powershell
cd "D:\Users\Administrator\测试\2"
python server_defense.py --help
python server_defense.py demo
```

`demo` 会用示例日志做一次分析、在临时目录里演示文件完整性检查，再对本机做只读的端口/连接审计。它不会改你的文件，也不会改防火墙。

CMD 用法相同，只需把引号按习惯调整即可：

```cmd
cd /d "D:\Users\Administrator\测试\2"
python server_defense.py demo
```

## 功能一：安全基线审计 `audit`

检查本机正在监听的 TCP/UDP 端口，标出对 `0.0.0.0` 或 `::`（也就是所有网卡）开放的高风险端口（如 21、23、445、3306、3389、6379 等）；读取 Windows 防火墙各配置文件开关，或 Linux 上的 ufw / iptables 状态；统计已经建立的连接里，哪些对端 IP 特别多（可能是扫描或连接洪水的迹象）。

```powershell
python server_defense.py audit
python server_defense.py audit --report report.json
```

没有管理员权限时，防火墙状态可能读不全，程序会提示原因并继续检查其他项。

## 功能二：日志分析 `scan-log`

分析 Apache / Nginx 常见的 Combined 日志，识别：

- SQL 注入探测、XSS 尝试、路径穿越（`../`）、命令注入特征
- 敏感文件或后台探测（`.env`、`.git`、`wp-login.php`、`phpmyadmin` 等）
- 可疑扫描器的 User-Agent
- 短时间内大量 4xx 失败请求（疑似爆破）

```powershell
python server_defense.py scan-log --file sample_access.log
python server_defense.py scan-log --file sample_access.log --report log_report.json
python server_defense.py scan-log --file sample_access.log --gen-block-script block_ips.ps1
```

`--gen-block-script` 只是生成一份 PowerShell（或 Linux 下的 `.sh`）封禁脚本，**不会自动执行**。请先确认名单里的 IP 确实是攻击来源，再以管理员身份手动运行。

Linux 示例：

```bash
python3 server_defense.py scan-log --file sample_access.log --gen-block-script block_ips.sh
```

## 功能三：防护反向代理 `shield-proxy`

在本机网站前面加一层迷你 WAF：监听本地端口，把正常请求转发到后端，同时做：

- 按 IP 的滑动窗口限流，超限后临时封禁一段时间（返回 429）
- 拦截带 SQL 注入 / XSS / 路径穿越 / 敏感路径特征的请求（返回 403）
- 限制请求体大小
- 为响应补上安全头（如 `X-Content-Type-Options`、`X-Frame-Options`）
- 把拦截和限流事件写入告警日志

假设你的网站在 `http://127.0.0.1:8000`，可以这样启动：

```powershell
python server_defense.py shield-proxy --listen 127.0.0.1:8080 --target http://127.0.0.1:8000
```

然后用浏览器访问 `http://127.0.0.1:8080`。告警默认写到当前目录的 `defense_alerts.log`，也可以改路径：

```powershell
python server_defense.py shield-proxy --listen 127.0.0.1:8080 --target http://127.0.0.1:8000 --alert-log D:\logs\defense_alerts.log
```

按 `Ctrl+C` 即可停止。默认只监听本机回环地址，不会把代理暴露到公网。若要给他人访问，请务必先用系统防火墙限制来源。

## 功能四：文件完整性监控 `fim`

给网站目录做一份 SHA-256 基线，之后对照检查哪些文件被新增、修改或删除，便于发现异常改动。

```powershell
python server_defense.py fim --init --path "D:\www" --db "D:\Users\Administrator\测试\2\fim_baseline.json"
python server_defense.py fim --check --path "D:\www" --db "D:\Users\Administrator\测试\2\fim_baseline.json"
python server_defense.py fim --check --path "D:\www" --db "D:\Users\Administrator\测试\2\fim_baseline.json" --report fim_report.json
```

建议把基线文件放在被监控目录外面，避免它自己也被算进去。网站有正常更新后，需要重新执行 `--init` 刷新基线。

## 策略文件 `defense_policy.json`

可以按需要修改，不改也能用默认值：

- `rate_limit.window_seconds` / `max_requests` / `ban_seconds`：限流窗口、窗口内最大请求数、临时封禁秒数
- `request_max_bytes`：防护代理允许的最大请求体
- `high_risk_ports`：审计时视为高风险的端口列表
- `allowlist_ips`：白名单 IP（日志分析时不记为可疑，代理中不限流）。默认是空的，以免本机测试时限流不生效
- `sensitive_paths`：视为敏感的路径关键词
- `connection_threshold`：同一对端 IP 的已建立连接数告警阈值
- `brute_force`：日志里短时间 4xx 次数达到多少算疑似爆破

指定其他策略文件：

```powershell
python server_defense.py audit --policy "D:\Users\Administrator\测试\2\defense_policy.json"
```

## 给新手的建议

1. 先运行 `demo` 看一遍完整流程，再对自己的日志或网站目录动手。
2. 家庭路由或云服务器本身就要改默认密码、关掉不需要的端口、打开系统防火墙。
3. 发现高风险端口对外网开放时，优先在系统防火墙或云安全组里限制来源，而不是只靠本工具。
4. 生成的封禁脚本一定要先看名单再执行，避免误封正常用户或自己的办公网。
5. 定期更新系统和应用程序，备份重要数据。本工具只是多一层观察和拦截。

## 许可与范围

本程序仅用于保护你自己管理的主机和网站。请不要用它去探测或干扰未经授权的系统。

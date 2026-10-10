# poc —— 协议验证脚本（Python）

这里放的是**协议逆向阶段用来验证的脚本**，不是最终交付物。

最终交付物是仓库根目录的 Go 程序（`auto-connect.exe`）。这个 Python 脚本的价值在于：

1. **记录协议是怎么被验证出来的** —— 配合 [`../docs/协议分析.md`](../docs/协议分析.md) 一起看，可以完整复现整个逆向过程。
2. **改一行就能试** —— 如果你要适配自己学校的网关，用 Python 试错比改 Go 快得多。验证通过后再翻译成 Go 适配器。

## 依赖

只用 Python 标准库，不需要 pip install 任何东西。

## 用法

```bash
# 查看当前联网状态（最安全，什么都不改）
python drcom_login.py --status

# 空跑：只打印将要发出的请求，不真的提交
python drcom_login.py --user 你的学号 --password 你的密码 --isp cmcc --dry-run --force

# 真实认证一次
python drcom_login.py --user 你的学号 --password 你的密码 --isp cmcc

# 常驻监控：掉线自动重连（Ctrl+C 退出）
python drcom_login.py --watch --user 你的学号 --isp cmcc

# 蹲守模式：先启动它，再去认证页点「退出」，程序捕获到掉线后立刻登录
python drcom_login.py --wait-offline 300 --user 你的学号 --password 你的密码 --isp cmcc

# 闭环自测：注销 -> 验证离线 -> 登录 -> 验证在线
python drcom_login.py --self-test --user 你的学号 --password 你的密码 --isp cmcc --mac 你的网卡MAC
```

`--isp` 可选：`telecom`（中国电信）/ `cmcc`（中国移动）/ `unicom`（中国联通）/ `campus`（校园内网）。

## 参数说明

| 参数 | 作用 |
|---|---|
| `--status` | 只探测联网状态 |
| `--dry-run` | 只打印请求，不提交 |
| `--force` | 已在线时也强行发一次登录 |
| `--no-prefix` | 账号不带前缀（个别学校需要） |
| `--mac` | 网卡 MAC（注销时需要，用 `ipconfig //all` 查） |
| `--watch` / `--interval` | 常驻监控与探测间隔 |
| `--wait-offline SEC` | 蹲守掉线后自动登录 |
| `--self-test` | 注销 + 登录闭环自测 |
| `--logout` | 只注销 |

## 注意

- 密码只存在于本次进程内存，**不会写入任何文件**；日志里一律脱敏。
- 程序遇到 `ret_code=1`（账号或密码错）会降低重试频率 —— 因为**密码连续输错会触发图形验证码**。

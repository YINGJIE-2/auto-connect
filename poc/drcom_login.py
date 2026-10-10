#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
auto-connect · Dr.COM(城市热点) Portal 认证 PoC
================================================
目标网关: 苏州城市学院  http://172.16.8.22  (Server: DrcomServer1.0)
协议模式: Portal 协议 (login_method = 1)，GET + JSONP，明文密码，无加密

本脚本是 M1 验证工具，只依赖 Python 标准库，不需要装任何第三方包。
用途：先证明"用程序能把网连上"，验证通过后再翻译成 Go 写成正式版。

用法
----
  # 1) 只看当前联网状态（最安全，什么都不改）
  python drcom_login.py --status

  # 2) 空跑：打印将要发出的完整请求，但不真的提交（推荐第一次这么用）
  python drcom_login.py --user 2023001234 --password 你的密码 --isp telecom --dry-run

  # 3) 真实认证
  python drcom_login.py --user 2023001234 --password 你的密码 --isp telecom

  # 4) 指定运营商（不填默认 campus 校园内网）
  #    telecom=中国电信  cmcc=中国移动  unicom=中国联通  campus=校园内网

安全说明
--------
* 本脚本不会保存任何凭证，密码只存在于本次进程内存中。
* 打印日志时密码一律脱敏。
* --dry-run 不会发出登录请求。
"""

import argparse
import getpass
import re
import socket
import sys
import time
import random
import urllib.error
import urllib.parse
import urllib.request

# --------------------------------------------------------------------------
# 从网关页面逆向出来的常量（详见 docs/协议分析.md）
# --------------------------------------------------------------------------

PORTAL_IP = "172.16.8.22"
PORTAL_PORT = 801
EPORTAL = "http://%s:%d/eportal/" % (PORTAL_IP, PORTAL_PORT)
JS_VERSION = "3.3.3"          # 来自 http://172.16.8.22/a41.js 的 jsVersion
LOGIN_METHOD = "1"            # Portal 协议模式
# 账号前缀：a41.js 里 accountPrefix=1，推导应为 ",0,"。
# 但 2026-10-10 实机测试发现：加与不加，服务端返回的错误完全相同
# （同样是 userid error2 / ldap auth error）→ 本校区实际不需要前缀，置空。
ACCOUNT_PREFIX = ""

# 运营商 -> 账号后缀。取值来自认证页 <select name="ISP_select"> 的 option value
ISP_SUFFIX = {
    "telecom": "@telecom",   # 中国电信
    "cmcc":    "@cmcc",      # 中国移动
    "unicom":  "@unicom",    # 中国联通
    "campus":  "",           # 校园内网
}

# 联网探测地址：Android / Windows 系统判断"是否需要登录 WiFi"用的标准地址。
# 已认证 -> 204 / 预期内容；未认证 -> 302 跳转到认证页。
PROBE_URLS = [
    "http://connect.rom.miui.com/generate_204",
    "http://www.msftconnecttest.com/connecttest.txt",
    "http://captive.apple.com/hotspot-detect.html",
]

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36")

TIMEOUT = 8


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """禁止自动跟随重定向 —— 我们必须拿到 302 的 Location 头。"""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_opener = urllib.request.build_opener(_NoRedirect)


# --------------------------------------------------------------------------
# 1. 联网状态探测
# --------------------------------------------------------------------------
def probe_online():
    """返回 (state, location, code)
    state: True=已联网  False=被拦截（需认证）  None=探测失败（网络不通/网关异常）
    """
    last_err = None
    for url in PROBE_URLS:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            resp = _opener.open(req, timeout=TIMEOUT)
            code = resp.status
            body = resp.read(4096)
            if code == 204:
                return True, None, code
            if b"Microsoft Connect Test" in body:
                return True, None, code
            if b"Success" in body:
                return True, None, code
            # 返回 200 但内容不对 —— 典型是被网关塞了一个提示页
            return False, None, code
        except urllib.error.HTTPError as e:
            if e.code in (301, 302, 303, 307, 308):
                return False, e.headers.get("Location"), e.code
            last_err = e
        except Exception as e:          # noqa: BLE001
            last_err = e
    return None, None, str(last_err)


# --------------------------------------------------------------------------
# 2. 取本机在校园网内的 IP / 解析重定向里的参数
# --------------------------------------------------------------------------
def local_ip_towards(ip, port):
    """问内核：要去 ip:port 的话，我该用哪个源地址。不真正发包。"""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((ip, port))
        return s.getsockname()[0]
    finally:
        s.close()


def parse_redirect(location):
    """从 302 的 Location 里抠出 wlanuserip / wlanacname / wlanacip。"""
    if not location:
        return {}
    q = urllib.parse.urlparse(location).query
    d = urllib.parse.parse_qs(q)

    def pick(*keys):
        for k in keys:
            if d.get(k):
                return d[k][0]
        return ""

    return {
        "wlan_user_ip": pick("wlanuserip", "wlan_user_ip", "userip", "user-ip", "ip"),
        "wlan_ac_name": pick("wlanacname", "wlan_ac_name", "sysname", "nasname"),
        "wlan_ac_ip":   pick("wlanacip", "wlan_ac_ip", "acip", "nasip"),
    }


# --------------------------------------------------------------------------
# 3. 构造并发送登录请求
# --------------------------------------------------------------------------
def build_account(user, isp, prefix=ACCOUNT_PREFIX):
    if isp not in ISP_SUFFIX:
        raise ValueError("未知运营商 %r，可选：%s" % (isp, "/".join(ISP_SUFFIX)))
    return prefix + user + ISP_SUFFIX[isp]


def build_login_url(user, password, isp, local_ip,
                    ac_name="", ac_ip="", mac="000000000000",
                    prefix=ACCOUNT_PREFIX):
    account = build_account(user, isp, prefix)
    params = [
        ("c",              "Portal"),
        ("a",              "login"),
        ("callback",       "dr%d" % random.randint(1000, 9999)),
        ("login_method",   LOGIN_METHOD),
        ("user_account",   account),
        ("user_password",  password),
        ("wlan_user_ip",   local_ip),
        ("wlan_user_ipv6", ""),
        ("wlan_user_mac",  mac),
        ("wlan_ac_ip",     ac_ip),
        ("wlan_ac_name",   ac_name),
        ("jsVersion",      JS_VERSION),
        ("v",              str(random.randint(100, 9999))),
    ]
    return EPORTAL + "?" + urllib.parse.urlencode(params)


def _mask(url):
    return re.sub(r"(user_password=)[^&]*", r"\1********", url)


def build_logout_url(local_ip, ac_name="", ac_ip="", vlan="0",
                     mac="000000000000"):
    """注销接口。注意 user_account / user_password 是占位串，随便填但要非空。"""
    params = [
        ("c",              "Portal"),
        ("a",              "logout"),
        ("callback",       "dr%d" % random.randint(1000, 9999)),
        ("login_method",   LOGIN_METHOD),
        ("user_account",   "drcom"),
        ("user_password",  "123"),
        ("ac_logout",      "1"),
        ("register_mode",  "1"),
        ("wlan_user_ip",   local_ip),
        ("wlan_user_ipv6", ""),
        ("wlan_vlan_id",   vlan),
        ("wlan_user_mac",  mac),
        ("wlan_ac_ip",     ac_ip),
        ("wlan_ac_name",   ac_name),
        ("jsVersion",      JS_VERSION),
        ("v",              str(random.randint(100, 9999))),
    ]
    return EPORTAL + "?" + urllib.parse.urlencode(params)


# 服务端 ret_code 对照表（从网关 a42.js 的 error.portal_login_err 里逐条抄的）
RET_CODE_MSG = {
    1:   "账号或密码不对，请重新输入",
    2:   "终端IP已经在线（本机已有会话，需先注销再测）",
    3:   "系统繁忙，请稍后再试",
    4:   "发生未知错误，请稍后再试",
    5:   "REQ_CHALLENGE 失败，请联系 AC 确认",
    6:   "REQ_CHALLENGE 超时，请联系 AC 确认",
    7:   "Radius 认证失败",
    8:   "Radius 认证超时",
    9:   "Radius 下线失败",
    10:  "Radius 下线超时",
    11:  "发生其他错误，请稍后再试",
    998: "Portal 协议参数不全",
}


def send_login(url):
    req = urllib.request.Request(url, headers={
        "User-Agent": UA,
        "Referer": "http://%s/" % PORTAL_IP,
        "Accept": "*/*",
    })
    with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
        raw = resp.read()
    return raw.decode("gb18030", "replace")


def parse_result(text):
    """解析 JSONP 返回，例如：dr1234({"result":"1","msg":"...","ret_code":2})
    返回 (ok, 人类可读信息, 原始对象)
    """
    m = re.search(r"\((\{.*\})\)\s*;?\s*$", text.strip(), re.S)
    payload = m.group(1) if m else text.strip()
    import json
    try:
        obj = json.loads(payload)
    except Exception:                              # noqa: BLE001
        return None, text.strip()[:300], None

    result = str(obj.get("result", ""))
    ok = result in ("1", "ok")
    if ok:
        return True, obj.get("msg") or "ok", obj

    ret = obj.get("ret_code")
    if ret is not None:
        try:
            human = RET_CODE_MSG.get(int(ret), "未知 ret_code=%s" % ret)
        except (TypeError, ValueError):
            human = str(ret)
        detail = ""
        # 失败详情：msg 是 Base64，解出来更直观
        raw_msg = obj.get("msg") or ""
        if raw_msg:
            try:
                import base64
                dec = base64.b64decode(raw_msg).decode("gb18030", "replace")
                detail = "  [msg=%s]" % dec
            except Exception:                      # noqa: BLE001
                detail = "  [msg=%s]" % raw_msg
        return False, "ret_code=%s %s%s" % (ret, human, detail), obj

    return False, obj.get("msg") or str(obj), obj


# --------------------------------------------------------------------------
# 常驻监控：掉线自动重连
# --------------------------------------------------------------------------
def watch_loop(args, password, prefix):
    """一直跑着，探测到未认证就立刻登录。Ctrl+C 退出。"""
    print("=" * 66)
    print("常驻监控模式 —— 掉线自动重连（Ctrl+C 退出）")
    print("  探测间隔: %d 秒    运营商: %s    账号: %s"
          % (args.interval, args.isp, args.user))
    print("=" * 66)
    print("  现在去认证页点『退出』试试，程序会在一个探测周期内自动登回来。\n")

    variants = [(prefix, args.isp)]
    if prefix:
        variants.append(("", args.isp))

    fail_streak = 0
    try:
        while True:
            ts = time.strftime("%H:%M:%S")
            st, loc, code = probe_online()

            if st is True:
                if fail_streak:
                    print("[%s] 已恢复在线。" % ts)
                fail_streak = 0
                print("[%s] 在线 (HTTP %s)" % (ts, code))
                time.sleep(args.interval)
                continue

            print("[%s] 检测到未认证 (HTTP %s)，开始登录 ..." % (ts, code))
            rp = parse_redirect(loc)
            lip = rp.get("wlan_user_ip") or local_ip_towards(PORTAL_IP, PORTAL_PORT)
            acn = rp.get("wlan_ac_name", "")
            aci = rp.get("wlan_ac_ip", "")

            ok = False
            for pfx, isp in variants:
                acct = build_account(args.user, isp, pfx)
                url = build_login_url(args.user, password, isp, lip,
                                      ac_name=acn, ac_ip=aci, prefix=pfx)
                try:
                    text = send_login(url)
                except Exception as e:                  # noqa: BLE001
                    print("    [%s] 请求异常: %s" % (acct, e))
                    continue
                ok, msg, _obj = parse_result(text)
                print("    [%s] -> %s" % (acct, "成功" if ok else msg))
                if ok:
                    break
                time.sleep(1)

            if ok:
                fail_streak = 0
                print("[%s] 认证成功，网关已放行。" % time.strftime("%H:%M:%S"))
                time.sleep(args.interval)
                continue

            fail_streak += 1
            if fail_streak == 2:
                print()
                print("    !! 连续失败。注意：'userid error2' 与 'ldap auth error'")
                print("       在 Dr.COM 官方错误表里都表示【账号或密码错误】。")
                print("       请先确认密码无误（可用浏览器登录一次验证）。")
                print()
            # 退避：5→10→20→40→60 秒；连续失败 5 次后降到每 5 分钟一次，
            # 避免疯狂重试把账号刷到弹验证码
            if fail_streak >= 5:
                wait = 300
            else:
                wait = min(5 * (2 ** (fail_streak - 1)), 60)
            print("[%s] 本次失败（连续 %d 次），%d 秒后重试。"
                  % (time.strftime("%H:%M:%S"), fail_streak, wait))
            time.sleep(wait)
    except KeyboardInterrupt:
        print("\n已退出监控。")
        return 0


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(
        description="Dr.COM 校园网 Portal 认证 PoC（苏州城市学院 172.16.8.22）")
    ap.add_argument("--user", help="学号 / 账号")
    ap.add_argument("--password", help="密码（不填则交互式输入）")
    ap.add_argument("--isp", default="campus",
                    choices=list(ISP_SUFFIX.keys()),
                    help="运营商：telecom/cmcc/unicom/campus（默认 campus 校园内网）")
    ap.add_argument("--status", action="store_true", help="只检测联网状态，不登录")
    ap.add_argument("--logout", action="store_true",
                    help="注销当前会话（会断网！用于制造未认证状态来测试）")
    ap.add_argument("--self-test", action="store_true",
                    help="闭环自测：注销 -> 验证离线 -> 登录 -> 验证在线")
    ap.add_argument("--dry-run", action="store_true", help="只打印请求，不真的提交")
    ap.add_argument("--force", action="store_true", help="已联网时也强行发一次登录")
    ap.add_argument("--no-prefix", action="store_true",
                    help="账号不带 ,0, 前缀（万一网关不接受前缀时用）")
    ap.add_argument("--mac", default="000000000000",
                    help="本机网卡 MAC（12位十六进制，无分隔符）。注销时需要它")
    ap.add_argument("--watch", action="store_true",
                    help="常驻监控：一直跑着，掉线自动重连（Ctrl+C 退出）")
    ap.add_argument("--interval", type=int, default=10,
                    help="监控模式下探测间隔，单位秒（默认 10）")
    ap.add_argument("--wait-offline", type=int, default=0, metavar="SEC",
                    help="蹲守模式：先启动它，再去认证页点『退出』，"
                         "程序捕获到掉线后立刻自动重新登录（推荐用这个做验证）")
    args = ap.parse_args()

    prefix = "" if args.no_prefix else ACCOUNT_PREFIX

    print("=" * 66)
    print("auto-connect · Dr.COM Portal 认证 PoC")
    print("=" * 66)

    # --- 状态探测 ---
    print("[1/3] 探测联网状态 ...")
    state, location, code = probe_online()
    if state is True:
        print("      -> 已联网（返回 %s），网关已放行本机。" % code)
    elif state is False:
        print("      -> 未认证（返回 %s），网关正在拦截。" % code)
        if location:
            print("      -> 重定向到: %s" % location[:160])
    else:
        print("      -> 探测失败: %s" % code)
        print("         可能网线没插/网卡没起来，或探测地址不可达。")

    if args.status:
        print("\n(--status 模式，到此结束)")
        return 0

    # --- 常驻监控模式 ---
    if args.watch:
        if not args.user:
            ap.error("--watch 需要 --user")
        pw = args.password
        if not pw:
            pw = getpass.getpass("      请输入密码（不回显，不会存到任何文件）: ")
        if not pw:
            ap.error("密码为空")
        return watch_loop(args, pw, "" if args.no_prefix else ACCOUNT_PREFIX)

    # --- 蹲守模式：等用户手动注销，捕获到掉线就立刻登录 ---
    if args.wait_offline:
        print("\n[蹲守] 每 1.5 秒探测一次，最多等 %d 秒。" % args.wait_offline)
        print("       现在请打开认证页点『退出』，程序会自动重新登录。")
        deadline = time.time() + args.wait_offline
        caught = False
        while time.time() < deadline:
            st, loc, code = probe_online()
            if st is not True:
                print("\n       >> 捕获到未认证状态（返回 %s），立即发起登录！" % code)
                state, location, caught = st, loc, True
                break
            time.sleep(1.5)
        if not caught:
            print("\n       超时，期间未检测到掉线。退出。")
            return 3
        print("       开始收集参数 ↓")

    # --- 注销（必要时 + 闭环自测）---
    if args.logout or args.self_test:
        lp = local_ip_towards(PORTAL_IP, PORTAL_PORT)
        # 注销变体：网关可能按 MAC 匹配会话，所以两个 MAC 都试；再退一步试 ACSetting 老接口
        logout_cands = [
            ("Portal + 指定MAC", build_logout_url(lp, mac=args.mac)),
            ("Portal + 全零MAC", build_logout_url(lp, mac="000000000000")),
        ]
        if args.self_test:
            logout_cands.append((
                "ACSetting 老接口(80端口)",
                "http://%s/eportal/?c=ACSetting&a=Logout&ver=1.0&wlanuserip=%s&wlanusermac=%s"
                % (PORTAL_IP, lp, args.mac),
            ))

        print("\n[注销] 尝试注销当前会话 ...")
        if args.dry_run:
            for label, u in logout_cands:
                print("      [%s] %s" % (label, u))
            print("      (--dry-run，未提交)")
            return 0

        offline = None
        for label, lurl in logout_cands:
            print("\n      -- %s" % label)
            print("         %s" % lurl)
            try:
                ltxt = send_login(lurl)
            except Exception as e:                  # noqa: BLE001
                print("         !! 请求异常: %s" % e)
                continue
            lok, lmsg, _ = parse_result(ltxt)
            print("         返回: %s" % ltxt.strip()[:200])
            print("         结果: %s" % ("注销成功" if lok else "失败 —— %s" % lmsg))
            time.sleep(1.5)
            offline, _, _ = probe_online()
            if offline is not True:
                print("         复检: 已离线 ✔")
                break
            print("         复检: 仍在线")
            if not args.self_test:
                break

        if not args.self_test:
            return 0
        if offline is True:
            print("\n所有注销方式都失败 —— 仍在线，无法继续测登录。")
            print("请打开浏览器访问任意网页，在认证页点『退出』，然后再跑一次 --force。")
            return 1
        print("\n已离线，继续执行登录测试 ↓")
        state, location = offline, None

    if state is True and not args.force:
        print("\n本机已联网，无需认证。想强行测试请加 --force。")
        return 0

    # --- 确定本机 IP 与其他参数 ---
    print("\n[2/3] 收集认证参数 ...")
    redirect_params = parse_redirect(location)
    local_ip = redirect_params.get("wlan_user_ip") or local_ip_towards(PORTAL_IP, PORTAL_PORT)
    ac_name = redirect_params.get("wlan_ac_name", "")
    ac_ip = redirect_params.get("wlan_ac_ip", "")
    print("      本机内网 IP : %s" % local_ip)
    print("      AC 名称     : %s" % (ac_name or "(空)"))
    print("      AC IP       : %s" % (ac_ip or "(空)"))

    if not args.user:
        ap.error("缺少 --user")
    password = args.password
    if not password:
        import getpass
        password = getpass.getpass("      请输入密码: ")

    # --- 提交 ---
    print("\n[3/3] 提交认证 ...")

    # 自测模式下启用兜底：第一组参数失败就自动换组合，尽量不让用户停在断网状态
    variants = [(prefix, args.isp)]
    if args.self_test or args.wait_offline:
        for v in [("", args.isp), (ACCOUNT_PREFIX, "campus"), ("", "campus")]:
            if v not in variants:
                variants.append(v)

    ok, msg, acct = False, "", ""
    for idx, (pfx, isp) in enumerate(variants, 1):
        acct = build_account(args.user, isp, pfx)
        url = build_login_url(args.user, password, isp, local_ip,
                              ac_name=ac_name, ac_ip=ac_ip, prefix=pfx)
        if len(variants) > 1:
            print("\n      尝试 %d/%d" % (idx, len(variants)))
        print("      登录账号    : %s" % acct)
        print("      最终 URL（密码已脱敏）:")
        print("      %s" % _mask(url))
        if args.dry_run:
            continue

        t0 = time.time()
        try:
            text = send_login(url)
        except Exception as e:                      # noqa: BLE001
            print("      !! 请求异常: %s" % e)
            continue
        dt = (time.time() - t0) * 1000
        ok, msg, _obj = parse_result(text)
        print("      原始返回: %s" % text.strip()[:300])
        print("      耗时: %.0f ms" % dt)
        print("      结果: %s  %s" % ("[成功] 认证通过" if ok else "[失败]", msg))
        if ok:
            break
        time.sleep(1)

    if args.dry_run:
        print("\n(--dry-run 模式，未真实提交)")
        return 0

    if ok:
        # 网关放行有 1~2 秒延迟，复检必须重试，否则会误报"仍未联网"
        st2, tries = None, 0
        for tries in range(1, 5):
            time.sleep(1.5)
            st2, _, _ = probe_online()
            if st2 is True:
                break
        print("\n      复检联网: %s（重试 %d 次）"
              % ("已联网 OK" if st2 else "仍未联网", tries))
        print("      最终生效账号: %s" % acct)
    else:
        print("\n      !! 所有参数组合都失败。请打开浏览器访问任意网页，手动认证一次。")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())

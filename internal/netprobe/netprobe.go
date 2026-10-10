// Package netprobe 负责两件事：
//  1. 判断「现在需不需要认证」—— 用 captive portal 标准探测地址，而不是 ping。
//  2. 从网关 302 重定向的 Location 里解析出本次认证需要的动态参数。
//
// 为什么不能用 ping：网关不封 ICMP，未认证时 ping 照样通。
// 为什么不能用 https：网关只劫持 http，https 会超时，无法区分「未认证」和「网络不通」。
package netprobe

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// State 表示探测结论。
type State int

const (
	// Unknown 所有探测地址都不可达 —— 通常意味着网线没插或网卡没起来。
	Unknown State = iota
	// Online 已认证。
	Online
	// Offline 被网关拦截，需要认证。
	Offline
)

func (s State) String() string {
	switch s {
	case Online:
		return "已联网"
	case Offline:
		return "未认证"
	default:
		return "未知"
	}
}

// Result 是一次探测的结果。
type Result struct {
	State    State
	Location string // Offline 时的 302 目标地址
	Code     int
	Err      error
}

const (
	defaultUA      = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
	defaultTimeout = 8 * time.Second
)

// httpClient 不跟随重定向 —— 我们必须拿到 302 的 Location 头。
var httpClient = &http.Client{
	Timeout: defaultTimeout,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

// Check 依次尝试各探测地址，返回第一个能得出结论的结果。
// 只有「所有地址都请求失败」时才返回 Unknown。
func Check(urls []string, timeout time.Duration) Result {
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	var lastErr error
	for _, u := range urls {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			cancel()
			lastErr = err
			continue
		}
		req.Header.Set("User-Agent", defaultUA)
		req.Header.Set("Cache-Control", "no-cache")

		resp, err := httpClient.Do(req)
		if err != nil {
			cancel()
			lastErr = err
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		loc := resp.Header.Get("Location")
		cancel()

		switch {
		case resp.StatusCode == http.StatusNoContent:
			return Result{State: Online, Code: resp.StatusCode}
		case strings.Contains(string(body), "Microsoft Connect Test"):
			return Result{State: Online, Code: resp.StatusCode}
		case strings.Contains(string(body), "Success"):
			return Result{State: Online, Code: resp.StatusCode}
		case resp.StatusCode >= 300 && resp.StatusCode < 400:
			return Result{State: Offline, Location: loc, Code: resp.StatusCode}
		case resp.StatusCode == http.StatusOK:
			// 200 但内容不符合预期 —— 典型是被网关塞了一个提示页
			return Result{State: Offline, Location: loc, Code: resp.StatusCode}
		default:
			lastErr = nil
			return Result{State: Offline, Location: loc, Code: resp.StatusCode}
		}
	}
	// 所有探测地址都不可用。
	//
	// ⚠️ 这里【绝不能】因为「TCP 能连上」就判定为 Online。
	// 未认证时网关根本不封 TCP —— 任何公网 IP 的 80 端口都连得上，
	// 「能连通」完全不能证明「已认证」。
	//
	// 实测教训：开机后 DNS 往往还没就绪，三个探测域名全部解析失败，
	// 旧代码据此兜底返回 Online（表现为日志里的 `在线 (HTTP 0)`），
	// 守护以为不需要认证便一直不干活 —— 用户开机能等到天荒地老也连不上网，
	// 最后只能手动去认证页登录。
	//
	// 返回 Unknown 才是对的：交给上层去尝试认证。认证请求是直连网关 IP 的
	// （172.16.8.22:801），根本不经过 DNS，恰恰是这种情况下的正确动作。
	return Result{State: Unknown, Err: lastErr}
}

// LocalIPTowards 问内核：要访问 host:port 时应该用哪个本机地址作为源地址。
// 只做路由查询，不会真的发包。
func LocalIPTowards(host string, port int) string {
	if host == "" {
		return ""
	}
	conn, err := net.Dial("udp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return ""
	}
	defer conn.Close()
	if addr, ok := conn.LocalAddr().(*net.UDPAddr); ok {
		return addr.IP.String()
	}
	return ""
}

// RedirectParams 是从 302 Location 里解析出来的可用信息。
type RedirectParams struct {
	UserIP string
	ACName string
	ACIP   string
	ACMAC  string
	Host   string // 网关主机
	Port   int    // 若 Location 带了端口则用它的
	Raw    string
}

// ParseRedirect 从重定向地址中提取参数。
// 各厂商字段名不同，这里把常见别名都认一遍。
func ParseRedirect(location string) RedirectParams {
	p := RedirectParams{Raw: location}
	if location == "" {
		return p
	}
	u, err := url.Parse(location)
	if err == nil && u.Host != "" {
		p.Host = u.Hostname()
		if pt := u.Port(); pt != "" {
			if n, err := strconv.Atoi(pt); err == nil {
				p.Port = n
			}
		}
	}
	q := u.Query()
	pick := func(keys ...string) string {
		for _, k := range keys {
			if v := q.Get(k); v != "" {
				return v
			}
		}
		return ""
	}
	p.UserIP = pick("wlanuserip", "wlan_user_ip", "userip", "user-ip", "UserIP", "uip", "station_ip", "ip")
	p.ACName = pick("wlanacname", "wlan_ac_name", "sysname", "nasname", "nas-name")
	p.ACIP = pick("wlanacip", "wlan_ac_ip", "acip", "nasip", "nas-ip", "switchip")
	p.ACMAC = strings.NewReplacer("-", "", ":", "").Replace(pick("wlanacmac", "gw_mac"))
	return p
}

// Package netprobe 负责两件事：
//  1. 判断「现在需不需要认证」—— 用 captive portal 标准探测地址，而不是 ping。
//  2. 从网关 302 重定向的 Location 里解析出本次认证需要的动态参数。
//
// 为什么不能用 ping：网关不封 ICMP，未认证时 ping 照样通。
// 为什么不能用 https：网关只劫持 http，https 会超时，无法区分「未认证」和「网络不通」。
package netprobe

import (
	"context"
	"errors"
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
	// URL 是给出结论的那个探测地址。
	// 并行探测下「谁先答谁算」，几个源返回的状态码并不一样
	// （小米 generate_204 在线时是 204，苹果 hotspot-detect 是 200 + "Success"），
	// 记下来才不会让日志看起来自相矛盾。
	URL string
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

// Check 并行请求所有探测地址，返回第一个能得出结论的结果。
// 只有「所有地址都请求失败」时才返回 Unknown。
//
// 为什么必须并行：timeout 是**整轮探测的总预算**，不是每个地址各自的。
// 串行版本（旧实现）会把超时乘上地址数量 —— 传 1.5 秒、3 个地址，
// 一次探测最坏要 4.5 秒；复检要试好几轮，用户就会看到「认证成功」前面
// 挂了 10 秒。并行之后单次探测被 ctx 统一封顶，不管几个地址都是一个 timeout。
func Check(urls []string, timeout time.Duration) Result {
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	if len(urls) == 0 {
		return Result{State: Unknown, Err: errors.New("未配置探测地址")}
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// 结果通道要留够缓冲，否则 ctx 超时后没被取走的 goroutine 会永远阻塞。
	type outcome struct {
		res Result
		err error
	}
	ch := make(chan outcome, len(urls))
	for _, u := range urls {
		go func(u string) {
			res, err := probeOne(ctx, u)
			ch <- outcome{res: res, err: err}
		}(u)
	}

	var lastErr error
	for range urls {
		select {
		case o := <-ch:
			if o.err == nil {
				return o.res // 有结论，立刻返回，不等其余地址
			}
			lastErr = o.err
		case <-ctx.Done():
			if lastErr == nil {
				lastErr = ctx.Err()
			}
			return Result{State: Unknown, Err: lastErr}
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

// probeOne 请求单个探测地址。
//
// 返回 (结果, nil) 表示这个地址给出了明确结论；
// 返回 (零值, err) 表示请求本身失败（DNS 解析不了、连不上、超时），
// 上层应该换别的地址继续试。
func probeOne(ctx context.Context, u string) (Result, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return Result{}, err
	}
	req.Header.Set("User-Agent", defaultUA)
	req.Header.Set("Cache-Control", "no-cache")

	resp, err := httpClient.Do(req)
	if err != nil {
		return Result{}, err
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	resp.Body.Close()

	res := Result{URL: u, Location: resp.Header.Get("Location"), Code: resp.StatusCode}
	switch {
	case resp.StatusCode == http.StatusNoContent:
		res.State = Online
	case strings.Contains(string(body), "Microsoft Connect Test"),
		strings.Contains(string(body), "Success"):
		res.State = Online
	default:
		// 3xx 跳转、200 但塞了提示页、以及其他状态码 —— 都说明被网关拦住了
		res.State = Offline
	}
	return res, nil
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

// Package drcom 实现 Dr.COM（城市热点）Web Portal 认证。
//
// 协议要点（实测确认，详见仓库 docs/协议分析.md）：
//   - 登录是 **GET + JSONP**，不是 POST
//   - 接口在 **801** 端口：/eportal/?c=Portal&a=login
//   - 密码 **明文** 提交，无任何加密
//   - 账号形如 学号@运营商后缀（多数学校不需要额外前缀）
//   - 响应形如 dr1234({"result":"1","msg":"认证成功"})
package drcom

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/YINGJIE-2/auto-connect/internal/portal"
)

const (
	defaultPort    = 801
	defaultJSVer   = "3.3.3"
	userAgent      = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
	requestTimeout = 10 * time.Second
)

// Adapter 是 Dr.COM 的适配器实现。
type Adapter struct{}

// New 返回一个 Dr.COM 适配器。
func New() *Adapter { return &Adapter{} }

// Name 实现 portal.Adapter。
func (a *Adapter) Name() string { return "Dr.COM" }

var detectMarkers = []string{
	"drcom", "Dr.COM", "eportal", "Dr.COMWebLoginID",
}

// Detect 实现 portal.Adapter：看认证页里有没有 Dr.COM 的指纹。
func (a *Adapter) Detect(portalBody []byte) bool {
	if len(portalBody) == 0 {
		return false
	}
	s := string(portalBody)
	for _, m := range detectMarkers {
		if strings.Contains(s, m) {
			return true
		}
	}
	return false
}

// FetchRoot 请求网关根页面，用于识别厂商。
// 认证服务器通常在 80 端口提供页面，而 eportal 接口在 801。
func FetchRoot(ctx context.Context, host string) (body []byte, server string, err error) {
	u := "http://" + host + "/"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("User-Agent", userAgent)
	client := &http.Client{Timeout: requestTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return b, resp.Header.Get("Server"), nil
}

// Login 实现 portal.Adapter：发一次认证请求。
func (a *Adapter) Login(ctx context.Context, env portal.Env) (portal.Result, error) {
	port := env.Port
	if port == 0 {
		port = defaultPort
	}
	jsVer := env.JSVersion
	if jsVer == "" {
		jsVer = defaultJSVer
	}

	callback := fmt.Sprintf("dr%d", rand.Intn(9000)+1000)
	q := url.Values{}
	q.Set("c", "Portal")
	q.Set("a", "login")
	q.Set("callback", callback)
	q.Set("login_method", strconv.Itoa(env.LoginMethod))
	q.Set("user_account", env.Account)
	q.Set("user_password", env.Password)
	q.Set("wlan_user_ip", env.UserIP)
	q.Set("wlan_user_ipv6", "")
	q.Set("wlan_user_mac", env.UserMAC)
	q.Set("wlan_ac_ip", env.ACIP)
	q.Set("wlan_ac_name", env.ACName)
	q.Set("jsVersion", jsVer)
	q.Set("v", strconv.Itoa(rand.Intn(9900)+100))

	endpoint := fmt.Sprintf("http://%s:%d/eportal/?%s", env.Host, port, q.Encode())

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return portal.Result{}, err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Referer", "http://"+env.Host+"/")

	client := &http.Client{Timeout: requestTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return portal.Result{}, fmt.Errorf("请求认证接口失败: %w", err)
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return parseResponse(string(raw))
}

var jsonpRe = regexp.MustCompile(`(?s)^[^(]*\((.*)\)[^)]*$`)

type loginResponse struct {
	Result  json.RawMessage `json:"result"`
	Msg     string          `json:"msg"`
	RetCode json.RawMessage `json:"ret_code"`
}

func parseResponse(raw string) (portal.Result, error) {
	out := portal.Result{Raw: strings.TrimSpace(raw)}

	body := out.Raw
	if m := jsonpRe.FindStringSubmatch(body); len(m) == 2 {
		body = m[1]
	}

	var lr loginResponse
	if err := json.Unmarshal([]byte(body), &lr); err != nil {
		return out, fmt.Errorf("响应不是预期的 JSON（原文: %s）", truncate(out.Raw, 200))
	}

	// result 可能是数字 1 或字符串 "1"/"ok"
	resStr := strings.Trim(string(lr.Result), `"`)
	out.OK = resStr == "1" || strings.EqualFold(resStr, "ok")
	out.RetCode = -1
	if len(lr.RetCode) > 0 {
		if n, err := strconv.Atoi(strings.Trim(string(lr.RetCode), `"`)); err == nil {
			out.RetCode = n
		}
	}

	// msg 可能是 Base64；解不开就用原文
	out.RawMsg = decodeMaybeBase64(lr.Msg)

	if out.OK {
		out.Message = "认证成功"
		return out, nil
	}
	// ret_code=2 表示「本机 IP 已有会话」，等价于已经在线，不应视为失败
	if out.RetCode == 2 {
		out.OK = true
		out.Message = "终端IP已经在线（无需重复认证）"
		return out, nil
	}
	if desc := portal.DescribeRetCode(out.RetCode); desc != "" {
		out.Message = fmt.Sprintf("[%d] %s", out.RetCode, desc)
	} else if out.RawMsg != "" {
		out.Message = out.RawMsg
	} else {
		out.Message = "认证失败"
	}
	if out.RawMsg != "" && !strings.Contains(out.Message, out.RawMsg) {
		out.Message += "（" + out.RawMsg + "）"
	}
	return out, nil
}

func decodeMaybeBase64(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		// 只接受可打印的结果，避免把普通文本误判
		if isPrintable(b) {
			return string(b)
		}
	}
	return s
}

func isPrintable(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	for _, c := range b {
		if c < 0x20 && c != '\t' && c != '\n' && c != '\r' {
			return false
		}
	}
	return true
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

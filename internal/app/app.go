// Package app 把配置、探测、适配器、重连策略串起来，提供三种运行方式：
// 单次状态检查、单次登录、常驻守护。
package app

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/YINGJIE-2/auto-connect/internal/config"
	"github.com/YINGJIE-2/auto-connect/internal/netprobe"
	"github.com/YINGJIE-2/auto-connect/internal/portal"
	"github.com/YINGJIE-2/auto-connect/internal/portal/drcom"
)

// App 是运行时实例。
type App struct {
	cfg      *config.Config
	password string
	logger   *log.Logger
}

// New 创建实例。password 传空表示尚未配置。
func New(cfg *config.Config, password string, logger *log.Logger) *App {
	if logger == nil {
		logger = log.New(os.Stdout, "", log.LstdFlags)
	}
	return &App{cfg: cfg, password: password, logger: logger}
}

// Check 做一次联网状态探测。
func (a *App) Check() netprobe.Result {
	return netprobe.Check(a.cfg.ProbeURLs, 8*time.Second)
}

// adapter 选择适配器。目前只有 Dr.COM，但接口已留好扩展位。
func (a *App) adapter(portalBody []byte) portal.Adapter {
	d := drcom.New()
	if a.cfg.Portal.Type == "drcom" || a.cfg.Portal.Type == "auto" {
		if len(portalBody) == 0 || d.Detect(portalBody) {
			return d
		}
	}
	return d
}

// resolveGateway 确定网关地址。优先用重定向里发现的，其次用配置里的。
// 学到新地址时会写回配置，实现「一次自愈、长期记住」。
func (a *App) resolveGateway(rp netprobe.RedirectParams) (string, int, error) {
	host := rp.Host
	port := rp.Port
	if host == "" {
		host = a.cfg.Portal.Host
	}
	if host == "" {
		return "", 0, fmt.Errorf(
			"无法确定认证网关地址：当前没有捕获到重定向，" +
				"请在 config.json 里填写 portal.host（例如 10.0.0.1）")
	}
	if port == 0 {
		port = a.cfg.Portal.Port
	}
	if port == 0 {
		port = 801
	}
	// 自学习：把探测到的地址记下来，以后即使拿不到重定向也能用
	if a.cfg.Portal.Host == "" && rp.Host != "" {
		a.cfg.Portal.Host = rp.Host
		if err := a.cfg.Save(); err == nil {
			a.logger.Printf("已自动记住网关地址：%s", rp.Host)
		}
	}
	return host, port, nil
}

// LoginOnce 执行一次完整认证。probe 传入已知的探测结果可省一次请求。
func (a *App) LoginOnce(ctx context.Context, probe *netprobe.Result) (portal.Result, error) {
	if a.password == "" {
		return portal.Result{}, fmt.Errorf("尚未配置密码，请先运行：auto-connect setup")
	}

	var pr netprobe.Result
	if probe != nil {
		pr = *probe
	} else {
		pr = a.Check()
	}

	rp := netprobe.ParseRedirect(pr.Location)

	// 重定向里没给本机 IP 就自己问内核
	userIP := rp.UserIP
	if userIP == "" {
		host := rp.Host
		if host == "" {
			host = a.cfg.Portal.Host
		}
		userIP = netprobe.LocalIPTowards(host, a.cfg.Portal.Port)
	}

	host, port, err := a.resolveGateway(rp)
	if err != nil {
		return portal.Result{}, err
	}

	// 这里原本会先抓一次网关首页来「识别厂商」，但工程里目前只有 Dr.COM
	// 一个适配器，adapter() 无论如何都会返回它 —— 那次 HTTP 往返纯属浪费
	// （实测约 0.5 秒）。等以后接入第二家网关时，把 drcom.FetchRoot 加回来即可。
	adapter := a.adapter(nil)
	env := portal.Env{
		Host:        host,
		Port:        port,
		LoginMethod: a.cfg.Portal.LoginMethod,
		JSVersion:   a.cfg.Portal.JSVersion,
		Account:     a.cfg.Account(),
		Password:    a.password,
		UserIP:      userIP,
		UserMAC:     "000000000000", // 网关不校验 MAC，实测全零可用
		ACName:      rp.ACName,
		ACIP:        rp.ACIP,
	}
	return adapter.Login(ctx, env)
}

// verifyOnline 认证后复检：确认网关真的放行了。
//
// 设计取舍 —— 复检只是「确认」，绝不能反过来拖慢整件事。
//
// 实测（2026-10-10）：认证请求本身稳定在 **0.1 秒**，但复检出现过 **10.8 秒**
// 才确认。日志拆分后看得一清二楚：`10.8 = 6 x (1.5 秒超时 + 0.3 秒间隔)`，
// 也就是认证后连着 6 次探测全部卡到超时 —— 网关在切换会话状态的这段时间里
// 根本不回应探测请求。
//
// 所以这里给一个**很短的硬预算**（budget），到点就放弃。认证请求已经明确
// 返回了 result=1，那是比探测更可靠的信号；拿不到复检结论就当「已提交、
// 等待放行」处理，交给主循环 5 秒后再看，而不是死等。
//
// 每次尝试都把「状态码 / 哪个源 / 耗时 / 失败原因」打出来 —— 只有这样才能
// 区分「DNS 解析卡住」和「网关不放行」，别再靠猜。
func (a *App) verifyOnline() bool {
	const (
		budget     = 4 * time.Second
		perAttempt = 1200 * time.Millisecond
		attemptGap = 200 * time.Millisecond
	)
	deadline := time.Now().Add(budget)
	for attempt := 1; time.Now().Before(deadline); attempt++ {
		start := time.Now()
		r := netprobe.Check(a.cfg.ProbeURLs, perAttempt)
		cost := time.Since(start).Seconds()

		if r.State == netprobe.Online {
			a.logger.Printf("  复检 #%d 通过：HTTP %d（%s）用时 %.1f 秒",
				attempt, r.Code, probeHost(r.URL), cost)
			return true
		}
		if r.State == netprobe.Unknown {
			a.logger.Printf("  复检 #%d 不通：用时 %.1f 秒（%v）", attempt, cost, r.Err)
		} else {
			a.logger.Printf("  复检 #%d：%s HTTP %d（%s）用时 %.1f 秒",
				attempt, r.State, r.Code, probeHost(r.URL), cost)
		}
		time.Sleep(attemptGap)
	}
	return false
}

// Daemon 常驻守护：在线时静默等待，掉线立刻重连。
func (a *App) Daemon(ctx context.Context) error {
	b := a.cfg.Behavior
	a.logger.Printf("守护启动：探测间隔 %ds，账号 %s（%s），网关 %s",
		b.CheckInterval, a.cfg.Username, config.ISPName(a.cfg.ISP), orDefault(a.cfg.Portal.Host, "自动探测"))

	failStreak := 0
	for {
		if err := ctx.Err(); err != nil {
			a.logger.Print("收到退出信号，守护结束")
			return nil
		}

		res := a.Check()
		if res.State == netprobe.Online {
			if failStreak > 0 {
				a.logger.Printf("已恢复在线（此前连续失败 %d 次）", failStreak)
			}
			failStreak = 0
			a.logger.Printf("在线 (HTTP %d，%s)", res.Code, probeHost(res.URL))
			if !sleepCtx(ctx, time.Duration(b.CheckInterval)*time.Second) {
				return nil
			}
			continue
		}

		if res.State == netprobe.Unknown {
			// 最常见的场景：刚开机，DNS 还没就绪，探测域名全部解析失败。
			// 这时不能干等 —— 认证请求直连网关 IP，不依赖 DNS，先试了再说。
			a.logger.Printf("探测不到联网状态（%v），直接尝试认证 ...", res.Err)
		} else {
			a.logger.Printf("检测到%s (HTTP %d，%s)，开始认证 ...",
				res.State, res.Code, probeHost(res.URL))
		}

		t0 := time.Now()
		r, err := a.LoginOnce(ctx, &res)
		loginCost := time.Since(t0)
		switch {
		case err != nil:
			a.logger.Printf("认证异常（用时 %.1f 秒）：%v", loginCost.Seconds(), err)
		case r.OK:
			// 认证请求返回 result=1 的这一刻，网关就已经放行了 ——
			// 这才是「网络恢复」的真实时刻，所以立刻打出来。
			// 后面的复检只是确认，不能让它影响用户对快慢的判断。
			a.logger.Printf("认证成功（用时 %.1f 秒），正在确认放行 ...", loginCost.Seconds())

			t1 := time.Now()
			verified := a.verifyOnline()
			verifyCost := time.Since(t1).Seconds()

			if verified {
				a.logger.Printf("网络已恢复（认证 %.1f 秒 + 确认 %.1f 秒）", loginCost.Seconds(), verifyCost)
			} else {
				a.logger.Printf("复检 %.1f 秒内没拿到确认（认证请求本身已成功），5 秒后再查", verifyCost)
			}

			// 关键：**认证已返回 result=1 就不能走失败退避**。
			// 否则网关放行慢几秒，重试间隔会被指数退避拉到 5 分钟，
			// 用户真的要等很久。复检没确认时只等 5 秒就再看一眼。
			failStreak = 0
			next := time.Duration(b.CheckInterval) * time.Second
			if !verified {
				next = 5 * time.Second
			}
			if !sleepCtx(ctx, next) {
				return nil
			}
			continue
		default:
			a.logger.Printf("认证失败：%s（原始响应 %s）", r.Message, truncate(r.Raw, 160))
			if r.RetCode == 1 {
				a.logger.Print("  提示：该错误表示「账号或密码错误」，请用浏览器登录一次核对密码；" +
					"程序会降低重试频率，避免账号被要求输验证码")
			}
		}

		failStreak++
		wait := time.Duration(b.ReconnectDelay) * time.Second * (1 << min(failStreak-1, 4))
		if failStreak >= b.MaxFailBeforeSlow {
			wait = time.Duration(b.SlowInterval) * time.Second
			a.logger.Printf("已连续失败 %d 次，切换到慢速重试（每 %d 秒一次）",
				failStreak, b.SlowInterval)
		}
		if wait > time.Duration(b.BackoffMax)*time.Second && failStreak < b.MaxFailBeforeSlow {
			wait = time.Duration(b.BackoffMax) * time.Second
		}
		a.logger.Printf("%d 秒后重试", int(wait.Seconds()))
		if !sleepCtx(ctx, wait) {
			return nil
		}
	}
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// probeHost 把探测地址压成主机名，让日志短一点。
func probeHost(u string) string {
	s := strings.TrimPrefix(strings.TrimPrefix(u, "http://"), "https://")
	if i := strings.IndexByte(s, '/'); i >= 0 {
		s = s[:i]
	}
	if s == "" {
		return "?"
	}
	return s
}

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

// Package app 把配置、探测、适配器、重连策略串起来，提供三种运行方式：
// 单次状态检查、单次登录、常驻守护。
package app

import (
	"context"
	"fmt"
	"log"
	"os"
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

// verifyOnline 登录成功后复检。
//
// 两个要点，都是实测踩出来的：
//  1. **必须重试** —— 网关放行有 1~2 秒延迟，认证一返回成功就立刻探测会误报「未联网」。
//  2. **每次探测必须用短超时**。用默认的 8 秒，网关放行期间第一个地址一旦卡住
//     就要白等 8 秒，日志上表现为「开始认证 → 认证成功」隔了 10~11 秒，
//     用户会觉得连得很慢。改成 1.5 秒后，正常情况下 2~3 秒就能确认。
func (a *App) verifyOnline() bool {
	for i := 0; i < 8; i++ {
		time.Sleep(800 * time.Millisecond)
		if netprobe.Check(a.cfg.ProbeURLs, 1500*time.Millisecond).State == netprobe.Online {
			return true
		}
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
			a.logger.Printf("在线 (HTTP %d)", res.Code)
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
			a.logger.Printf("检测到%s (HTTP %d)，开始认证 ...", res.State, res.Code)
		}

		t0 := time.Now()
		r, err := a.LoginOnce(ctx, &res)
		switch {
		case err != nil:
			a.logger.Printf("认证异常（用时 %.1f 秒）：%v", time.Since(t0).Seconds(), err)
		case r.OK:
			if a.verifyOnline() {
				a.logger.Printf("认证成功，网络已恢复（账号 %s，全程 %.1f 秒）",
					a.cfg.Account(), time.Since(t0).Seconds())
				failStreak = 0
				if !sleepCtx(ctx, time.Duration(b.CheckInterval)*time.Second) {
					return nil
				}
				continue
			}
			a.logger.Printf("认证返回成功，但复检仍不通 —— 继续观察")
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

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

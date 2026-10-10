// auto-connect —— 校园网自动认证工具
//
// 用法：
//
//	auto-connect            首次运行进入配置向导；已配置则启动守护
//	auto-connect setup      重新配置
//	auto-connect daemon     常驻守护（掉线自动重连）
//	auto-connect status     查看当前联网状态
//	auto-connect login      立刻认证一次
//	auto-connect install    注册开机自启
//	auto-connect uninstall  取消开机自启
//	auto-connect log        显示日志文件位置
//	auto-connect version    显示版本
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/YINGJIE-2/auto-connect/internal/app"
	"github.com/YINGJIE-2/auto-connect/internal/autostart"
	"github.com/YINGJIE-2/auto-connect/internal/config"
	"github.com/YINGJIE-2/auto-connect/internal/netprobe"
	"github.com/YINGJIE-2/auto-connect/internal/win"
)

const version = "0.1.0"

const banner = `  auto-connect · 校园网自动认证
  开箱即用：填一次学号密码，以后开机自动联网、掉线自动重连。
`

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "\n错误："+err.Error())
		os.Exit(1)
	}
}

func run() error {
	args := os.Args[1:]
	cmd := ""
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd = args[0]
		args = args[1:]
	} else if len(args) > 0 {
		switch args[0] {
		case "-v", "--version":
			cmd = "version"
		case "-h", "--help":
			cmd = "help"
		}
	}

	switch cmd {
	case "setup":
		return cmdSetup(args)
	case "daemon", "run":
		return cmdDaemon(args)
	case "status":
		return cmdStatus()
	case "login":
		return cmdLogin()
	case "install":
		return cmdInstall()
	case "uninstall":
		return cmdUninstall()
	case "log":
		return cmdLog()
	case "version":
		fmt.Printf("auto-connect v%s\n", version)
		return nil
	case "help":
		usage()
		return nil
	case "":
		// 无参数：没配置就走向导，配好了就常驻守护
		if !config.Exists() {
			return cmdSetup(nil)
		}
		return cmdDaemon(args)
	default:
		usage()
		return fmt.Errorf("未知命令：%s", cmd)
	}
}

func usage() {
	fmt.Print(banner)
	fmt.Print(`
命令：
  setup       首次配置（填学号、密码、选运营商）
  daemon      常驻后台，掉线自动重连
  status      查看当前联网状态
  login       立刻认证一次
  install     注册开机自启
  uninstall   取消开机自启
  log         显示日志文件路径
  version     显示版本

配置完成后，直接双击本程序即可开始守护。
文件位置：`)
	p, _ := config.Path()
	fmt.Println("  " + p)
}

// ---------------------------------------------------------------- 配置向导

func cmdSetup(args []string) error {
	fs := flag.NewFlagSet("setup", flag.ExitOnError)
	user := fs.String("user", "", "学号（非交互模式下使用）")
	pass := fs.String("password", "", "密码（非交互模式下使用）")
	isp := fs.String("isp", "", "运营商：telecom/cmcc/unicom/campus")
	portal := fs.String("portal", "", "认证页地址（可留空，留空会在掉线时自动识别）")
	yes := fs.Bool("yes", false, "自动确认（自动注册开机自启）")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg := config.Default()
	if config.Exists() {
		if old, err := config.Load(); err == nil {
			cfg = old
			fmt.Println("（检测到已有配置，回车可沿用原值）")
		}
	}

	fmt.Print("\n" + banner)
	fmt.Println("-----------------------------------------------------------")

	// 学号
	username := *user
	if username == "" {
		username = prompt("学号", cfg.Username)
	}
	if username == "" {
		return fmt.Errorf("学号不能为空")
	}
	cfg.Username = username

	// 密码
	password := *pass
	if password == "" {
		var err error
		password, err = promptPassword()
		if err != nil {
			return err
		}
	}
	if password == "" {
		return fmt.Errorf("密码不能为空")
	}

	// 运营商
	ispKey := *isp
	if ispKey == "" {
		fmt.Println("\n你在认证页第一个下拉框里选的是哪个？")
		for i, k := range config.ISPChoices {
			fmt.Printf("  %d) %s\n", i+1, config.ISPName(k))
		}
		answer := prompt("请输入编号", strconv.Itoa(indexOf(cfg.ISP, config.ISPChoices)+1))
		n, err := strconv.Atoi(strings.TrimSpace(answer))
		if err != nil || n < 1 || n > len(config.ISPChoices) {
			return fmt.Errorf("运营商编号无效：%s", answer)
		}
		ispKey = config.ISPChoices[n-1]
	}
	cfg.ISP = ispKey

	// 认证页地址（可以留空）
	if *portal != "" {
		cfg.Portal.Host = normalizeHost(*portal)
	} else if cfg.Portal.Host == "" {
		fmt.Println("\n认证页地址（直接回车可跳过）")
		fmt.Println("  这一步可以跳过。程序在检测到掉线时会自动识别网关并记住，")
		fmt.Println("  所以大多数情况下不用手填。只有自动识别失败时才需要它，")
		fmt.Println("  格式形如 http://10.0.0.1/ ，把你浏览器被跳转到的地址贴进来即可。")
		if answer := prompt("认证页地址", ""); answer != "" {
			cfg.Portal.Host = normalizeHost(answer)
		}
	}

	// 保存
	if err := saveCredential(password); err != nil {
		return err
	}
	if err := cfg.Save(); err != nil {
		return err
	}
	fmt.Println("\n[1/3] 配置已保存")
	fmt.Println("      密码用 Windows DPAPI 加密后存放，只有当前 Windows 账号能解开，")
	fmt.Println("      换电脑或换账号都无法解密，也不会出现在配置文件和 Git 仓库里。")

	// 试登录
	fmt.Println("\n[2/3] 正在测试认证 ...")
	lg := newLogger(false)
	a := app.New(cfg, password, lg)
	ctx := context.Background()

	res := a.Check()
	if res.State == netprobe.Online {
		fmt.Println("      当前已联网，无需认证。配置看起来没问题。")
	} else {
		r, err := a.LoginOnce(ctx, &res)
		switch {
		case err != nil:
			fmt.Println("      测试失败：" + err.Error())
			fmt.Println("      配置已保存，你可以先用 auto-connect status 查看状态。")
		case r.OK:
			fmt.Println("      认证成功！账号 " + cfg.Account())
		default:
			fmt.Println("      认证失败：" + r.Message)
			fmt.Println("      常见原因是密码不对，或运营商选错了。可重新运行 setup 修改。")
		}
	}

	// 开机自启
	fmt.Println("\n[3/3] 注册开机自启 ...")
	if err := autostart.Install(""); err != nil {
		fmt.Println("      注册失败（可稍后手动执行 auto-connect install）：" + err.Error())
	} else {
		fmt.Println("      已注册。开机会自动启动，且不弹窗口。")
	}

	fmt.Println("\n-----------------------------------------------------------")
	fmt.Println("全部完成！以后不用再管它了。")
	fmt.Println("想看看现在什么状态，执行：auto-connect status")
	if !*yes {
		fmt.Println("\n（按回车关闭这个窗口）")
		var b [1]byte
		os.Stdin.Read(b[:])
	}
	return nil
}

func prompt(label, def string) string {
	if def != "" {
		fmt.Printf("%s [%s]: ", label, def)
	} else {
		fmt.Printf("%s: ", label)
	}
	var line string
	fmt.Scanln(&line)
	line = strings.TrimSpace(line)
	if line == "" {
		return def
	}
	return line
}

func promptPassword() (string, error) {
	fmt.Print("密码（输入时不显示）: ")
	pw, err := win.ReadPassword()
	if err != nil {
		return "", fmt.Errorf("读取密码失败: %w", err)
	}
	fmt.Print("再输一次确认: ")
	pw2, err := win.ReadPassword()
	if err != nil {
		return "", fmt.Errorf("读取密码失败: %w", err)
	}
	if pw != pw2 {
		return "", fmt.Errorf("两次输入的密码不一致")
	}
	return pw, nil
}

func indexOf(s string, list []string) int {
	for i, v := range list {
		if v == s {
			return i
		}
	}
	return 0
}

// normalizeHost 把用户粘贴的地址规整成纯主机名。
// 支持 http://10.0.0.1/ 、10.0.0.1:801 、https://portal.xxx.edu.cn/login 等各种写法。
func normalizeHost(s string) string {
	s = strings.TrimSpace(s)
	for _, p := range []string{"http://", "https://"} {
		s = strings.TrimPrefix(strings.ToLower(s), p)
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	if i := strings.LastIndex(s, ":"); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}

// ---------------------------------------------------------------- 凭证

func saveCredential(pw string) error {
	enc, err := win.Encrypt([]byte(pw))
	if err != nil {
		return err
	}
	p, err := config.CredPath()
	if err != nil {
		return err
	}
	return os.WriteFile(p, enc, 0o600)
}

func loadCredential() (string, error) {
	p, err := config.CredPath()
	if err != nil {
		return "", err
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		return "", fmt.Errorf("读取凭证失败，请先运行 auto-connect setup")
	}
	dec, err := win.Decrypt(raw)
	if err != nil {
		return "", err
	}
	return string(dec), nil
}

// ---------------------------------------------------------------- 守护

func cmdDaemon(args []string) error {
	fs := flag.NewFlagSet("daemon", flag.ExitOnError)
	hidden := fs.Bool("hidden", false, "隐藏控制台窗口（被任务计划程序拉起时使用）")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *hidden {
		win.HideConsole()
	}

	release, ok, err := win.SingleInstance("auto-connect-daemon")
	if err != nil {
		return err
	}
	if !ok {
		fmt.Println("已有一个 auto-connect 在运行，本次直接退出。")
		return nil
	}
	defer release()

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("读取配置失败（请先运行 auto-connect setup）: %w", err)
	}
	pw, err := loadCredential()
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	a := app.New(cfg, pw, newLogger(!*hidden))
	return a.Daemon(ctx)
}

// ---------------------------------------------------------------- 单次命令

func cmdStatus() error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("读取配置失败（请先运行 auto-connect setup）: %w", err)
	}
	a := app.New(cfg, "", newLogger(false))
	res := a.Check()

	fmt.Print("\n" + banner + "\n")
	fmt.Printf("  当前状态 : %s", res.State)
	if res.Code != 0 {
		fmt.Printf("（探测返回 HTTP %d）", res.Code)
	}
	fmt.Println()
	if res.Location != "" {
		fmt.Printf("  重定向到 : %s\n", res.Location)
	}
	fmt.Printf("  账号     : %s\n", cfg.Account())
	fmt.Printf("  运营商   : %s\n", config.ISPName(cfg.ISP))
	fmt.Printf("  网关     : %s:%d\n", orDefault(cfg.Portal.Host, "(自动探测)"), cfg.Portal.Port)
	fmt.Printf("  开机自启 : %s\n", yesNo(autostart.IsInstalled()))
	fmt.Println()
	return nil
}

func cmdLogin() error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("读取配置失败（请先运行 auto-connect setup）: %w", err)
	}
	pw, err := loadCredential()
	if err != nil {
		return err
	}
	a := app.New(cfg, pw, newLogger(false))

	res := a.Check()
	if res.State == netprobe.Online {
		fmt.Println("当前已在线，无需认证。")
		return nil
	}
	r, err := a.LoginOnce(context.Background(), &res)
	if err != nil {
		return err
	}
	if r.OK {
		fmt.Println("认证成功：" + cfg.Account())
		return nil
	}
	return fmt.Errorf("认证失败：%s（原始响应 %s）", r.Message, r.Raw)
}

func cmdInstall() error {
	if err := autostart.Install(""); err != nil {
		return err
	}
	fmt.Println("已注册开机自启（任务名：" + autostart.TaskName + "）")
	return nil
}

func cmdUninstall() error {
	if err := autostart.Uninstall(); err != nil {
		return err
	}
	fmt.Println("已取消开机自启。")
	return nil
}

func cmdLog() error {
	p, err := config.LogPath()
	if err != nil {
		return err
	}
	fmt.Println(p)
	return nil
}

// ---------------------------------------------------------------- 工具

// newLogger 返回同时写控制台和日志文件的 logger。
func newLogger(alsoStdout bool) *log.Logger {
	var writers []io.Writer
	if alsoStdout {
		writers = append(writers, os.Stdout)
	}
	if p, err := config.LogPath(); err == nil {
		if f, err := os.OpenFile(p, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600); err == nil {
			writers = append(writers, f)
		}
	}
	if len(writers) == 0 {
		writers = append(writers, os.Stdout)
	}
	return log.New(io.MultiWriter(writers...), "", log.LstdFlags)
}

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

func yesNo(b bool) string {
	if b {
		return "已开启"
	}
	return "未开启"
}

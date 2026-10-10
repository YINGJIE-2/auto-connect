// auto-connect —— 校园网自动认证工具
//
// 用法：
//
//	auto-connect            打开操作菜单（双击本程序就是这个）
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
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/YINGJIE-2/auto-connect/internal/app"
	"github.com/YINGJIE-2/auto-connect/internal/autostart"
	"github.com/YINGJIE-2/auto-connect/internal/config"
	"github.com/YINGJIE-2/auto-connect/internal/netprobe"
	"github.com/YINGJIE-2/auto-connect/internal/win"
)

// daemonMutex 是守护进程的单实例名。菜单靠它判断「后台守护是否在跑」。
const daemonMutex = "auto-connect-daemon"

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
		// 无参数（双击 exe）：打开操作菜单
		return cmdMenu()
	default:
		usage()
		return fmt.Errorf("未知命令：%s", cmd)
	}
}

func usage() {
	fmt.Print(banner)
	fmt.Print(`
命令：
  setup       重新配置（填学号、密码、选运营商）
  daemon      当前窗口里常驻守护（关掉窗口就停）
  status      查看当前联网状态
  login       立刻认证一次
  install     注册开机自启
  uninstall   取消开机自启
  log         显示日志文件路径
  version     显示版本

直接双击程序 = 打开操作菜单，所有功能都在里面。
配置文件位置：`)
	p, _ := config.Path()
	fmt.Println("  " + p)
}

// ---------------------------------------------------------------- 操作菜单

// cmdMenu 是双击程序后的主界面。
//
// 设计取舍：这个窗口只是一个「遥控器」。
// 真正的守护是菜单启动的独立后台进程，所以**用户随时可以关掉这个窗口**，
// 不会像以前那样一关窗口就断掉守护。
func cmdMenu() error {
	fmt.Print("\n" + banner)
	fmt.Println("  本窗口只是操作面板，随时可以关闭；后台守护是独立进程，不受影响。")

	if !config.Exists() {
		fmt.Println("\n还没配置过，先带你配一遍（大约 30 秒）。")
		if err := cmdSetup(nil); err != nil {
			return err
		}
	}

	for {
		cfg, err := config.Load()
		if err != nil {
			return fmt.Errorf("读取配置失败: %w", err)
		}
		running := daemonRunning()
		auto := autostart.IsInstalled()

		fmt.Println("\n===========================================================")
		fmt.Printf("  账号     : %s（%s）\n", cfg.Account(), config.ISPName(cfg.ISP))
		fmt.Printf("  当前状态 : %s\n", stateText(cfg))
		fmt.Printf("  后台守护 : %s\n", boolText(running, "运行中", "未运行"))
		fmt.Printf("  开机自启 : %s\n", boolText(auto, "已开启", "未开启"))
		fmt.Println("-----------------------------------------------------------")
		fmt.Println("  1) 立即检测并重连")
		fmt.Println("  2) 修改配置（学号 / 密码 / 运营商）")
		fmt.Println("  3) 启动后台守护（关掉本窗口也会继续跑）")
		fmt.Println("  4) 停止后台守护")
		fmt.Println("  5) 开机自启  开启 / 关闭")
		fmt.Println("  6) 查看日志")
		fmt.Println("  0) 退出")
		fmt.Println("-----------------------------------------------------------")

		// 一句话告诉用户「现在到底还要不要做点什么」
		switch {
		case running && auto:
			fmt.Println("  提示：已全部就绪，以后开机不用管它。")
		case running && !auto:
			fmt.Println("  提示：守护在跑，但没开开机自启。选 5 开启后，重启就不用手动来了。")
		case !running && auto:
			fmt.Println("  提示：开机自启已开，重启后会自动生效；想立刻生效就选 3。")
		default:
			fmt.Println("  提示：目前没有任何守护在跑。选 3 启动后台守护，选 5 让它开机自动来。")
		}

		choice := strings.TrimSpace(readLineInput("\n请选择"))
		switch choice {
		case "1":
			menuReconnect(cfg)
		case "2":
			if err := cmdSetup(nil); err != nil {
				fmt.Println("\n配置未完成：" + err.Error())
			}
		case "3":
			menuStartDaemon()
		case "4":
			menuStopDaemon()
		case "5":
			menuToggleAutostart()
		case "6":
			menuShowLog()
		case "0", "q", "Q":
			fmt.Println("\n再见。")
			return nil
		default:
			fmt.Println("\n请输入 0 ~ 6 之间的数字。")
		}
	}
}

// stateText 做一次实时探测。
// 超时特意设短（4 秒/地址）：菜单是要反复刷新的，在线时它 0.2 秒就返回，
// 离线时也不能让界面卡上二十几秒。
func stateText(cfg *config.Config) string {
	res := netprobe.Check(cfg.ProbeURLs, 4*time.Second)
	switch res.State {
	case netprobe.Online:
		return "已联网"
	case netprobe.Offline:
		return "需要认证（现在上不了外网）"
	default:
		return "无法判断（网线没插或网卡没启用？）"
	}
}

func menuReconnect(cfg *config.Config) {
	pw, err := loadCredential()
	if err != nil {
		fmt.Println("\n读取密码失败：" + err.Error())
		fmt.Println("请先用菜单 2) 重新配置一次。")
		return
	}
	a := app.New(cfg, pw, newLogger(false))

	res := a.Check()
	if res.State == netprobe.Online {
		fmt.Println("\n当前已经联网了，不用认证。")
		return
	}

	fmt.Printf("\n检测到%s，正在认证 ...\n", res.State)
	r, err := a.LoginOnce(context.Background(), &res)
	if err != nil {
		fmt.Println("认证异常：" + err.Error())
		return
	}
	if r.OK {
		fmt.Println("认证成功，账号 " + cfg.Account())
		return
	}
	fmt.Printf("认证失败：%s\n", r.Message)
	fmt.Println("常见原因是密码不对或运营商选错。可以用菜单 2) 改一下。")
}

func menuStartDaemon() {
	if daemonRunning() {
		fmt.Println("\n后台守护已经在跑了，不用重复启动。")
		return
	}

	exe, err := os.Executable()
	if err != nil {
		fmt.Println("\n无法定位程序路径：" + err.Error())
		return
	}
	// 清掉可能残留的停止标记，否则新守护会立刻自杀
	_ = os.Remove(stopFlagPath())

	if err := win.LaunchDetached(exe, "daemon", "--hidden"); err != nil {
		fmt.Println("\n启动失败：" + err.Error())
		return
	}

	// 给它 1 秒起来，然后确认一下，避免「看起来成功其实没起来」
	time.Sleep(time.Second)
	if !daemonRunning() {
		fmt.Println("\n启动似乎没有成功，请稍后重试，或改用菜单外的命令行：auto-connect daemon")
		return
	}
	fmt.Println("\n已启动后台守护：掉线会自动重连，关掉本窗口也不受影响。")
	fmt.Println("日志文件：" + logPathOrEmpty())
}

func menuStopDaemon() {
	if !daemonRunning() {
		fmt.Println("\n后台守护当前没有在运行。")
		return
	}
	if err := os.WriteFile(stopFlagPath(), []byte("stop"), 0o600); err != nil {
		fmt.Println("\n发送停止指令失败：" + err.Error())
		return
	}
	fmt.Print("\n已发送停止指令，正在等待它退出 ...")
	for i := 0; i < 20; i++ { // 最多等 10 秒
		time.Sleep(500 * time.Millisecond)
		if !daemonRunning() {
			fmt.Println(" 已停止。")
			return
		}
	}
	fmt.Println()
	fmt.Println("它还在运行（可能正卡在联网探测的超时等待里）。再等几秒重试，")
	fmt.Println("或打开任务管理器结束 auto-connect.exe。")
}

func menuToggleAutostart() {
	if autostart.IsInstalled() {
		if err := autostart.Uninstall(); err != nil {
			fmt.Println("\n关闭开机自启失败：" + err.Error())
			return
		}
		fmt.Println("\n已关闭开机自启。以后开机需要自己双击本程序。")
		return
	}
	if err := autostart.Install(""); err != nil {
		fmt.Println("\n开启开机自启失败：" + err.Error())
		fmt.Println("建议把程序放到固定的目录（例如 D:\\Tools\\auto-connect\\）再试一次，")
		fmt.Println("放在桌面或下载文件夹里，路径变动后自启会失效。")
		return
	}
	fmt.Println("\n已开启开机自启：开机会延迟 30 秒、等网络就绪后自动联网，不弹窗口。")
}

func menuShowLog() {
	p, err := config.LogPath()
	if err != nil {
		fmt.Println("\n" + err.Error())
		return
	}
	data, err := os.ReadFile(p)
	if err != nil || len(data) == 0 {
		fmt.Println("\n还没有日志。日志要等守护跑起来之后才会产生。")
		fmt.Println("日志文件：" + p)
		return
	}
	lines := strings.Split(strings.TrimRight(string(data), "\r\n"), "\n")
	const tail = 20
	if len(lines) > tail {
		lines = lines[len(lines)-tail:]
	}
	fmt.Printf("\n------- 最近 %d 行日志 -------\n", len(lines))
	for _, l := range lines {
		fmt.Println("  " + strings.TrimRight(l, "\r"))
	}
	fmt.Println("-------------------------------------")
	fmt.Println("完整日志：" + p)
}

// daemonRunning 判断后台守护是否在运行。
// 原理：守护进程持有一个命名互斥体；能抢到锁说明没人在跑。
func daemonRunning() bool {
	release, ok, err := win.SingleInstance(daemonMutex)
	if err != nil {
		return false
	}
	if !ok {
		return true // 抢不到 = 已经有守护在跑
	}
	release()
	return false
}

// stopFlagPath 返回停止标记文件路径。守护每轮探测都会看它一眼。
func stopFlagPath() string {
	dir, err := config.Dir()
	if err != nil {
		return "auto-connect.stop"
	}
	return filepath.Join(dir, "stop.flag")
}

func readLineInput(label string) string {
	fmt.Print(label + " > ")
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && line == "" {
		return ""
	}
	return strings.TrimSpace(line)
}

func boolText(b bool, yes, no string) string {
	if b {
		return yes
	}
	return no
}

func logPathOrEmpty() string {
	p, err := config.LogPath()
	if err != nil {
		return "(不可用)"
	}
	return p
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

	release, ok, err := win.SingleInstance(daemonMutex)
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

	// 清掉上次可能遗留的停止标记，否则刚起来就会立刻退出
	flagPath := stopFlagPath()
	_ = os.Remove(flagPath)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// 监听「停止标记文件」。
	// 菜单里的「停止后台守护」就是写这个文件 —— 用文件而不是杀进程，
	// 既避开权限问题，也让守护能在安全点优雅退出而不是被强杀。
	go func() {
		t := time.NewTicker(2 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if _, err := os.Stat(flagPath); err == nil {
					_ = os.Remove(flagPath)
					fmt.Println("收到停止指令，守护结束")
					stop()
					return
				}
			}
		}
	}()

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

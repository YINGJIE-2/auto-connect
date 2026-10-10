//go:build windows

// Package autostart 注册开机自启，提供两条通道：
//
//  1. **任务计划程序**（首选）—— 能延迟启动、只在网络可用时启动、崩溃自动重启、隐藏窗口
//  2. **注册表启动项**（降级）—— 兼容性最好，几乎不会被组策略挡住；
//     代价是没有延迟和崩溃重启，所以延迟改由程序自己用 `daemon --hidden --delay 30` 实现
//
// 先试 1，失败自动落到 2。这样即使学校电脑/安全软件禁用了任务计划程序，自启依然能成。
package autostart

import (
	"bytes"
	"encoding/binary"
	"encoding/xml"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"unicode/utf16"

	"github.com/YINGJIE-2/auto-connect/internal/win"
)

const (
	// TaskName 是任务计划程序里的任务名，也是卸载时的依据。
	TaskName = "auto-connect"
	// runKey 是注册表启动项所在位置（只写 HKCU，不需要管理员权限）。
	runKey = `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
	// valueName 是注册表启动项的名字。
	valueName = "auto-connect"

	// MethodTask 表示自启挂在「任务计划程序」上（首选）。
	MethodTask = "task"
	// MethodStartup 表示自启挂在「注册表启动项」上（降级）。
	MethodStartup = "startup"
)

const taskXMLTemplate = `<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>auto-connect 校园网自动认证：开机自动联网，掉线自动重连。</Description>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
      <Delay>PT30S</Delay>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>true</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
    <RestartOnFailure>
      <Interval>PT1M</Interval>
      <Count>3</Count>
    </RestartOnFailure>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>%s</Command>
      <Arguments>daemon --hidden</Arguments>
    </Exec>
  </Actions>
</Task>
`

// Install 注册（或覆盖）开机自启，返回实际生效的方式（MethodTask / MethodStartup）。
func Install(exePath string) (string, error) {
	abs, err := resolveExe(exePath)
	if err != nil {
		return "", err
	}

	taskErr := installTask(abs)
	if taskErr == nil {
		// 已经挂上任务计划，清掉可能残留的注册表项，免得开机启动两次
		_ = uninstallStartup()
		return MethodTask, nil
	}

	if startupErr := installStartup(abs); startupErr != nil {
		return "", fmt.Errorf("两种自启方式都没能注册成功\n      任务计划程序：%v\n      注册表启动项：%v",
			taskErr, startupErr)
	}
	return MethodStartup, nil
}

// Uninstall 取消开机自启。两条通道都清理，避免残留导致仍然自动启动。
func Uninstall() error {
	var errs []string
	if err := uninstallTask(); err != nil {
		errs = append(errs, err.Error())
	}
	if err := uninstallStartup(); err != nil {
		errs = append(errs, err.Error())
	}
	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "；"))
	}
	return nil
}

// Method 返回当前实际生效的自启方式。
// 返回空字符串表示没有开启开机自启。
func Method() string {
	if taskInstalled() {
		return MethodTask
	}
	if startupInstalled() {
		return MethodStartup
	}
	return ""
}

// IsInstalled 判断是否已注册开机自启（任一种方式都算）。
func IsInstalled() bool {
	return Method() != ""
}

// RunNow 立即触发一次自启任务（仅任务计划方式可用，用于测试）。
func RunNow() error {
	out, err := run("schtasks", "/Run", "/TN", TaskName)
	if err != nil {
		return fmt.Errorf("%v —— %s", err, tidy(out))
	}
	return nil
}

// ---------------------------------------------------------------- 任务计划程序

func installTask(abs string) error {
	body := fmt.Sprintf(taskXMLTemplate, escapeXML(abs))

	tmp, err := os.CreateTemp("", "auto-connect-task-*.xml")
	if err != nil {
		return fmt.Errorf("创建临时文件失败: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)

	// schtasks 要求 XML 为 UTF-16（带 BOM）
	if _, err := tmp.Write(utf16LEWithBOM(body)); err != nil {
		tmp.Close()
		return err
	}
	tmp.Close()

	out, err := run("schtasks", "/Create", "/TN", TaskName, "/XML", tmpPath, "/F")
	if err != nil {
		return fmt.Errorf("%v —— %s", err, tidy(out))
	}
	return nil
}

func uninstallTask() error {
	out, err := run("schtasks", "/Delete", "/TN", TaskName, "/F")
	if err != nil {
		if isNotFound(out) {
			return nil // 本来就没装，视为成功
		}
		return fmt.Errorf("%v —— %s", err, tidy(out))
	}
	return nil
}

func taskInstalled() bool {
	_, err := run("schtasks", "/Query", "/TN", TaskName)
	return err == nil
}

// ---------------------------------------------------------------- 注册表启动项

func installStartup(abs string) error {
	// 注册表启动项没有「延迟启动」能力，所以让程序自己等：
	// --delay 30 → 启动后最多等 30 秒，一旦网卡拿到 IP 就立刻开工。
	// 路径必须加引号，否则放在带空格的目录里会启动失败。
	cmdline := `"` + abs + `" daemon --hidden --delay 30`

	out, err := run("reg", "add", runKey, "/v", valueName, "/t", "REG_SZ", "/d", cmdline, "/f")
	if err != nil {
		return fmt.Errorf("%v —— %s", err, tidy(out))
	}
	return nil
}

func uninstallStartup() error {
	out, err := run("reg", "delete", runKey, "/v", valueName, "/f")
	if err != nil {
		if isNotFound(out) {
			return nil
		}
		return fmt.Errorf("%v —— %s", err, tidy(out))
	}
	return nil
}

func startupInstalled() bool {
	_, err := run("reg", "query", runKey, "/v", valueName)
	return err == nil
}

// ---------------------------------------------------------------- 工具

func resolveExe(exePath string) (string, error) {
	if exePath != "" {
		return exePath, nil
	}
	p, err := os.Executable()
	if err != nil {
		return "", err
	}
	return p, nil
}

// run 执行外部命令，并把输出按系统 ANSI 代码页解码。
//
// 解码这一步很关键：中文 Windows 上 schtasks / reg 的报错是 GBK，
// 按 UTF-8 硬读会变成一串问号，真正的失败原因就丢了。
func run(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	return win.DecodeANSI(buf.Bytes()), err
}

// isNotFound 判断命令输出是否表示「目标不存在」。
// 用于把「删一个本来就没有的东西」当成成功。
func isNotFound(out string) bool {
	low := strings.ToLower(out)
	for _, kw := range []string{
		"unable to find", "cannot find", "not find", "does not exist",
		"找不到", "不存在",
	} {
		if strings.Contains(low, strings.ToLower(kw)) {
			return true
		}
	}
	return false
}

// tidy 把命令输出压成一行，方便嵌进错误信息里完整显示出来。
func tidy(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "（命令没有输出）"
	}
	var kept []string
	for _, l := range strings.Split(s, "\n") {
		l = strings.TrimSpace(strings.TrimRight(l, "\r"))
		if l != "" {
			kept = append(kept, l)
		}
	}
	return strings.Join(kept, " / ")
}

func escapeXML(s string) string {
	var buf bytes.Buffer
	xml.EscapeText(&buf, []byte(s))
	return buf.String()
}

func utf16LEWithBOM(s string) []byte {
	u := utf16.Encode([]rune(s))
	buf := make([]byte, 0, len(u)*2+2)
	buf = append(buf, 0xFF, 0xFE)
	tmp := make([]byte, 4)
	for _, v := range u {
		binary.LittleEndian.PutUint16(tmp, v)
		buf = append(buf, tmp[0], tmp[1])
	}
	return buf
}

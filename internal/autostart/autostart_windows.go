//go:build windows

// Package autostart 通过「任务计划程序」注册开机自启。
//
// 相比注册表 Run 键，任务计划程序可以：
//   - 设置延迟启动（避开网卡还没就绪的时间窗）
//   - 只在网络可用时启动
//   - 进程异常退出时自动重启
//   - 以隐藏方式运行，不弹控制台窗口
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
)

// TaskName 是任务计划程序里的任务名，也是卸载时的依据。
const TaskName = "auto-connect"

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

// Install 注册（或覆盖）开机自启任务。
func Install(exePath string) error {
	abs, err := resolveExe(exePath)
	if err != nil {
		return err
	}
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
		return fmt.Errorf("注册开机自启失败: %v\n%s", err, out)
	}
	return nil
}

// Uninstall 删除自启任务。
func Uninstall() error {
	out, err := run("schtasks", "/Delete", "/TN", TaskName, "/F")
	if err != nil {
		if strings.Contains(out, "找不到") || strings.Contains(strings.ToLower(out), "cannot find") {
			return nil // 本来就没装，视为成功
		}
		return fmt.Errorf("取消开机自启失败: %v\n%s", err, out)
	}
	return nil
}

// IsInstalled 判断自启任务是否存在。
func IsInstalled() bool {
	_, err := run("schtasks", "/Query", "/TN", TaskName)
	return err == nil
}

// RunNow 立即触发一次自启任务（用于测试）。
func RunNow() error {
	out, err := run("schtasks", "/Run", "/TN", TaskName)
	if err != nil {
		return fmt.Errorf("启动任务失败: %v\n%s", err, out)
	}
	return nil
}

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

func run(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	// 让 schtasks 用系统默认代码页输出，避免乱码
	cmd.Env = append(os.Environ(), "LANG=")
	err := cmd.Run()
	return decodeConsole(buf.Bytes()), err
}

// decodeConsole 把控制台输出转成可读字符串（GBK 环境下尽力而为）。
func decodeConsole(b []byte) string {
	s := string(b)
	// 常见的中文 Windows 控制台是 GBK；这里只把明显的乱码字符清理掉
	return strings.TrimSpace(strings.ToValidUTF8(s, "?"))
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

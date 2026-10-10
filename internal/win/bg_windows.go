//go:build windows

package win

import (
	"os"
	"os/exec"
	"syscall"
)

const (
	// detachedProcess 让子进程完全脱离父进程与父进程的控制台。
	detachedProcess = 0x00000008
	// createNewProcessGroup 让子进程独立于父进程的 Ctrl+C 广播。
	createNewProcessGroup = 0x00000200
)

// LaunchDetached 以「无窗口、脱离父进程」的方式启动一个子进程。
//
// 用途：菜单里点「启动后台守护」时，守护进程必须能在菜单窗口被关闭后继续存活。
// 普通的 exec.Command + Start 做不到这一点 —— 子进程会随父进程所在的控制台一起结束。
//
// logFile 非空时，子进程的标准输出与错误都会追加写入该文件。
// 后台进程没有窗口，一旦启动失败，日志文件是唯一能看到线索的地方。
func LaunchDetached(logFile, exe string, args ...string) error {
	cmd := exec.Command(exe, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: detachedProcess | createNewProcessGroup,
	}
	if logFile != "" {
		if f, err := os.OpenFile(logFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600); err == nil {
			cmd.Stdout = f
			cmd.Stderr = f
			defer f.Close() // 句柄已被子进程继承，父进程这份可以关掉
		}
	}
	return cmd.Start()
}

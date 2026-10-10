//go:build windows

package win

import (
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
func LaunchDetached(exe string, args ...string) error {
	cmd := exec.Command(exe, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: detachedProcess | createNewProcessGroup,
	}
	cmd.Stdin = nil
	cmd.Stdout = nil
	cmd.Stderr = nil
	return cmd.Start()
}

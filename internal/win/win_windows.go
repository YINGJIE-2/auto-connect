//go:build windows

// Package win 封装本项目用到的 Windows 专有能力：
//   - DPAPI 加解密（密码绑定当前 Windows 用户，换机/换用户无法解密）
//   - 单实例互斥锁（避免开机自启和手动启动跑出两个守护进程）
//   - 无回显读取密码
package win

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"
	"unicode/utf16"
	"unicode/utf8"
	"unsafe"
)

var (
	kernel32 = syscall.NewLazyDLL("kernel32.dll")
	crypt32  = syscall.NewLazyDLL("crypt32.dll")

	procLocalFree           = kernel32.NewProc("LocalFree")
	procCreateMutexW        = kernel32.NewProc("CreateMutexW")
	procFreeConsole         = kernel32.NewProc("FreeConsole")
	procGetConsoleMode      = kernel32.NewProc("GetConsoleMode")
	procSetConsoleMode      = kernel32.NewProc("SetConsoleMode")
	procCryptProtectData    = crypt32.NewProc("CryptProtectData")
	procCryptUnprotectData  = crypt32.NewProc("CryptUnprotectData")
	procMultiByteToWideChar = kernel32.NewProc("MultiByteToWideChar")
)

// 这些字节作为「附加熵」参与密钥派生。
// 作用是：即使别的程序也调用 DPAPI，也解不开我们这个文件。
var entropy = []byte("auto-connect/v1")

const (
	cryptprotectUIForbidden = 0x1
	enableEchoInput         = 0x0004
	errorAlreadyExists      = 183
)

type dataBlob struct {
	cbData uint32
	pbData *byte
}

func newBlob(b []byte) dataBlob {
	var blob dataBlob
	if len(b) > 0 {
		blob.cbData = uint32(len(b))
		blob.pbData = &b[0]
	}
	return blob
}

func (b dataBlob) bytes() []byte {
	if b.pbData == nil || b.cbData == 0 {
		return nil
	}
	out := make([]byte, b.cbData)
	copy(out, unsafe.Slice(b.pbData, b.cbData))
	return out
}

// Encrypt 用 DPAPI 加密数据。加密结果只能在**当前 Windows 用户**下解开。
func Encrypt(plain []byte) ([]byte, error) {
	in := newBlob(plain)
	ent := newBlob(entropy)
	var out dataBlob

	r, _, err := procCryptProtectData.Call(
		uintptr(unsafe.Pointer(&in)),
		0, // 描述文本，不需要
		uintptr(unsafe.Pointer(&ent)),
		0, // 保留参数
		0, // 不使用弹窗
		uintptr(cryptprotectUIForbidden),
		uintptr(unsafe.Pointer(&out)),
	)
	if r == 0 {
		return nil, fmt.Errorf("DPAPI 加密失败: %w", err)
	}
	defer procLocalFree.Call(uintptr(unsafe.Pointer(out.pbData)))
	return out.bytes(), nil
}

// Decrypt 解密 DPAPI 数据。
func Decrypt(cipher []byte) ([]byte, error) {
	in := newBlob(cipher)
	ent := newBlob(entropy)
	var out dataBlob

	r, _, _ := procCryptUnprotectData.Call(
		uintptr(unsafe.Pointer(&in)),
		0,
		uintptr(unsafe.Pointer(&ent)),
		0,
		0,
		uintptr(cryptprotectUIForbidden),
		uintptr(unsafe.Pointer(&out)),
	)
	if r == 0 {
		return nil, errors.New("DPAPI 解密失败：凭证可能是在别的电脑或别的 Windows 账号下加密的")
	}
	defer procLocalFree.Call(uintptr(unsafe.Pointer(out.pbData)))
	return out.bytes(), nil
}

// SingleInstance 用命名互斥体保证同一时间只有一个守护进程。
// 返回的 release 必须在退出时调用。
func SingleInstance(name string) (release func(), ok bool, err error) {
	namePtr, err := syscall.UTF16PtrFromString(`Global\` + name)
	if err != nil {
		return nil, false, err
	}
	h, _, callErr := procCreateMutexW.Call(0, 0, uintptr(unsafe.Pointer(namePtr)))
	if h == 0 {
		return nil, false, fmt.Errorf("创建互斥体失败: %w", callErr)
	}
	// CreateMutexW 在对象已存在时返回有效句柄，但 GetLastError 为 ERROR_ALREADY_EXISTS
	lastErr, _, _ := kernel32.NewProc("GetLastError").Call()
	if lastErr == errorAlreadyExists {
		syscall.CloseHandle(syscall.Handle(h))
		return func() {}, false, nil
	}
	release = func() {
		syscall.CloseHandle(syscall.Handle(h))
	}
	return release, true, nil
}

// ReadPassword 从控制台读取密码且不回显。
// 若标准输入不是控制台（例如被管道重定向），退化为普通读取。
func ReadPassword() (string, error) {
	handle := syscall.Handle(os.Stdin.Fd())

	var mode uint32
	r, _, _ := procGetConsoleMode.Call(uintptr(handle), uintptr(unsafe.Pointer(&mode)))
	if r == 0 {
		return readLine()
	}
	// 关闭回显
	procSetConsoleMode.Call(uintptr(handle), uintptr(mode&^enableEchoInput))
	defer procSetConsoleMode.Call(uintptr(handle), uintptr(mode))

	s, err := readLine()
	fmt.Println()
	return s, err
}

func readLine() (string, error) {
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && line == "" {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// HideConsole 让当前进程脱离控制台，从而不显示窗口。
// 用在被任务计划程序拉起时 —— 用户完全无感。
// 如果控制台是终端自己开的，只是本进程脱离，那个窗口依然存在。
func HideConsole() {
	procFreeConsole.Call()
}

// CP_ACP：当前系统的 ANSI 代码页。中文 Windows 上就是 936（GBK）。
const cpACP = 0

// DecodeANSI 把命令行工具输出的 ANSI（中文系统上是 GBK）字节解码成 UTF-8。
//
// 为什么必须做这件事：schtasks、reg 这些工具的输出走系统 ANSI 代码页，
// 直接按 UTF-8 处理会把每个汉字变成无效字节，最终显示成一串问号 ——
// 错误信息就此丢失，用户只看到「exit status 1」和一堆 ????。
func DecodeANSI(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	// 已经是合法 UTF-8（例如输出全是 ASCII）就直接用，不做多余转换
	if utf8.Valid(b) {
		return string(b)
	}

	// 先问长度，再转换
	n, _, _ := procMultiByteToWideChar.Call(
		uintptr(cpACP), 0,
		uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)),
		0, 0,
	)
	if n == 0 {
		return strings.ToValidUTF8(string(b), "?")
	}
	buf := make([]uint16, n)
	procMultiByteToWideChar.Call(
		uintptr(cpACP), 0,
		uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)),
		uintptr(unsafe.Pointer(&buf[0])), n,
	)
	return string(utf16.Decode(buf))
}

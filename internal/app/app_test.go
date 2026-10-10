package app

import (
	"io"
	"log"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/YINGJIE-2/auto-connect/internal/config"
)

// blackhole 起一个「接受连接但永不响应」的 TCP 服务，用来模拟卡死的探测源。
// 返回它的地址，测试结束记得关闭。
func blackhole(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c // 故意不关、不写，让它挂着
		}
	}()
	return ln
}

// 探测源全部卡死时，复检必须被硬预算截断。
//
// 回归背景：实测出现过认证后「复检 10.8 秒」才返回（= 6 x (1.5 秒超时 +
// 0.3 秒间隔)）。复检只是「确认」，不能反过来把日志拖成十几秒。
func TestVerifyOnlineHonoursBudget(t *testing.T) {
	ln := blackhole(t)
	defer ln.Close()

	cfg := config.Default()
	cfg.ProbeURLs = []string{"http://" + ln.Addr().String() + "/generate_204"}
	a := New(cfg, "x", log.New(io.Discard, "", 0))

	start := time.Now()
	if a.verifyOnline() {
		t.Fatal("探测源卡死时不该判定为在线")
	}
	cost := time.Since(start)
	if cost > 6*time.Second {
		t.Fatalf("复检耗时 %v，已远超预算（应约 4 秒）", cost)
	}
	t.Logf("复检在 %v 后放弃（预算 4 秒）", cost)
}

// 网关延迟放行时，复检应当「一放行就返回」，不额外空耗。
func TestVerifyOnlineReturnsAsSoonAsFlushed(t *testing.T) {
	flushAt := time.Now().Add(1200 * time.Millisecond)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if time.Now().Before(flushAt) {
			// 还没放行：返回网关的劫持页
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("<html>please login</html>"))
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()

	cfg := config.Default()
	cfg.ProbeURLs = []string{"http://" + ln.Addr().String() + "/generate_204"}
	a := New(cfg, "x", log.New(io.Discard, "", 0))

	start := time.Now()
	if !a.verifyOnline() {
		t.Fatal("网关放行后应当复检通过")
	}
	cost := time.Since(start)
	if cost > 3*time.Second {
		t.Fatalf("复检耗时 %v，明显超出网关放行延迟", cost)
	}
	t.Logf("网关 1.2 秒后放行，复检 %v 确认", cost)
}

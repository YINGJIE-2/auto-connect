// Package config 负责读写配置文件。
//
// 设计原则：配置文件里**永远不出现密码**。
// 密码由 internal/win 用 Windows DPAPI 加密后单独存放（cred.bin）。
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	AppDirName     = "auto-connect"
	ConfigFileName = "config.json"
	CredFileName   = "cred.bin"
	LogFileName    = "auto-connect.log"
)

// Portal 描述认证网关。
type Portal struct {
	// Type: auto / drcom。auto 表示自动识别。
	Type string `json:"type"`
	// Host 网关地址，例如 172.16.8.22。留空则由 302 重定向自动推断。
	Host string `json:"host"`
	// Port eportal 接口端口。Dr.COM 城市热点通常是 801（不是 80）。
	Port int `json:"port"`
	// LoginMethod 认证模式。1 = Portal 协议（多数情况），0 = 本地协议。
	LoginMethod int `json:"login_method"`
	// JSVersion 页面脚本版本号，随学校升级可能变化。
	JSVersion string `json:"js_version"`
	// AccountPrefix 账号前缀。多数学校为空；个别学校需要 ",0,"。
	AccountPrefix string `json:"account_prefix"`
	// ISPSuffix 运营商 -> 账号后缀 的映射。
	ISPSuffix map[string]string `json:"isp_suffix"`
}

// Behavior 描述重连策略。
type Behavior struct {
	// CheckInterval 在线时的探测间隔（秒）。
	CheckInterval int `json:"check_interval"`
	// ReconnectDelay 首次失败后的重试间隔（秒），随后指数退避。
	ReconnectDelay int `json:"reconnect_delay"`
	// BackoffMax 退避封顶（秒）。
	BackoffMax int `json:"backoff_max"`
	// MaxFailBeforeSlow 连续失败多少次后切换到慢速重试（防止触发验证码）。
	MaxFailBeforeSlow int `json:"max_fail_before_slow"`
	// SlowInterval 慢速重试间隔（秒）。
	SlowInterval int `json:"slow_interval"`
}

// Config 是完整的配置。
type Config struct {
	Username  string   `json:"username"`
	ISP       string   `json:"isp"`
	Portal    Portal   `json:"portal"`
	Behavior  Behavior `json:"behavior"`
	ProbeURLs []string `json:"probe_urls,omitempty"`

	// 运行时字段，不写入文件。
	path string `json:"-"`
}

// Default 返回一份带默认值的配置。
// 默认值按「苏州城市学院 Dr.COM 城市热点」预置，其他学校只需改 Portal。
func Default() *Config {
	return &Config{
		ISP: "campus",
		Portal: Portal{
			Type:          "auto",
			Host:          "",
			Port:          801,
			LoginMethod:   1,
			JSVersion:     "3.3.3",
			AccountPrefix: "",
			ISPSuffix: map[string]string{
				"telecom": "@telecom", // 中国电信
				"cmcc":    "@cmcc",    // 中国移动
				"unicom":  "@unicom",  // 中国联通
				"campus":  "",         // 校园内网
			},
		},
		Behavior: Behavior{
			CheckInterval:     30,
			ReconnectDelay:    5,
			BackoffMax:        60,
			MaxFailBeforeSlow: 5,
			SlowInterval:      300,
		},
		ProbeURLs: []string{
			"http://connect.rom.miui.com/generate_204",
			"http://www.msftconnecttest.com/connecttest.txt",
			"http://captive.apple.com/hotspot-detect.html",
		},
	}
}

// Dir 返回程序的数据目录 %APPDATA%\auto-connect。
func Dir() (string, error) {
	base := os.Getenv("APPDATA")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", errors.New("无法定位用户数据目录（APPDATA 为空）")
		}
		base = filepath.Join(home, ".config")
	}
	dir := filepath.Join(base, AppDirName)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("创建数据目录失败: %w", err)
	}
	return dir, nil
}

// Path 返回配置文件完整路径。
func Path() (string, error) {
	dir, err := Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, ConfigFileName), nil
}

// CredPath 返回加密凭证文件路径。
func CredPath() (string, error) {
	dir, err := Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, CredFileName), nil
}

// LogPath 返回日志文件路径。
func LogPath() (string, error) {
	dir, err := Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, LogFileName), nil
}

// Exists 判断配置是否已存在。
func Exists() bool {
	p, err := Path()
	if err != nil {
		return false
	}
	_, err = os.Stat(p)
	return err == nil
}

// Load 读取配置，缺失字段用默认值补齐。
func Load() (*Config, error) {
	p, err := Path()
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	cfg := Default()
	if err := json.Unmarshal(raw, cfg); err != nil {
		return nil, fmt.Errorf("配置文件格式错误: %w", err)
	}
	cfg.path = p
	cfg.normalize()
	return cfg, nil
}

func (c *Config) normalize() {
	d := Default()
	if c.Portal.Port == 0 {
		c.Portal.Port = d.Portal.Port
	}
	if c.Portal.LoginMethod == 0 && !strings.Contains(strings.ToLower(c.Portal.Type), "local") {
		// 0 是合法值，但默认应为 1；这里只在完全未设置时兜底。
		// 由于 json 反序列化无法区分「未设置」与「显式 0」，
		// 约定用 -1 表示未设置。
	}
	if c.Portal.JSVersion == "" {
		c.Portal.JSVersion = d.Portal.JSVersion
	}
	if c.Portal.ISPSuffix == nil {
		c.Portal.ISPSuffix = d.Portal.ISPSuffix
	}
	for k, v := range d.Portal.ISPSuffix {
		if _, ok := c.Portal.ISPSuffix[k]; !ok {
			c.Portal.ISPSuffix[k] = v
		}
	}
	if c.Behavior.CheckInterval <= 0 {
		c.Behavior.CheckInterval = d.Behavior.CheckInterval
	}
	if c.Behavior.ReconnectDelay <= 0 {
		c.Behavior.ReconnectDelay = d.Behavior.ReconnectDelay
	}
	if c.Behavior.BackoffMax <= 0 {
		c.Behavior.BackoffMax = d.Behavior.BackoffMax
	}
	if c.Behavior.MaxFailBeforeSlow <= 0 {
		c.Behavior.MaxFailBeforeSlow = d.Behavior.MaxFailBeforeSlow
	}
	if c.Behavior.SlowInterval <= 0 {
		c.Behavior.SlowInterval = d.Behavior.SlowInterval
	}
	if len(c.ProbeURLs) == 0 {
		c.ProbeURLs = d.ProbeURLs
	}
	if c.ISP == "" {
		c.ISP = d.ISP
	}
}

// Save 写回配置文件（不含密码）。
func (c *Config) Save() error {
	p, err := Path()
	if err != nil {
		return err
	}
	c.path = p
	buf, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	buf = append(buf, '\n')
	return os.WriteFile(p, buf, 0o600)
}

// Account 返回最终提交给网关的账号。
func (c *Config) Account() string {
	suffix := ""
	if c.Portal.ISPSuffix != nil {
		suffix = c.Portal.ISPSuffix[c.ISP]
	}
	return c.Portal.AccountPrefix + c.Username + suffix
}

// ISPName 返回运营商中文名，用于界面显示。
func ISPName(key string) string {
	switch key {
	case "telecom":
		return "中国电信"
	case "cmcc":
		return "中国移动"
	case "unicom":
		return "中国联通"
	case "campus":
		return "校园内网"
	}
	return key
}

// ISPChoices 返回可选项，顺序与向导中的编号一致。
var ISPChoices = []string{"telecom", "cmcc", "unicom", "campus"}

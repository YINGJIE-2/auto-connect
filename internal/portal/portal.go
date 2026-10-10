// Package portal 定义认证网关的抽象接口。
//
// 设计意图：学校换网关时，只需要新增一个适配器实现，主流程零改动。
// 目前实现了 Dr.COM（城市热点）。
package portal

import "context"

// Env 是一次认证所需的全套环境信息，由上层组装好交给适配器。
type Env struct {
	Host        string // 网关地址
	Port        int    // eportal 端口
	LoginMethod int    // 认证模式
	JSVersion   string // 页面脚本版本
	Account     string // 已拼好的账号（学号 + 运营商后缀）
	Password    string
	UserIP      string // 本机在校园网内的地址
	UserMAC     string
	ACName      string
	ACIP        string
}

// Result 是认证结果。
type Result struct {
	OK      bool   // 是否成功
	RetCode int    // 服务端返回码，-1 表示未提供
	RawMsg  string // 后端（RADIUS/LDAP）透传的原文，已解 Base64
	Message string // 人类可读说明
	Raw     string // 原始响应，便于排查
}

// Adapter 是可插拔的网关适配器。
type Adapter interface {
	// Name 返回适配器名称，用于日志。
	Name() string
	// Detect 根据认证页内容判断自己能否处理这个网关。
	Detect(portalBody []byte) bool
	// Login 执行一次登录。
	Login(ctx context.Context, env Env) (Result, error)
}

// RetCodeMessages 是 Dr.COM 的 ret_code 对照表，
// 逐条抄自网关页面脚本 a42.js 的 error.portal_login_err。
var RetCodeMessages = map[int]string{
	1:   "账号或密码不对，请重新输入",
	2:   "终端IP已经在线",
	3:   "系统繁忙，请稍后再试",
	4:   "发生未知错误，请稍后再试",
	5:   "REQ_CHALLENGE 失败，请联系 AC 确认",
	6:   "REQ_CHALLENGE 超时，请联系 AC 确认",
	7:   "Radius 认证失败",
	8:   "Radius 认证超时",
	9:   "Radius 下线失败",
	10:  "Radius 下线超时",
	11:  "发生其他错误，请稍后再试",
	998: "Portal 协议参数不全",
}

// DescribeRetCode 把返回码翻译成中文。
func DescribeRetCode(code int) string {
	if m, ok := RetCodeMessages[code]; ok {
		return m
	}
	return ""
}

package main

import (
	"errors"
	"fmt"
	"time"

	"github.com/TBXark/confstore"
)

// StdioMCPClientConfig 标准输入输出MCP客户端配置
type StdioMCPClientConfig struct {
	Command string            `json:"command"`
	Env     map[string]string `json:"env"`
	Args    []string          `json:"args"`
}

// SSEMCPClientConfig SSE类型MCP客户端配置
type SSEMCPClientConfig struct {
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers"`
}

// StreamableMCPClientConfig 可流式HTTP类型MCP客户端配置
type StreamableMCPClientConfig struct {
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers"`
	Timeout time.Duration     `json:"timeout"`
}

// MCPClientType 客户端类型枚举
type MCPClientType string

// 客户端类型常量
const (
	MCPClientTypeStdio      MCPClientType = "stdio"
	MCPClientTypeSSE        MCPClientType = "sse"
	MCPClientTypeStreamable MCPClientType = "streamable-http"
)

// Options MCP服务选项
type Options struct {
	PanicIfInvalid *bool    `json:"panicIfInvalid,omitempty"`
	LogEnabled     *bool    `json:"logEnabled,omitempty"`
	AuthTokens     []string `json:"authTokens,omitempty"`
}

// MCPProxyConfig 代理服务器配置
type MCPProxyConfig struct {
	BaseURL string   `json:"baseURL"`
	Addr    string   `json:"addr"`
	Name    string   `json:"name"`
	Version string   `json:"version"`
	Options *Options `json:"options,omitempty"`
}

// MCPClientConfig MCP客户端配置
type MCPClientConfig struct {
	TransportType MCPClientType `json:"transportType,omitempty"`

	// Stdio配置
	Command string            `json:"command,omitempty"`
	Args    []string          `json:"args,omitempty"`
	Env     map[string]string `json:"env,omitempty"`

	// SSE或Streamable HTTP配置
	URL     string            `json:"url,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
	Timeout time.Duration     `json:"timeout,omitempty"`

	Options *Options `json:"options,omitempty"`
}

// parseMCPClientConfig 解析MCP客户端配置
func parseMCPClientConfig(conf *MCPClientConfig) (any, error) {
	// 命令行类型客户端
	if conf.Command != "" || conf.TransportType == MCPClientTypeStdio {
		if conf.Command == "" {
			return nil, errors.New("stdio类型客户端必须提供command参数")
		}
		return &StdioMCPClientConfig{
			Command: conf.Command,
			Env:     conf.Env,
			Args:    conf.Args,
		}, nil
	}

	// URL类型客户端
	if conf.URL != "" {
		if conf.TransportType == MCPClientTypeStreamable {
			return &StreamableMCPClientConfig{
				URL:     conf.URL,
				Headers: conf.Headers,
				Timeout: conf.Timeout,
			}, nil
		} else {
			return &SSEMCPClientConfig{
				URL:     conf.URL,
				Headers: conf.Headers,
			}, nil
		}
	}

	return nil, errors.New("无效的服务器类型")
}

// Config 总配置结构
type Config struct {
	McpProxy   *MCPProxyConfig             `json:"mcpProxy"`
	McpServers map[string]*MCPClientConfig `json:"mcpServers"`
}

// load 从文件加载配置
func load(path string) (*Config, error) {
	// 定义完整配置结构
	type FullConfig struct {
		McpProxy   *MCPProxyConfig             `json:"mcpProxy"`
		McpServers map[string]*MCPClientConfig `json:"mcpServers"`
	}

	// 加载配置文件
	conf, err := confstore.Load[FullConfig](path)
	if err != nil {
		return nil, fmt.Errorf("加载配置文件失败: %w", err)
	}

	// 验证主代理配置必须存在
	if conf.McpProxy == nil {
		return nil, errors.New("缺少mcpProxy配置")
	}

	// 设置默认选项
	if conf.McpProxy.Options == nil {
		falseVal := false
		conf.McpProxy.Options = &Options{
			PanicIfInvalid: &falseVal,
			LogEnabled:     &falseVal,
		}
	}

	// 为每个客户端设置默认值
	for _, clientConfig := range conf.McpServers {
		if clientConfig.Options == nil {
			clientConfig.Options = &Options{}
		}

		// 如果客户端没有指定选项，则继承代理的选项
		if clientConfig.Options.AuthTokens == nil {
			clientConfig.Options.AuthTokens = conf.McpProxy.Options.AuthTokens
		}
		if clientConfig.Options.PanicIfInvalid == nil {
			clientConfig.Options.PanicIfInvalid = conf.McpProxy.Options.PanicIfInvalid
		}
		if clientConfig.Options.LogEnabled == nil {
			clientConfig.Options.LogEnabled = conf.McpProxy.Options.LogEnabled
		}
	}

	return &Config{
		McpProxy:   conf.McpProxy,
		McpServers: conf.McpServers,
	}, nil
}

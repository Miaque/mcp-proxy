package main

import (
	"errors"
	"github.com/TBXark/confstore"
	"time"
)

type StdioMCPClientConfig struct {
	Command string            `json:"command"`
	Env     map[string]string `json:"env"`
	Args    []string          `json:"args"`
}

type SSEMCPClientConfig struct {
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers"`
}

type StreamableMCPClientConfig struct {
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers"`
	Timeout time.Duration     `json:"timeout"`
}

type MCPClientType string

const (
	MCPClientTypeStdio      MCPClientType = "stdio"
	MCPClientTypeSSE        MCPClientType = "sse"
	MCPClientTypeStreamable MCPClientType = "streamable-http"
)

type Options struct {
	PanicIfInvalid *bool    `json:"panicIfInvalid,omitempty"`
	LogEnabled     *bool    `json:"logEnabled,omitempty"`
	AuthTokens     []string `json:"authTokens,omitempty"`
}

type MCPProxyConfig struct {
	BaseURL string   `json:"baseURL"`
	Addr    string   `json:"addr"`
	Name    string   `json:"name"`
	Version string   `json:"version"`
	Options *Options `json:"options,omitempty"`
}

type MCPClientConfig struct {
	TransportType MCPClientType `json:"transportType,omitempty"`

	// Stdio
	Command string            `json:"command,omitempty"`
	Args    []string          `json:"args,omitempty"`
	Env     map[string]string `json:"env,omitempty"`

	// SSE or Streamable HTTP
	URL     string            `json:"url,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
	Timeout time.Duration     `json:"timeout,omitempty"`

	Options *Options `json:"options,omitempty"`
}

func parseMCPClientConfig(conf *MCPClientConfig) (any, error) {
	if conf.Command != "" || conf.TransportType == MCPClientTypeStdio {
		if conf.Command == "" {
			return nil, errors.New("command is required for stdio transport")
		}
		return &StdioMCPClientConfig{
			Command: conf.Command,
			Env:     conf.Env,
			Args:    conf.Args,
		}, nil
	}
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
	return nil, errors.New("invalid server type")
}

// ---- Config ----

type Config struct {
	McpProxy   *MCPProxyConfig             `json:"mcpProxy"`
	McpServers map[string]*MCPClientConfig `json:"mcpServers"`
}

func load(path string) (*Config, error) {
	type FullConfig struct {
		McpProxy   *MCPProxyConfig             `json:"mcpProxy"`
		McpServers map[string]*MCPClientConfig `json:"mcpServers"`
	}
	conf, err := confstore.Load[FullConfig](path)
	if err != nil {
		return nil, err
	}

	if conf.McpProxy == nil {
		return nil, errors.New("mcpProxy is required")
	}
	if conf.McpProxy.Options == nil {
		falseVal := false
		conf.McpProxy.Options = &Options{
			PanicIfInvalid: &falseVal,
			LogEnabled:     &falseVal,
		}
	}
	for _, clientConfig := range conf.McpServers {
		if clientConfig.Options == nil {
			clientConfig.Options = &Options{}
		}
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

package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/mark3labs/mcp-go/client"
	"github.com/mark3labs/mcp-go/client/transport"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// Client 表示MCP客户端连接
type Client struct {
	name            string
	needPing        bool
	needManualStart bool
	client          *client.Client
}

// newMCPClient 创建一个新的MCP客户端
func newMCPClient(name string, conf *MCPClientConfig) (*Client, error) {
	clientInfo, err := parseMCPClientConfig(conf)
	if err != nil {
		return nil, fmt.Errorf("解析客户端配置失败: %w", err)
	}

	switch v := clientInfo.(type) {
	case *StdioMCPClientConfig:
		envs := make([]string, 0, len(v.Env))
		for key, value := range v.Env {
			envs = append(envs, fmt.Sprintf("%s=%s", key, value))
		}
		mcpClient, err := client.NewStdioMCPClient(v.Command, envs, v.Args...)
		if err != nil {
			return nil, fmt.Errorf("创建stdio客户端失败: %w", err)
		}

		return &Client{
			name:   name,
			client: mcpClient,
		}, nil
	case *SSEMCPClientConfig:
		var options []transport.ClientOption
		if len(v.Headers) > 0 {
			options = append(options, client.WithHeaders(v.Headers))
		}
		mcpClient, err := client.NewSSEMCPClient(v.URL, options...)
		if err != nil {
			return nil, fmt.Errorf("创建SSE客户端失败: %w", err)
		}
		return &Client{
			name:            name,
			needPing:        true,
			needManualStart: true,
			client:          mcpClient,
		}, nil
	case *StreamableMCPClientConfig:
		var options []transport.StreamableHTTPCOption
		if len(v.Headers) > 0 {
			options = append(options, transport.WithHTTPHeaders(v.Headers))
		}
		if v.Timeout > 0 {
			options = append(options, transport.WithHTTPTimeout(v.Timeout))
		}
		mcpClient, err := client.NewStreamableHttpClient(v.URL, options...)
		if err != nil {
			return nil, fmt.Errorf("创建Streamable HTTP客户端失败: %w", err)
		}
		return &Client{
			name:            name,
			needPing:        true,
			needManualStart: true,
			client:          mcpClient,
		}, nil
	}
	return nil, errors.New("无效的客户端类型")
}

// addToMCPServer 将客户端添加到MCP服务器
func (c *Client) addToMCPServer(ctx context.Context, clientInfo mcp.Implementation, mcpServer *server.MCPServer) error {
	if c.needManualStart {
		if err := c.client.Start(ctx); err != nil {
			return fmt.Errorf("启动客户端失败: %w", err)
		}
	}

	// 初始化MCP客户端
	initRequest := mcp.InitializeRequest{}
	initRequest.Params.ProtocolVersion = mcp.LATEST_PROTOCOL_VERSION
	initRequest.Params.ClientInfo = clientInfo
	initRequest.Params.Capabilities = mcp.ClientCapabilities{
		Experimental: make(map[string]interface{}),
		Roots:        nil,
		Sampling:     nil,
	}

	_, err := c.client.Initialize(ctx, initRequest)
	if err != nil {
		return fmt.Errorf("初始化客户端失败: %w", err)
	}
	log.Printf("<%s> 成功初始化MCP客户端", c.name)

	// 添加工具到服务器
	if err := c.addToolsToServer(ctx, mcpServer); err != nil {
		return err
	}

	// 添加其他资源到服务器（忽略错误）
	_ = c.addPromptsToServer(ctx, mcpServer)
	_ = c.addResourcesToServer(ctx, mcpServer)
	_ = c.addResourceTemplatesToServer(ctx, mcpServer)

	// 开始定期ping连接
	if c.needPing {
		go c.startPingTask(ctx)
	}
	return nil
}

// startPingTask 定期发送ping请求以保持连接
func (c *Client) startPingTask(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

PingLoop:
	for {
		select {
		case <-ctx.Done():
			log.Printf("<%s> 上下文结束，停止ping", c.name)
			break PingLoop
		case <-ticker.C:
			if err := c.client.Ping(ctx); err != nil {
				log.Printf("<%s> Ping失败: %v", c.name, err)
			}
		}
	}
}

// addToolsToServer 将工具添加到服务器
func (c *Client) addToolsToServer(ctx context.Context, mcpServer *server.MCPServer) error {
	toolsRequest := mcp.ListToolsRequest{}

	for {
		tools, err := c.client.ListTools(ctx, toolsRequest)
		if err != nil {
			return fmt.Errorf("获取工具列表失败: %w", err)
		}

		if len(tools.Tools) == 0 {
			break
		}

		log.Printf("<%s> 成功列出 %d 个工具", c.name, len(tools.Tools))
		for _, tool := range tools.Tools {
			log.Printf("<%s> 添加工具 %s", c.name, tool.Name)
			mcpServer.AddTool(tool, c.client.CallTool)
		}

		if tools.NextCursor == "" {
			break
		}

		toolsRequest.Params.Cursor = tools.NextCursor
	}

	return nil
}

// addPromptsToServer 将提示添加到服务器
func (c *Client) addPromptsToServer(ctx context.Context, mcpServer *server.MCPServer) error {
	promptsRequest := mcp.ListPromptsRequest{}

	for {
		prompts, err := c.client.ListPrompts(ctx, promptsRequest)
		if err != nil {
			return fmt.Errorf("获取提示列表失败: %w", err)
		}

		if len(prompts.Prompts) == 0 {
			break
		}

		log.Printf("<%s> 成功列出 %d 个提示", c.name, len(prompts.Prompts))
		for _, prompt := range prompts.Prompts {
			log.Printf("<%s> 添加提示 %s", c.name, prompt.Name)
			mcpServer.AddPrompt(prompt, c.client.GetPrompt)
		}

		if prompts.NextCursor == "" {
			break
		}

		promptsRequest.Params.Cursor = prompts.NextCursor
	}

	return nil
}

// addResourcesToServer 将资源添加到服务器
func (c *Client) addResourcesToServer(ctx context.Context, mcpServer *server.MCPServer) error {
	resourcesRequest := mcp.ListResourcesRequest{}

	for {
		resources, err := c.client.ListResources(ctx, resourcesRequest)
		if err != nil {
			return fmt.Errorf("获取资源列表失败: %w", err)
		}

		if len(resources.Resources) == 0 {
			break
		}

		log.Printf("<%s> 成功列出 %d 个资源", c.name, len(resources.Resources))
		for _, resource := range resources.Resources {
			log.Printf("<%s> 添加资源 %s", c.name, resource.Name)
			mcpServer.AddResource(resource, func(ctx context.Context, request mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
				readResource, e := c.client.ReadResource(ctx, request)
				if e != nil {
					return nil, e
				}
				return readResource.Contents, nil
			})
		}

		if resources.NextCursor == "" {
			break
		}

		resourcesRequest.Params.Cursor = resources.NextCursor
	}

	return nil
}

// addResourceTemplatesToServer 将资源模板添加到服务器
func (c *Client) addResourceTemplatesToServer(ctx context.Context, mcpServer *server.MCPServer) error {
	resourceTemplatesRequest := mcp.ListResourceTemplatesRequest{}

	for {
		resourceTemplates, err := c.client.ListResourceTemplates(ctx, resourceTemplatesRequest)
		if err != nil {
			return fmt.Errorf("获取资源模板列表失败: %w", err)
		}

		if len(resourceTemplates.ResourceTemplates) == 0 {
			break
		}

		log.Printf("<%s> 成功列出 %d 个资源模板", c.name, len(resourceTemplates.ResourceTemplates))
		for _, template := range resourceTemplates.ResourceTemplates {
			log.Printf("<%s> 添加资源模板 %s", c.name, template.Name)
			mcpServer.AddResourceTemplate(template, func(ctx context.Context, request mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
				readResource, e := c.client.ReadResource(ctx, request)
				if e != nil {
					return nil, e
				}
				return readResource.Contents, nil
			})
		}

		if resourceTemplates.NextCursor == "" {
			break
		}

		resourceTemplatesRequest.PaginatedRequest.Params.Cursor = resourceTemplates.NextCursor
	}

	return nil
}

// Close 关闭客户端连接
func (c *Client) Close() error {
	if c.client != nil {
		return c.client.Close()
	}
	return nil
}

// Server 表示MCP服务器实例
type Server struct {
	tokens    []string
	mcpServer *server.MCPServer
	sseServer http.Handler
}

// newMCPServer 创建一个新的MCP服务器
func newMCPServer(name, version, baseURL string, clientConfig *MCPClientConfig) *Server {
	// 配置服务器选项
	serverOpts := []server.ServerOption{
		server.WithResourceCapabilities(true, true),
		server.WithRecovery(),
	}

	// 添加日志选项
	if clientConfig.Options != nil && *clientConfig.Options.LogEnabled {
		serverOpts = append(serverOpts, server.WithLogging())
	}

	// 创建MCP服务器
	mcpServer := server.NewMCPServer(
		name,
		version,
		serverOpts...,
	)

	// 创建SSE服务器
	sseServer := server.NewSSEServer(mcpServer,
		server.WithBasePath(name),
		server.WithBaseURL(baseURL),
	)

	// 创建并返回服务器实例
	srv := &Server{
		mcpServer: mcpServer,
		sseServer: sseServer,
	}

	// 设置认证令牌
	if clientConfig.Options != nil && len(clientConfig.Options.AuthTokens) > 0 {
		srv.tokens = clientConfig.Options.AuthTokens
	}

	return srv
}

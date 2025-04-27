package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/mark3labs/mcp-go/mcp"
	"golang.org/x/sync/errgroup"
)

// ServerState 用于存储已添加的服务器和管理路由
type ServerState struct {
	mu         sync.RWMutex
	config     *Config
	ginEngine  *gin.Engine
	ctx        context.Context
	cancel     context.CancelFunc
	mcpServers map[string]*Server
}

// API处理函数结构
type APIHandlers struct {
	state *ServerState
	info  mcp.Implementation
}

// 创建新的API处理函数
func NewAPIHandlers(state *ServerState, info mcp.Implementation) *APIHandlers {
	return &APIHandlers{
		state: state,
		info:  info,
	}
}

// 添加新服务器
func (h *APIHandlers) AddServer(c *gin.Context) {
	var newServer struct {
		Name   string           `json:"name" binding:"required"`
		Config *MCPClientConfig `json:"config" binding:"required"`
	}

	if err := c.ShouldBindJSON(&newServer); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的请求数据", "details": err.Error()})
		return
	}

	// 检查服务器名称是否已存在
	h.state.mu.RLock()
	_, exists := h.state.config.McpServers[newServer.Name]
	h.state.mu.RUnlock()

	if exists {
		c.JSON(http.StatusConflict, gin.H{"error": "服务器名称已存在"})
		return
	}

	// 创建MCP客户端
	mcpClient, err := newMCPClient(newServer.Name, newServer.Config)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "创建MCP客户端失败", "details": err.Error()})
		return
	}

	// 创建MCP服务器
	server := newMCPServer(newServer.Name, h.state.config.McpProxy.Version, h.state.config.McpProxy.BaseURL, newServer.Config)

	// 将客户端添加到服务器
	err = mcpClient.addToMCPServer(h.state.ctx, h.info, server.mcpServer)
	if err != nil {
		_ = mcpClient.Close()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "无法添加客户端到服务器", "details": err.Error()})
		return
	}

	// 注册路由
	routePath := fmt.Sprintf("/%s/", newServer.Name)
	h.state.mu.Lock()
	// 添加到配置
	h.state.config.McpServers[newServer.Name] = newServer.Config
	// 添加到服务器表
	h.state.mcpServers[newServer.Name] = server

	// 注册路由处理
	if len(server.tokens) > 0 {
		h.state.ginEngine.Group(routePath).Use(newAuthMiddleware(server.tokens)).Any("*path", SSEHandlerAdapter(server.sseServer))
	} else {
		h.state.ginEngine.Any(routePath+"*path", SSEHandlerAdapter(server.sseServer))
	}
	h.state.mu.Unlock()

	log.Printf("<%s> 服务器添加成功", newServer.Name)
	c.JSON(http.StatusOK, gin.H{
		"message": fmt.Sprintf("服务器 %s 添加成功", newServer.Name),
		"path":    routePath,
	})
}

// 移除服务器
func (h *APIHandlers) RemoveServer(c *gin.Context) {
	serverName := c.Param("name")
	if serverName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "服务器名称为空"})
		return
	}

	h.state.mu.Lock()
	defer h.state.mu.Unlock()

	_, exists := h.state.mcpServers[serverName]
	if !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "服务器不存在"})
		return
	}

	// 清理资源并移除
	delete(h.state.mcpServers, serverName)
	delete(h.state.config.McpServers, serverName)

	// 注意：Gin不支持动态移除路由，因此我们只能移除服务器配置
	// 在下一次请求中，路由处理程序会检查服务器是否存在

	c.JSON(http.StatusOK, gin.H{
		"message": fmt.Sprintf("服务器 %s 移除成功", serverName),
	})
}

// 列出所有服务器
func (h *APIHandlers) ListServers(c *gin.Context) {
	h.state.mu.RLock()
	defer h.state.mu.RUnlock()

	servers := make(map[string]interface{})
	for name := range h.state.mcpServers {
		servers[name] = struct {
			Path string `json:"path"`
		}{
			Path: fmt.Sprintf("/%s/", name),
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"servers": servers,
	})
}

// GinMiddleware 定义Gin中间件函数类型
type GinMiddleware = gin.HandlerFunc

// 创建认证中间件，验证请求中的token
func newAuthMiddleware(tokens []string) GinMiddleware {
	tokenSet := make(map[string]struct{}, len(tokens))
	for _, token := range tokens {
		tokenSet[token] = struct{}{}
	}
	return func(c *gin.Context) {
		if len(tokens) == 0 {
			c.Next()
			return
		}

		token := c.GetHeader("Authorization")
		if strings.HasPrefix(token, "Bearer ") {
			token = strings.TrimPrefix(token, "Bearer ")
		}
		if token == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			return
		}
		if _, ok := tokenSet[token]; !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			return
		}

		c.Next()
	}
}

// SSEHandlerAdapter 将SSE处理函数适配为Gin处理函数
func SSEHandlerAdapter(handler http.Handler) gin.HandlerFunc {
	return func(c *gin.Context) {
		handler.ServeHTTP(c.Writer, c.Request)
	}
}

// setupAPIRoutes 配置API路由
func setupAPIRoutes(router *gin.Engine, handlers *APIHandlers, config *Config) {
	apiGroup := router.Group("/api")

	// 如果需要认证，添加认证中间件
	if config.McpProxy.Options != nil && len(config.McpProxy.Options.AuthTokens) > 0 {
		apiGroup.Use(newAuthMiddleware(config.McpProxy.Options.AuthTokens))
	}

	// 添加API端点
	apiGroup.POST("/servers", handlers.AddServer)
	apiGroup.DELETE("/servers/:name", handlers.RemoveServer)
	apiGroup.GET("/servers", handlers.ListServers)
}

// setupMCPServers 初始化和配置MCP服务器
func setupMCPServers(state *ServerState, info mcp.Implementation, httpServer *http.Server) error {
	var eg errgroup.Group

	for name, clientConfig := range state.config.McpServers {
		name := name // 确保闭包中的变量不会被后续循环修改
		clientConfig := clientConfig

		mcpClient, err := newMCPClient(name, clientConfig)
		if err != nil {
			return fmt.Errorf("<%s> Failed to create client: %w", name, err)
		}

		server := newMCPServer(name, state.config.McpProxy.Version, state.config.McpProxy.BaseURL, clientConfig)

		// 保存服务器实例
		state.mcpServers[name] = server

		eg.Go(func() error {
			log.Printf("<%s> Connecting", name)
			addErr := mcpClient.addToMCPServer(state.ctx, info, server.mcpServer)
			if addErr != nil {
				log.Printf("<%s> Failed to add client to server: %v", name, addErr)
				if *clientConfig.Options.PanicIfInvalid {
					return addErr
				}
				return nil
			}
			log.Printf("<%s> Connected", name)

			// 使用Gin路由和中间件
			routePath := fmt.Sprintf("/%s/", name)

			// 如果需要认证，添加认证中间件
			if len(server.tokens) > 0 {
				state.ginEngine.Group(routePath).Use(newAuthMiddleware(server.tokens)).Any("*path", SSEHandlerAdapter(server.sseServer))
			} else {
				state.ginEngine.Any(routePath+"*path", SSEHandlerAdapter(server.sseServer))
			}

			httpServer.RegisterOnShutdown(func() {
				log.Printf("<%s> Shutting down", name)
				_ = mcpClient.Close()
			})
			return nil
		})
	}

	return eg.Wait()
}

// startHTTPServer 初始化并启动HTTP服务器
func startHTTPServer(config *Config) {
	// 根据环境配置Gin模式
	gin.SetMode(gin.ReleaseMode)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 创建Gin引擎
	ginEngine := gin.New()
	ginEngine.Use(gin.Logger())
	ginEngine.Use(gin.Recovery())

	httpServer := &http.Server{
		Addr:    config.McpProxy.Addr,
		Handler: ginEngine,
	}

	info := mcp.Implementation{
		Name:    config.McpProxy.Name,
		Version: config.McpProxy.Version,
	}

	// 创建服务器状态
	state := &ServerState{
		config:     config,
		ginEngine:  ginEngine,
		ctx:        ctx,
		cancel:     cancel,
		mcpServers: make(map[string]*Server),
	}

	// 创建API处理函数
	handlers := NewAPIHandlers(state, info)

	// 配置API路由
	setupAPIRoutes(ginEngine, handlers, config)

	// 设置MCP服务器
	go func() {
		if err := setupMCPServers(state, info, httpServer); err != nil {
			log.Fatalf("Failed to set up MCP servers: %v", err)
		}
		log.Printf("All clients initialized")
	}()

	// 启动HTTP服务器
	go func() {
		log.Printf("Starting Gin server on %s", config.McpProxy.Addr)
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("Failed to start server: %v", err)
		}
	}()

	// 等待终止信号
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan
	log.Println("Shutdown signal received")

	// 优雅关闭服务器
	shutdownCtx, shutdownCancel := context.WithTimeout(ctx, 5*time.Second)
	defer shutdownCancel()

	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		log.Printf("Server shutdown error: %v", err)
	}
}

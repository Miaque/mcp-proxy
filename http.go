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
	"github.com/google/uuid"
	"github.com/mark3labs/mcp-go/mcp"
	"golang.org/x/sync/errgroup"
)

// 常量定义
const (
	// 服务器关闭超时时间
	shutdownTimeout = 15 * time.Second

	// 认证头前缀
	bearerPrefix = "Bearer "

	// 临时服务器名称前缀
	tempServerPrefix = "temp-"

	// 默认路径前缀模板
	pathPrefixTemplate = "/%s/"

	// 错误消息常量
	errMissingTransportType = "缺少必需的 transportType 参数"
	errMissingCommand       = "stdio 类型必须提供 command 参数"
	errMissingURL           = "%s 类型必须提供 url 参数"
	errUnsupportedType      = "不支持的传输类型"
)

// 错误定义
var (
	ErrServerNotFound   = errors.New("服务器不存在")
	ErrEmptyServerName  = errors.New("服务器名称为空")
	ErrServerExists     = errors.New("服务器名称已存在")
	ErrInvalidTransport = errors.New("不支持的传输类型")
	ErrMissingURL       = errors.New("缺少必要参数：url")
	ErrMissingCommand   = errors.New("stdio类型必须提供command参数")
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

// APIHandlers API处理函数结构体
type APIHandlers struct {
	state *ServerState
	info  mcp.Implementation
}

// NewAPIHandlers 创建新的API处理函数
func NewAPIHandlers(state *ServerState, info mcp.Implementation) *APIHandlers {
	return &APIHandlers{
		state: state,
		info:  info,
	}
}

// ServerAddRequest 添加服务器的请求结构体
type ServerAddRequest struct {
	Name   string           `json:"name" binding:"required"`
	Config *MCPClientConfig `json:"config" binding:"required"`
}

// AddServer 添加新服务器
func (h *APIHandlers) AddServer(c *gin.Context) {
	var newServer ServerAddRequest

	if err := c.ShouldBindJSON(&newServer); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的请求数据", "details": err.Error()})
		return
	}

	// 检查服务器名称是否已存在
	if h.serverExists(newServer.Name) {
		c.JSON(http.StatusConflict, gin.H{"error": ErrServerExists.Error()})
		return
	}

	// 创建服务器
	server, err := h.createAndInitServer(newServer.Name, newServer.Config)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "服务器创建失败", "details": err.Error()})
		return
	}

	// 添加路由
	routePath := h.addServerRoutes(newServer.Name, server)

	log.Printf("<%s> 服务器添加成功", newServer.Name)
	c.JSON(http.StatusOK, gin.H{
		"message": fmt.Sprintf("服务器 %s 添加成功", newServer.Name),
		"path":    routePath,
	})
}

// serverExists 检查服务器是否已存在
func (h *APIHandlers) serverExists(name string) bool {
	h.state.mu.RLock()
	defer h.state.mu.RUnlock()
	_, exists := h.state.config.McpServers[name]
	return exists
}

// createAndInitServer 创建并初始化服务器
func (h *APIHandlers) createAndInitServer(name string, config *MCPClientConfig) (*Server, error) {
	// 创建MCP客户端
	mcpClient, err := newMCPClient(name, config)
	if err != nil {
		return nil, fmt.Errorf("创建MCP客户端失败: %w", err)
	}

	// 创建MCP服务器
	server := newMCPServer(name, h.state.config.McpProxy.Version, h.state.config.McpProxy.BaseURL, config)

	// 将客户端添加到服务器
	err = mcpClient.addToMCPServer(h.state.ctx, h.info, server.mcpServer)
	if err != nil {
		_ = mcpClient.Close()
		return nil, fmt.Errorf("无法添加客户端到服务器: %w", err)
	}

	return server, nil
}

// addServerRoutes 添加服务器路由并保存配置
func (h *APIHandlers) addServerRoutes(name string, server *Server) string {
	routePath := fmt.Sprintf(pathPrefixTemplate, name)

	h.state.mu.Lock()
	defer h.state.mu.Unlock()

	// 仅保存到服务器表，配置在添加服务器时已经保存
	h.state.mcpServers[name] = server

	// 注册路由处理
	h.registerServerRoutes(routePath, server)

	return routePath
}

// registerServerRoutes 注册服务器路由
func (h *APIHandlers) registerServerRoutes(routePath string, server *Server) {
	if len(server.tokens) > 0 {
		h.state.ginEngine.Group(routePath).
			Use(newAuthMiddleware(server.tokens)).
			Any("*path", SSEHandlerAdapter(server.sseServer))
	} else {
		h.state.ginEngine.Any(routePath+"*path", SSEHandlerAdapter(server.sseServer))
	}
}

// parseKeyValuePairs 解析键值对字符串为 map
func parseKeyValuePairs(pairs string) map[string]string {
	if pairs == "" {
		return nil
	}

	result := make(map[string]string)
	for _, pair := range strings.Split(pairs, ",") {
		parts := strings.SplitN(pair, ":", 2)
		if len(parts) == 2 {
			result[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	return result
}

// parseOptions 解析通用选项
func parseOptions(c *gin.Context, config *MCPClientConfig) {
	// 解析认证令牌
	if authTokens := c.Query("authTokens"); authTokens != "" {
		if config.Options == nil {
			config.Options = &Options{}
		}
		config.Options.AuthTokens = strings.Split(authTokens, ",")
	}

	// 解析布尔选项
	if logEnabled := c.Query("logEnabled"); logEnabled != "" {
		if config.Options == nil {
			config.Options = &Options{}
		}
		enabled := logEnabled == "true"
		config.Options.LogEnabled = &enabled
	}

	if panicIfInvalid := c.Query("panicIfInvalid"); panicIfInvalid != "" {
		if config.Options == nil {
			config.Options = &Options{}
		}
		panic := panicIfInvalid == "true"
		config.Options.PanicIfInvalid = &panic
	}
}

// parseStdioConfig 解析 stdio 类型的配置
func parseStdioConfig(c *gin.Context, config *MCPClientConfig) error {
	command := c.Query("command")
	if command == "" {
		return errors.New(errMissingCommand)
	}

	config.Command = command
	if args := c.Query("args"); args != "" {
		config.Args = strings.Fields(args)
	}

	if env := c.Query("env"); env != "" {
		if envMap := parseKeyValuePairs(env); len(envMap) > 0 {
			config.Env = envMap
		}
	}

	return nil
}

// parseHTTPBasedConfig 解析基于 HTTP 的配置（SSE 和 Streamable）
func parseHTTPBasedConfig(c *gin.Context, config *MCPClientConfig) error {
	url := c.Query("url")
	if url == "" {
		return fmt.Errorf(errMissingURL, config.TransportType)
	}

	config.URL = url
	if headers := c.Query("headers"); headers != "" {
		if headerMap := parseKeyValuePairs(headers); len(headerMap) > 0 {
			config.Headers = headerMap
		}
	}

	// 仅为 streamable-http 类型处理超时设置
	if config.TransportType == MCPClientTypeStreamable {
		if timeout := c.Query("timeout"); timeout != "" {
			if duration, err := time.ParseDuration(timeout); err == nil {
				config.Timeout = duration
			} else {
				log.Printf("解析超时参数失败: %v", err)
			}
		}
	}

	return nil
}

// HandleSSE 处理直接的SSE连接请求
func (h *APIHandlers) HandleSSE(c *gin.Context) {
	var clientConfig MCPClientConfig

	// 解析并验证传输类型
	transportType := c.Query("transportType")
	if transportType == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": errMissingTransportType})
		return
	}
	clientConfig.TransportType = MCPClientType(transportType)

	// 根据传输类型解析特定配置
	var err error
	switch clientConfig.TransportType {
	case MCPClientTypeStdio:
		err = parseStdioConfig(c, &clientConfig)
	case MCPClientTypeSSE, MCPClientTypeStreamable:
		err = parseHTTPBasedConfig(c, &clientConfig)
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": errUnsupportedType})
		return
	}

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 解析通用选项
	parseOptions(c, &clientConfig)

	// 验证和设置默认值
	if err := h.validateAndSetDefaults(&clientConfig); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 生成唯一的临时服务器名称
	serverName := fmt.Sprintf("%s%s", tempServerPrefix, uuid.New().String())

	// 创建服务器
	server, err := h.createAndInitServer(serverName, &clientConfig)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "服务器创建失败", "details": err.Error()})
		return
	}

	// 注册路由
	routePath := h.addServerRoutes(serverName, server)

	// 设置连接关闭检测
	go func() {
		// 使用请求的上下文来检测连接关闭
		<-c.Request.Context().Done()
		log.Printf("<%s> SSE连接断开，计划清理资源", serverName)
		// 延迟一段时间后清理，以防止连接断开后立即重连
		time.Sleep(30 * time.Second)

		h.state.mu.Lock()
		defer h.state.mu.Unlock()
		if _, exists := h.state.mcpServers[serverName]; exists {
			// 关闭MCP客户端连接
			delete(h.state.mcpServers, serverName)
			log.Printf("<%s> 临时服务器资源已清理", serverName)
		}
	}()

	// 修改请求路径，并将请求转发
	h.forwardToSSEServer(c, routePath)
}

// validateAndSetDefaults 验证并设置默认值
func (h *APIHandlers) validateAndSetDefaults(config *MCPClientConfig) error {
	// 设置默认传输类型
	if config.TransportType == "" {
		config.TransportType = MCPClientTypeStdio
	}

	// 根据不同类型验证参数
	switch config.TransportType {
	case MCPClientTypeSSE, MCPClientTypeStreamable:
		if config.URL == "" {
			return ErrMissingURL
		}
	case MCPClientTypeStdio:
		if config.Command == "" {
			return ErrMissingCommand
		}
	default:
		return ErrInvalidTransport
	}

	// 初始化Options
	h.initializeClientOptions(config)

	return nil
}

// initializeClientOptions 初始化客户端选项
func (h *APIHandlers) initializeClientOptions(config *MCPClientConfig) {
	if config.Options == nil {
		config.Options = &Options{}
	}

	// 设置默认值
	if config.Options.LogEnabled == nil {
		logEnabled := false
		config.Options.LogEnabled = &logEnabled
	}
	if config.Options.PanicIfInvalid == nil {
		panicIfInvalid := false
		config.Options.PanicIfInvalid = &panicIfInvalid
	}
}

// forwardToSSEServer 将请求转发到SSE服务器
func (h *APIHandlers) forwardToSSEServer(c *gin.Context, routePath string) {
	// 修改请求路径
	c.Request.URL.Path = fmt.Sprintf("%ssse", routePath)

	// 设置会话ID
	h.ensureSessionID(c)

	// 使用SSE处理器处理请求
	server := h.state.mcpServers[strings.Trim(routePath, "/")]
	SSEHandlerAdapter(server.sseServer)(c)
}

// ensureSessionID 确保请求中有会话ID
func (h *APIHandlers) ensureSessionID(c *gin.Context) {
	q := c.Request.URL.Query()
	if q.Get("sessionId") == "" {
		sessionID := uuid.New().String()
		q.Set("sessionId", sessionID)
		c.Request.URL.RawQuery = q.Encode()
	}
}

// RemoveServer 移除服务器
func (h *APIHandlers) RemoveServer(c *gin.Context) {
	serverName := c.Param("name")
	if serverName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": ErrEmptyServerName.Error()})
		return
	}

	h.state.mu.Lock()
	defer h.state.mu.Unlock()

	_, exists := h.state.mcpServers[serverName]
	if !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": ErrServerNotFound.Error()})
		return
	}

	// 清理资源并移除
	delete(h.state.mcpServers, serverName)
	if h.state.config.McpServers != nil {
		delete(h.state.config.McpServers, serverName)
	}

	// 注意：Gin不支持动态移除路由，因此我们只能移除服务器配置
	// 在下一次请求中，路由处理程序会检查服务器是否存在

	c.JSON(http.StatusOK, gin.H{
		"message": fmt.Sprintf("服务器 %s 移除成功", serverName),
	})
}

// ListServers 列出所有服务器
func (h *APIHandlers) ListServers(c *gin.Context) {
	h.state.mu.RLock()
	defer h.state.mu.RUnlock()

	servers := make(map[string]interface{})
	for name := range h.state.mcpServers {
		servers[name] = struct {
			Path string `json:"path"`
		}{
			Path: fmt.Sprintf(pathPrefixTemplate, name),
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"servers": servers,
	})
}

// GinMiddleware 定义Gin中间件函数类型
type GinMiddleware = gin.HandlerFunc

// newAuthMiddleware 创建认证中间件，验证请求中的token
func newAuthMiddleware(tokens []string) GinMiddleware {
	if len(tokens) == 0 {
		return func(c *gin.Context) {
			c.Next()
		}
	}

	tokenSet := make(map[string]struct{}, len(tokens))
	for _, token := range tokens {
		tokenSet[token] = struct{}{}
	}

	return func(c *gin.Context) {
		token := extractToken(c)
		if token == "" || !isValidToken(token, tokenSet) {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			return
		}

		c.Next()
	}
}

// extractToken 从请求中提取token
func extractToken(c *gin.Context) string {
	token := c.GetHeader("Authorization")
	if strings.HasPrefix(token, bearerPrefix) {
		return strings.TrimPrefix(token, bearerPrefix)
	}
	return token
}

// isValidToken 检查token是否有效
func isValidToken(token string, validTokens map[string]struct{}) bool {
	if token == "" {
		return false
	}
	_, valid := validTokens[token]
	return valid
}

// SSEHandlerAdapter 将SSE处理函数适配为Gin处理函数
func SSEHandlerAdapter(handler http.Handler) gin.HandlerFunc {
	return func(c *gin.Context) {
		handler.ServeHTTP(c.Writer, c.Request)
	}
}

// corsMiddleware 创建一个 CORS 中间件
func corsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
		c.Writer.Header().Set("Access-Control-Max-Age", "86400")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	}
}

// setupAPIRoutes 配置API路由
func setupAPIRoutes(router *gin.Engine, handlers *APIHandlers, config *Config) {
	// 应用 CORS 中间件
	router.Use(corsMiddleware())

	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})
	router.GET("/config", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"defaultEnvironment": make(map[string]string),
			"defaultCommand":     "",
			"defaultArgs":        "",
		})
	})
	apiGroup := router.Group("/api")

	// 如果需要认证，添加认证中间件
	if config.McpProxy != nil && config.McpProxy.Options != nil && len(config.McpProxy.Options.AuthTokens) > 0 {
		apiGroup.Use(newAuthMiddleware(config.McpProxy.Options.AuthTokens))
	}

	// 添加API端点
	apiGroup.POST("/servers", handlers.AddServer)
	apiGroup.DELETE("/servers/:name", handlers.RemoveServer)
	apiGroup.GET("/servers", handlers.ListServers)

	// 添加直接SSE处理路由
	router.GET("/sse", handlers.HandleSSE)
	router.GET("/stdio", handlers.HandleSSE)
}

// setupMCPServers 初始化和配置MCP服务器
func setupMCPServers(state *ServerState, info mcp.Implementation, httpServer *http.Server) error {
	var eg errgroup.Group

	for name, clientConfig := range state.config.McpServers {
		name := name // 确保闭包中的变量不会被后续循环修改
		clientConfig := clientConfig

		eg.Go(func() error {
			return initializeSingleServer(state, name, clientConfig, info, httpServer)
		})
	}

	return eg.Wait()
}

// initializeSingleServer 初始化单个MCP服务器
func initializeSingleServer(state *ServerState, name string, clientConfig *MCPClientConfig, info mcp.Implementation, httpServer *http.Server) error {
	log.Printf("<%s> 连接中", name)

	mcpClient, err := newMCPClient(name, clientConfig)
	if err != nil {
		return fmt.Errorf("<%s> 创建客户端失败: %w", name, err)
	}

	server := newMCPServer(name, state.config.McpProxy.Version, state.config.McpProxy.BaseURL, clientConfig)

	// 保存服务器实例
	state.mu.Lock()
	state.mcpServers[name] = server
	state.mu.Unlock()

	// 连接服务器
	addErr := mcpClient.addToMCPServer(state.ctx, info, server.mcpServer)
	if addErr != nil {
		log.Printf("<%s> 添加客户端到服务器失败: %v", name, addErr)
		if clientConfig.Options != nil && clientConfig.Options.PanicIfInvalid != nil && *clientConfig.Options.PanicIfInvalid {
			return addErr
		}
		return nil
	}

	log.Printf("<%s> 连接成功", name)

	// 注册路由
	registerServerRoutes(state, name, server)

	// 注册关闭回调
	httpServer.RegisterOnShutdown(func() {
		log.Printf("<%s> 正在关闭", name)
		_ = mcpClient.Close()
	})

	return nil
}

// registerServerRoutes 注册服务器路由
func registerServerRoutes(state *ServerState, name string, server *Server) {
	state.mu.Lock()
	defer state.mu.Unlock()

	routePath := fmt.Sprintf(pathPrefixTemplate, name)

	// 注册路由处理
	if len(server.tokens) > 0 {
		state.ginEngine.Group(routePath).
			Use(newAuthMiddleware(server.tokens)).
			Any("*path", SSEHandlerAdapter(server.sseServer))
	} else {
		state.ginEngine.Any(routePath+"*path", SSEHandlerAdapter(server.sseServer))
	}
}

// startHTTPServer 初始化并启动HTTP服务器
func startHTTPServer(config *Config) {
	// 配置Gin模式
	gin.SetMode(gin.ReleaseMode)

	// 创建上下文
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 创建Gin引擎
	ginEngine := gin.New()
	ginEngine.Use(gin.Logger())
	ginEngine.Use(gin.Recovery())

	// 创建HTTP服务器
	httpServer := &http.Server{
		Addr:    config.McpProxy.Addr,
		Handler: ginEngine,
	}

	// 设置服务器信息
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
	go initializeAllServers(state, info, httpServer)

	// 启动HTTP服务器
	go startServerWithGracefulShutdown(httpServer)

	// 等待终止信号
	waitForShutdownSignal(ctx, httpServer)
}

// initializeAllServers 初始化所有MCP服务器
func initializeAllServers(state *ServerState, info mcp.Implementation, httpServer *http.Server) {
	if err := setupMCPServers(state, info, httpServer); err != nil {
		log.Fatalf("设置MCP服务器失败: %v", err)
	}
	log.Printf("所有客户端初始化完成")
}

// startServerWithGracefulShutdown 启动HTTP服务器
func startServerWithGracefulShutdown(httpServer *http.Server) {
	log.Printf("正在启动Gin服务器，监听地址 %s", httpServer.Addr)
	if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("启动服务器失败: %v", err)
	}
}

// waitForShutdownSignal 等待关闭信号
func waitForShutdownSignal(ctx context.Context, httpServer *http.Server) {
	// 等待终止信号
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan
	log.Println("收到关闭信号")

	// 优雅关闭服务器
	shutdownCtx, shutdownCancel := context.WithTimeout(ctx, shutdownTimeout)
	defer shutdownCancel()

	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		log.Printf("服务器关闭错误: %v", err)
	}
}

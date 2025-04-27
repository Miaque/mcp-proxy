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
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/mark3labs/mcp-go/mcp"
	"golang.org/x/sync/errgroup"
)

// GinMiddleware 定义Gin中间件函数类型
type GinMiddleware = gin.HandlerFunc

// 认证中间件，验证请求中的token
func newAuthMiddleware(tokens []string) GinMiddleware {
	tokenSet := make(map[string]struct{}, len(tokens))
	for _, token := range tokens {
		tokenSet[token] = struct{}{}
	}
	return func(c *gin.Context) {
		if len(tokens) != 0 {
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

func startHTTPServer(config *Config) {
	// 根据环境配置Gin模式
	gin.SetMode(gin.ReleaseMode)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var errorGroup errgroup.Group

	// 创建Gin引擎替代http.ServeMux
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

	for name, clientConfig := range config.McpServers {
		mcpClient, err := newMCPClient(name, clientConfig)
		if err != nil {
			log.Fatalf("<%s> Failed to create client: %v", name, err)
		}
		server := newMCPServer(name, config.McpProxy.Version, config.McpProxy.BaseURL, clientConfig)
		errorGroup.Go(func() error {
			log.Printf("<%s> Connecting", name)
			addErr := mcpClient.addToMCPServer(ctx, info, server.mcpServer)
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
				ginEngine.Group(routePath).Use(newAuthMiddleware(server.tokens)).Any("*path", SSEHandlerAdapter(server.sseServer))
			} else {
				ginEngine.Any(routePath+"*path", SSEHandlerAdapter(server.sseServer))
			}

			httpServer.RegisterOnShutdown(func() {
				log.Printf("<%s> Shutting down", name)
				_ = mcpClient.Close()
			})
			return nil
		})
	}

	go func() {
		err := errorGroup.Wait()
		if err != nil {
			log.Fatalf("Failed to add clients: %v", err)
		}
		log.Printf("All clients initialized")
	}()

	go func() {
		log.Printf("Starting Gin server")
		log.Printf("Gin server listening on %s", config.McpProxy.Addr)
		hErr := httpServer.ListenAndServe()
		if hErr != nil && !errors.Is(hErr, http.ErrServerClosed) {
			log.Fatalf("Failed to start server: %v", hErr)
		}
	}()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	<-sigChan
	log.Println("Shutdown signal received")

	shutdownCtx, shutdownCancel := context.WithTimeout(ctx, 5*time.Second)
	defer shutdownCancel()

	err := httpServer.Shutdown(shutdownCtx)
	if err != nil {
		log.Printf("Server shutdown error: %v", err)
	}
}

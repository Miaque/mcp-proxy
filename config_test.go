package main

import (
	"fmt"
	"testing"
)

func TestConfig(t *testing.T) {
	config, err := load("config.json")
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	fmt.Println("🚀 ~ funcTestConfig ~ config:", config)

	if len(config.McpServers) != 3 {
		t.Fatalf("Expected 3 MCP servers, got %d", len(config.McpServers))
	}
}

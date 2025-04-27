package main

import (
	"flag"
	"fmt"
	"log"
)

// BuildVersion 构建版本号，通过编译时注入
var BuildVersion = "dev"

func main() {
	// 解析命令行参数
	configPath := flag.String("config", "config.json", "配置文件路径或HTTP(S)链接")
	showVersion := flag.Bool("version", false, "显示版本信息并退出")
	showHelp := flag.Bool("help", false, "显示帮助信息并退出")
	flag.Parse()

	// 处理帮助和版本信息
	if *showHelp {
		flag.Usage()
		return
	}

	if *showVersion {
		fmt.Println(BuildVersion)
		return
	}

	// 加载配置文件
	config, err := load(*configPath)
	if err != nil {
		log.Fatalf("加载配置文件失败: %v", err)
	}

	// 启动HTTP服务器
	startHTTPServer(config)
}

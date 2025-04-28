# MCP Proxy Server

An MCP proxy server that aggregates and serves multiple MCP resource servers through a single HTTP server.

## Features

- **Proxy Multiple MCP Clients**: Connects to multiple MCP resource servers and aggregates their tools and capabilities.
- **SSE Support**: Provides an SSE (Server-Sent Events) server for real-time updates.
- **Flexible Configuration**: Supports multiple client types (`stdio`, `sse` or `streamable-http`) with customizable settings.

## Installation

### Build from Source

 ```bash
git clone https://github.com/TBXark/mcp-proxy.git
cd mcp-proxy
make build
./build/mcp-proxy --config path/to/config.json
```

### Install by go

```bash
go install github.com/TBXark/mcp-proxy@latest
````

### Docker

> The Docker image supports two MCP calling methods by default: `npx` and `uvx`.
```bash
docker run -d -p 9090:9090 -v /path/to/config.json:/config/config.json ghcr.io/tbxark/mcp-proxy:latest
# or 
docker run -d -p 9090:9090 ghcr.io/tbxark/mcp-proxy:latest --config https://example.com/path/to/config.json
```

## Configuration

The server is configured using a JSON file. Below is an example configuration:
> This is the format for the new version's configuration. The old version's configuration will be automatically converted to the new format's configuration when it is loaded.

```jsonc
{
  "mcpProxy": {
    "baseURL": "https://mcp.example.com",
    "addr": ":9090",
    "name": "MCP Proxy",
    "version": "1.0.0",
    "options": {
      "panicIfInvalid": false,
      "logEnabled": true,
      "authTokens": [
        "DefaultTokens"
      ]
    }
  },
  "mcpServers": {
    "github": {
      "command": "npx",
      "args": [
        "-y",
        "@modelcontextprotocol/server-github"
      ],
      "env": {
        "GITHUB_PERSONAL_ACCESS_TOKEN": "<YOUR_TOKEN>"
      }
    },
    "fetch": {
      "command": "uvx",
      "args": [
        "mcp-server-fetch"
      ],
      "options": {
        "panicIfInvalid": true,
        "logEnabled": false,
        "authTokens": [
          "SpecificTokens"
        ]
      }
    },
    "amap": {
      "url": "https://mcp.amap.com/sse?key=<YOUR_TOKEN>"
    }
  }
}
```

### **`options`**
Common options for `mcpProxy` and `mcpServers`.

- `panicIfInvalid`: If true, the server will panic if the client is invalid.
- `logEnabled`: If true, the server will log the client's requests.
- `authTokens`: A list of authentication tokens for the client. The `Authorization` header will be checked against this list. 

> In the new configuration, the `authTokens` of `mcpProxy` is not a global authentication token, but rather the default authentication token for `mcpProxy`. When `authTokens` is set in `mcpServers`, the value of `authTokens` in `mcpServers` will be used instead of the value in `mcpProxy`. In other words, the `authTokens` of `mcpProxy` serves as a default value and is only applied when `authTokens` is not set in `mcpServers`.
> Other fields are the same.

### **`mcpProxy`**
Proxy HTTP server configuration
- `baseURL`: The public accessible URL of the server. This is used to generate the URLs for the clients.
- `addr`: The address the server listens on.
- `name`: The name of the server.
- `version`: The version of the server.
- `options`: Default options for the `mcpServers`.

### **`mcpServers`**
MCP server configuration, Adopt the same configuration format as other MCP Clients.
- `transportType`: The transport type of the MCP client. Except for `streamable-http`, which requires manual configuration, the rest will be automatically configured according to the content of the configuration file.
  - `stdio`: The MCP client is a command line tool that is run in a subprocess.
  - `sse`: The MCP client is a server that supports SSE (Server-Sent Events).
  - `streamable-http`: The MCP client is a server that supports HTTP streaming.

For stdio mcp servers, the `command` field is required.
- `command`: The command to run the MCP client.
- `args`: The arguments to pass to the command.
- `env`: The environment variables to set for the command.
- `options`: Options specific to the client.

For sse mcp servers, the `url` field is required. When the current `url` exists, `sse` will be automatically configured.
- `url`: The URL of the MCP client.
- `headers`: The headers to send with the request to the MCP client.

For http streaming mcp servers, the `url` field is required. and `transportType` need to manually set to `streamable-http`.
- `url`: The URL of the MCP client.
- `headers`: The headers to send with the request to the MCP client.
- `timeout`: The timeout for the request to the MCP client. 


## Usage

```
Usage of mcp-proxy:
  -config string
        path to config file or a http(s) url (default "config.json")
  -help
        print help and exit
  -version
        print version and exit
```
1. The server will start and aggregate the tools and capabilities of the configured MCP clients.
2. You can access the server at `http(s)://{baseURL}/{clientName}/sse`. (e.g., `https://mcp.example.com/fetch/sse`, based on the example configuration)
3. If your MCP client does not support custom request headers., you can change the key in `clients` such as `fetch` to `fetch/{authToken}`, and then access it via `fetch/{authToken}`.

## Thanks

- This project was inspired by the [adamwattis/mcp-proxy-server](https://github.com/adamwattis/mcp-proxy-server) project
- If you have any questions about deployment, you can refer to  [《在 Docker 沙箱中运行 MCP Server》](https://miantiao.me/posts/guide-to-running-mcp-server-in-a-sandbox/)([@ccbikai](https://github.com/ccbikai))

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## 动态管理MCP服务器

除了通过配置文件静态配置MCP服务器外，mcp-proxy还支持通过HTTP API动态添加、删除和查询MCP服务器。

### API端点

#### 列出所有服务器

```
GET /api/servers
```

**响应示例:**

```json
{
  "servers": {
    "fetch": {
      "path": "/fetch/"
    },
    "tavily-mcp-sse": {
      "path": "/tavily-mcp-sse/"
    }
  }
}
```

#### 添加新服务器

```
POST /api/servers
```

**请求体:**

```json
{
  "name": "new-server-name",
  "config": {
    "url": "https://example.com/mcp-endpoint",
    "headers": {
      "Authorization": "Bearer your-token"
    },
    "options": {
      "logEnabled": true,
      "authTokens": ["token1", "token2"]
    }
  }
}
```

也可以添加stdio类型的服务器:

```json
{
  "name": "stdio-server",
  "config": {
    "transportType": "stdio",
    "command": "npx",
    "args": ["-y", "@modelcontextprotocol/server-everything"],
    "env": {},
    "options": {
      "logEnabled": true
    }
  }
}
```

或者添加streamable-http类型的服务器:

```json
{
  "name": "streamable-server",
  "config": {
    "transportType": "streamable-http",
    "url": "https://router.mcp.so/mcp/example",
    "options": {
      "logEnabled": true
    }
  }
}
```

**响应示例:**

```json
{
  "message": "服务器 new-server-name 添加成功",
  "path": "/new-server-name/"
}
```

#### 删除服务器

```
DELETE /api/servers/:name
```

**响应示例:**

```json
{
  "message": "服务器 new-server-name 移除成功"
}
```

### 认证

如果在配置文件中设置了`mcpProxy.options.authTokens`，则需要在请求API端点时提供认证令牌。将令牌放在`Authorization`头中：

```
Authorization: Bearer your-token
```

使用动态添加的服务器时，如果该服务器配置了`authTokens`，同样需要提供认证令牌。

## 直接访问MCP服务器

除了通过配置文件和API管理MCP服务器外，mcp-proxy还支持直接通过请求访问MCP服务器，无需预先注册。

### 通过/sse端点访问

您可以直接通过POST请求到`/sse`端点，在请求体中提供MCP服务器配置，即可访问该服务器：

```
POST /sse
```

**请求体:**

```json
{
  "config": {
    "url": "https://example.com/mcp-endpoint",
    "headers": {
      "Authorization": "Bearer your-token"
    },
    "options": {
      "logEnabled": true
    }
  }
}
```

**工作原理:**
1. 系统会为每个请求自动创建一个唯一ID的服务器
2. 所有服务器(包括配置文件中的、通过API添加的和通过/sse访问的)统一管理
3. 当请求结束后，系统会自动清理这些资源
4. 所有服务器都可以通过列表API查看

**使用场景:**
- 前端应用需要直接访问MCP服务器，无需预先配置
- 临时测试MCP服务器配置
- 快速集成第三方MCP服务

### 认证

如果在配置文件中设置了`mcpProxy.options.authTokens`，则需要在请求API端点时提供认证令牌。将令牌放在`Authorization`头中：

```
Authorization: Bearer your-token
```
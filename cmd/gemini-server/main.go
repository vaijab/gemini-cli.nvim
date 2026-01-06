package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"reflect"
	"time"
	"unsafe"

	"github.com/google/uuid"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/neovim/go-client/nvim"
)

var (
	nvimClient *nvim.Nvim
	mcpServer  *mcp.Server
	logFile    = flag.String("log-file", "", "path to log file")
	portFlag   = flag.Int("port", 0, "port to listen on (0 for random)")
	tokenFlag  = flag.String("auth-token", "", "auth token to use (empty for random)")
)

func main() {
	flag.Parse()

	if *logFile != "" {
		f, err := os.OpenFile(*logFile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0o666)
		if err == nil {
			log.SetOutput(f)
			defer func() {
				if err := f.Close(); err != nil {
					fmt.Fprintf(os.Stderr, "Error closing log file: %v\n", err)
				}
			}()
		}
	} else {
		log.SetOutput(os.Stderr)
	}

	if flag.Arg(0) == "client" {
		runClient(flag.Arg(1))
		return
	}

	log.Println("Gemini Server Starting (Stdio)...")

	var err error
	nvimClient, err = nvim.New(os.Stdin, os.Stdout, os.Stdout, log.Printf)
	if err != nil {
		log.Fatalf("Failed to start nvim client: %v", err)
	}

	mcpServer = mcp.NewServer(&mcp.Implementation{
		Name:    "gemini-cli-nvim",
		Version: "0.1.0",
	}, &mcp.ServerOptions{
		Capabilities: &mcp.ServerCapabilities{
			Tools: &mcp.ToolCapabilities{ListChanged: true},
		},
	})

	registerTools(mcpServer)

	if err := nvimClient.RegisterHandler("context_update", func(args ...any) {
		if len(args) > 0 {
			if payload, ok := args[0].(map[string]any); ok {
				for session := range mcpServer.Sessions() {
					sendNotification(session, "ide/contextUpdate", payload)
				}
			}
		}
	}); err != nil {
		log.Fatalf("Failed to register context_update handler: %v", err)
	}

	if err := nvimClient.RegisterHandler("diff_accepted", func(args ...any) {
		if len(args) > 0 {
			if payload, ok := args[0].(map[string]any); ok {
				for session := range mcpServer.Sessions() {
					sendNotification(session, "ide/diffAccepted", payload)
				}
			}
		}
	}); err != nil {
		log.Fatalf("Failed to register diff_accepted handler: %v", err)
	}

	if err := nvimClient.RegisterHandler("diff_rejected", func(args ...any) {
		if len(args) > 0 {
			if payload, ok := args[0].(map[string]any); ok {
				for session := range mcpServer.Sessions() {
					sendNotification(session, "ide/diffRejected", payload)
				}
			}
		}
	}); err != nil {
		log.Fatalf("Failed to register diff_rejected handler: %v", err)
	}

	if err := nvimClient.RegisterHandler("initialize", func() {
		go runInitialization()
	}); err != nil {
		log.Fatalf("Failed to register initialize handler: %v", err)
	}

	log.Println("Serving RPC...")

	// Keep-alive loop for MCP sessions
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			for session := range mcpServer.Sessions() {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				if err := session.Ping(ctx, &mcp.PingParams{}); err != nil {
					log.Printf("Ping failed for session %s: %v", session.ID(), err)
				}
				cancel()
			}
		}
	}()

	if err := nvimClient.Serve(); err != nil {
		log.Printf("Nvim RPC closed: %v", err)
	}
}

func runClient(targetURL string) {
	if targetURL == "" {
		log.Fatal("Client: target URL is required")
	}

	ctx := context.Background()

	clientTransport := &mcp.StreamableClientTransport{
		Endpoint: targetURL,
	}
	clientConn, err := clientTransport.Connect(ctx)
	if err != nil {
		log.Fatalf("Client: Failed to connect to server at %s: %v", targetURL, err)
	}
	defer func() {
		if err := clientConn.Close(); err != nil {
			log.Printf("Client: Error closing connection: %v", err)
		}
	}()

	stdioTransport := &mcp.StdioTransport{}
	stdioConn, err := stdioTransport.Connect(ctx)
	if err != nil {
		log.Fatalf("Client: Failed to connect to Stdio: %v", err)
	}
	defer func() {
		if err := stdioConn.Close(); err != nil {
			log.Printf("Client: Error closing stdio connection: %v", err)
		}
	}()

	errChan := make(chan error, 2)
	go func() {
		for {
			msg, err := clientConn.Read(ctx)
			if err != nil {
				errChan <- fmt.Errorf("read from server: %w", err)
				return
			}
			if err := stdioConn.Write(ctx, msg); err != nil {
				errChan <- fmt.Errorf("write to stdio: %w", err)
				return
			}
		}
	}()
	go func() {
		for {
			msg, err := stdioConn.Read(ctx)
			if err != nil {
				errChan <- fmt.Errorf("read from stdio: %w", err)
				return
			}
			if err := clientConn.Write(ctx, msg); err != nil {
				errChan <- fmt.Errorf("write to server: %w", err)
				return
			}
		}
	}()

	log.Printf("Client running (Target: %s)", targetURL)
	select {
	case err := <-errChan:
		log.Printf("Client error: %v", err)
	case <-ctx.Done():
		log.Println("Client shutting down")
	}
}

func sendNotification(s *mcp.ServerSession, method string, params any) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("Panic sending notification: %v", r)
		}
	}()

	// This is a hack until go mcp sdk provides a way to send notifications.
	// See https://github.com/modelcontextprotocol/go-sdk/issues/745
	rv := reflect.ValueOf(s).Elem()
	rf := rv.FieldByName("conn")
	rf = reflect.NewAt(rf.Type(), unsafe.Pointer(rf.UnsafeAddr())).Elem()

	ctx := context.Background()
	results := rf.MethodByName("Notify").Call([]reflect.Value{
		reflect.ValueOf(ctx),
		reflect.ValueOf(method),
		reflect.ValueOf(params),
	})

	if len(results) > 0 && !results[0].IsNil() {
		log.Printf("Failed to send notification %s: %v", method, results[0].Interface())
	}
}

func runInitialization() {
	log.Println("Initializing MCP Server...")
	addr := fmt.Sprintf("127.0.0.1:%d", *portFlag)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("Failed to listen on %s: %v", addr, err)
	}
	port := listener.Addr().(*net.TCPAddr).Port

	authToken := *tokenFlag
	if authToken == "" {
		authToken = uuid.New().String()
	}

	mcpHandler := mcp.NewStreamableHTTPHandler(func(r *http.Request) *mcp.Server {
		auth := r.Header.Get("Authorization")
		if auth == "Bearer "+authToken {
			return mcpServer
		}
		if r.URL.Query().Get("token") == authToken {
			return mcpServer
		}
		return nil
	}, nil)

	log.Printf("MCP Server listening at http://127.0.0.1:%d", port)
	if err := http.Serve(listener, mcpHandler); err != nil {
		log.Printf("HTTP Server error: %v", err)
	}
}

type OpenDiffArgs struct {
	FilePath   string `json:"filePath"`
	NewContent string `json:"newContent"`
}

type CloseDiffArgs struct {
	FilePath string `json:"filePath"`
}

type GetDiagnosticsArgs struct {
	FilePath string `json:"filePath,omitempty"`
}

type LspArgs struct {
	FilePath  string `json:"filePath"`
	Line      int    `json:"line"`
	Character int    `json:"character"`
}

type GetTreesitterNodeArgs struct {
	FilePath  string `json:"filePath"`
	Line      int    `json:"line"`
	Character int    `json:"character"`
}

type RunTreesitterQueryArgs struct {
	FilePath string `json:"filePath"`
	Query    string `json:"query"`
}

type GetWorkspaceStructureArgs struct {
	RootDir  string `json:"rootDir"`
	MaxDepth int    `json:"maxDepth"`
}

type SearchWorkspaceSymbolArgs struct {
	Query string `json:"query"`
}

type GetFileOutlineArgs struct {
	FilePath string `json:"filePath"`
}

type ReadSymbolArgs struct {
	FilePath   string `json:"filePath"`
	SymbolName string `json:"symbolName"`
}

type ResolveDefinitionArgs struct {
	FilePath  string `json:"filePath"`
	Line      int    `json:"line"`
	Character int    `json:"character"`
}

func registerTools(s *mcp.Server) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "openDiff",
		Description: "Opens a diff view in Neovim to show proposed changes.",
	}, func(ctx context.Context, request *mcp.CallToolRequest, args OpenDiffArgs) (*mcp.CallToolResult, any, error) {
		var errStr string
		err := nvimClient.ExecLua("return require('gemini.tools').open_diff(...)", &errStr, args.FilePath, args.NewContent)
		if err != nil {
			return nil, nil, fmt.Errorf("RPC Error: %w", err)
		}
		if errStr != "" {
			return nil, nil, fmt.Errorf("%s", errStr)
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{
				&mcp.TextContent{
					Text: "Diff view opened in Neovim.",
				},
			},
		}, nil, nil
	})

	mcp.AddTool(s, &mcp.Tool{
		Name:        "closeDiff",
		Description: "Closes the diff view for a specific file.",
	}, func(ctx context.Context, request *mcp.CallToolRequest, args CloseDiffArgs) (*mcp.CallToolResult, any, error) {
		var result struct {
			Content string `json:"content"`
			Error   string `json:"error"`
		}
		err := nvimClient.ExecLua("return require('gemini.tools').close_diff(...)", &result, args.FilePath)
		if err != nil {
			return nil, nil, fmt.Errorf("RPC Error: %w", err)
		}
		if result.Error != "" {
			return nil, nil, fmt.Errorf("%s", result.Error)
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{
				&mcp.TextContent{
					Text: result.Content,
				},
			},
		}, nil, nil
	})

	mcp.AddTool(s, &mcp.Tool{
		Name:        "getDiagnostics",
		Description: "Retrieves diagnostics (errors, warnings) for a file or the entire workspace if no file is specified.",
	}, func(ctx context.Context, request *mcp.CallToolRequest, args GetDiagnosticsArgs) (*mcp.CallToolResult, any, error) {
		var result any
		err := nvimClient.ExecLua("return require('gemini.tools').get_diagnostics(...)", &result, args.FilePath)
		if err != nil {
			return nil, nil, fmt.Errorf("RPC Error: %w", err)
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{
				&mcp.TextContent{
					Text: handleLuaResult(result),
				},
			},
		}, nil, nil
	})

	mcp.AddTool(s, &mcp.Tool{
		Name:        "getDefinition",
		Description: "Go to definition for the symbol at the given position (Line: 1-indexed, Character: 0-indexed).",
	}, func(ctx context.Context, request *mcp.CallToolRequest, args LspArgs) (*mcp.CallToolResult, any, error) {
		var result any
		err := nvimClient.ExecLua("return require('gemini.tools').get_definition(...)", &result, args.FilePath, args.Line, args.Character)
		if err != nil {
			return nil, nil, fmt.Errorf("RPC Error: %w", err)
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{
				&mcp.TextContent{
					Text: handleLuaResult(result),
				},
			},
		}, nil, nil
	})

	mcp.AddTool(s, &mcp.Tool{
		Name:        "getReferences",
		Description: "Finds usages of a symbol (Line: 1-indexed, Character: 0-indexed). IMPORTANT: Returns code snippets (context) for every usage, so you can see HOW it is used without opening the file. This is the 'Semantic Grep' - use it instead of text search.",
	}, func(ctx context.Context, request *mcp.CallToolRequest, args LspArgs) (*mcp.CallToolResult, any, error) {
		var result any
		err := nvimClient.ExecLua("return require('gemini.tools').get_references(...)", &result, args.FilePath, args.Line, args.Character)
		if err != nil {
			return nil, nil, fmt.Errorf("RPC Error: %w", err)
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{
				&mcp.TextContent{
					Text: handleLuaResult(result),
				},
			},
		}, nil, nil
	})

	mcp.AddTool(s, &mcp.Tool{
		Name:        "getHover",
		Description: "Fastest way to get the documentation and type signature of a symbol at a specific position (Line: 1-indexed, Character: 0-indexed). Use this to quickly understand what a function does or what arguments it expects without reading the source file.",
	}, func(ctx context.Context, request *mcp.CallToolRequest, args LspArgs) (*mcp.CallToolResult, any, error) {
		var result any
		err := nvimClient.ExecLua("return require('gemini.tools').get_hover(...)", &result, args.FilePath, args.Line, args.Character)
		if err != nil {
			return nil, nil, fmt.Errorf("RPC Error: %w", err)
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{
				&mcp.TextContent{
					Text: handleLuaResult(result),
				},
			},
		}, nil, nil
	})

	mcp.AddTool(s, &mcp.Tool{
		Name:        "getTreesitterNode",
		Description: "Get details about the Treesitter node at a specific position (Line: 1-indexed, Character: 0-indexed).",
	}, func(ctx context.Context, request *mcp.CallToolRequest, args GetTreesitterNodeArgs) (*mcp.CallToolResult, any, error) {
		var result any
		err := nvimClient.ExecLua("return require('gemini.tools').get_treesitter_node(...)", &result, args.FilePath, args.Line, args.Character)
		if err != nil {
			return nil, nil, fmt.Errorf("RPC Error: %w", err)
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{
				&mcp.TextContent{
					Text: handleLuaResult(result),
				},
			},
		}, nil, nil
	})

	mcp.AddTool(s, &mcp.Tool{
		Name:        "runTreesitterQuery",
		Description: "Run a Treesitter query against a file to extract specific code sections.",
	}, func(ctx context.Context, request *mcp.CallToolRequest, args RunTreesitterQueryArgs) (*mcp.CallToolResult, any, error) {
		var result any
		err := nvimClient.ExecLua("return require('gemini.tools').run_treesitter_query(...)", &result, args.FilePath, args.Query)
		if err != nil {
			return nil, nil, fmt.Errorf("RPC Error: %w", err)
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{
				&mcp.TextContent{
					Text: handleLuaResult(result),
				},
			},
		}, nil, nil
	})

	mcp.AddTool(s, &mcp.Tool{
		Name:        "getWorkspaceStructure",
		Description: "Returns a text-based tree representation of the project's directory structure (respecting .gitignore). Use this tool FIRST to build a mental map of the codebase, understand component relationships, and locate relevant files without listing everything.",
	}, func(ctx context.Context, request *mcp.CallToolRequest, args GetWorkspaceStructureArgs) (*mcp.CallToolResult, any, error) {
		var result any
		err := nvimClient.ExecLua("return require('gemini.tools').get_workspace_structure(...)", &result, args.RootDir, args.MaxDepth)
		if err != nil {
			return nil, nil, fmt.Errorf("RPC Error: %w", err)
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{
				&mcp.TextContent{
					Text: handleLuaResult(result),
				},
			},
		}, nil, nil
	})

	mcp.AddTool(s, &mcp.Tool{
		Name:        "searchWorkspaceSymbol",
		Description: "The generic Entry Point for code navigation. Finds the EXACT definition location of a symbol (class, function, struct). Use this FIRST to locate a symbol, then use 'getReferences' or 'readSymbol' on that location. More precise than 'grep' because it ignores comments and partial string matches.",
	}, func(ctx context.Context, request *mcp.CallToolRequest, args SearchWorkspaceSymbolArgs) (*mcp.CallToolResult, any, error) {
		var result any
		err := nvimClient.ExecLua("return require('gemini.tools').search_workspace_symbol(...)", &result, args.Query)
		if err != nil {
			return nil, nil, fmt.Errorf("RPC Error: %w", err)
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{
				&mcp.TextContent{
					Text: handleLuaResult(result),
				},
			},
		}, nil, nil
	})

	mcp.AddTool(s, &mcp.Tool{
		Name:        "getFileOutline",
		Description: "Generates a high-level table of contents for a file using Tree-sitter. It lists functions, methods, structs, interfaces, and classes with their line numbers. Use this to quickly understand a file's structure before reading specific symbols.",
	}, func(ctx context.Context, request *mcp.CallToolRequest, args GetFileOutlineArgs) (*mcp.CallToolResult, any, error) {
		var result any
		err := nvimClient.ExecLua("return require('gemini.tools').get_file_outline(...)", &result, args.FilePath)
		if err != nil {
			return nil, nil, fmt.Errorf("RPC Error: %w", err)
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{
				&mcp.TextContent{
					Text: handleLuaResult(result),
				},
			},
		}, nil, nil
	})

	mcp.AddTool(s, &mcp.Tool{
		Name:        "readSymbol",
		Description: "Reads the FULL implementation of a symbol (including docstrings) by name. Safer than 'read_file' because it guarantees you get the complete code block (start to end) without guessing line numbers.",
	}, func(ctx context.Context, request *mcp.CallToolRequest, args ReadSymbolArgs) (*mcp.CallToolResult, any, error) {
		var result any
		err := nvimClient.ExecLua("return require('gemini.tools').read_symbol(...)", &result, args.FilePath, args.SymbolName)
		if err != nil {
			return nil, nil, fmt.Errorf("RPC Error: %w", err)
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{
				&mcp.TextContent{
					Text: handleLuaResult(result),
				},
			},
		}, nil, nil
	})

	mcp.AddTool(s, &mcp.Tool{
		Name:        "resolveDefinition",
		Description: "The 'Go To Definition' power tool. Use this when you see a function call or type and need to see its implementation immediately. It locates the definition (LSP) and returns the full code block (Tree-sitter) in one step (Line: 1-indexed, Character: 0-indexed).",
	}, func(ctx context.Context, request *mcp.CallToolRequest, args ResolveDefinitionArgs) (*mcp.CallToolResult, any, error) {
		var result any
		err := nvimClient.ExecLua("return require('gemini.tools').resolve_definition(...)", &result, args.FilePath, args.Line, args.Character)
		if err != nil {
			return nil, nil, fmt.Errorf("RPC Error: %w", err)
		}
		return &mcp.CallToolResult{
			Content: []mcp.Content{
				&mcp.TextContent{
					Text: handleLuaResult(result),
				},
			},
		}, nil, nil
	})
}

func handleLuaResult(result any) string {
	if str, ok := result.(string); ok {
		return str
	}
	jsonBytes, _ := json.MarshalIndent(result, "", "  ")
	return string(jsonBytes)
}

// Command agent-cli signs a user in to a Kinde-protected MCP server through a loopback
// redirect and calls its initialize method.
//
//	go run . -resource-url https://mcp.example.com/mcp \
//	    -client-metadata-url https://agent.example.com/oauth/client-metadata.json
//
// Without -client-metadata-url (or -client-id) the agent falls back to dynamic client
// registration; pass a fixed-port -redirect-uri so the registration can be reused.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"mime"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"github.com/kinde-oss/kinde-go/agents"
	"github.com/kinde-oss/kinde-go/frameworks/cli"
)

const initializeRequest = `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"kinde-agent-cli","version":"0.0.1"}}}`

func main() {
	resourceURL := flag.String("resource-url", "", "MCP server URL (required)")
	clientMetadataURL := flag.String("client-metadata-url", "", "https URL of this agent's client ID metadata document")
	clientID := flag.String("client-id", "", "pre-registered client ID")
	redirectURI := flag.String("redirect-uri", "http://127.0.0.1/callback", "loopback redirect URI; no port picks an ephemeral one")
	disconnect := flag.Bool("disconnect", false, "revoke and forget the stored tokens")
	flag.Parse()
	if *resourceURL == "" {
		flag.Usage()
		os.Exit(2)
	}

	// Tokens and the DCR registration go to the OS keychain.
	storage, err := cli.NewCliSession("kinde-agent-cli")
	if err != nil {
		log.Fatalf("failed to open keychain: %v", err)
	}
	client, err := agents.NewKindeAgentClient(agents.AgentClientConfig{
		ResourceURL:       *resourceURL,
		ClientMetadataURL: *clientMetadataURL,
		ClientID:          *clientID,
		ClientName:        "Kinde Go agent CLI example",
		RedirectURI:       *redirectURI,
		Storage:           storage,
		OpenBrowser:       openBrowser,
	})
	if err != nil {
		log.Fatal(err)
	}

	ctx := context.Background()
	if *disconnect {
		if err := client.Disconnect(ctx, false); err != nil {
			log.Fatal(err)
		}
		fmt.Println("Disconnected.")
		return
	}

	if err := client.Connect(ctx); err != nil {
		log.Fatal(err)
	}
	if info, ok := client.TokenInfo(); ok {
		fmt.Printf("Connected as client %s (scopes %v, expires %v)\n", info.ClientID, info.Scopes, info.ExpiresAt)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, *resourceURL, strings.NewReader(initializeRequest))
	if err != nil {
		log.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	resp, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	body, err := readResponse(resp)
	resp.Body.Close()
	if err != nil {
		log.Fatalf("%s: %v", resp.Status, err)
	}
	fmt.Printf("%s\n%s\n", resp.Status, body)
	// A failed initialize can still come back as 200 with a JSON-RPC error.
	var result struct {
		Error json.RawMessage `json:"error"`
	}
	rpcFailed := json.Unmarshal(body, &result) == nil && len(result.Error) > 0 && string(result.Error) != "null"
	if resp.StatusCode < 200 || resp.StatusCode > 299 || rpcFailed {
		os.Exit(1)
	}
}

// readResponse returns the body, or for an event stream the JSON-RPC response to the
// initialize request: the server may keep the stream open after sending it.
func readResponse(resp *http.Response) ([]byte, error) {
	body := io.LimitReader(resp.Body, 64<<10)
	if mediaType, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type")); mediaType != "text/event-stream" {
		return io.ReadAll(body)
	}
	scanner := bufio.NewScanner(body)
	var data []string
	for scanner.Scan() {
		line := scanner.Text()
		if v, ok := strings.CutPrefix(line, "data:"); ok {
			data = append(data, strings.TrimPrefix(v, " "))
			continue
		}
		if line != "" || len(data) == 0 {
			continue
		}
		// A blank line ends the event.
		event := strings.Join(data, "\n")
		data = nil
		var msg struct {
			ID json.RawMessage `json:"id"`
		}
		if json.Unmarshal([]byte(event), &msg) == nil && string(msg.ID) == "1" {
			return []byte(event), nil
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("event stream ended without the initialize response")
}

// openBrowser opens the system browser; never an embedded webview.
func openBrowser(authURL string) error {
	fmt.Printf("Opening your browser to sign in. If it doesn't open, visit:\n%s\n", authURL)
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", authURL)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", authURL)
	default:
		cmd = exec.Command("xdg-open", authURL)
	}
	if err := cmd.Start(); err != nil {
		// The URL was printed, so the user can still open it by hand.
		fmt.Fprintf(os.Stderr, "could not open the browser: %v\n", err)
	}
	return nil
}

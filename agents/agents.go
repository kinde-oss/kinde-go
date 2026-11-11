// Package agents implements Kinde's "AI agents and MCP" login flow.
//
// It has two halves:
//   - resource-server helpers (KindeAgentAuth) that protect an MCP server or any
//     HTTP API with tokens issued through a Kinde AI agents and MCP application;
//   - agent-client helpers (KindeAgentClient) that let a Go program sign a user in
//     to such a server using a client ID metadata document (CIMD), a pre-registered
//     client, or dynamic client registration (DCR) as a fallback.
//
// Every application of this type has its own scoped issuer:
//
//	https://<kinde_domain>/oauth2/agents/<application_client_id>
//
// The scoped issuer refuses the openid scope, so this package never uses the
// authorization_code package, which always adds openid.
package agents

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
)

// maxResponseBytes caps how much of a metadata, token or introspection response is read.
const maxResponseBytes = 1 << 20

// normalizeDomain turns "yourbiz.kinde.com" or "https://yourbiz.kinde.com/" into
// "https://yourbiz.kinde.com". Plain http is only accepted for loopback hosts.
func normalizeDomain(domain string) (string, error) {
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return "", fmt.Errorf("domain is required")
	}
	if !strings.Contains(domain, "://") {
		domain = "https://" + domain
	}
	u, err := url.Parse(domain)
	if err != nil {
		return "", fmt.Errorf("invalid domain %q: %w", domain, err)
	}
	if u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || strings.Trim(u.Path, "/") != "" {
		return "", fmt.Errorf("invalid domain %q: expected https://<host>", domain)
	}
	if err := requireSecureURL(u); err != nil {
		return "", err
	}
	return u.Scheme + "://" + u.Host, nil
}

// requireSecureURL refuses anything but https, except http on a loopback host.
func requireSecureURL(u *url.URL) error {
	switch {
	case u.Scheme == "https" && u.Host != "":
		return nil
	case u.Scheme == "http" && isLoopbackHost(u.Hostname()):
		return nil
	default:
		return fmt.Errorf("refusing insecure or invalid URL %q: https is required", u.Redacted())
	}
}

func parseSecureURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid URL %q: %w", raw, err)
	}
	if err := requireSecureURL(u); err != nil {
		return nil, err
	}
	return u, nil
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func origin(u *url.URL) string {
	return u.Scheme + "://" + u.Host
}

func sameOrigin(a, b *url.URL) bool {
	return strings.EqualFold(a.Scheme, b.Scheme) && strings.EqualFold(a.Host, b.Host)
}

// wellKnownURL inserts a well-known segment between the host and the path of u,
// as RFC 8414 and RFC 9728 require. The path suffix is omitted when the path is "/".
func wellKnownURL(u *url.URL, wellKnown string) string {
	path := u.EscapedPath()
	if path == "/" {
		path = ""
	}
	return origin(u) + "/.well-known/" + wellKnown + path
}

// oauthErrorBody is the RFC 6749 / RFC 7591 error shape.
type oauthErrorBody struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}

// OAuthError is an error response from an authorization server endpoint.
type OAuthError struct {
	StatusCode  int
	Code        string
	Description string
}

func (e *OAuthError) Error() string {
	if e.Description != "" {
		return fmt.Sprintf("oauth error %d: %s: %s", e.StatusCode, e.Code, e.Description)
	}
	return fmt.Sprintf("oauth error %d: %s", e.StatusCode, e.Code)
}

func newOAuthError(resp *http.Response) *OAuthError {
	var body oauthErrorBody
	_ = json.NewDecoder(io.LimitReader(resp.Body, maxResponseBytes)).Decode(&body)
	return &OAuthError{StatusCode: resp.StatusCode, Code: body.Error, Description: body.ErrorDescription}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

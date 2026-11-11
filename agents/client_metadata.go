package agents

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

const maxClientMetadataBytes = 64 << 10

// ClientMetadataOptions describes an agent's client ID metadata document (CIMD).
type ClientMetadataOptions struct {
	// ClientID is the https URL the document is served at, e.g.
	// "https://agent.example.com/oauth/client-metadata.json". It must match byte for byte.
	ClientID   string
	ClientName string
	ClientURI  string
	LogoURI    string
	// RedirectURIs must be https on the ClientID host, or http on localhost, 127.0.0.1 or [::1]
	// (any port). Kinde drops anything else, including custom schemes and other hosts.
	RedirectURIs []string
}

// ClientMetadataDocument is the JSON document Kinde fetches from the client ID URL.
type ClientMetadataDocument struct {
	ClientID                string   `json:"client_id"`
	ClientName              string   `json:"client_name"`
	ClientURI               string   `json:"client_uri,omitempty"`
	LogoURI                 string   `json:"logo_uri,omitempty"`
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
}

// BuildClientMetadataDocument validates opts and builds the document. Add the ClientID host to
// the Kinde application's Trusted agent hosts.
func BuildClientMetadataDocument(opts ClientMetadataOptions) (*ClientMetadataDocument, error) {
	clientID, err := url.Parse(opts.ClientID)
	if err != nil {
		return nil, fmt.Errorf("invalid client_id: %w", err)
	}
	if clientID.Scheme != "https" || clientID.Host == "" {
		return nil, fmt.Errorf("client_id must be an https URL")
	}
	if clientID.Path == "" || clientID.Path == "/" {
		return nil, fmt.Errorf("client_id must have a path, e.g. https://%s/oauth/client-metadata.json", clientID.Host)
	}
	if clientID.User != nil || clientID.RawQuery != "" || clientID.Fragment != "" || strings.HasSuffix(opts.ClientID, "#") {
		return nil, fmt.Errorf("client_id must not contain userinfo, a query or a fragment")
	}
	if strings.TrimSpace(opts.ClientName) == "" {
		return nil, fmt.Errorf("client_name is required")
	}
	if len(opts.RedirectURIs) == 0 {
		return nil, fmt.Errorf("at least one redirect URI is required")
	}
	for _, raw := range opts.RedirectURIs {
		u, err := url.Parse(raw)
		if err != nil {
			return nil, fmt.Errorf("invalid redirect URI %q: %w", raw, err)
		}
		if u.User != nil || u.Fragment != "" || strings.Contains(raw, "#") {
			return nil, fmt.Errorf("redirect URI %q must not contain userinfo or a fragment", raw)
		}
		sameHost := u.Scheme == "https" && strings.EqualFold(u.Hostname(), clientID.Hostname())
		loopback := u.Scheme == "http" && isLoopbackHost(u.Hostname())
		if !sameHost && !loopback {
			return nil, fmt.Errorf("redirect URI %q would be dropped by Kinde: use https on %s or an http loopback URI", raw, clientID.Hostname())
		}
	}

	return &ClientMetadataDocument{
		ClientID:                opts.ClientID,
		ClientName:              opts.ClientName,
		ClientURI:               opts.ClientURI,
		LogoURI:                 opts.LogoURI,
		RedirectURIs:            append([]string(nil), opts.RedirectURIs...),
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: "none",
	}, nil
}

// ClientMetadataHandler serves doc. Mount it at the exact path of doc.ClientID, on a publicly
// reachable host: Kinde refuses private addresses and follows redirects only within trusted hosts.
func ClientMetadataHandler(doc *ClientMetadataDocument) (http.Handler, error) {
	body, err := json.Marshal(doc)
	if err != nil {
		return nil, err
	}
	if len(body) > maxClientMetadataBytes {
		return nil, fmt.Errorf("client metadata document is %d bytes; Kinde reads at most %d", len(body), maxClientMetadataBytes)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET")
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		_, _ = w.Write(body)
	}), nil
}

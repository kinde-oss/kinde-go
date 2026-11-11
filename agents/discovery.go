package agents

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
)

// AuthorizationServerMetadata holds the RFC 8414 fields the agent client uses.
type AuthorizationServerMetadata struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	RegistrationEndpoint              string   `json:"registration_endpoint,omitempty"`
	RevocationEndpoint                string   `json:"revocation_endpoint,omitempty"`
	ScopesSupported                   []string `json:"scopes_supported,omitempty"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported,omitempty"`
	ClientIDMetadataDocumentSupported bool     `json:"client_id_metadata_document_supported,omitempty"`
}

// getJSON fetches an https (or loopback http) URL and decodes a 200 JSON response into out.
func getJSON(ctx context.Context, client *http.Client, rawURL string, out any) error {
	if _, err := parseSecureURL(rawURL); err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: status %d", rawURL, resp.StatusCode)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBytes)).Decode(out); err != nil {
		return fmt.Errorf("GET %s: invalid JSON: %w", rawURL, err)
	}
	return nil
}

// discoverProtectedResource calls the resource without a token, reads resource_metadata from the
// 401 challenge, and falls back to the path-suffixed, then root, well-known URLs.
func discoverProtectedResource(ctx context.Context, client *http.Client, resource *url.URL) (*ProtectedResourceMetadata, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, resource.String(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to reach resource: %w", err)
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBytes))
	resp.Body.Close()

	var candidates []string
	if resp.StatusCode == http.StatusUnauthorized {
		if rm := bearerParam(resp.Header.Values("WWW-Authenticate"), "resource_metadata"); rm != "" {
			candidates = []string{rm}
		}
	}
	if candidates == nil {
		candidates = []string{wellKnownURL(resource, prmWellKnown)}
		if root := origin(resource) + "/.well-known/" + prmWellKnown; root != candidates[0] {
			candidates = append(candidates, root)
		}
	}

	var errs []error
	for _, candidate := range candidates {
		var prm ProtectedResourceMetadata
		if err := getJSON(ctx, client, candidate, &prm); err != nil {
			errs = append(errs, err)
			continue
		}
		if !resourceCovers(prm.Resource, resource) {
			return nil, fmt.Errorf("protected resource metadata is for %q, not %q", prm.Resource, resource)
		}
		if len(prm.AuthorizationServers) == 0 {
			return nil, fmt.Errorf("protected resource metadata lists no authorization servers")
		}
		return &prm, nil
	}
	return nil, fmt.Errorf("failed to discover protected resource metadata: %w", errors.Join(errs...))
}

// resourceCovers reports whether target has the same origin as resource and its path equals
// resource's path or sits under it, ignoring one trailing slash.
func resourceCovers(resource string, target *url.URL) bool {
	r, err := url.Parse(resource)
	if err != nil || !sameOrigin(r, target) {
		return false
	}
	rp := strings.TrimSuffix(r.Path, "/")
	tp := strings.TrimSuffix(target.Path, "/")
	return tp == rp || strings.HasPrefix(tp, rp+"/")
}

// discoverAuthorizationServer fetches RFC 8414 metadata for issuer, trying the path-insertion
// form first (the one Kinde serves), then the OpenID Connect forms for other servers.
func discoverAuthorizationServer(ctx context.Context, client *http.Client, issuer string) (*AuthorizationServerMetadata, error) {
	u, err := parseSecureURL(issuer)
	if err != nil {
		return nil, fmt.Errorf("authorization server: %w", err)
	}
	var candidates []string
	if path := strings.TrimSuffix(u.EscapedPath(), "/"); path != "" {
		candidates = []string{
			origin(u) + "/.well-known/oauth-authorization-server" + path,
			origin(u) + "/.well-known/openid-configuration" + path,
			origin(u) + path + "/.well-known/openid-configuration",
		}
	} else {
		candidates = []string{
			origin(u) + "/.well-known/oauth-authorization-server",
			origin(u) + "/.well-known/openid-configuration",
		}
	}

	var errs []error
	for _, candidate := range candidates {
		var m AuthorizationServerMetadata
		if err := getJSON(ctx, client, candidate, &m); err != nil {
			errs = append(errs, err)
			continue
		}
		if m.Issuer != issuer {
			return nil, fmt.Errorf("authorization server metadata issuer %q does not match %q", m.Issuer, issuer)
		}
		if !slices.Contains(m.CodeChallengeMethodsSupported, "S256") {
			return nil, fmt.Errorf("authorization server %q does not support PKCE S256", issuer)
		}
		for _, endpoint := range []string{m.AuthorizationEndpoint, m.TokenEndpoint} {
			if endpoint == "" {
				return nil, fmt.Errorf("authorization server metadata is missing an endpoint")
			}
		}
		for _, endpoint := range []string{m.AuthorizationEndpoint, m.TokenEndpoint, m.RegistrationEndpoint, m.RevocationEndpoint} {
			if endpoint == "" {
				continue
			}
			if _, err := parseSecureURL(endpoint); err != nil {
				return nil, fmt.Errorf("authorization server metadata: %w", err)
			}
		}
		return &m, nil
	}
	return nil, fmt.Errorf("failed to discover authorization server metadata: %w", errors.Join(errs...))
}

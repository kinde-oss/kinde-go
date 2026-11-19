package authorization_code

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"golang.org/x/oauth2"
)

const (
	// discoveryCacheTTL matches the refresh interval of the JWKS cache.
	discoveryCacheTTL = time.Hour
	// discoveryRetryInterval is how long a cached document keeps being served
	// after a failed refresh before the next attempt.
	discoveryRetryInterval = time.Minute
	// discoveryErrorTTL is how long a failed first fetch is remembered, so that
	// checks made while discovery is down fail at once instead of each waiting
	// for a timeout.
	discoveryErrorTTL   = 10 * time.Second
	discoveryTimeout    = 10 * time.Second
	discoveryMaxBodyLen = 1 << 20
)

type (
	// discoveryDocument holds the fields of /.well-known/openid-configuration the SDK reads.
	discoveryDocument struct {
		AcrValuesSupported []string `json:"acr_values_supported"`
	}

	discoveryCacheEntry struct {
		document discoveryDocument
		// err is set when no document could be fetched yet.
		err error
		// refreshAfter is when the document should be fetched again.
		refreshAfter time.Time
	}

	// discoveryFetch is a fetch in progress that later callers wait for.
	discoveryFetch struct {
		done     chan struct{}
		document discoveryDocument
		err      error
	}
)

var (
	discoveryMu      sync.Mutex
	discoveryCache   = map[string]discoveryCacheEntry{}
	discoveryFetches = map[string]*discoveryFetch{}
)

// IsStepUpSupported reports whether the Kinde environment supports step-up
// authentication, that is whether its discovery document lists acr_values_supported.
//
// When it does not, Kinde ignores acr_values and max_age, tokens carry no acr or
// amr, and auth_time can be the time a token was issued. No token will then meet
// an acr requirement, so deny the sensitive action instead of treating a sign-in
// as a step-up.
//
// The discovery document is fetched once per Kinde domain and cached in memory
// for an hour. If it cannot be refreshed after that, the cached document keeps
// being used and the fetch is retried a minute later. Only a failed first
// fetch is returned as an error; it is remembered for ten seconds, so checks
// made while discovery is down do not each wait for a timeout.
func (flow *AuthorizationCodeFlow) IsStepUpSupported(ctx context.Context) (bool, error) {
	document, err := flow.getDiscoveryDocument(ctx)
	if err != nil {
		return false, err
	}
	return len(document.AcrValuesSupported) > 0, nil
}

func (flow *AuthorizationCodeFlow) getDiscoveryDocument(ctx context.Context) (discoveryDocument, error) {
	discoveryURL := flow.discoveryURL
	if discoveryURL == "" {
		return discoveryDocument{}, fmt.Errorf("discovery URL is not set")
	}

	discoveryMu.Lock()
	entry, cached := discoveryCache[discoveryURL]
	if cached && time.Now().Before(entry.refreshAfter) {
		discoveryMu.Unlock()
		return entry.document, entry.err
	}
	// One fetch per Kinde domain at a time, shared by everyone who needs it. It
	// runs apart from the caller that started it, so that caller giving up does
	// not fail the others.
	fetch, running := discoveryFetches[discoveryURL]
	if !running {
		fetch = &discoveryFetch{done: make(chan struct{})}
		discoveryFetches[discoveryURL] = fetch
		go refreshDiscoveryDocument(context.WithoutCancel(ctx), discoveryURL, fetch, entry, cached && entry.err == nil)
	}
	discoveryMu.Unlock()

	select {
	case <-fetch.done:
		return fetch.document, fetch.err
	case <-ctx.Done():
		return discoveryDocument{}, ctx.Err()
	}
}

// refreshDiscoveryDocument fetches the discovery document, updates the cache
// and hands the result to everyone waiting on fetch. last is the document
// fetched before, when there is one.
func refreshDiscoveryDocument(ctx context.Context, discoveryURL string, fetch *discoveryFetch, last discoveryCacheEntry, hasLast bool) {
	document, err := fetchDiscoveryDocument(ctx, discoveryURL)

	discoveryMu.Lock()
	switch {
	case err == nil:
		discoveryCache[discoveryURL] = discoveryCacheEntry{document: document, refreshAfter: time.Now().Add(discoveryCacheTTL)}
	case hasLast:
		// Keep answering from the last good document, and try again in a while
		document, err = last.document, nil
		discoveryCache[discoveryURL] = discoveryCacheEntry{document: document, refreshAfter: time.Now().Add(discoveryRetryInterval)}
	default:
		err = fmt.Errorf("failed to fetch discovery document: %w", err)
		discoveryCache[discoveryURL] = discoveryCacheEntry{err: err, refreshAfter: time.Now().Add(discoveryErrorTTL)}
	}
	fetch.document, fetch.err = document, err
	delete(discoveryFetches, discoveryURL)
	discoveryMu.Unlock()
	close(fetch.done)
}

func fetchDiscoveryDocument(ctx context.Context, discoveryURL string) (discoveryDocument, error) {
	var document discoveryDocument

	ctx, cancel := context.WithTimeout(ctx, discoveryTimeout)
	defer cancel()

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return document, err
	}

	// Same convention as the oauth2 package for supplying a custom HTTP client
	client := http.DefaultClient
	if custom, ok := ctx.Value(oauth2.HTTPClient).(*http.Client); ok && custom != nil {
		client = custom
	}

	response, err := client.Do(request)
	if err != nil {
		return document, err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return document, fmt.Errorf("unexpected status %d from %s", response.StatusCode, discoveryURL)
	}

	if err := json.NewDecoder(io.LimitReader(response.Body, discoveryMaxBodyLen)).Decode(&document); err != nil {
		return document, fmt.Errorf("invalid discovery document: %w", err)
	}

	return document, nil
}

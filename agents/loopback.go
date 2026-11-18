package agents

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"
)

const (
	defaultRedirectURI = "http://127.0.0.1/callback"
	loopbackTimeout    = 5 * time.Minute
)

const callbackPage = `<!doctype html><html><head><meta charset="utf-8"><title>Signed in</title></head>` +
	`<body><p>You can close this tab and return to the application.</p></body></html>`

// loopbackServer receives exactly one authorization response on a 127.0.0.1 (RFC 8252) redirect.
type loopbackServer struct {
	redirectURI string
	listener    net.Listener
	server      *http.Server
	result      chan url.Values
	once        sync.Once
}

// startLoopback listens on the host and port of redirectURI. A missing or zero port picks an
// ephemeral one, which is reflected in the returned redirectURI.
func startLoopback(redirectURI string) (*loopbackServer, error) {
	u, err := url.Parse(redirectURI)
	if err != nil {
		return nil, fmt.Errorf("invalid redirect URI: %w", err)
	}
	if u.Scheme != "http" || !isLoopbackHost(u.Hostname()) || u.Fragment != "" || u.User != nil {
		return nil, fmt.Errorf("redirect URI %q must be an http loopback URI, e.g. %s", redirectURI, defaultRedirectURI)
	}
	port := u.Port()
	if port == "" {
		port = "0"
	}
	listener, err := net.Listen("tcp", net.JoinHostPort(u.Hostname(), port))
	if err != nil {
		return nil, fmt.Errorf("failed to listen for the redirect: %w", err)
	}
	u.Host = net.JoinHostPort(u.Hostname(), fmt.Sprint(listener.Addr().(*net.TCPAddr).Port))
	path := u.Path
	if path == "" {
		path = "/"
	}

	l := &loopbackServer{redirectURI: u.String(), listener: listener, result: make(chan url.Values, 1)}
	mux := http.NewServeMux()
	mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != path {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(callbackPage))
		l.once.Do(func() { l.result <- r.URL.Query() })
	})
	l.server = &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = l.server.Serve(listener) }()
	return l, nil
}

// wait returns the authorization code once the redirect arrives with the expected state.
func (l *loopbackServer) wait(ctx context.Context, state, issuer string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, loopbackTimeout)
	defer cancel()
	var query url.Values
	select {
	case query = <-l.result:
	case <-ctx.Done():
		return "", fmt.Errorf("timed out waiting for the browser sign-in: %w", ctx.Err())
	}
	if subtle.ConstantTimeCompare([]byte(query.Get("state")), []byte(state)) != 1 {
		return "", errors.New("authorization response state does not match; aborting")
	}
	if code := query.Get("error"); code != "" {
		return "", &OAuthError{Code: code, Description: query.Get("error_description")}
	}
	if iss := query.Get("iss"); iss != "" && iss != issuer {
		return "", fmt.Errorf("authorization response issuer %q does not match %q", iss, issuer)
	}
	code := query.Get("code")
	if code == "" {
		return "", errors.New("authorization response has no code")
	}
	return code, nil
}

func (l *loopbackServer) close() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_ = l.server.Shutdown(ctx)
}

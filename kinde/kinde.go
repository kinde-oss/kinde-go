package kinde

import (
	"context"
	"net/http"

	"github.com/kinde-oss/kinde-go/jwt"
	"golang.org/x/oauth2"
)

type contextKey string

const kindeContextKey contextKey = "kinde_context"

type KindeContext interface {
	GetHttpClient(ctx context.Context) *http.Client
	GetAccessToken() *jwt.Token
	GetIDToken() *jwt.Token
}

type kindeContext struct {
	tokenSource  oauth2.TokenSource
	tokenOptions []func(*jwt.Token)
}

func (kc *kindeContext) GetHttpClient(ctx context.Context) *http.Client {
	return oauth2.NewClient(ctx, kc.tokenSource)
}

func (kc *kindeContext) GetAccessToken() *jwt.Token {
	receivedToken, _ := kc.tokenSource.Token()
	parsedToken, _ := jwt.ParseOAuth2Token(receivedToken, kc.tokenOptions...)
	return parsedToken
}
func (kc *kindeContext) GetIDToken() *jwt.Token {
	receivedToken, _ := kc.tokenSource.Token()
	parsedToken, _ := jwt.ParseOAuth2Token(receivedToken.WithExtra("id_token"), kc.tokenOptions...)
	return parsedToken
}

func newKindeContext(tokenSource oauth2.TokenSource, tokenOptions []func(*jwt.Token)) KindeContext {
	if tokenOptions == nil {
		tokenOptions = []func(*jwt.Token){}
	}

	return &kindeContext{
		tokenSource:  tokenSource,
		tokenOptions: tokenOptions,
	}
}

func getContextValueAs[T any](key any, ctx context.Context) (val *T, hasValue bool) {
	anyValue := ctx.Value(key)
	if anyValue != nil {
		castValue := anyValue.(T)
		return &castValue, true
	}
	return nil, false
}

func SetKindeContext(ctx context.Context, tokenSource oauth2.TokenSource, tokenOptions []func(*jwt.Token)) context.Context {
	return context.WithValue(ctx, kindeContextKey, newKindeContext(tokenSource, tokenOptions))
}

func GetKindeContext(ctx context.Context) KindeContext {
	if kindeContext, ok := getContextValueAs[KindeContext](kindeContextKey, ctx); ok {
		return *kindeContext
	}
	return newKindeContext(nil, nil)
}

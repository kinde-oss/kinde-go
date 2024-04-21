package jwt

import "golang.org/x/oauth2"

type Token struct {
	rawToken *oauth2.Token
}

func NewJwtToken(rawToken *oauth2.Token) *Token {
	return &Token{rawToken: rawToken}
}

func (j *Token) GetRawToken() *oauth2.Token {
	return j.rawToken
}

package jwt

import "golang.org/x/oauth2"

type JwtToken struct {
	rawToken *oauth2.Token
}

func NewJwtToken(rawToken *oauth2.Token) *JwtToken {
	return &JwtToken{rawToken: rawToken}
}

func (j *JwtToken) GetRawToken() *oauth2.Token {
	return j.rawToken
}

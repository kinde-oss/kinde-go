package jwt

import (
	golangjwt "github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
)

type parsedToken struct {
	keyFunc        func(*golangjwt.Token) (interface{}, error)
	parsingOptions []golangjwt.ParserOption
	parsed         *golangjwt.Token
}

type Token struct {
	rawToken     *oauth2.Token
	parsing      parsedToken
	IsTokenValid bool
}

func ParseJwtToken(rawToken *oauth2.Token, options ...func(*Token)) (*Token, error) {

	token := Token{
		rawToken: rawToken,
		parsing: parsedToken{
			parsingOptions: []golangjwt.ParserOption{},
		},
	}

	for _, o := range options {
		o(&token)
	}

	parsedToken, err := golangjwt.Parse(token.rawToken.AccessToken, token.parsing.keyFunc, token.parsing.parsingOptions...)

	if err != nil {
		token.IsTokenValid = false
	} else {
		token.IsTokenValid = parsedToken.Valid
	}
	token.parsing.parsed = parsedToken

	return &token, err
}

func (j *Token) GetRawToken() *oauth2.Token {
	return j.rawToken
}

func WillValidateSignature(keyFunc func(*golangjwt.Token) (interface{}, error)) func(*Token) {
	return func(s *Token) {
		s.parsing.keyFunc = keyFunc
	}
}

func WillValidateAlgorythm() func(*Token) {
	return func(s *Token) {
		s.parsing.parsingOptions = append(s.parsing.parsingOptions, golangjwt.WithValidMethods([]string{"RS256"}))
	}
}

func WillValidateAudience(audiences []string) func(*Token) {
	return func(s *Token) {
		for _, audience := range audiences {
			s.parsing.parsingOptions = append(s.parsing.parsingOptions, golangjwt.WithAudience(audience))
		}
	}
}

package jwt

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	golangjwt "github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
)

type tokenProcessing struct {
	keyFunc        func(*golangjwt.Token) (interface{}, error)
	parsingOptions []golangjwt.ParserOption
	validations    []func(claims golangjwt.MapClaims) (isValid bool, err error)
	parsed         *golangjwt.Token
}

// Token represents a JWT token.
type Token struct {
	rawToken   *oauth2.Token
	processing tokenProcessing
	isValid    bool
}

// ParseFromAuthorizationHeader will parse the token from the Authorization header and validate it with the given options.
func ParseFromAuthorizationHeader(r *http.Request, options ...func(*Token)) (*Token, error) {
	requestedToken := r.Header.Get("Authorization")
	splitToken := strings.Split(requestedToken, "Bearer")
	if len(splitToken) != 2 {
		return nil, fmt.Errorf("invalid token")
	}
	requestedToken = strings.TrimSpace(splitToken[1])
	return ParseOAuth2Token(&oauth2.Token{AccessToken: requestedToken}, options...)
}

// ParseFromString will parse the given token and validate it with the given options.
func ParseFromString(rawAccessToken string, options ...func(*Token)) (*Token, error) {
	return ParseOAuth2Token(&oauth2.Token{AccessToken: rawAccessToken}, options...)
}

// ParseFromString will parse the given token and validate it with the given options.
func ParseFromSessionStorage(rawToken string, options ...func(*Token)) (*Token, error) {
	token := oauth2.Token{}
	json.Unmarshal([]byte(rawToken), &token)

	var extra map[string]interface{}
	json.Unmarshal([]byte(rawToken), &extra)
	tokenExtra := token.WithExtra(extra)

	return ParseOAuth2Token(tokenExtra, options...)
}

// ParseOAuth2Token will parse the given token and validate it with the given options.
func ParseOAuth2Token(rawToken *oauth2.Token, options ...func(*Token)) (*Token, error) {

	token := Token{
		rawToken: rawToken,
		processing: tokenProcessing{
			parsingOptions: []golangjwt.ParserOption{},
			validations:    []func(claims golangjwt.MapClaims) (bool, error){},
		},
	}

	for _, o := range options {
		o(&token)
	}

	parsedToken, err := golangjwt.Parse(token.rawToken.AccessToken, token.processing.keyFunc, token.processing.parsingOptions...)

	errors := []error{}

	if err != nil {
		errors = append(errors, err)
		token.isValid = false
	} else {
		claims := parsedToken.Claims.(golangjwt.MapClaims)
		isTokenValid := true
		for _, verificationOption := range token.processing.validations {
			isValid, error := verificationOption(claims)
			if error != nil {
				errors = append(errors, error)
				isTokenValid = false
			}
			if !isValid {
				isTokenValid = false
			}
		}
		token.isValid = isTokenValid
	}
	token.processing.parsed = parsedToken

	if len(errors) == 0 {
		return &token, nil
	}

	return &token, newError("error parsing or validating token", err, errors...)
}

// GetRawToken returns the raw token.
func (j *Token) GetRawToken() *oauth2.Token {
	return j.rawToken
}

// GetRawToken returns the raw token.
func (j *Token) AsString() (string, error) {
	marshalledToken, err := json.Marshal(j.rawToken)
	if err != nil {
		return "", err
	}
	return string(marshalledToken), nil
}

// IsValid returns if the token is valid.
func (j *Token) IsValid() bool {
	return j.isValid
}

func (j *Token) GetSubject() string {
	subject, _ := j.processing.parsed.Claims.GetSubject()
  return subject
}

package jwt

import (
	"crypto/rsa"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/MicahParks/keyfunc/v3"
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
func ParseFromString(rawToken string, options ...func(*Token)) (*Token, error) {
	return ParseOAuth2Token(&oauth2.Token{AccessToken: rawToken}, options...)
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

func (j *Token) GetRawToken() *oauth2.Token {
	return j.rawToken
}

func (j *Token) IsValid() bool {
	return j.isValid
}

// WillValidateWithKeys receives a token and needs to return a public RSA key to validate the token signature.
func WillValidateWithKeys(keyFunc func(rawToken string) (*rsa.PublicKey, error)) func(*Token) {
	return func(s *Token) {
		wrapped := func(token *golangjwt.Token) (interface{}, error) {
			return keyFunc(token.Raw)
		}
		s.processing.keyFunc = wrapped
	}
}

// WillValidateWithJWKSUrl will validate the token with the given JWKS URL.
func WillValidateWithJWKSUrl(url string) func(*Token) {
	return func(s *Token) {
		jwks, err := keyfunc.NewDefault([]string{url})
		if err != nil {
			return
		}
		s.processing.keyFunc = jwks.Keyfunc
	}
}

// WillValidateWithKeyFunc will validate the token with the given keyFunc.
func WillValidateWithKeyFunc(keyFunc func(*golangjwt.Token) (interface{}, error)) func(*Token) {
	return func(s *Token) {
		s.processing.keyFunc = keyFunc
	}
}

// WillValidateAlgorythm will validate the token with the given algorithm, defaults to RS256.
func WillValidateAlgorythm(alg ...string) func(*Token) {
	return func(s *Token) {
		if len(alg) > 0 {
			s.processing.parsingOptions = append(s.processing.parsingOptions, golangjwt.WithValidMethods(alg))
		} else {
			s.processing.parsingOptions = append(s.processing.parsingOptions, golangjwt.WithValidMethods([]string{"RS256"}))
		}
	}
}

// WillValidateAudience will validate the audience is present in the token.
func WillValidateAudience(expectedAudience string) func(*Token) {
	return func(s *Token) {
		f := func(receivedClaims golangjwt.MapClaims) (bool, error) {
			aud, err := receivedClaims.GetAudience()
			if err != nil {
				return false, err
			}
			if !slices.Contains(aud, expectedAudience) {
				return false, fmt.Errorf("audience not valid")
			}
			return true, nil
		}
		s.processing.validations = append(s.processing.validations, f)
	}
}

func newError(message string, err error, more ...error) error {
	var format string
	var args []any
	if message != "" {
		format = "%w: %s"
		args = []any{err, message}
	} else {
		format = "%w"
		args = []any{err}
	}

	for _, e := range more {
		format += ": %w"
		args = append(args, e)
	}

	err = fmt.Errorf(format, args...)
	return err
}

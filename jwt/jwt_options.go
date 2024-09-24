package jwt

import (
	"crypto/rsa"
	"fmt"
	"slices"
	"time"

	"github.com/MicahParks/keyfunc/v3"
	golangjwt "github.com/golang-jwt/jwt/v5"
)

// WillValidateWithPublicKey receives a token and needs to return a public RSA key to validate the token signature.
func WillValidateWithPublicKey(keyFunc func(rawToken string) (*rsa.PublicKey, error)) func(*Token) {
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

// WillValidateWithTimeFunc will validate the token with the given time, used fopr testing.
func WillValidateWithTimeFunc(timeFunc func() time.Time) func(*Token) {
	return func(s *Token) {
		s.processing.parsingOptions = append(s.processing.parsingOptions, golangjwt.WithTimeFunc(timeFunc))
	}
}

// WillValidateWithClockSkew will validate the token with the allowed clock skew.
func WillValidateWithClockSkew(leeway time.Duration) func(*Token) {
	return func(s *Token) {
		s.processing.parsingOptions = append(s.processing.parsingOptions, golangjwt.WithLeeway(leeway))
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

package jwt

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	golangjwt "github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
)

type (
	tokenProcessing struct {
		keyFunc        func(*golangjwt.Token) (interface{}, error)
		parsingOptions []golangjwt.ParserOption
		validations    []func(claims golangjwt.MapClaims) (isValid bool, err error)
		parsed         *golangjwt.Token
	}

	// Token represents a JWT token.
	Token struct {
		rawToken         *oauth2.Token
		processing       tokenProcessing
		isValid          bool
		validationErrors []error
	}
)

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

// ParseIDTokenUnverified parses an ID token without cryptographic validation.
//
// This function should ONLY be used for ID tokens that have already been validated
// during the OAuth flow (e.g., tokens obtained directly from a trusted OAuth2 token exchange).
// It parses the JWT structure and extracts claims without verifying the signature or
// standard JWT claims (exp, iat, nbf, etc.).
//
// Use cases:
//   - Extracting user profile information from an ID token obtained via OAuth2 code flow
//   - Reading organization memberships from a validated ID token
//   - Accessing custom claims from a trusted ID token
//
// DO NOT use this function to parse:
//   - Access tokens that require validation
//   - ID tokens from untrusted sources
//   - Tokens that haven't been obtained through a secure OAuth2 flow
//
// Parameters:
//   - idTokenStr: The raw JWT string to parse
//
// Returns the parsed JWT claims as a map, or an error if parsing fails.
func ParseIDTokenUnverified(idTokenStr string) (golangjwt.MapClaims, error) {
	// Parse without verification - the token was already validated in OAuth flow
	parser := golangjwt.NewParser()
	token, _, err := parser.ParseUnverified(idTokenStr, golangjwt.MapClaims{})
	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(golangjwt.MapClaims); ok {
		return claims, nil
	}

	return nil, golangjwt.ErrTokenMalformed
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
	token.validationErrors = errors

	if len(errors) == 0 {
		return &token, nil
	}

	return &token, newError("error parsing or validating token", err, errors...)
}

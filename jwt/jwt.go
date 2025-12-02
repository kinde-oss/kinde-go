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
	// tokenProcessing holds internal state for JWT token parsing and validation.
	// It stores the key function for signature verification, parser options,
	// custom validation functions, and the parsed token result.
	tokenProcessing struct {
		// keyFunc is used to retrieve the cryptographic key for JWT signature verification.
		keyFunc func(*golangjwt.Token) (interface{}, error)
		// parsingOptions contains parser configuration options (e.g., allowed algorithms, clock skew).
		parsingOptions []golangjwt.ParserOption
		// validations contains custom validation functions that check token claims.
		validations []func(claims golangjwt.MapClaims) (isValid bool, err error)
		// parsed stores the successfully parsed JWT token.
		parsed *golangjwt.Token
	}

	// Token represents a JWT token.
	Token struct {
		rawToken         *oauth2.Token
		processing       tokenProcessing
		isValid          bool
		validationErrors []error
	}
)

// ParseFromAuthorizationHeader extracts and parses a JWT token from the HTTP Authorization header.
//
// The function expects the Authorization header to be in the format "Bearer <token>".
// It extracts the token string, creates an OAuth2 token, and parses it with the provided options.
//
// Parameters:
//   - r: The HTTP request containing the Authorization header
//   - options: Optional configuration functions for token parsing and validation
//     (e.g., WillValidateWithJWKSUrl, WillValidateIssuer, WillValidateAudience)
//
// Returns a parsed and validated Token, or an error if:
//   - The Authorization header is missing or malformed
//   - The token format is invalid (not "Bearer <token>")
//   - Token parsing or validation fails
//
// Example:
//
//	token, err := jwt.ParseFromAuthorizationHeader(r,
//	    jwt.WillValidateWithJWKSUrl("https://yourdomain.kinde.com/.well-known/jwks.json"),
//	    jwt.WillValidateIssuer("https://yourdomain.kinde.com"),
//	)
func ParseFromAuthorizationHeader(r *http.Request, options ...func(*Token)) (*Token, error) {
	requestedToken := r.Header.Get("Authorization")
	splitToken := strings.Split(requestedToken, "Bearer")
	if len(splitToken) != 2 {
		return nil, fmt.Errorf("invalid token")
	}
	requestedToken = strings.TrimSpace(splitToken[1])
	return ParseOAuth2Token(&oauth2.Token{AccessToken: requestedToken}, options...)
}

// ParseFromString parses a raw JWT access token string and validates it with the given options.
//
// This is a convenience function that wraps a raw token string in an OAuth2 token structure
// and parses it. Use this when you have the token as a string and want to validate it.
//
// Parameters:
//   - rawAccessToken: The raw JWT access token string to parse
//   - options: Optional configuration functions for token parsing and validation
//     (e.g., WillValidateWithJWKSUrl, WillValidateIssuer, WillValidateAudience)
//
// Returns a parsed and validated Token, or an error if token parsing or validation fails.
//
// Example:
//
//	token, err := jwt.ParseFromString(accessTokenString,
//	    jwt.WillValidateWithJWKSUrl("https://yourdomain.kinde.com/.well-known/jwks.json"),
//	)
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

// ParseFromSessionStorage parses a JWT token from a JSON string stored in session storage.
//
// This function is designed to reconstruct an OAuth2 token from a JSON-encoded string
// that was previously stored (e.g., in a session cookie or database). It unmarshals the
// JSON string to extract both the standard OAuth2 token fields and any extra fields
// (such as id_token) that may have been stored.
//
// Parameters:
//   - rawToken: A JSON-encoded string representation of an oauth2.Token
//   - options: Optional configuration functions for token parsing and validation
//     (e.g., WillValidateWithJWKSUrl, WillValidateIssuer, WillValidateAudience)
//
// Returns a parsed and validated Token, or an error if:
//   - The JSON string is malformed
//   - Token parsing or validation fails
//
// Example:
//
//	// Token was stored as JSON string in session
//	tokenJSON := `{"access_token":"...","token_type":"Bearer","id_token":"..."}`
//	token, err := jwt.ParseFromSessionStorage(tokenJSON,
//	    jwt.WillValidateWithJWKSUrl("https://yourdomain.kinde.com/.well-known/jwks.json"),
//	)
func ParseFromSessionStorage(rawToken string, options ...func(*Token)) (*Token, error) {
	token := oauth2.Token{}
	json.Unmarshal([]byte(rawToken), &token)

	var extra map[string]interface{}
	json.Unmarshal([]byte(rawToken), &extra)
	tokenExtra := token.WithExtra(extra)

	return ParseOAuth2Token(tokenExtra, options...)
}

// ParseOAuth2Token parses and validates an OAuth2 token with the given options.
//
// This is the core parsing function that all other parse functions ultimately call.
// It extracts the access token from the OAuth2 token structure, applies configuration
// options (such as key functions, validation rules, and parser settings), and performs
// JWT parsing and validation.
//
// The function supports various validation options:
//   - Signature verification via JWKS URL or public key
//   - Issuer validation
//   - Audience validation
//   - Custom claim validation
//   - Algorithm validation
//   - Clock skew tolerance
//
// Parameters:
//   - rawToken: The OAuth2 token containing the access token and optional extra fields (e.g., id_token)
//   - options: Optional configuration functions for token parsing and validation
//     (e.g., WillValidateWithJWKSUrl, WillValidateIssuer, WillValidateAudience, WillValidateClaims)
//
// Returns a Token with validation results. The Token will contain:
//   - The parsed JWT claims (accessible via GetClaims, GetSubject, etc.)
//   - Validation status (checkable via IsValid)
//   - Any validation errors (accessible via GetValidationErrors)
//
// Even if validation fails, a Token is returned (with isValid=false) along with an error
// containing details about what failed. This allows callers to inspect the token and errors.
//
// Example:
//
//	oauth2Token := &oauth2.Token{AccessToken: "eyJhbGc..."}
//	token, err := jwt.ParseOAuth2Token(oauth2Token,
//	    jwt.WillValidateWithJWKSUrl("https://yourdomain.kinde.com/.well-known/jwks.json"),
//	    jwt.WillValidateIssuer("https://yourdomain.kinde.com"),
//	    jwt.WillValidateAudience("your-client-id"),
//	)
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

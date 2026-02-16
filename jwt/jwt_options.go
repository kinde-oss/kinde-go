package jwt

import (
	"crypto/rsa"
	"fmt"
	"slices"
	"time"

	"github.com/MicahParks/jwkset"
	"github.com/MicahParks/keyfunc/v3"
	golangjwt "github.com/golang-jwt/jwt/v5"
	"golang.org/x/time/rate"
)

// Option is a function type that configures a Token during parsing and validation.
// Options are passed to parse functions (e.g., ParseFromString, ParseOAuth2Token)
// to customize token validation behavior, such as signature verification, claim
// validation, and parser settings.
type Option func(*Token)

// WillValidateWithPublicKey configures token validation to use a custom function
// that retrieves an RSA public key for signature verification.
//
// This option is useful when you have a custom key retrieval mechanism or when
// you need to extract key information from the token itself (e.g., from a "kid"
// claim) to determine which key to use.
//
// Parameters:
//   - keyFunc: A function that receives the raw token string and returns the
//     RSA public key to use for signature verification, or an error if the key
//     cannot be retrieved.
//
// Returns an Option that configures the token to use the provided key function.
//
// Example:
//
//	token, err := jwt.ParseFromString(tokenString,
//	    jwt.WillValidateWithPublicKey(func(rawToken string) (*rsa.PublicKey, error) {
//	        // Extract key ID from token and return corresponding public key
//	        return getPublicKeyFromToken(rawToken)
//	    }),
//	)
func WillValidateWithPublicKey(keyFunc func(rawToken string) (*rsa.PublicKey, error)) Option {
	return func(s *Token) {
		wrapped := func(token *golangjwt.Token) (interface{}, error) {
			return keyFunc(token.Raw)
		}
		s.processing.keyFunc = wrapped
	}
}

// WillValidateWithJWKSUrl configures token validation to use a JSON Web Key Set (JWKS)
// endpoint for automatic signature verification.
//
// This option fetches public keys from the specified JWKS URL and automatically
// selects the appropriate key based on the token's "kid" (key ID) claim. The JWKS
// client handles caching and automatic key refresh.
//
// This is the recommended approach for validating tokens issued by Kinde, as it
// automatically handles key rotation and key discovery.
//
// Parameters:
//   - url: The JWKS endpoint URL (e.g., "https://yourdomain.kinde.com/.well-known/jwks.json")
//
// Returns an Option that configures the token to use the JWKS endpoint for validation.
// If the JWKS client cannot be created, the option will add a validation error to the token.
//
// Example:
//
//	token, err := jwt.ParseFromString(tokenString,
//	    jwt.WillValidateWithJWKSUrl("https://yourdomain.kinde.com/.well-known/jwks.json"),
//	)
func WillValidateWithJWKSUrl(url string) Option {
	client, err := jwkset.NewHTTPClient(jwkset.HTTPClientOptions{
		PrioritizeHTTP:    false,
		HTTPURLs:          map[string]jwkset.Storage{url: nil},
		RateLimitWaitMax:  time.Minute,
		RefreshUnknownKID: rate.NewLimiter(rate.Every(5*time.Minute), 1),
	})
	if err != nil {
		return func(s *Token) {
			s.validationErrors = append(s.validationErrors, fmt.Errorf("failed to create JWK client: %w", err))
		}
	}

	options := keyfunc.Options{
		Storage: client,
	}

	jwks, err := keyfunc.New(options)
	if err != nil {
		return nil
	}

	return func(s *Token) {
		s.processing.keyFunc = jwks.Keyfunc
	}
}

// WillValidateWithKeyFunc configures token validation to use a custom key function
// that returns the cryptographic key for signature verification.
//
// This option provides maximum flexibility for key retrieval, allowing you to
// implement any custom logic needed to determine which key to use for validation.
// The key function receives the parsed JWT token and can inspect its claims (e.g.,
// "kid", "alg") to select the appropriate key.
//
// Parameters:
//   - keyFunc: A function that receives the parsed JWT token and returns the
//     cryptographic key (interface{} to support various key types) or an error
//     if the key cannot be retrieved.
//
// Returns an Option that configures the token to use the provided key function.
//
// Example:
//
//	token, err := jwt.ParseFromString(tokenString,
//	    jwt.WillValidateWithKeyFunc(func(t *jwt.Token) (interface{}, error) {
//	        kid, _ := t.Header["kid"].(string)
//	        return getKeyByKid(kid)
//	    }),
//	)
func WillValidateWithKeyFunc(keyFunc func(*golangjwt.Token) (interface{}, error)) Option {
	return func(s *Token) {
		s.processing.keyFunc = keyFunc
	}
}

// WillValidateWithTimeFunc configures token validation to use a custom time function
// instead of the current system time.
//
// This option is primarily useful for testing, allowing you to control the "current"
// time used for expiration and issued-at claim validation. It can also be used
// to handle clock synchronization issues in production.
//
// Parameters:
//   - timeFunc: A function that returns the time to use as the "current" time for
//     validation. Typically returns time.Now() in production, but can return a
//     fixed time for testing.
//
// Returns an Option that configures the token to use the provided time function.
//
// Example:
//
//	// For testing with a fixed time
//	fixedTime := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
//	token, err := jwt.ParseFromString(tokenString,
//	    jwt.WillValidateWithTimeFunc(func() time.Time { return fixedTime }),
//	)
func WillValidateWithTimeFunc(timeFunc func() time.Time) Option {
	return func(s *Token) {
		s.processing.parsingOptions = append(s.processing.parsingOptions, golangjwt.WithTimeFunc(timeFunc))
	}
}

// WillValidateWithClockSkew configures token validation to allow a time leeway
// (clock skew) when validating expiration and issued-at claims.
//
// This option is useful when there are small time differences between the token
// issuer's clock and your server's clock. The leeway is applied to both expiration
// and issued-at validation, allowing tokens to be accepted slightly before or after
// their exact expiration time.
//
// Parameters:
//   - leeway: The maximum time difference allowed (e.g., 5*time.Minute). Positive
//     values allow tokens to be accepted slightly after expiration or before issuance.
//
// Returns an Option that configures the token to use the specified clock skew.
//
// Example:
//
//	token, err := jwt.ParseFromString(tokenString,
//	    jwt.WillValidateWithJWKSUrl("https://yourdomain.kinde.com/.well-known/jwks.json"),
//	    jwt.WillValidateWithClockSkew(5*time.Minute), // Allow 5 minute clock skew
//	)
func WillValidateWithClockSkew(leeway time.Duration) Option {
	return func(s *Token) {
		s.processing.parsingOptions = append(s.processing.parsingOptions, golangjwt.WithLeeway(leeway))
	}
}

// WillValidateAlgorithm configures token validation to only accept tokens signed
// with the specified algorithm(s).
//
// This option provides security by ensuring that only tokens signed with expected
// algorithms are accepted. If no algorithms are specified, it defaults to RS256
// (RSA with SHA-256), which is the standard algorithm used by Kinde.
//
// Parameters:
//   - alg: One or more algorithm names to accept (e.g., "RS256", "ES256").
//     If no algorithms are provided, defaults to ["RS256"].
//
// Returns an Option that configures the token to validate the algorithm.
//
// Example:
//
//	token, err := jwt.ParseFromString(tokenString,
//	    jwt.WillValidateWithJWKSUrl("https://yourdomain.kinde.com/.well-known/jwks.json"),
//	    jwt.WillValidateAlgorithm("RS256", "ES256"), // Accept only RS256 or ES256
//	)
func WillValidateAlgorithm(alg ...string) func(*Token) {
	return func(s *Token) {
		if len(alg) > 0 {
			s.processing.parsingOptions = append(s.processing.parsingOptions, golangjwt.WithValidMethods(alg))
		} else {
			s.processing.parsingOptions = append(s.processing.parsingOptions, golangjwt.WithValidMethods([]string{"RS256"}))
		}
	}
}

// WillValidateIssuer configures token validation to verify that the token's
// issuer (iss) claim matches the expected issuer.
//
// This option ensures that tokens were issued by the expected authorization server,
// preventing tokens from other issuers from being accepted. The issuer is typically
// your Kinde domain URL (e.g., "https://yourdomain.kinde.com").
//
// Parameters:
//   - issuer: The expected issuer string that must match the token's "iss" claim.
//
// Returns an Option that configures the token to validate the issuer.
//
// Example:
//
//	token, err := jwt.ParseFromString(tokenString,
//	    jwt.WillValidateWithJWKSUrl("https://yourdomain.kinde.com/.well-known/jwks.json"),
//	    jwt.WillValidateIssuer("https://yourdomain.kinde.com"),
//	)
func WillValidateIssuer(issuer string) Option {
	return func(s *Token) {
		s.processing.parsingOptions = append(s.processing.parsingOptions, golangjwt.WithIssuer(issuer))
	}
}

// WillValidateAudience configures token validation to verify that the token's
// audience (aud) claim contains the expected audience value.
//
// This option ensures that tokens were issued for the expected client/application,
// preventing tokens intended for other applications from being accepted. The audience
// is typically your Kinde client ID.
//
// Parameters:
//   - expectedAudience: The expected audience string that must be present in the
//     token's "aud" claim (which can be a single string or an array of strings).
//
// Returns an Option that configures the token to validate the audience.
//
// Example:
//
//	token, err := jwt.ParseFromString(tokenString,
//	    jwt.WillValidateWithJWKSUrl("https://yourdomain.kinde.com/.well-known/jwks.json"),
//	    jwt.WillValidateAudience("your-client-id"),
//	)
func WillValidateAudience(expectedAudience string) Option {
	return func(s *Token) {
		f := func(receivedClaims golangjwt.MapClaims) (bool, error) {
			aud, err := receivedClaims.GetAudience()
			if err != nil {
				return false, err
			}
			if !slices.Contains(aud, expectedAudience) {
				return false, fmt.Errorf("audience not valid %v", expectedAudience)
			}
			return true, nil
		}
		s.processing.validations = append(s.processing.validations, f)
	}
}

// WillValidateClaims configures token validation to use a custom function for
// validating token claims.
//
// This option provides maximum flexibility for claim validation, allowing you to
// implement any custom logic needed to validate claims beyond the standard JWT
// validations. The validation function receives all claims and can perform complex
// checks, such as validating custom claims, checking claim combinations, or
// implementing business logic.
//
// Parameters:
//   - f: A validation function that receives the token claims and returns:
//     - bool: true if validation passes, false otherwise
//     - error: an error describing why validation failed (if any)
//
//     If the function is nil, a validation error will be added to the token.
//
// Returns an Option that configures the token to use the provided validation function.
//
// Example:
//
//	token, err := jwt.ParseFromString(tokenString,
//	    jwt.WillValidateWithJWKSUrl("https://yourdomain.kinde.com/.well-known/jwks.json"),
//	    jwt.WillValidateClaims(func(claims jwt.MapClaims) (bool, error) {
//	        // Validate custom claim
//	        if role, ok := claims["role"].(string); ok {
//	            if role != "admin" && role != "user" {
//	                return false, fmt.Errorf("invalid role: %s", role)
//	            }
//	        }
//	        return true, nil
//	    }),
//	)
func WillValidateClaims(f func(golangjwt.MapClaims) (bool, error)) Option {
	return func(s *Token) {
		if f == nil {
			s.validationErrors = append(s.validationErrors, fmt.Errorf("nil claims validator"))
			return
		}
		s.processing.validations = append(s.processing.validations, f)
	}
}

// newError creates an aggregated error from a message, primary error, and additional errors.
//
// This is an internal helper function used to combine multiple validation errors
// into a single error message. It formats errors in a chain, with each error
// providing context about what failed.
//
// This function is used internally by the token parsing and validation logic
// to aggregate validation failures.
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

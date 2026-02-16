package jwt

import (
	"context"
	"encoding/json"
	"time"

	golangjwt "github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
)

// GetRawToken returns the underlying OAuth2 token structure.
//
// This provides access to the original OAuth2 token that was parsed, including
// the access token, refresh token (if available), expiration time, and any extra
// fields such as the ID token.
//
// Returns the raw OAuth2 token, or nil if the token was not initialized.
func (j *Token) GetRawToken() *oauth2.Token {
	return j.rawToken
}

// GetIdToken returns the ID token string if it exists in the OAuth2 token.
//
// The ID token is typically included in the OAuth2 token's extra fields during
// the authorization code flow. It contains user identity information and can be
// used to extract user profile data via GetUserProfile().
//
// Returns the ID token string and true if the ID token exists, or empty string
// and false if it is not present in the token.
func (j *Token) GetIdToken() (string, bool) {
	if j.rawToken == nil {
		return "", false
	}
	if token, ok := j.rawToken.Extra("id_token").(string); ok {
		return token, true
	}
	return "", false
}

// GetAccessToken returns the access token string from the OAuth2 token.
//
// The access token is the JWT that was parsed and validated. It can be used to
// make authenticated API requests to protected resources.
//
// Returns the access token string and true if the access token exists, or empty
// string and false if the token is not available.
func (j *Token) GetAccessToken() (string, bool) {
	if j.rawToken == nil {
		return "", false
	}
	return j.rawToken.AccessToken, j.rawToken.AccessToken != ""
}

// GetRefreshToken returns the refresh token string if it exists in the OAuth2 token.
//
// The refresh token can be used to obtain a new access token when the current
// access token expires, without requiring the user to re-authenticate.
//
// Returns the refresh token string and true if a refresh token exists, or empty
// string and false if no refresh token is available.
func (j *Token) GetRefreshToken() (string, bool) {
	if j.rawToken == nil {
		return "", false
	}
	return j.rawToken.RefreshToken, j.rawToken.RefreshToken != ""
}

// AsString serializes the underlying OAuth2 token to a JSON string.
//
// This is useful for storing the token in session storage or transmitting it
// as a string. The resulting JSON can be parsed back using ParseFromSessionStorage().
//
// Returns the JSON-encoded token string, or an error if JSON marshaling fails.
func (j *Token) AsString() (string, error) {
	marshalledToken, err := json.Marshal(j.rawToken)
	if err != nil {
		return "", err
	}
	return string(marshalledToken), nil
}

// IsValid returns whether the token passed all validation checks.
//
// A token is considered valid if:
//   - It was successfully parsed as a JWT
//   - All signature verification checks passed
//   - All configured validation functions returned true
//   - No validation errors occurred
//
// Returns true if the token is valid, false otherwise. For detailed error
// information, use GetValidationErrors().
func (j *Token) IsValid() bool {
	return j.isValid
}

// GetSubject returns the subject (sub) claim from the JWT token.
//
// The subject claim identifies the principal that the token is about, typically
// the user ID. This is a standard JWT claim defined in RFC 7519.
//
// Returns the subject string, or an empty string if the claim is not present
// or the token was not parsed successfully.
func (j *Token) GetSubject() string {
	if j.processing.parsed == nil || j.processing.parsed.Claims == nil {
		return ""
	}
	subject, _ := j.processing.parsed.Claims.GetSubject()
	return subject
}

// GetIssuer returns the issuer (iss) claim from the JWT token.
//
// The issuer claim identifies the principal that issued the JWT, typically the
// authorization server URL (e.g., "https://yourdomain.kinde.com"). This is a
// standard JWT claim defined in RFC 7519.
//
// Returns the issuer string, or an empty string if the claim is not present
// or the token was not parsed successfully.
func (j *Token) GetIssuer() string {
	if j.processing.parsed == nil || j.processing.parsed.Claims == nil {
		return ""
	}
	if claims, ok := j.processing.parsed.Claims.(golangjwt.MapClaims); ok {
		if issuer, exists := claims["iss"]; exists {
			if issuerStr, ok := issuer.(string); ok {
				return issuerStr
			}
		}
	}
	return ""
}

// GetAudience returns the audience (aud) claim from the JWT token.
//
// The audience claim identifies the recipients that the JWT is intended for,
// typically the client ID. This is a standard JWT claim defined in RFC 7519.
// The claim can be either a single string or an array of strings.
//
// Returns a slice of audience strings, or nil if the claim is not present
// or the token was not parsed successfully.
func (j *Token) GetAudience() []string {
	if j.processing.parsed == nil || j.processing.parsed.Claims == nil {
		return nil
	}
	if claims, ok := j.processing.parsed.Claims.(golangjwt.MapClaims); ok {
		if audience, exists := claims["aud"]; exists {
			switch aud := audience.(type) {
			case string:
				return []string{aud}
			case []interface{}:
				result := make([]string, 0, len(aud))
				for _, a := range aud {
					if aStr, ok := a.(string); ok {
						result = append(result, aStr)
					}
				}
				return result
			}
		}
	}
	return nil
}

// GetExpiration returns the expiration time (exp) claim from the JWT token.
//
// The expiration time claim identifies the time after which the JWT must not be
// accepted for processing, represented as a Unix timestamp (seconds since epoch).
// This is a standard JWT claim defined in RFC 7519.
//
// Returns the expiration timestamp and true if the claim exists, or 0 and false
// if the claim is not present or the token was not parsed successfully.
func (j *Token) GetExpiration() (int64, bool) {
	if j.processing.parsed == nil || j.processing.parsed.Claims == nil {
		return 0, false
	}
	if claims, ok := j.processing.parsed.Claims.(golangjwt.MapClaims); ok {
		if exp, exists := claims["exp"]; exists {
			switch expVal := exp.(type) {
			case float64:
				return int64(expVal), true
			case int64:
				return expVal, true
			case int:
				return int64(expVal), true
			}
		}
	}
	return 0, false
}

// GetIssuedAt returns the issued at (iat) claim from the JWT token.
//
// The issued at claim identifies the time at which the JWT was issued, represented
// as a Unix timestamp (seconds since epoch). This is a standard JWT claim defined
// in RFC 7519.
//
// Returns the issued at timestamp and true if the claim exists, or 0 and false
// if the claim is not present or the token was not parsed successfully.
func (j *Token) GetIssuedAt() (int64, bool) {
	if j.processing.parsed == nil || j.processing.parsed.Claims == nil {
		return 0, false
	}
	if claims, ok := j.processing.parsed.Claims.(golangjwt.MapClaims); ok {
		if iat, exists := claims["iat"]; exists {
			switch iatVal := iat.(type) {
			case float64:
				return int64(iatVal), true
			case int64:
				return iatVal, true
			case int:
				return int64(iatVal), true
			}
		}
	}
	return 0, false
}

// GetJWTID returns the JWT ID (jti) claim from the token.
//
// The JWT ID claim provides a unique identifier for the JWT, which can be used
// to prevent token replay attacks. This is a standard JWT claim defined in RFC 7519.
//
// Returns the JWT ID string, or an empty string if the claim is not present
// or the token was not parsed successfully.
func (j *Token) GetJWTID() string {
	if j.processing.parsed == nil || j.processing.parsed.Claims == nil {
		return ""
	}
	if claims, ok := j.processing.parsed.Claims.(golangjwt.MapClaims); ok {
		if jti, exists := claims["jti"]; exists {
			if jtiStr, ok := jti.(string); ok {
				return jtiStr
			}
		}
	}
	return ""
}

// GetPermissions returns the permissions claim of the token.
// Supports both standard "permissions" and Hasura "x-hasura-permissions" claim formats.
func (j *Token) GetPermissions() []string {
	if j.processing.parsed == nil || j.processing.parsed.Claims == nil {
		return nil
	}
	if claims, ok := j.processing.parsed.Claims.(golangjwt.MapClaims); ok {
		// Try standard permissions claim first
		if permissions, exists := claims["permissions"]; exists {
			if perms, ok := permissions.([]interface{}); ok {
				result := make([]string, 0, len(perms))
				for _, p := range perms {
					if pStr, ok := p.(string); ok {
						result = append(result, pStr)
					}
				}
				return result
			}
		}
		// Fallback to Hasura format
		if hasuraPermissions, exists := claims["x-hasura-permissions"]; exists {
			if perms, ok := hasuraPermissions.([]interface{}); ok {
				result := make([]string, 0, len(perms))
				for _, p := range perms {
					if pStr, ok := p.(string); ok {
						result = append(result, pStr)
					}
				}
				return result
			}
		}
	}
	return nil
}

// GetScopes returns the scope (scp) claim from the JWT token.
//
// The scope claim contains the OAuth2 scopes granted to the token, which define
// the permissions and access rights. Scopes are typically space-separated strings
// in OAuth2, but in JWT they are often represented as arrays.
//
// Returns a slice of scope strings, or nil if the claim is not present
// or the token was not parsed successfully.
func (j *Token) GetScopes() []string {
	if j.processing.parsed == nil || j.processing.parsed.Claims == nil {
		return nil
	}
	if claims, ok := j.processing.parsed.Claims.(golangjwt.MapClaims); ok {
		if scopes, exists := claims["scp"]; exists {
			if scps, ok := scopes.([]interface{}); ok {
				result := make([]string, 0, len(scps))
				for _, s := range scps {
					if sStr, ok := s.(string); ok {
						result = append(result, sStr)
					}
				}
				return result
			}
		}
	}
	return nil
}

// GetOrganizationCode returns the org_code claim of the token.
// Supports both standard "org_code" and Hasura "x-hasura-org-code" claim formats.
func (j *Token) GetOrganizationCode() string {
	if j.processing.parsed == nil || j.processing.parsed.Claims == nil {
		return ""
	}
	if claims, ok := j.processing.parsed.Claims.(golangjwt.MapClaims); ok {
		// Try standard org_code claim first
		if orgCode, exists := claims["org_code"]; exists {
			if orgCodeStr, ok := orgCode.(string); ok {
				return orgCodeStr
			}
		}
		// Fallback to Hasura format
		if hasuraOrgCode, exists := claims["x-hasura-org-code"]; exists {
			if orgCodeStr, ok := hasuraOrgCode.(string); ok {
				return orgCodeStr
			}
		}
	}
	return ""
}

// GetAuthorizedParty returns the authorized party (azp) claim from the JWT token.
//
// The authorized party claim identifies the party to which the JWT was issued.
// This is typically the client ID that requested the token. This claim is defined
// in the OpenID Connect specification.
//
// Returns the authorized party string, or an empty string if the claim is not present
// or the token was not parsed successfully.
func (j *Token) GetAuthorizedParty() string {
	if j.processing.parsed == nil || j.processing.parsed.Claims == nil {
		return ""
	}
	if claims, ok := j.processing.parsed.Claims.(golangjwt.MapClaims); ok {
		if azp, exists := claims["azp"]; exists {
			if azpStr, ok := azp.(string); ok {
				return azpStr
			}
		}
	}
	return ""
}

// FeatureFlag represents a single feature flag with its type and value.
type FeatureFlag struct {
	Type  string      `json:"t"`
	Value interface{} `json:"v"`
}

// GetFeatureFlags returns the feature_flags claim of the token.
// The feature flags use short codes: t=type, v=value, b=boolean, i=integer, s=string
// Supports both standard "feature_flags" and Hasura "x-hasura-feature-flags" claim formats.
func (j *Token) GetFeatureFlags() map[string]FeatureFlag {
	if j.processing.parsed == nil || j.processing.parsed.Claims == nil {
		return nil
	}
	if claims, ok := j.processing.parsed.Claims.(golangjwt.MapClaims); ok {
		// Try standard feature_flags claim first
		if featureFlags, exists := claims["feature_flags"]; exists {
			if flagsMap, ok := featureFlags.(map[string]interface{}); ok {
				return extractFeatureFlags(flagsMap)
			}
		}
		// Fallback to Hasura format
		if hasuraFeatureFlags, exists := claims["x-hasura-feature-flags"]; exists {
			if flagsMap, ok := hasuraFeatureFlags.(map[string]interface{}); ok {
				return extractFeatureFlags(flagsMap)
			}
		}
	}
	return nil
}

// extractFeatureFlags extracts feature flags from a JWT claim map.
//
// The function expects a map where each key is a feature flag code and each value
// is a map containing "t" (type) and "v" (value) fields following the Kinde feature flag format.
//
// This is an internal helper used by GetFeatureFlag and other feature flag methods.
func extractFeatureFlags(flagsMap map[string]interface{}) map[string]FeatureFlag {
	result := make(map[string]FeatureFlag)
	for key, flagData := range flagsMap {
		if flag, ok := flagData.(map[string]interface{}); ok {
			if flagType, exists := flag["t"]; exists {
				if flagValue, exists := flag["v"]; exists {
					result[key] = FeatureFlag{
						Type:  toString(flagType),
						Value: flagValue,
					}
				}
			}
		}
	}
	return result
}

// GetFeatureFlag retrieves a specific feature flag by its name/code.
//
// Feature flags are used to enable or disable features for specific users or
// organizations. This method looks up a flag by its key in the feature_flags claim.
//
// Parameters:
//   - name: The feature flag code/name to retrieve
//
// Returns the FeatureFlag and true if the flag exists, or an empty FeatureFlag
// and false if the flag is not present in the token.
func (j *Token) GetFeatureFlag(name string) (FeatureFlag, bool) {
	flags := j.GetFeatureFlags()
	if flags == nil {
		return FeatureFlag{}, false
	}
	flag, exists := flags[name]
	return flag, exists
}

// GetFeatureFlagBool retrieves a boolean feature flag value by name.
//
// This is a convenience method that retrieves a feature flag and type-checks
// that it is a boolean (type "b"). If the flag exists and is a boolean, it
// returns the boolean value.
//
// Parameters:
//   - name: The feature flag code/name to retrieve
//
// Returns the boolean value and true if the flag exists and is a boolean type,
// or false and false if the flag doesn't exist or is not a boolean.
func (j *Token) GetFeatureFlagBool(name string) (bool, bool) {
	flag, exists := j.GetFeatureFlag(name)
	if !exists || flag.Type != "b" {
		return false, false
	}
	if boolVal, ok := flag.Value.(bool); ok {
		return boolVal, true
	}
	return false, false
}

// GetFeatureFlagString retrieves a string feature flag value by name.
//
// This is a convenience method that retrieves a feature flag and type-checks
// that it is a string (type "s"). If the flag exists and is a string, it
// returns the string value.
//
// Parameters:
//   - name: The feature flag code/name to retrieve
//
// Returns the string value and true if the flag exists and is a string type,
// or empty string and false if the flag doesn't exist or is not a string.
func (j *Token) GetFeatureFlagString(name string) (string, bool) {
	flag, exists := j.GetFeatureFlag(name)
	if !exists || flag.Type != "s" {
		return "", false
	}
	if strVal, ok := flag.Value.(string); ok {
		return strVal, true
	}
	return "", false
}

// GetFeatureFlagInt retrieves an integer feature flag value by name.
//
// This is a convenience method that retrieves a feature flag and type-checks
// that it is an integer (type "i"). If the flag exists and is an integer, it
// returns the integer value. The method handles int, int64, and float64 types
// (converting float64 to int64).
//
// Parameters:
//   - name: The feature flag code/name to retrieve
//
// Returns the integer value and true if the flag exists and is an integer type,
// or 0 and false if the flag doesn't exist or is not an integer.
func (j *Token) GetFeatureFlagInt(name string) (int64, bool) {
	flag, exists := j.GetFeatureFlag(name)
	if !exists || flag.Type != "i" {
		return 0, false
	}
	switch val := flag.Value.(type) {
	case int64:
		return val, true
	case int:
		return int64(val), true
	case float64:
		return int64(val), true
	}
	return 0, false
}

// Role represents a user role with id, name, and key.
type Role struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Key  string `json:"key"`
}

// GetRoles returns the roles claim of the token.
// Supports both standard "roles" and Hasura "x-hasura-roles" claim formats.
// Returns an empty slice if no roles are found.
func (j *Token) GetRoles() []Role {
	if j.processing.parsed == nil || j.processing.parsed.Claims == nil {
		return nil
	}
	if claims, ok := j.processing.parsed.Claims.(golangjwt.MapClaims); ok {
		// Try standard roles claim first
		if roles, exists := claims["roles"]; exists {
			return extractRoles(roles)
		}
		// Fallback to Hasura format
		if hasuraRoles, exists := claims["x-hasura-roles"]; exists {
			return extractRoles(hasuraRoles)
		}
	}
	return nil
}

// extractRoles extracts roles from a JWT claim value.
//
// This function handles multiple role formats:
//   - Array of strings (e.g., ["admin", "user"]) - creates Role objects with Key only
//   - Array of role objects with "id", "key", and "name" fields
//
// This flexibility allows the SDK to work with both simplified and detailed role representations.
//
// This is an internal helper used by GetRoles and related methods.
func extractRoles(roles interface{}) []Role {
	if roles == nil {
		return nil
	}

	rolesSlice, ok := roles.([]interface{})
	if !ok {
		return nil
	}

	result := make([]Role, 0, len(rolesSlice))
	for _, r := range rolesSlice {
		switch roleVal := r.(type) {
		case string:
			// Simple string role - create Role with key only
			result = append(result, Role{
				Key: roleVal,
			})
		case map[string]interface{}:
			// Role object with id, name, key
			role := Role{}
			if id, ok := roleVal["id"].(string); ok {
				role.ID = id
			}
			if name, ok := roleVal["name"].(string); ok {
				role.Name = name
			}
			if key, ok := roleVal["key"].(string); ok {
				role.Key = key
			}
			// Only include roles with a Key, since HasRoles only checks role.Key
			if role.Key != "" {
				result = append(result, role)
			}
		}
	}
	return result
}

// HasRoles checks if the token contains any of the specified roles.
// Returns true if the user has at least one of the provided role keys.
func (j *Token) HasRoles(roleKeys ...string) bool {
	if len(roleKeys) == 0 {
		return true
	}

	roles := j.GetRoles()
	if len(roles) == 0 {
		return false
	}

	// Create a map of user role keys for efficient lookup
	userRoleKeys := make(map[string]bool, len(roles))
	for _, role := range roles {
		if role.Key != "" {
			userRoleKeys[role.Key] = true
		}
	}

	// Check if any of the requested roles exist
	for _, requestedKey := range roleKeys {
		if userRoleKeys[requestedKey] {
			return true
		}
	}

	return false
}

// UserProfile represents user profile information extracted from the ID token.
// It contains the core user identity and profile claims defined in the OpenID Connect specification.
type UserProfile struct {
	// ID is the unique identifier for the user (from the "sub" claim).
	// This is the primary key that should be used to identify the user in your application.
	ID string
	// GivenName is the user's first name or given name (from the "given_name" claim).
	GivenName string
	// FamilyName is the user's last name or family name (from the "family_name" claim).
	FamilyName string
	// Email is the user's email address (from the "email" claim).
	Email string
	// Picture is the URL to the user's profile picture (from the "picture" claim).
	Picture string
}

// GetUserProfile extracts user profile information from the ID token.
//
// The method parses the ID token without validation since the token has already been
// validated as part of the OAuth flow. It extracts standard OpenID Connect claims
// including the subject (user ID), given name, family name, email, and picture URL.
//
// The subject (sub) claim is required - if it's missing or empty, the method returns nil.
// All other profile fields are optional and will be empty strings if not present in the token.
//
// Returns nil if:
//   - The ID token is not available in the OAuth2 token
//   - The ID token cannot be parsed
//   - The subject (sub) claim is missing or empty
//
// Returns a UserProfile pointer containing the extracted profile information otherwise.
func (j *Token) GetUserProfile() *UserProfile {
	idTokenStr, exists := j.GetIdToken()
	if !exists || idTokenStr == "" {
		return nil
	}

	// Parse the ID token without validation (it's already validated in OAuth flow)
	claims, err := ParseIDTokenUnverified(idTokenStr)
	if err != nil {
		return nil
	}

	if claims == nil {
		return nil
	}

	profile := &UserProfile{}

	// Extract subject (user ID) - required
	if sub, ok := claims["sub"].(string); ok && sub != "" {
		profile.ID = sub
	} else {
		// Subject is required
		return nil
	}

	// Extract optional fields
	if givenName, ok := claims["given_name"].(string); ok {
		profile.GivenName = givenName
	}
	if familyName, ok := claims["family_name"].(string); ok {
		profile.FamilyName = familyName
	}
	if email, ok := claims["email"].(string); ok {
		profile.Email = email
	}
	if picture, ok := claims["picture"].(string); ok {
		profile.Picture = picture
	}

	return profile
}

// GetClaim retrieves a specific claim value from the token by key.
//
// This method provides direct access to any claim in the JWT, including both
// standard claims (sub, iss, aud, exp, etc.) and custom claims. The returned
// value is an interface{} that may need type assertion based on the expected
// claim type.
//
// Parameters:
//   - key: The claim key to retrieve (e.g., "sub", "permissions", "custom_claim")
//
// Returns the claim value and true if the claim exists, or nil and false if
// the claim is not present or the token was not parsed successfully.
func (j *Token) GetClaim(key string) (interface{}, bool) {
	if j.processing.parsed == nil || j.processing.parsed.Claims == nil {
		return nil, false
	}
	if claims, ok := j.processing.parsed.Claims.(golangjwt.MapClaims); ok {
		value, exists := claims[key]
		return value, exists
	}
	return nil, false
}

// GetUserOrganizations returns all organization codes that the user belongs to.
//
// The method parses the ID token without validation since the token has already been
// validated as part of the OAuth flow. It looks for organization codes in two possible
// claim formats:
//   - "org_codes" - Standard Kinde claim format (checked first)
//   - "x-hasura-org-codes" - Hasura integration format (fallback)
//
// The organization codes are extracted from whichever claim is present, and returned
// as a slice of strings. Each string represents a unique organization identifier.
//
// Returns nil if:
//   - The ID token is not available in the OAuth2 token
//   - The ID token cannot be parsed
//   - Neither org_codes nor x-hasura-org-codes claims are present
//
// Returns a string slice containing organization codes otherwise.
func (j *Token) GetUserOrganizations() []string {
	idTokenStr, exists := j.GetIdToken()
	if !exists || idTokenStr == "" {
		return nil
	}

	// Parse the ID token without validation (it's already validated in OAuth flow)
	claims, err := ParseIDTokenUnverified(idTokenStr)
	if err != nil {
		return nil
	}

	if claims == nil {
		return nil
	}

	// Try standard org_codes claim first
	if orgCodes, exists := claims["org_codes"]; exists {
		return extractStringArray(orgCodes)
	}

	// Fallback to Hasura format
	if hasuraOrgCodes, exists := claims["x-hasura-org-codes"]; exists {
		return extractStringArray(hasuraOrgCodes)
	}

	return nil
}

// extractStringArray extracts a string array from an interface{} value.
//
// This function handles multiple array formats:
//   - []string - returned directly
//   - []interface{} - each element is type-asserted to string
//
// Non-string elements in []interface{} arrays are silently skipped.
//
// This is an internal helper used by GetUserOrganizations and other array extraction methods.
func extractStringArray(value interface{}) []string {
	if value == nil {
		return nil
	}

	switch arr := value.(type) {
	case []string:
		return arr
	case []interface{}:
		result := make([]string, 0, len(arr))
		for _, item := range arr {
			if str, ok := item.(string); ok {
				result = append(result, str)
			}
		}
		return result
	}

	return nil
}

// toString converts an interface{} value to a string safely.
//
// This is an internal helper function used for type-safe string conversion.
// It handles nil values gracefully and only converts values that are already strings.
// Non-string values are returned as empty strings.
//
// This function is used internally by feature flag extraction and other claim parsing logic.
func toString(v interface{}) string {
	if v == nil {
		return ""
	}
	if str, ok := v.(string); ok {
		return str
	}
	return ""
}

// GetClaims returns all claims from the JWT token as a map.
//
// This method provides direct access to the entire claims map, allowing you to
// inspect all claims in the token, including standard JWT claims and any custom
// claims that were included.
//
// Returns a map of all claims, or an empty map if the token was not parsed
// successfully. The map keys are claim names (strings) and values are the
// claim values (interface{}).
func (j *Token) GetClaims() map[string]any {
	if j.processing.parsed == nil {
		return make(map[string]any)
	}
	if claims, ok := j.processing.parsed.Claims.(golangjwt.MapClaims); ok {
		return claims
	}
	return make(map[string]any)
}

// GetValidationErrors returns an aggregated error containing all validation errors
// that occurred during token parsing and validation.
//
// If the token was parsed and validated successfully, this method returns nil.
// If validation failed, it returns an error that aggregates all validation failures,
// which may include:
//   - Signature verification failures
//   - Expired token errors
//   - Invalid issuer errors
//   - Invalid audience errors
//   - Custom claim validation failures
//   - Algorithm mismatch errors
//
// Use this method to get detailed information about why a token validation failed,
// especially when IsValid() returns false.
//
// Returns nil if there are no validation errors, or an aggregated error containing
// all validation failures.
func (j *Token) GetValidationErrors() error {
	if len(j.validationErrors) == 0 {
		return nil
	}
	return newError("token validation errors", nil, j.validationErrors...)
}

// IsTokenExpired checks if the token is expired, optionally considering a threshold.
//
// The threshold parameter allows you to consider a token expired before its actual
// expiration time. This is useful for refreshing tokens proactively to avoid
// expiration during API calls.
//
// Parameters:
//   - threshold: Optional threshold in seconds. If provided, the token is considered
//     expired if it will expire within this many seconds. Defaults to 0 (only check actual expiration).
//
// Returns true if the token is expired (or will expire within the threshold),
// false otherwise. Returns true if the expiration claim is missing or invalid.
func (j *Token) IsTokenExpired(threshold int64) bool {
	exp, exists := j.GetExpiration()
	if !exists {
		// If no expiration claim, consider it expired for safety
		return true
	}

	// Get current time
	now := time.Now().Unix()

	// Check if expired (with threshold)
	return exp < (now + threshold)
}

// IsAuthenticatedOptions contains options for checking authentication status.
type IsAuthenticatedOptions struct {
	// UseRefreshToken, if true, attempts to refresh the token if it's expired.
	// This requires a token source that supports refresh (e.g., AuthorizationCodeFlow).
	UseRefreshToken bool
	// ExpiredThreshold is the threshold in seconds to consider a token expired.
	// If the token will expire within this many seconds, it's considered expired.
	ExpiredThreshold int64
}

// IsAuthenticated checks if the user is authenticated based on the token.
//
// If UseRefreshToken is true and the token is expired, this method will attempt
// to refresh the token using the provided token source. This is useful for
// automatically refreshing tokens before they expire.
//
// Note: This method requires a token source that supports refresh (e.g., from
// AuthorizationCodeFlow). If UseRefreshToken is true but no refresh mechanism
// is available, it will only check if the token is currently valid.
//
// Parameters:
//   - ctx: Context for the request (used for token refresh if needed)
//   - options: Configuration options for the authentication check
//
// Returns true if the user is authenticated (token is valid or was successfully refreshed),
// false otherwise.
func (j *Token) IsAuthenticated(ctx context.Context, options IsAuthenticatedOptions) bool {
	isExpired := j.IsTokenExpired(options.ExpiredThreshold)

	if !isExpired {
		return true
	}

	// If expired and refresh is requested, we would need a token source
	// For now, we'll just return false as token refresh requires flow context
	// This can be enhanced later with a token source interface
	if options.UseRefreshToken {
		// Token refresh would need to be implemented at the flow level
		// For now, return false if expired
		return false
	}

	return false
}

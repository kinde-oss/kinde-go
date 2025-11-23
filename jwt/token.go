package jwt

import (
	"encoding/json"

	golangjwt "github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
)

// GetRawToken returns the raw token.
func (j *Token) GetRawToken() *oauth2.Token {
	return j.rawToken
}

// GetIdToken returns the ID token if it exists.
func (j *Token) GetIdToken() (string, bool) {
	if j.rawToken == nil {
		return "", false
	}
	if token, ok := j.rawToken.Extra("id_token").(string); ok {
		return token, true
	}
	return "", false
}

// GetAccessToken returns the access token.
func (j *Token) GetAccessToken() (string, bool) {
	if j.rawToken == nil {
		return "", false
	}
	return j.rawToken.AccessToken, j.rawToken.AccessToken != ""
}

// GetRefreshToken returns the refresh token if it exists.
func (j *Token) GetRefreshToken() (string, bool) {
	if j.rawToken == nil {
		return "", false
	}
	return j.rawToken.RefreshToken, j.rawToken.RefreshToken != ""
}

// AsString returns the token as a JSON string.
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

// GetSubject returns the sub claim of the token.
func (j *Token) GetSubject() string {
	if j.processing.parsed == nil || j.processing.parsed.Claims == nil {
		return ""
	}
	subject, _ := j.processing.parsed.Claims.GetSubject()
	return subject
}

// GetIssuer returns the iss claim of the token.
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

// GetAudience returns the aud claim of the token.
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

// GetExpiration returns the exp claim of the token.
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

// GetIssuedAt returns the iat claim of the token.
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

// GetJWTID returns the jti claim of the token.
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

// GetScopes returns the scp claim of the token.
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

// GetAuthorizedParty returns the azp claim of the token.
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

// extractFeatureFlags extracts feature flags from a map.
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

// GetFeatureFlag returns a specific feature flag by name.
func (j *Token) GetFeatureFlag(name string) (FeatureFlag, bool) {
	flags := j.GetFeatureFlags()
	if flags == nil {
		return FeatureFlag{}, false
	}
	flag, exists := flags[name]
	return flag, exists
}

// GetFeatureFlagBool returns a boolean feature flag value.
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

// GetFeatureFlagString returns a string feature flag value.
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

// GetFeatureFlagInt returns an integer feature flag value.
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

// extractRoles extracts roles from a claim value.
// Handles both array of strings and array of role objects.
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
			// If we have at least a key or id, add the role
			if role.Key != "" || role.ID != "" {
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

// UserProfile represents user profile information from the ID token.
type UserProfile struct {
	ID         string
	GivenName  string
	FamilyName string
	Email      string
	Picture    string
}

// GetUserProfile extracts user profile information from the ID token.
// Returns nil if the ID token is not available or doesn't contain required claims.
// The ID token is parsed without validation since it's already been validated
// as part of the OAuth flow.
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
// Returns the value and a boolean indicating if the claim exists.
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

// GetUserOrganizations returns all organization codes the user belongs to.
// Extracts from the ID token's org_codes or x-hasura-org-codes claim.
// Returns nil if the ID token is not available or doesn't contain organization codes.
// The ID token is parsed without validation since it's already been validated
// as part of the OAuth flow.
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

// toString converts interface{} to string safely.
func toString(v interface{}) string {
	if v == nil {
		return ""
	}
	if str, ok := v.(string); ok {
		return str
	}
	return ""
}

// GetClaims returns the claims of the token.
func (j *Token) GetClaims() map[string]any {
	if j.processing.parsed == nil {
		return make(map[string]any)
	}
	if claims, ok := j.processing.parsed.Claims.(golangjwt.MapClaims); ok {
		return claims
	}
	return make(map[string]any)
}

func (j *Token) GetValidationErrors() error {
	return newError("token validation errors", nil, j.validationErrors...)
}

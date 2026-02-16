package jwt

import (
	"context"
	"fmt"

	"github.com/kinde-oss/kinde-go/kinde/account_api"
)

// GetPermissionsOptions contains options for GetPermissionsWithAPI.
// It controls whether to fetch permissions from the Account API or the token.
type GetPermissionsOptions struct {
	// ForceAPI when true, forces fetching permissions from the Account API instead of the token.
	// When false, permissions are read from the access token claims.
	ForceAPI bool
}

// PermissionsWithOrg represents permissions associated with an organization.
// It contains both the organization code and the list of permission strings
// that the user has within that organization.
type PermissionsWithOrg struct {
	// OrgCode is the unique identifier for the organization.
	OrgCode string
	// Permissions is a list of permission strings (e.g., "read:users", "write:posts")
	// that the user has been granted within the organization.
	Permissions []string
}

// GetPermissionsWithAPI retrieves user permissions either from the access token or the Account API.
//
// If options.ForceAPI is false, permissions are extracted from the access token's claims,
// which is faster but may not reflect the most recent permission changes.
//
// If options.ForceAPI is true, permissions are fetched from the Kinde Account API with
// automatic pagination support, ensuring the most up-to-date permission data.
//
// The method returns a PermissionsWithOrg structure containing both the organization code
// and the list of permission strings.
//
// Parameters:
//   - ctx: Context for the API request (only used when ForceAPI is true)
//   - apiClient: The Account API client for making requests (only used when ForceAPI is true)
//   - options: Configuration options controlling the fetch behavior
//
// Returns an error if the API request fails (when ForceAPI is true).
func (j *Token) GetPermissionsWithAPI(ctx context.Context, apiClient *account_api.Client, options GetPermissionsOptions) (*PermissionsWithOrg, error) {
	if !options.ForceAPI {
		// Read from token
		permissions := j.GetPermissions()
		orgCode := j.GetOrganizationCode()
		return &PermissionsWithOrg{
			OrgCode:     orgCode,
			Permissions: permissions,
		}, nil
	}

	// Fetch from Account API
	type AccountPermissionsData struct {
		OrgCode     string `json:"org_code"`
		Permissions []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
			Key  string `json:"key"`
		} `json:"permissions"`
	}

	var result AccountPermissionsData
	if err := apiClient.CallAccountAPIPaginated(ctx, "account_api/v1/permissions", &result); err != nil {
		return nil, fmt.Errorf("failed to fetch permissions from API: %w", err)
	}

	permissions := make([]string, 0, len(result.Permissions))
	for _, perm := range result.Permissions {
		permissions = append(permissions, perm.Key)
	}

	return &PermissionsWithOrg{
		OrgCode:     result.OrgCode,
		Permissions: permissions,
	}, nil
}

// GetRolesWithAPI retrieves user roles either from the access token or the Account API.
//
// If forceAPI is false, roles are extracted from the access token's claims,
// supporting both standard "roles" and Hasura "x-hasura-roles" claim formats.
//
// If forceAPI is true, roles are fetched from the Kinde Account API with
// automatic pagination support, ensuring the most up-to-date role data.
//
// The method returns a slice of Role objects, each containing the role's key and name.
//
// Parameters:
//   - ctx: Context for the API request (only used when forceAPI is true)
//   - apiClient: The Account API client for making requests (only used when forceAPI is true)
//   - forceAPI: When true, forces fetching from the Account API instead of the token
//
// Returns an error if the API request fails (when forceAPI is true).
func (j *Token) GetRolesWithAPI(ctx context.Context, apiClient *account_api.Client, forceAPI bool) ([]Role, error) {
	if !forceAPI {
		// Read from token
		return j.GetRoles(), nil
	}

	// Fetch from Account API
	type AccountRolesData struct {
		OrgCode string `json:"org_code"`
		Roles   []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
			Key  string `json:"key"`
		} `json:"roles"`
	}

	var result AccountRolesData
	if err := apiClient.CallAccountAPIPaginated(ctx, "account_api/v1/roles", &result); err != nil {
		return nil, fmt.Errorf("failed to fetch roles from API: %w", err)
	}

	roles := make([]Role, 0, len(result.Roles))
	for _, role := range result.Roles {
		roles = append(roles, Role{
			ID:   role.ID,
			Name: role.Name,
			Key:  role.Key,
		})
	}

	return roles, nil
}

// GetFeatureFlagsWithAPI retrieves feature flags either from the access token or the Account API.
//
// If forceAPI is false, feature flags are extracted from the access token's claims,
// supporting both standard "feature_flags" and Hasura "x-hasura-feature-flags" claim formats.
//
// If forceAPI is true, feature flags are fetched from the Kinde Account API with
// automatic pagination support, ensuring the most up-to-date feature flag data.
//
// The method returns a map of feature flag codes to FeatureFlag objects, each containing
// the flag's code, type, and value.
//
// Parameters:
//   - ctx: Context for the API request (only used when forceAPI is true)
//   - apiClient: The Account API client for making requests (only used when forceAPI is true)
//   - forceAPI: When true, forces fetching from the Account API instead of the token
//
// Returns an error if the API request fails (when forceAPI is true).
func (j *Token) GetFeatureFlagsWithAPI(ctx context.Context, apiClient *account_api.Client, forceAPI bool) (map[string]FeatureFlag, error) {
	if !forceAPI {
		// Read from token
		return j.GetFeatureFlags(), nil
	}

	// Fetch from Account API
	type AccountFeatureFlagsData struct {
		FeatureFlags []struct {
			ID    string      `json:"id"`
			Name  string      `json:"name"`
			Key   string      `json:"key"`
			Type  string      `json:"type"`
			Value interface{} `json:"value"`
		} `json:"feature_flags"`
	}

	var result AccountFeatureFlagsData
	if err := apiClient.CallAccountAPIPaginated(ctx, "account_api/v1/feature_flags", &result); err != nil {
		return nil, fmt.Errorf("failed to fetch feature flags from API: %w", err)
	}

	flags := make(map[string]FeatureFlag)
	for _, flag := range result.FeatureFlags {
		flags[flag.Key] = FeatureFlag{
			Type:  flag.Type,
			Value: flag.Value,
		}
	}

	return flags, nil
}

// Entitlement represents a billing entitlement assigned to an organization.
// It defines access to features and their associated billing information.
type Entitlement struct {
	// ID is the unique identifier for this entitlement.
	ID string
	// FixedCharge is the fixed charge amount for this entitlement.
	FixedCharge float64
	// PriceName is the display name of the pricing tier or plan.
	PriceName string
	// UnitAmount is the per-unit charge amount for usage-based billing.
	UnitAmount float64
	// FeatureKey is the unique key identifying the feature this entitlement grants access to.
	FeatureKey string
	// FeatureName is the human-readable name of the feature.
	FeatureName string
	// EntitlementLimitMax is the maximum usage limit for this entitlement (0 = unlimited).
	EntitlementLimitMax int
	// EntitlementLimitMin is the minimum usage limit for this entitlement.
	EntitlementLimitMin int
}

// Plan represents a subscription plan that an organization is subscribed to.
type Plan struct {
	// Key is the unique identifier for the subscription plan.
	Key string
	// SubscribedOn is the ISO 8601 timestamp when the organization subscribed to this plan.
	SubscribedOn string
}

// EntitlementsResult represents the complete billing entitlements information for an organization.
// It includes the organization code, active subscription plans, and all entitlements.
type EntitlementsResult struct {
	// OrgCode is the unique identifier for the organization.
	OrgCode string
	// Plans is the list of subscription plans the organization is currently subscribed to.
	Plans []Plan
	// Entitlements is the list of all billing entitlements granted to the organization.
	Entitlements []Entitlement
}

// GetEntitlements fetches billing entitlements from the Kinde Account API.
//
// Note: Entitlements are always fetched from the API and are never included in the token,
// as they contain sensitive billing information that may change frequently.
//
// The method automatically handles pagination to retrieve all entitlements if there
// are multiple pages of results.
//
// Parameters:
//   - ctx: Context for the API request
//   - apiClient: The Account API client for making authenticated requests
//
// Returns EntitlementsResult containing the organization code, active plans,
// and all entitlements, or an error if the API request fails.
func (j *Token) GetEntitlements(ctx context.Context, apiClient *account_api.Client) (*EntitlementsResult, error) {
	type AccountEntitlementsData struct {
		OrgCode      string `json:"org_code"`
		Plans        []struct {
			Key          string `json:"key"`
			SubscribedOn string `json:"subscribed_on"`
		} `json:"plans"`
		Entitlements []struct {
			ID                 string  `json:"id"`
			FixedCharge        float64 `json:"fixed_charge"`
			PriceName          string  `json:"price_name"`
			UnitAmount         float64 `json:"unit_amount"`
			FeatureKey         string  `json:"feature_key"`
			FeatureName        string  `json:"feature_name"`
			EntitlementLimitMax int     `json:"entitlement_limit_max"`
			EntitlementLimitMin int     `json:"entitlement_limit_min"`
		} `json:"entitlements"`
	}

	var result AccountEntitlementsData
	if err := apiClient.CallAccountAPIPaginated(ctx, "account_api/v1/entitlements", &result); err != nil {
		return nil, fmt.Errorf("failed to fetch entitlements from API: %w", err)
	}

	plans := make([]Plan, 0, len(result.Plans))
	for _, plan := range result.Plans {
		plans = append(plans, Plan{
			Key:          plan.Key,
			SubscribedOn: plan.SubscribedOn,
		})
	}

	entitlements := make([]Entitlement, 0, len(result.Entitlements))
	for _, ent := range result.Entitlements {
		entitlements = append(entitlements, Entitlement{
			ID:                 ent.ID,
			FixedCharge:        ent.FixedCharge,
			PriceName:          ent.PriceName,
			UnitAmount:         ent.UnitAmount,
			FeatureKey:          ent.FeatureKey,
			FeatureName:        ent.FeatureName,
			EntitlementLimitMax: ent.EntitlementLimitMax,
			EntitlementLimitMin: ent.EntitlementLimitMin,
		})
	}

	return &EntitlementsResult{
		OrgCode:      result.OrgCode,
		Plans:        plans,
		Entitlements: entitlements,
	}, nil
}


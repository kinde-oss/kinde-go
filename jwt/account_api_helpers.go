package jwt

import (
	"context"
	"fmt"
	"net/url"

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
		OrgCode string `json:"org_code"`
		Plans   []struct {
			Key          string `json:"key"`
			SubscribedOn string `json:"subscribed_on"`
		} `json:"plans"`
		Entitlements []struct {
			ID                  string  `json:"id"`
			FixedCharge         float64 `json:"fixed_charge"`
			PriceName           string  `json:"price_name"`
			UnitAmount          float64 `json:"unit_amount"`
			FeatureKey          string  `json:"feature_key"`
			FeatureName         string  `json:"feature_name"`
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
			ID:                  ent.ID,
			FixedCharge:         ent.FixedCharge,
			PriceName:           ent.PriceName,
			UnitAmount:          ent.UnitAmount,
			FeatureKey:          ent.FeatureKey,
			FeatureName:         ent.FeatureName,
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

// PermissionAccess represents the access status for a specific permission.
// It contains the permission key, organization code, and whether the permission is granted.
type PermissionAccess struct {
	// PermissionKey is the key of the permission being checked.
	PermissionKey string
	// OrgCode is the organization code associated with the permission, or empty if not applicable.
	OrgCode string
	// IsGranted indicates whether the user has been granted this permission.
	IsGranted bool
}

// GetPermissionOptions contains options for GetPermission.
type GetPermissionOptions struct {
	// ForceAPI when true, forces fetching the permission from the Account API instead of the token.
	// When false, the permission is checked against the access token claims.
	ForceAPI bool
}

// GetPermission checks if a specific permission is granted to the user.
//
// If options.ForceAPI is false, the permission is checked against the access token's claims,
// which is faster but may not reflect the most recent permission changes.
//
// If options.ForceAPI is true, the permission is fetched from the Kinde Account API,
// ensuring the most up-to-date permission data.
//
// Parameters:
//   - ctx: Context for the API request (only used when ForceAPI is true)
//   - apiClient: The Account API client for making requests (only used when ForceAPI is true)
//   - permissionKey: The key of the permission to check (e.g., "read:users", "write:posts")
//   - options: Configuration options controlling the fetch behavior
//
// Returns PermissionAccess containing the permission key, organization code, and grant status,
// or an error if the API request fails (when ForceAPI is true).
func (j *Token) GetPermission(ctx context.Context, apiClient *account_api.Client, permissionKey string, options GetPermissionOptions) (*PermissionAccess, error) {
	if !options.ForceAPI {
		// Read from token
		permissions := j.GetPermissions()
		orgCode := j.GetOrganizationCode()
		isGranted := false
		for _, perm := range permissions {
			if perm == permissionKey {
				isGranted = true
				break
			}
		}
		return &PermissionAccess{
			PermissionKey: permissionKey,
			OrgCode:       orgCode,
			IsGranted:     isGranted,
		}, nil
	}

	// Fetch from Account API
	route := fmt.Sprintf("account_api/v1/permission/%s", url.PathEscape(permissionKey))
	type AccountPermissionData struct {
		OrgCode    string `json:"org_code"`
		IsGranted  bool   `json:"is_granted"`
		Permission *struct {
			ID   string `json:"id"`
			Name string `json:"name"`
			Key  string `json:"key"`
		} `json:"permission,omitempty"`
	}

	var result AccountPermissionData
	if err := apiClient.CallAccountAPI(ctx, route, &result); err != nil {
		return nil, fmt.Errorf("failed to fetch permission from API: %w", err)
	}

	return &PermissionAccess{
		PermissionKey: permissionKey,
		OrgCode:       result.OrgCode,
		IsGranted:     result.IsGranted,
	}, nil
}

// GetFlag retrieves a specific feature flag by key.
//
// If forceAPI is false, the feature flag is extracted from the access token's claims,
// supporting both standard "feature_flags" and Hasura "x-hasura-feature-flags" claim formats.
// The parameter should be the feature flag key (not the display name).
//
// If forceAPI is true, the feature flag is fetched from the Kinde Account API,
// ensuring the most up-to-date feature flag data. The parameter should be the feature flag key
// (matching the "key" field from the API response, not the "name" field).
//
// Note: For consistency, both token and API lookups use the feature flag key. The key is the
// unique identifier used in tokens, while "name" is the human-readable display name.
//
// Parameters:
//   - ctx: Context for the API request (only used when forceAPI is true)
//   - apiClient: The Account API client for making requests (only used when forceAPI is true)
//   - key: The key of the feature flag to retrieve (not the display name)
//   - forceAPI: When true, forces fetching from the Account API instead of the token
//
// Returns the feature flag value (which can be string, boolean, number, or object),
// or nil if the flag is not found. Returns an error if the API request fails (when forceAPI is true).
func (j *Token) GetFlag(ctx context.Context, apiClient *account_api.Client, key string, forceAPI bool) (interface{}, error) {
	if !forceAPI {
		// Read from token - lookup by key
		flags := j.GetFeatureFlags()
		if flag, exists := flags[key]; exists {
			return flag.Value, nil
		}
		return nil, nil
	}

	// Fetch from Account API
	var result struct {
		FeatureFlags []struct {
			ID    string      `json:"id"`
			Name  string      `json:"name"`
			Key   string      `json:"key"`
			Type  string      `json:"type"`
			Value interface{} `json:"value"`
		} `json:"feature_flags"`
	}

	if err := apiClient.CallAccountAPIPaginated(ctx, "account_api/v1/feature_flags", &result); err != nil {
		return nil, fmt.Errorf("failed to fetch feature flags from API: %w", err)
	}

	// Find the flag by key (for consistency with token lookup)
	for _, flag := range result.FeatureFlags {
		if flag.Key == key {
			return flag.Value, nil
		}
	}

	return nil, nil
}

// GetEntitlement fetches a single billing entitlement by key from the Kinde Account API.
//
// Note: Entitlements are always fetched from the API and are never included in the token,
// as they contain sensitive billing information that may change frequently.
//
// Parameters:
//   - ctx: Context for the API request
//   - apiClient: The Account API client for making authenticated requests
//   - key: The entitlement key to fetch
//
// Returns Entitlement containing the entitlement details, or an error if the API request fails.
func (j *Token) GetEntitlement(ctx context.Context, apiClient *account_api.Client, key string) (*Entitlement, error) {
	route := fmt.Sprintf("account_api/v1/entitlement/%s", url.PathEscape(key))
	type AccountEntitlementData struct {
		OrgCode     string `json:"org_code"`
		Entitlement struct {
			ID                  string  `json:"id"`
			FixedCharge         float64 `json:"fixed_charge"`
			PriceName           string  `json:"price_name"`
			UnitAmount          float64 `json:"unit_amount"`
			FeatureKey          string  `json:"feature_key"`
			FeatureName         string  `json:"feature_name"`
			EntitlementLimitMax int     `json:"entitlement_limit_max"`
			EntitlementLimitMin int     `json:"entitlement_limit_min"`
		} `json:"entitlement"`
	}

	var result AccountEntitlementData
	if err := apiClient.CallAccountAPI(ctx, route, &result); err != nil {
		return nil, fmt.Errorf("failed to fetch entitlement from API: %w", err)
	}

	return &Entitlement{
		ID:                  result.Entitlement.ID,
		FixedCharge:         result.Entitlement.FixedCharge,
		PriceName:           result.Entitlement.PriceName,
		UnitAmount:          result.Entitlement.UnitAmount,
		FeatureKey:          result.Entitlement.FeatureKey,
		FeatureName:         result.Entitlement.FeatureName,
		EntitlementLimitMax: result.Entitlement.EntitlementLimitMax,
		EntitlementLimitMin: result.Entitlement.EntitlementLimitMin,
	}, nil
}

// PermissionCondition is a function type for custom permission validation.
// It receives the permission key and organization code, and returns whether the condition is met.
type PermissionCondition func(permissionKey string, orgCode string) bool

// HasPermissionsOptions contains options for HasPermissions.
type HasPermissionsOptions struct {
	// ForceAPI when true, forces fetching permissions from the Account API instead of the token.
	ForceAPI bool
	// CustomConditions is a map of permission keys to custom validation functions.
	// If a permission key has a custom condition, it will be called to validate the permission.
	CustomConditions map[string]PermissionCondition
}

// HasPermissions checks if the user has all of the specified permissions.
//
// If options.ForceAPI is false, permissions are checked against the access token's claims.
// If options.ForceAPI is true, permissions are fetched from the Kinde Account API.
//
// Custom conditions can be provided for each permission to perform additional validation
// beyond simple existence checks (e.g., checking organization context, custom business logic).
//
// Parameters:
//   - ctx: Context for the API request (only used when ForceAPI is true)
//   - apiClient: The Account API client for making requests (only used when ForceAPI is true)
//   - permissionKeys: The list of permission keys to check
//   - options: Configuration options controlling the check behavior
//
// Returns true if all permissions are granted (and pass custom conditions if provided),
// false otherwise. Returns an error if the API request fails (when ForceAPI is true).
func (j *Token) HasPermissions(ctx context.Context, apiClient *account_api.Client, permissionKeys []string, options HasPermissionsOptions) (bool, error) {
	if len(permissionKeys) == 0 {
		return true, nil
	}

	var permissionsWithOrg *PermissionsWithOrg
	var err error

	if options.ForceAPI {
		permissionsWithOrg, err = j.GetPermissionsWithAPI(ctx, apiClient, GetPermissionsOptions{ForceAPI: true})
		if err != nil {
			return false, fmt.Errorf("failed to get permissions: %w", err)
		}
	} else {
		permissionsWithOrg, err = j.GetPermissionsWithAPI(ctx, apiClient, GetPermissionsOptions{ForceAPI: false})
		if err != nil {
			return false, fmt.Errorf("failed to get permissions: %w", err)
		}
	}

	// Create a map for efficient lookup
	permissionMap := make(map[string]bool, len(permissionsWithOrg.Permissions))
	for _, perm := range permissionsWithOrg.Permissions {
		permissionMap[perm] = true
	}

	// Check each permission
	for _, permissionKey := range permissionKeys {
		hasPermission := permissionMap[permissionKey]
		if !hasPermission {
			return false, nil
		}

		// Apply custom condition if provided
		if condition, hasCondition := options.CustomConditions[permissionKey]; hasCondition {
			if !condition(permissionKey, permissionsWithOrg.OrgCode) {
				return false, nil
			}
		}
	}

	return true, nil
}

// RoleCondition is a function type for custom role validation.
// It receives the role and returns whether the condition is met.
type RoleCondition func(role Role) bool

// HasRolesOptions contains options for HasRoles.
type HasRolesOptions struct {
	// ForceAPI when true, forces fetching roles from the Account API instead of the token.
	ForceAPI bool
	// CustomConditions is a map of role keys to custom validation functions.
	// If a role key has a custom condition, it will be called to validate the role.
	CustomConditions map[string]RoleCondition
}

// HasRolesWithAPI checks if the user has all of the specified roles.
//
// If options.ForceAPI is false, roles are checked against the access token's claims.
// If options.ForceAPI is true, roles are fetched from the Kinde Account API.
//
// Custom conditions can be provided for each role to perform additional validation
// beyond simple existence checks (e.g., checking role properties, custom business logic).
//
// This is an enhanced version of HasRoles that supports API fetching and custom conditions.
// Use the simpler HasRoles() method if you only need basic token-based role checking.
//
// Parameters:
//   - ctx: Context for the API request (only used when ForceAPI is true)
//   - apiClient: The Account API client for making requests (only used when ForceAPI is true)
//   - roleKeys: The list of role keys to check
//   - options: Configuration options controlling the check behavior
//
// Returns true if all roles are present (and pass custom conditions if provided),
// false otherwise. Returns an error if the API request fails (when ForceAPI is true).
func (j *Token) HasRolesWithAPI(ctx context.Context, apiClient *account_api.Client, roleKeys []string, options HasRolesOptions) (bool, error) {
	if len(roleKeys) == 0 {
		return true, nil
	}

	var roles []Role
	var err error

	if options.ForceAPI {
		roles, err = j.GetRolesWithAPI(ctx, apiClient, true)
		if err != nil {
			return false, fmt.Errorf("failed to get roles: %w", err)
		}
	} else {
		roles, err = j.GetRolesWithAPI(ctx, apiClient, false)
		if err != nil {
			return false, fmt.Errorf("failed to get roles: %w", err)
		}
	}

	// Create a map for efficient lookup
	roleMap := make(map[string]Role, len(roles))
	for _, role := range roles {
		roleMap[role.Key] = role
	}

	// Check each role
	for _, roleKey := range roleKeys {
		role, hasRole := roleMap[roleKey]
		if !hasRole {
			return false, nil
		}

		// Apply custom condition if provided
		if condition, hasCondition := options.CustomConditions[roleKey]; hasCondition {
			if !condition(role) {
				return false, nil
			}
		}
	}

	return true, nil
}

// FeatureFlagCondition represents a condition for checking feature flags.
// It can be either a simple existence check or a value comparison.
type FeatureFlagCondition struct {
	// Value, if set, requires the flag to have this specific value.
	// If nil, only checks for existence.
	Value interface{}
}

// HasFeatureFlagsOptions contains options for HasFeatureFlags.
type HasFeatureFlagsOptions struct {
	// ForceAPI when true, forces fetching feature flags from the Account API instead of the token.
	ForceAPI bool
	// Conditions is a map of feature flag keys to their validation conditions.
	// The keys should match the feature flag keys (not display names), consistent with GetFlag().
	// If a condition has a Value set, the flag must match that value.
	// If Value is nil, only checks for existence.
	Conditions map[string]FeatureFlagCondition
}

// HasFeatureFlags checks if the user has all of the specified feature flags.
//
// If options.ForceAPI is false, feature flags are checked against the access token's claims.
// If options.ForceAPI is true, feature flags are fetched from the Kinde Account API.
//
// Conditions can be provided for each flag to check for specific values
// (e.g., flag must equal "enabled" or a specific number).
//
// Note: The parameter should be feature flag keys (not display names), consistent with GetFlag().
// The key is the unique identifier used in tokens, while "name" is the human-readable display name.
//
// Parameters:
//   - ctx: Context for the API request (only used when ForceAPI is true)
//   - apiClient: The Account API client for making requests (only used when ForceAPI is true)
//   - flagKeys: The list of feature flag keys to check (not display names)
//   - options: Configuration options controlling the check behavior
//
// Returns true if all flags exist (and match their conditions if provided),
// false otherwise. Returns an error if the API request fails (when ForceAPI is true).
func (j *Token) HasFeatureFlags(ctx context.Context, apiClient *account_api.Client, flagKeys []string, options HasFeatureFlagsOptions) (bool, error) {
	if len(flagKeys) == 0 {
		return true, nil
	}

	var flags map[string]FeatureFlag
	var err error

	if options.ForceAPI {
		flags, err = j.GetFeatureFlagsWithAPI(ctx, apiClient, true)
		if err != nil {
			return false, fmt.Errorf("failed to get feature flags: %w", err)
		}
	} else {
		flags, err = j.GetFeatureFlagsWithAPI(ctx, apiClient, false)
		if err != nil {
			return false, fmt.Errorf("failed to get feature flags: %w", err)
		}
	}

	// Check each flag
	for _, flagKey := range flagKeys {
		flag, exists := flags[flagKey]
		if !exists {
			return false, nil
		}

		// Check condition if provided
		if condition, hasCondition := options.Conditions[flagKey]; hasCondition {
			if condition.Value != nil {
				// Value comparison with type-aware comparison
				// This handles cases where JSON unmarshaling produces float64 for numbers
				// but the condition value might be an int
				if !compareValues(flag.Value, condition.Value) {
					return false, nil
				}
			}
			// If Value is nil, just check existence (already done above)
		}
	}

	return true, nil
}

// EntitlementCondition is a function type for custom entitlement validation.
// It receives the entitlement and returns whether the condition is met.
type EntitlementCondition func(entitlement Entitlement) bool

// HasBillingEntitlementsOptions contains options for HasBillingEntitlements.
type HasBillingEntitlementsOptions struct {
	// CustomConditions is a map of entitlement price names to custom validation functions.
	// If an entitlement has a custom condition, it will be called to validate the entitlement.
	CustomConditions map[string]EntitlementCondition
}

// HasBillingEntitlements checks if the organization has all of the specified billing entitlements.
//
// Note: Entitlements are always fetched from the API and are never included in the token,
// as they contain sensitive billing information that may change frequently.
//
// Custom conditions can be provided for each entitlement to perform additional validation
// beyond simple existence checks (e.g., checking limits, usage, custom business logic).
//
// Parameters:
//   - ctx: Context for the API request
//   - apiClient: The Account API client for making authenticated requests
//   - priceNames: The list of entitlement price names to check
//   - options: Configuration options controlling the check behavior
//
// Returns true if all entitlements exist (and pass custom conditions if provided),
// false otherwise. Returns an error if the API request fails.
func (j *Token) HasBillingEntitlements(ctx context.Context, apiClient *account_api.Client, priceNames []string, options HasBillingEntitlementsOptions) (bool, error) {
	if len(priceNames) == 0 {
		return true, nil
	}

	entitlementsResult, err := j.GetEntitlements(ctx, apiClient)
	if err != nil {
		return false, fmt.Errorf("failed to get entitlements: %w", err)
	}

	// Create a map for efficient lookup by price name
	entitlementMap := make(map[string]Entitlement, len(entitlementsResult.Entitlements))
	for _, ent := range entitlementsResult.Entitlements {
		entitlementMap[ent.PriceName] = ent
	}

	// Check each entitlement
	for _, priceName := range priceNames {
		entitlement, hasEntitlement := entitlementMap[priceName]
		if !hasEntitlement {
			return false, nil
		}

		// Apply custom condition if provided
		if condition, hasCondition := options.CustomConditions[priceName]; hasCondition {
			if !condition(entitlement) {
				return false, nil
			}
		}
	}

	return true, nil
}

// compareValues performs a type-aware comparison of two values.
//
// This function handles cases where JSON unmarshaling produces float64 for numbers
// but the condition value might be an int, causing direct equality to fail.
// For example, it correctly compares 100.0 (float64 from JSON) with 100 (int).
//
// The comparison logic:
//   - First attempts direct equality comparison (works for strings, bools, exact type matches)
//   - If both values are numeric types, converts them to float64 for comparison
//   - Returns false for non-numeric type mismatches
//
// Parameters:
//   - a: First value to compare
//   - b: Second value to compare
//
// Returns true if the values are equal (accounting for numeric type differences), false otherwise.
func compareValues(a, b interface{}) bool {
	// Direct comparison if types match
	if a == b {
		return true
	}

	// Handle numeric type mismatches (common with JSON unmarshaling)
	// Convert both to float64 for comparison
	if aNum, aIsNum := toFloat64(a); aIsNum {
		if bNum, bIsNum := toFloat64(b); bIsNum {
			return aNum == bNum
		}
	}

	// For non-numeric types, direct comparison (strings, bools, etc.)
	return false
}

// toFloat64 attempts to convert a value to float64.
//
// This helper function is used to normalize numeric types for comparison.
// It supports conversion from all Go numeric types: int, int8-64, uint, uint8-64, float32, float64.
//
// This is particularly useful when comparing JSON-unmarshaled values (which are float64)
// with Go integer literals or variables.
//
// Parameters:
//   - v: The value to convert to float64
//
// Returns:
//   - float64: The converted value (0 if conversion is not possible)
//   - bool: True if the value is a numeric type and conversion succeeded, false otherwise
func toFloat64(v interface{}) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case float32:
		return float64(n), true
	case int:
		return float64(n), true
	case int8:
		return float64(n), true
	case int16:
		return float64(n), true
	case int32:
		return float64(n), true
	case int64:
		return float64(n), true
	case uint:
		return float64(n), true
	case uint8:
		return float64(n), true
	case uint16:
		return float64(n), true
	case uint32:
		return float64(n), true
	case uint64:
		return float64(n), true
	default:
		return 0, false
	}
}

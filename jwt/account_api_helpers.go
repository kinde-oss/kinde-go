package jwt

import (
	"context"
	"fmt"

	"github.com/kinde-oss/kinde-go/kinde/account_api"
)

// GetPermissionsOptions contains options for GetPermissionsWithAPI.
type GetPermissionsOptions struct {
	ForceAPI bool
}

// PermissionsWithOrg represents permissions with organization code.
type PermissionsWithOrg struct {
	OrgCode     string
	Permissions []string
}

// GetPermissionsWithAPI gets permissions from the token or Account API.
// If ForceAPI is true, fetches from Account API with pagination.
// Otherwise, reads from the token.
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

// GetRolesWithAPI gets roles from the token or Account API.
// If ForceAPI is true, fetches from Account API with pagination.
// Otherwise, reads from the token.
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

// GetFeatureFlagsWithAPI gets feature flags from the token or Account API.
// If ForceAPI is true, fetches from Account API with pagination.
// Otherwise, reads from the token.
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

// Entitlement represents a billing entitlement.
type Entitlement struct {
	ID                 string
	FixedCharge        float64
	PriceName          string
	UnitAmount         float64
	FeatureKey         string
	FeatureName        string
	EntitlementLimitMax int
	EntitlementLimitMin int
}

// Plan represents a subscription plan.
type Plan struct {
	Key          string
	SubscribedOn string
}

// EntitlementsResult represents the result of GetEntitlements.
type EntitlementsResult struct {
	OrgCode     string
	Plans       []Plan
	Entitlements []Entitlement
}

// GetEntitlements fetches entitlements from the Account API (always uses API, not in token).
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


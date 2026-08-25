package management_api

import (
	"testing"

	"github.com/go-faster/jx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCreateIdentityResponse_Decode_WithId verifies that a response with "id" field decodes correctly.
func TestCreateIdentityResponse_Decode_WithId(t *testing.T) {
	json := `{
		"message": "Identity created",
		"code": "IDENTITY_CREATED",
		"identity": {
			"id": "idl_abc123"
		}
	}`

	d := jx.DecodeBytes([]byte(json))
	var response CreateIdentityResponse

	err := response.Decode(d)
	require.NoError(t, err)

	require.True(t, response.Identity.IsSet(), "Identity should be set")
	identity, _ := response.Identity.Get()
	assert.True(t, identity.ID.IsSet(), "Identity ID should be set")
	id, ok := identity.ID.Get()
	require.True(t, ok)
	assert.Equal(t, "idl_abc123", id)

	effectiveID, ok := identity.EffectiveIdentityID()
	require.True(t, ok)
	assert.Equal(t, "idl_abc123", effectiveID)
}

// TestCreateIdentityResponse_Decode_WithIdentityId verifies the bug fix: when the API returns
// "identity_id" (e.g. for existing enterprise identity), the identity is decoded and EffectiveIdentityID works.
func TestCreateIdentityResponse_Decode_WithIdentityId(t *testing.T) {
	json := `{
		"message": "Identity created",
		"code": "IDENTITY_CREATED",
		"identity": {
			"identity_id": "idl_existing_enterprise_123"
		}
	}`

	d := jx.DecodeBytes([]byte(json))
	var response CreateIdentityResponse

	err := response.Decode(d)
	require.NoError(t, err)

	require.True(t, response.Identity.IsSet(), "Identity should be set")
	identity, _ := response.Identity.Get()
	assert.True(t, identity.IdentityID.IsSet(), "IdentityID should be set (from identity_id field)")
	id, ok := identity.IdentityID.Get()
	require.True(t, ok)
	assert.Equal(t, "idl_existing_enterprise_123", id)

	effectiveID, ok := identity.EffectiveIdentityID()
	require.True(t, ok, "EffectiveIdentityID should return the identity_id value")
	assert.Equal(t, "idl_existing_enterprise_123", effectiveID)
}

// TestCreateIdentityResponseIdentity_Decode_IdentityIdField verifies the identity object
// decoder accepts "identity_id" and populates IdentityID.
func TestCreateIdentityResponseIdentity_Decode_IdentityIdField(t *testing.T) {
	json := `{"identity_id": "idl_xyz789"}`

	d := jx.DecodeBytes([]byte(json))
	var identity CreateIdentityResponseIdentity

	err := identity.Decode(d)
	require.NoError(t, err)

	assert.True(t, identity.IdentityID.IsSet(), "IdentityID should be set from identity_id field")
	id, ok := identity.IdentityID.Get()
	require.True(t, ok)
	assert.Equal(t, "idl_xyz789", id)

	effectiveID, ok := identity.EffectiveIdentityID()
	require.True(t, ok)
	assert.Equal(t, "idl_xyz789", effectiveID)
}

// TestCreateIdentityResponseIdentity_EffectiveIdentityID_prefers_id verifies EffectiveIdentityID
// returns ID when both ID and IdentityID are set (e.g. spec allows both).
func TestCreateIdentityResponseIdentity_EffectiveIdentityID_prefers_id(t *testing.T) {
	identity := CreateIdentityResponseIdentity{}
	identity.SetID(NewOptString("idl_primary"))
	identity.SetIdentityID(NewOptString("idl_secondary"))

	effectiveID, ok := identity.EffectiveIdentityID()
	require.True(t, ok)
	assert.Equal(t, "idl_primary", effectiveID)
}

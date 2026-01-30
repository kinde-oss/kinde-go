package management_api

import (
	"testing"

	"github.com/go-faster/jx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCreateIdentityResponse_Decode_WithId verifies that a response with "id" field decodes correctly.
func TestCreateIdentityResponse_Decode_WithId(t *testing.T) {
	// Standard API response with "id" field
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

	assert.True(t, response.Identity.IsSet(), "Identity should be set")
	identity, ok := response.Identity.Get()
	require.True(t, ok)
	assert.True(t, identity.ID.IsSet(), "Identity ID should be set")
	id, ok := identity.ID.Get()
	require.True(t, ok)
	assert.Equal(t, "idl_abc123", id, "Identity ID should be decoded correctly")
}

// TestCreateIdentityResponse_Decode_WithIdentityId reproduces the bug: when the API returns
// "identity_id" (e.g. for existing enterprise identity), the current decoder only looks for "id",
// so the identity object is present but ID is empty - "no identity is created" from the client's view.
func TestCreateIdentityResponse_Decode_WithIdentityId(t *testing.T) {
	// API response when creating identity with existing enterprise value - returns "identity_id" not "id"
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

	assert.True(t, response.Identity.IsSet(), "Identity should be set")
	identity, ok := response.Identity.Get()
	require.True(t, ok)
	// BUG: With current code, ID is not set because we only decode "id", not "identity_id"
	assert.True(t, identity.ID.IsSet(), "Identity ID should be set (from identity_id field)")
	id, ok := identity.ID.Get()
	require.True(t, ok)
	assert.Equal(t, "idl_existing_enterprise_123", id, "Identity ID should be decoded from identity_id field")
}

// TestCreateIdentityResponseIdentity_Decode_IdentityIdField verifies the identity object
// decoder accepts "identity_id" and populates ID (for API compatibility).
func TestCreateIdentityResponseIdentity_Decode_IdentityIdField(t *testing.T) {
	json := `{"identity_id": "idl_xyz789"}`

	d := jx.DecodeBytes([]byte(json))
	var identity CreateIdentityResponseIdentity

	err := identity.Decode(d)
	require.NoError(t, err)

	assert.True(t, identity.ID.IsSet(), "ID should be set from identity_id field")
	id, ok := identity.ID.Get()
	require.True(t, ok)
	assert.Equal(t, "idl_xyz789", id)
}

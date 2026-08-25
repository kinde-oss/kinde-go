package management_api

// EffectiveIdentityID returns the identity ID from the CreateIdentity response.
// The API returns "id" (normal case) or "identity_id" (when creating with an
// existing enterprise identity). This helper returns whichever is set so
// callers get a single value regardless of which key the API returned.
func (s *CreateIdentityResponseIdentity) EffectiveIdentityID() (string, bool) {
	if s == nil {
		return "", false
	}
	if id, ok := s.ID.Get(); ok && id != "" {
		return id, true
	}
	if id, ok := s.IdentityID.Get(); ok && id != "" {
		return id, true
	}
	return "", false
}

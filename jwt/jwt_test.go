package jwt

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"

	golangjwt "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"golang.org/x/oauth2"
)

func TestTokenNeedsKeyFuncToWork(t *testing.T) {
	t.Parallel()
	t.Run("TestTokenNeedsKeyFuncToWork", func(t *testing.T) {
		parsedToken, err := ParseFromString(testJwtToken())
		assert.NotNil(t, err, "expecting error validating a token")
		assert.False(t, parsedToken.IsValid(), "token should be not valid")
	})
	t.Run("TestTokenParsedAndValidated", func(t *testing.T) {
		parsedToken, err := ParseFromString(testJwtToken(),
			WillValidateWithPublicKey(func(rawToken string) (*rsa.PublicKey, error) { return testPublicPEM(), nil }),
			WillValidateAlgorithm(),
			WillValidateAudience("http://my.api.com/api"),
		)
		assert.Nil(t, err, "unexpected error")
		assert.True(t, parsedToken.IsValid(), "token should be valid")
	})

	t.Run("TestTokenWithInvalidAudience", func(t *testing.T) {
		parsedToken, err := ParseFromString(testJwtToken(),
			WillValidateWithPublicKey(func(rawToken string) (*rsa.PublicKey, error) { return testPublicPEM(), nil }),
			WillValidateAlgorithm(),
			WillValidateAudience("incorrect audience"),
		)
		assert.NotNil(t, err, "expecting error validating a token")
		assert.False(t, parsedToken.IsValid(), "token should be not valid")
	})

}

func TestToken_GetClaims(t *testing.T) {
	t.Parallel()

	t.Run("returns empty map when parsed is nil", func(t *testing.T) {
		token := &Token{}
		claims := token.GetClaims()
		assert.NotNil(t, claims)
		assert.Equal(t, 0, len(claims))
	})

	t.Run("returns claims when parsed is set and claims are MapClaims", func(t *testing.T) {
		expectedClaims := map[string]any{
			"sub": "test_subject",
			"aud": "test_audience",
		}
		token := &Token{
			processing: tokenProcessing{
				parsed: &golangjwt.Token{
					Claims: golangjwt.MapClaims{
						"sub": "test_subject",
						"aud": "test_audience",
					},
				},
			},
		}
		claims := token.GetClaims()
		assert.Equal(t, expectedClaims, claims)
	})

}

func TestToken_GetIssuer(t *testing.T) {
	t.Parallel()

	t.Run("returns empty string when parsed is nil", func(t *testing.T) {
		token := &Token{}
		issuer := token.GetIssuer()
		assert.Equal(t, "", issuer)
	})

	t.Run("returns issuer when parsed is set and issuer exists", func(t *testing.T) {
		token := &Token{
			processing: tokenProcessing{
				parsed: &golangjwt.Token{
					Claims: golangjwt.MapClaims{
						"iss": "https://testing.kinde.com",
					},
				},
			},
		}
		issuer := token.GetIssuer()
		assert.Equal(t, "https://testing.kinde.com", issuer)
	})

	t.Run("returns empty string when issuer claim is missing", func(t *testing.T) {
		token := &Token{
			processing: tokenProcessing{
				parsed: &golangjwt.Token{
					Claims: golangjwt.MapClaims{
						"sub": "test_subject",
					},
				},
			},
		}
		issuer := token.GetIssuer()
		assert.Equal(t, "", issuer)
	})
}

func TestToken_GetAudience(t *testing.T) {
	t.Parallel()

	t.Run("returns nil when parsed is nil", func(t *testing.T) {
		token := &Token{}
		audience := token.GetAudience()
		assert.Nil(t, audience)
	})

	t.Run("returns single audience as slice when audience is string", func(t *testing.T) {
		token := &Token{
			processing: tokenProcessing{
				parsed: &golangjwt.Token{
					Claims: golangjwt.MapClaims{
						"aud": "http://my.api.com/api",
					},
				},
			},
		}
		audience := token.GetAudience()
		assert.Equal(t, []string{"http://my.api.com/api"}, audience)
	})

	t.Run("returns audience array when audience is array", func(t *testing.T) {
		token := &Token{
			processing: tokenProcessing{
				parsed: &golangjwt.Token{
					Claims: golangjwt.MapClaims{
						"aud": []interface{}{"http://my.api.com/api", "https://my_kinde_tenant.kinde.com/api"},
					},
				},
			},
		}
		audience := token.GetAudience()
		assert.Equal(t, []string{"http://my.api.com/api", "https://my_kinde_tenant.kinde.com/api"}, audience)
	})

	t.Run("returns nil when audience claim is missing", func(t *testing.T) {
		token := &Token{
			processing: tokenProcessing{
				parsed: &golangjwt.Token{
					Claims: golangjwt.MapClaims{
						"sub": "test_subject",
					},
				},
			},
		}
		audience := token.GetAudience()
		assert.Nil(t, audience)
	})
}

func TestToken_GetExpiration(t *testing.T) {
	t.Parallel()

	t.Run("returns false when parsed is nil", func(t *testing.T) {
		token := &Token{}
		exp, exists := token.GetExpiration()
		assert.Equal(t, int64(0), exp)
		assert.False(t, exists)
	})

	t.Run("returns expiration when exp claim exists as float64", func(t *testing.T) {
		token := &Token{
			processing: tokenProcessing{
				parsed: &golangjwt.Token{
					Claims: golangjwt.MapClaims{
						"exp": float64(1168335720000),
					},
				},
			},
		}
		exp, exists := token.GetExpiration()
		assert.Equal(t, int64(1168335720000), exp)
		assert.True(t, exists)
	})

	t.Run("returns expiration when exp claim exists as int64", func(t *testing.T) {
		token := &Token{
			processing: tokenProcessing{
				parsed: &golangjwt.Token{
					Claims: golangjwt.MapClaims{
						"exp": int64(1168335720000),
					},
				},
			},
		}
		exp, exists := token.GetExpiration()
		assert.Equal(t, int64(1168335720000), exp)
		assert.True(t, exists)
	})

	t.Run("returns false when exp claim is missing", func(t *testing.T) {
		token := &Token{
			processing: tokenProcessing{
				parsed: &golangjwt.Token{
					Claims: golangjwt.MapClaims{
						"sub": "test_subject",
					},
				},
			},
		}
		exp, exists := token.GetExpiration()
		assert.Equal(t, int64(0), exp)
		assert.False(t, exists)
	})
}

func TestToken_GetIssuedAt(t *testing.T) {
	t.Parallel()

	t.Run("returns false when parsed is nil", func(t *testing.T) {
		token := &Token{}
		iat, exists := token.GetIssuedAt()
		assert.Equal(t, int64(0), iat)
		assert.False(t, exists)
	})

	t.Run("returns issued at when iat claim exists as float64", func(t *testing.T) {
		token := &Token{
			processing: tokenProcessing{
				parsed: &golangjwt.Token{
					Claims: golangjwt.MapClaims{
						"iat": float64(1516239022),
					},
				},
			},
		}
		iat, exists := token.GetIssuedAt()
		assert.Equal(t, int64(1516239022), iat)
		assert.True(t, exists)
	})

	t.Run("returns false when iat claim is missing", func(t *testing.T) {
		token := &Token{
			processing: tokenProcessing{
				parsed: &golangjwt.Token{
					Claims: golangjwt.MapClaims{
						"sub": "test_subject",
					},
				},
			},
		}
		iat, exists := token.GetIssuedAt()
		assert.Equal(t, int64(0), iat)
		assert.False(t, exists)
	})
}

func TestToken_GetJWTID(t *testing.T) {
	t.Parallel()

	t.Run("returns empty string when parsed is nil", func(t *testing.T) {
		token := &Token{}
		jti := token.GetJWTID()
		assert.Equal(t, "", jti)
	})

	t.Run("returns JWT ID when jti claim exists", func(t *testing.T) {
		token := &Token{
			processing: tokenProcessing{
				parsed: &golangjwt.Token{
					Claims: golangjwt.MapClaims{
						"jti": "27daa125-2fb2-4e14-9270-742cd56e764b",
					},
				},
			},
		}
		jti := token.GetJWTID()
		assert.Equal(t, "27daa125-2fb2-4e14-9270-742cd56e764b", jti)
	})

	t.Run("returns empty string when jti claim is missing", func(t *testing.T) {
		token := &Token{
			processing: tokenProcessing{
				parsed: &golangjwt.Token{
					Claims: golangjwt.MapClaims{
						"sub": "test_subject",
					},
				},
			},
		}
		jti := token.GetJWTID()
		assert.Equal(t, "", jti)
	})
}

func TestToken_GetPermissions(t *testing.T) {
	t.Parallel()

	t.Run("returns nil when parsed is nil", func(t *testing.T) {
		token := &Token{}
		permissions := token.GetPermissions()
		assert.Nil(t, permissions)
	})

	t.Run("returns permissions when permissions claim exists", func(t *testing.T) {
		token := &Token{
			processing: tokenProcessing{
				parsed: &golangjwt.Token{
					Claims: golangjwt.MapClaims{
						"permissions": []interface{}{"read:users", "read:competitions"},
					},
				},
			},
		}
		permissions := token.GetPermissions()
		assert.Equal(t, []string{"read:users", "read:competitions"}, permissions)
	})

	t.Run("returns nil when permissions claim is missing", func(t *testing.T) {
		token := &Token{
			processing: tokenProcessing{
				parsed: &golangjwt.Token{
					Claims: golangjwt.MapClaims{
						"sub": "test_subject",
					},
				},
			},
		}
		permissions := token.GetPermissions()
		assert.Nil(t, permissions)
	})
}

func TestToken_GetScopes(t *testing.T) {
	t.Parallel()

	t.Run("returns nil when parsed is nil", func(t *testing.T) {
		token := &Token{}
		scopes := token.GetScopes()
		assert.Nil(t, scopes)
	})

	t.Run("returns scopes when scp claim exists", func(t *testing.T) {
		token := &Token{
			processing: tokenProcessing{
				parsed: &golangjwt.Token{
					Claims: golangjwt.MapClaims{
						"scp": []interface{}{"openid", "profile", "email", "offline"},
					},
				},
			},
		}
		scopes := token.GetScopes()
		assert.Equal(t, []string{"openid", "profile", "email", "offline"}, scopes)
	})

	t.Run("returns nil when scp claim is missing", func(t *testing.T) {
		token := &Token{
			processing: tokenProcessing{
				parsed: &golangjwt.Token{
					Claims: golangjwt.MapClaims{
						"sub": "test_subject",
					},
				},
			},
		}
		scopes := token.GetScopes()
		assert.Nil(t, scopes)
	})
}

func TestToken_GetOrganizationCode(t *testing.T) {
	t.Parallel()

	t.Run("returns empty string when parsed is nil", func(t *testing.T) {
		token := &Token{}
		orgCode := token.GetOrganizationCode()
		assert.Equal(t, "", orgCode)
	})

	t.Run("returns organization code when org_code claim exists", func(t *testing.T) {
		token := &Token{
			processing: tokenProcessing{
				parsed: &golangjwt.Token{
					Claims: golangjwt.MapClaims{
						"org_code": "org_123456789",
					},
				},
			},
		}
		orgCode := token.GetOrganizationCode()
		assert.Equal(t, "org_123456789", orgCode)
	})

	t.Run("returns empty string when org_code claim is missing", func(t *testing.T) {
		token := &Token{
			processing: tokenProcessing{
				parsed: &golangjwt.Token{
					Claims: golangjwt.MapClaims{
						"sub": "test_subject",
					},
				},
			},
		}
		orgCode := token.GetOrganizationCode()
		assert.Equal(t, "", orgCode)
	})
}

func TestToken_GetAuthorizedParty(t *testing.T) {
	t.Parallel()

	t.Run("returns empty string when parsed is nil", func(t *testing.T) {
		token := &Token{}
		azp := token.GetAuthorizedParty()
		assert.Equal(t, "", azp)
	})

	t.Run("returns authorized party when azp claim exists", func(t *testing.T) {
		token := &Token{
			processing: tokenProcessing{
				parsed: &golangjwt.Token{
					Claims: golangjwt.MapClaims{
						"azp": "b9da18c441b44d81bab3e8232de2e18d",
					},
				},
			},
		}
		azp := token.GetAuthorizedParty()
		assert.Equal(t, "b9da18c441b44d81bab3e8232de2e18d", azp)
	})

	t.Run("returns empty string when azp claim is missing", func(t *testing.T) {
		token := &Token{
			processing: tokenProcessing{
				parsed: &golangjwt.Token{
					Claims: golangjwt.MapClaims{
						"sub": "test_subject",
					},
				},
			},
		}
		azp := token.GetAuthorizedParty()
		assert.Equal(t, "", azp)
	})
}

func TestToken_GetRawToken(t *testing.T) {
	t.Parallel()

	t.Run("returns raw token when set", func(t *testing.T) {
		rawToken := &oauth2.Token{
			AccessToken: "test_access_token",
		}
		token := &Token{
			rawToken: rawToken,
		}
		result := token.GetRawToken()
		assert.Equal(t, rawToken, result)
	})

	t.Run("returns nil when raw token is not set", func(t *testing.T) {
		token := &Token{}
		result := token.GetRawToken()
		assert.Nil(t, result)
	})
}

func TestToken_GetIdToken(t *testing.T) {
	t.Parallel()

	t.Run("returns id token when it exists", func(t *testing.T) {
		rawToken := &oauth2.Token{}
		rawToken = rawToken.WithExtra(map[string]interface{}{
			"id_token": "test_id_token",
		})
		token := &Token{
			rawToken: rawToken,
		}
		idToken, exists := token.GetIdToken()
		assert.Equal(t, "test_id_token", idToken)
		assert.True(t, exists)
	})

	t.Run("returns false when id token is missing", func(t *testing.T) {
		rawToken := &oauth2.Token{}
		token := &Token{
			rawToken: rawToken,
		}
		idToken, exists := token.GetIdToken()
		assert.Equal(t, "", idToken)
		assert.False(t, exists)
	})

	t.Run("returns false when raw token is nil", func(t *testing.T) {
		token := &Token{}
		idToken, exists := token.GetIdToken()
		assert.Equal(t, "", idToken)
		assert.False(t, exists)
	})
}

func TestToken_GetAccessToken(t *testing.T) {
	t.Parallel()

	t.Run("returns access token when it exists", func(t *testing.T) {
		rawToken := &oauth2.Token{
			AccessToken: "test_access_token",
		}
		token := &Token{
			rawToken: rawToken,
		}
		accessToken, exists := token.GetAccessToken()
		assert.Equal(t, "test_access_token", accessToken)
		assert.True(t, exists)
	})

	t.Run("returns false when access token is empty", func(t *testing.T) {
		rawToken := &oauth2.Token{
			AccessToken: "",
		}
		token := &Token{
			rawToken: rawToken,
		}
		accessToken, exists := token.GetAccessToken()
		assert.Equal(t, "", accessToken)
		assert.False(t, exists)
	})

	t.Run("returns false when raw token is nil", func(t *testing.T) {
		token := &Token{}
		accessToken, exists := token.GetAccessToken()
		assert.Equal(t, "", accessToken)
		assert.False(t, exists)
	})
}

func TestToken_GetRefreshToken(t *testing.T) {
	t.Parallel()

	t.Run("returns refresh token when it exists", func(t *testing.T) {
		rawToken := &oauth2.Token{
			RefreshToken: "test_refresh_token",
		}
		token := &Token{
			rawToken: rawToken,
		}
		refreshToken, exists := token.GetRefreshToken()
		assert.Equal(t, "test_refresh_token", refreshToken)
		assert.True(t, exists)
	})

	t.Run("returns false when refresh token is empty", func(t *testing.T) {
		rawToken := &oauth2.Token{
			RefreshToken: "",
		}
		token := &Token{
			rawToken: rawToken,
		}
		refreshToken, exists := token.GetRefreshToken()
		assert.Equal(t, "", refreshToken)
		assert.False(t, exists)
	})

	t.Run("returns false when raw token is nil", func(t *testing.T) {
		token := &Token{}
		refreshToken, exists := token.GetRefreshToken()
		assert.Equal(t, "", refreshToken)
		assert.False(t, exists)
	})
}

func TestToken_AsString(t *testing.T) {
	t.Parallel()

	t.Run("returns token as JSON string when valid", func(t *testing.T) {
		rawToken := &oauth2.Token{
			AccessToken: "test_access_token",
		}
		token := &Token{
			rawToken: rawToken,
		}
		result, err := token.AsString()
		assert.NoError(t, err)
		assert.Contains(t, result, "test_access_token")
	})

	t.Run("returns error when marshaling fails", func(t *testing.T) {
		// This test would require a more complex scenario to trigger marshaling failure
		// For now, we'll test the happy path
		t.Skip("Complex marshaling failure scenario not implemented")
	})
}

func TestToken_IsValid(t *testing.T) {
	t.Parallel()

	t.Run("returns true when token is valid", func(t *testing.T) {
		token := &Token{
			isValid: true,
		}
		assert.True(t, token.IsValid())
	})

	t.Run("returns false when token is invalid", func(t *testing.T) {
		token := &Token{
			isValid: false,
		}
		assert.False(t, token.IsValid())
	})
}

func TestToken_GetSubject(t *testing.T) {
	t.Parallel()

	t.Run("returns subject when parsed is set and subject exists", func(t *testing.T) {
		token := &Token{
			processing: tokenProcessing{
				parsed: &golangjwt.Token{
					Claims: golangjwt.MapClaims{
						"sub": "kp_cfcb1ae5b9254ad99521214014c54f43",
					},
				},
			},
		}
		subject := token.GetSubject()
		assert.Equal(t, "kp_cfcb1ae5b9254ad99521214014c54f43", subject)
	})

	t.Run("returns empty string when parsed is nil", func(t *testing.T) {
		token := &Token{}
		subject := token.GetSubject()
		assert.Equal(t, "", subject)
	})

	t.Run("returns empty string when claims are nil", func(t *testing.T) {
		token := &Token{
			processing: tokenProcessing{
				parsed: &golangjwt.Token{},
			},
		}
		subject := token.GetSubject()
		assert.Equal(t, "", subject)
	})
}

func TestToken_GetFeatureFlags(t *testing.T) {
	t.Parallel()

	t.Run("returns nil when parsed is nil", func(t *testing.T) {
		token := &Token{}
		flags := token.GetFeatureFlags()
		assert.Nil(t, flags)
	})

	t.Run("returns nil when claims are nil", func(t *testing.T) {
		token := &Token{
			processing: tokenProcessing{
				parsed: &golangjwt.Token{},
			},
		}
		flags := token.GetFeatureFlags()
		assert.Nil(t, flags)
	})

	t.Run("returns nil when feature_flags claim is missing", func(t *testing.T) {
		token := &Token{
			processing: tokenProcessing{
				parsed: &golangjwt.Token{
					Claims: golangjwt.MapClaims{
						"sub": "test_subject",
					},
				},
			},
		}
		flags := token.GetFeatureFlags()
		assert.Nil(t, flags)
	})

	t.Run("returns feature flags when feature_flags claim exists", func(t *testing.T) {
		token := &Token{
			processing: tokenProcessing{
				parsed: &golangjwt.Token{
					Claims: golangjwt.MapClaims{
						"feature_flags": map[string]interface{}{
							"analytics": map[string]interface{}{
								"t": "b",
								"v": true,
							},
							"theme": map[string]interface{}{
								"t": "s",
								"v": "pink",
							},
							"max_users": map[string]interface{}{
								"t": "i",
								"v": float64(100),
							},
						},
					},
				},
			},
		}
		flags := token.GetFeatureFlags()
		assert.NotNil(t, flags)
		assert.Equal(t, 3, len(flags))

		// Check analytics flag
		analyticsFlag, exists := flags["analytics"]
		assert.True(t, exists)
		assert.Equal(t, "b", analyticsFlag.Type)
		assert.Equal(t, true, analyticsFlag.Value)

		// Check theme flag
		themeFlag, exists := flags["theme"]
		assert.True(t, exists)
		assert.Equal(t, "s", themeFlag.Type)
		assert.Equal(t, "pink", themeFlag.Value)

		// Check max_users flag
		maxUsersFlag, exists := flags["max_users"]
		assert.True(t, exists)
		assert.Equal(t, "i", maxUsersFlag.Type)
		assert.Equal(t, float64(100), maxUsersFlag.Value)
	})

	t.Run("handles malformed feature flags gracefully", func(t *testing.T) {
		token := &Token{
			processing: tokenProcessing{
				parsed: &golangjwt.Token{
					Claims: golangjwt.MapClaims{
						"feature_flags": map[string]interface{}{
							"valid_flag": map[string]interface{}{
								"t": "b",
								"v": true,
							},
							"malformed_flag": "not_a_map",
							"incomplete_flag": map[string]interface{}{
								"t": "b",
								// missing "v" key
							},
						},
					},
				},
			},
		}
		flags := token.GetFeatureFlags()
		assert.NotNil(t, flags)
		assert.Equal(t, 1, len(flags)) // Only valid_flag should be included

		validFlag, exists := flags["valid_flag"]
		assert.True(t, exists)
		assert.Equal(t, "b", validFlag.Type)
		assert.Equal(t, true, validFlag.Value)
	})
}

func TestToken_GetFeatureFlag(t *testing.T) {
	t.Parallel()

	t.Run("returns false when feature flag doesn't exist", func(t *testing.T) {
		token := &Token{
			processing: tokenProcessing{
				parsed: &golangjwt.Token{
					Claims: golangjwt.MapClaims{
						"feature_flags": map[string]interface{}{
							"existing_flag": map[string]interface{}{
								"t": "b",
								"v": true,
							},
						},
					},
				},
			},
		}
		flag, exists := token.GetFeatureFlag("non_existent_flag")
		assert.False(t, exists)
		assert.Equal(t, FeatureFlag{}, flag)
	})

	t.Run("returns feature flag when it exists", func(t *testing.T) {
		token := &Token{
			processing: tokenProcessing{
				parsed: &golangjwt.Token{
					Claims: golangjwt.MapClaims{
						"feature_flags": map[string]interface{}{
							"test_flag": map[string]interface{}{
								"t": "s",
								"v": "test_value",
							},
						},
					},
				},
			},
		}
		flag, exists := token.GetFeatureFlag("test_flag")
		assert.True(t, exists)
		assert.Equal(t, "s", flag.Type)
		assert.Equal(t, "test_value", flag.Value)
	})
}

func TestToken_GetFeatureFlagBool(t *testing.T) {
	t.Parallel()

	t.Run("returns false when feature flag doesn't exist", func(t *testing.T) {
		token := &Token{
			processing: tokenProcessing{
				parsed: &golangjwt.Token{
					Claims: golangjwt.MapClaims{
						"feature_flags": map[string]interface{}{
							"other_flag": map[string]interface{}{
								"t": "s",
								"v": "string_value",
							},
						},
					},
				},
			},
		}
		value, exists := token.GetFeatureFlagBool("non_existent_flag")
		assert.False(t, exists)
		assert.False(t, value)
	})

	t.Run("returns false when feature flag type is not boolean", func(t *testing.T) {
		token := &Token{
			processing: tokenProcessing{
				parsed: &golangjwt.Token{
					Claims: golangjwt.MapClaims{
						"feature_flags": map[string]interface{}{
							"string_flag": map[string]interface{}{
								"t": "s",
								"v": "string_value",
							},
						},
					},
				},
			},
		}
		value, exists := token.GetFeatureFlagBool("string_flag")
		assert.False(t, exists)
		assert.False(t, value)
	})

	t.Run("returns boolean value when feature flag is boolean type", func(t *testing.T) {
		token := &Token{
			processing: tokenProcessing{
				parsed: &golangjwt.Token{
					Claims: golangjwt.MapClaims{
						"feature_flags": map[string]interface{}{
							"enabled": map[string]interface{}{
								"t": "b",
								"v": true,
							},
							"disabled": map[string]interface{}{
								"t": "b",
								"v": false,
							},
						},
					},
				},
			},
		}

		enabled, exists := token.GetFeatureFlagBool("enabled")
		assert.True(t, exists)
		assert.True(t, enabled)

		disabled, exists := token.GetFeatureFlagBool("disabled")
		assert.True(t, exists)
		assert.False(t, disabled)
	})
}

func TestToken_GetFeatureFlagString(t *testing.T) {
	t.Parallel()

	t.Run("returns false when feature flag doesn't exist", func(t *testing.T) {
		token := &Token{
			processing: tokenProcessing{
				parsed: &golangjwt.Token{
					Claims: golangjwt.MapClaims{
						"feature_flags": map[string]interface{}{
							"other_flag": map[string]interface{}{
								"t": "b",
								"v": true,
							},
						},
					},
				},
			},
		}
		value, exists := token.GetFeatureFlagString("non_existent_flag")
		assert.False(t, exists)
		assert.Equal(t, "", value)
	})

	t.Run("returns false when feature flag type is not string", func(t *testing.T) {
		token := &Token{
			processing: tokenProcessing{
				parsed: &golangjwt.Token{
					Claims: golangjwt.MapClaims{
						"feature_flags": map[string]interface{}{
							"bool_flag": map[string]interface{}{
								"t": "b",
								"v": true,
							},
						},
					},
				},
			},
		}
		value, exists := token.GetFeatureFlagString("bool_flag")
		assert.False(t, exists)
		assert.Equal(t, "", value)
	})

	t.Run("returns string value when feature flag is string type", func(t *testing.T) {
		token := &Token{
			processing: tokenProcessing{
				parsed: &golangjwt.Token{
					Claims: golangjwt.MapClaims{
						"feature_flags": map[string]interface{}{
							"theme": map[string]interface{}{
								"t": "s",
								"v": "dark",
							},
							"version": map[string]interface{}{
								"t": "s",
								"v": "1.0.0",
							},
						},
					},
				},
			},
		}

		theme, exists := token.GetFeatureFlagString("theme")
		assert.True(t, exists)
		assert.Equal(t, "dark", theme)

		version, exists := token.GetFeatureFlagString("version")
		assert.True(t, exists)
		assert.Equal(t, "1.0.0", version)
	})
}

func TestToken_GetFeatureFlagInt(t *testing.T) {
	t.Parallel()

	t.Run("returns false when feature flag doesn't exist", func(t *testing.T) {
		token := &Token{
			processing: tokenProcessing{
				parsed: &golangjwt.Token{
					Claims: golangjwt.MapClaims{
						"feature_flags": map[string]interface{}{
							"other_flag": map[string]interface{}{
								"t": "s",
								"v": "string_value",
							},
						},
					},
				},
			},
		}
		value, exists := token.GetFeatureFlagInt("non_existent_flag")
		assert.False(t, exists)
		assert.Equal(t, int64(0), value)
	})

	t.Run("returns false when feature flag type is not integer", func(t *testing.T) {
		token := &Token{
			processing: tokenProcessing{
				parsed: &golangjwt.Token{
					Claims: golangjwt.MapClaims{
						"feature_flags": map[string]interface{}{
							"string_flag": map[string]interface{}{
								"t": "s",
								"v": "string_value",
							},
						},
					},
				},
			},
		}
		value, exists := token.GetFeatureFlagInt("string_flag")
		assert.False(t, exists)
		assert.Equal(t, int64(0), value)
	})

	t.Run("returns integer value when feature flag is integer type", func(t *testing.T) {
		token := &Token{
			processing: tokenProcessing{
				parsed: &golangjwt.Token{
					Claims: golangjwt.MapClaims{
						"feature_flags": map[string]interface{}{
							"max_users": map[string]interface{}{
								"t": "i",
								"v": float64(100),
							},
							"timeout": map[string]interface{}{
								"t": "i",
								"v": float64(300),
							},
						},
					},
				},
			},
		}

		maxUsers, exists := token.GetFeatureFlagInt("max_users")
		assert.True(t, exists)
		assert.Equal(t, int64(100), maxUsers)

		timeout, exists := token.GetFeatureFlagInt("timeout")
		assert.True(t, exists)
		assert.Equal(t, int64(300), timeout)
	})

	t.Run("handles different integer representations", func(t *testing.T) {
		token := &Token{
			processing: tokenProcessing{
				parsed: &golangjwt.Token{
					Claims: golangjwt.MapClaims{
						"feature_flags": map[string]interface{}{
							"float_flag": map[string]interface{}{
								"t": "i",
								"v": float64(42.0),
							},
							"int_flag": map[string]interface{}{
								"t": "i",
								"v": 123,
							},
						},
					},
				},
			},
		}

		floatFlag, exists := token.GetFeatureFlagInt("float_flag")
		assert.True(t, exists)
		assert.Equal(t, int64(42), floatFlag)

		intFlag, exists := token.GetFeatureFlagInt("int_flag")
		assert.True(t, exists)
		assert.Equal(t, int64(123), intFlag)
	})
}

func TestToString(t *testing.T) {
	t.Parallel()

	t.Run("returns empty string for nil", func(t *testing.T) {
		result := toString(nil)
		assert.Equal(t, "", result)
	})

	t.Run("returns string value for string", func(t *testing.T) {
		result := toString("test_string")
		assert.Equal(t, "test_string", result)
	})

	t.Run("returns empty string for non-string", func(t *testing.T) {
		result := toString(123)
		assert.Equal(t, "", result)
	})
}

func testJwtToken() string {
	// {
	//   "aud": ["http://my.api.com/api", "https://my_kinde_tenant.kinde.com/api"],
	//   "azp": "b9da18c441b44d81bab3e8232de2e18d",
	//   "exp": 1168335720000,
	//   "iat": 1516239022,
	//   "iss": "https://testing.kinde.com",
	//   "jti": "27daa125-2fb2-4e14-9270-742cd56e764b",
	//   "org_code": "org_123456789",
	//   "permissions": [
	//     "read:users",
	//     "read:competitions"
	//   ],
	//   "scp": [
	//     "openid",
	//     "profile",
	//     "email",
	//     "offline"
	//   ],
	//   "sub": "kp_cfcb1ae5b9254ad99521214014c54f43"
	// }
	return `eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IjU2ZWVkZGMwNTUwM2YyMzBlYWNmNmQxMmMxOGViNDQwIn0.eyJhdWQiOlsiaHR0cDovL215LmFwaS5jb20vYXBpIiwiaHR0cHM6Ly9teV9raW5kZV90ZW5hbnQua2luZGUuY29tL2FwaSJdLCJhenAiOiJiOWRhMThjNDQxYjQ0ZDgxYmFiM2U4MjMyZGUyZTE4ZCIsImV4cCI6MTE2ODMzNTcyMDAwMCwiaWF0IjoxNTE2MjM5MDIyLCJpc3MiOiJodHRwczovL3Rlc3Rpbmcua2luZGUuY29tIiwianRpIjoiMjdkYWExMjUtMmZiMi00ZTE0LTkyNzAtNzQyY2Q1NmU3NjRiIiwib3JnX2NvZGUiOiJvcmdfMTIzNDU2Nzg5IiwicGVybWlzc2lvbnMiOlsicmVhZDp1c2VycyIsInJlYWQ6Y29tcGV0aXRpb25zIl0sInNjcCI6WyJvcGVuaWQiLCJwcm9maWxlIiwiZW1haWwiLCJvZmZsaW5lIl0sInN1YiI6ImtwX2NmY2IxYWU1YjkyNTRhZDk5NTIxMjE0MDE0YzU0ZjQzIn0.nozeVFfLZxK2vvlFvmPZl5sce0D1IkNsPYuDxx5dCEuQ-gM36TI1pqVVL57UEH-IRNGqhwxG3mBXVcucz_hZF3HvOVe8CkWhBoFmlB_wLqYBsUS2Mzt4vQJd4Ob5MszsHwLDYtPo643ber1lfI8KccEouPZDT1XHNExUkvhiD7jU-f3QZQRFjmxEaGOYlPScNxnGMZMgBgasIxfHnQHSdoyASh1puXauNFFQnqEwlMk77L-UXV6sd5hYFNcapiOazB6yhRfq6xivupOSJXtfY96NTgRBvgyWRN32Ba_aF1NIik0NMxmrXUzLAsUKsYUfyDgiV-zzvsd5WPEmmNwRqg`
}

func testJWKSPublicKeys() []byte {
	key := `{"keys":
  [
    {
      "alg": "RS256",
      "e": "AQAB",
      "key_ops": [
        "verify"
      ],
      "kty": "RSA",
      "n": "uOaDKcdR8JR7PiVEHjRO1dQVbLFoMRSiBio-rRlq-ljouBFJtehghnkIk0sSJlmoJY8329RdF9122IL0NYxO-QTFJmAamSdUcmSgg4D3qI3Nc82H7L7ocad2OfhhXmBwz-O_8cxK-xYAnvKGmHf_tSmqVWJVbvBFG1r7sU3WBfLZPoivofFKjnhPG5jFbC2AziTFqKiQ7i2T2F0APIPTJ5Bf05zI2BpIYwyZyaP1F5EWmBEOvOP02Mr0L3Rj0lOJGQJ8gJh9uacGCt_RZAlx0ZMiK93fk3vfszfKv0UhOpYKBcElR_5U1gJfXuDF6j10vG-8rwoorIPzCwu3wKZPew",
      "use": "sig",
      "kid": "56eeddc05503f230eacf6d12c18eb440"
    }
  ]}`

	return []byte(key)
}

func testPublicPEM() *rsa.PublicKey {
	publicKey := `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuOaDKcdR8JR7PiVEHjRO
1dQVbLFoMRSiBio+rRlq+ljouBFJtehghnkIk0sSJlmoJY8329RdF9122IL0NYxO
+QTFJmAamSdUcmSgg4D3qI3Nc82H7L7ocad2OfhhXmBwz+O/8cxK+xYAnvKGmHf/
tSmqVWJVbvBFG1r7sU3WBfLZPoivofFKjnhPG5jFbC2AziTFqKiQ7i2T2F0APIPT
J5Bf05zI2BpIYwyZyaP1F5EWmBEOvOP02Mr0L3Rj0lOJGQJ8gJh9uacGCt/RZAlx
0ZMiK93fk3vfszfKv0UhOpYKBcElR/5U1gJfXuDF6j10vG+8rwoorIPzCwu3wKZP
ewIDAQAB
-----END PUBLIC KEY-----`
	block, _ := pem.Decode([]byte(publicKey))
	pemKey, _ := x509.ParsePKIXPublicKey(block.Bytes)
	return pemKey.(*rsa.PublicKey)
}

func TestToken_GetRoles(t *testing.T) {
	t.Parallel()

	t.Run("returns nil when parsed is nil", func(t *testing.T) {
		token := &Token{}
		roles := token.GetRoles()
		assert.Nil(t, roles)
	})

	t.Run("returns roles from standard roles claim", func(t *testing.T) {
		token := &Token{
			processing: tokenProcessing{
				parsed: &golangjwt.Token{
					Claims: golangjwt.MapClaims{
						"roles": []interface{}{
							map[string]interface{}{
								"id":   "role_123",
								"name": "Admin",
								"key":  "admin",
							},
							map[string]interface{}{
								"id":   "role_456",
								"name": "User",
								"key":  "user",
							},
						},
					},
				},
			},
		}
		roles := token.GetRoles()
		assert.Len(t, roles, 2)
		assert.Equal(t, "role_123", roles[0].ID)
		assert.Equal(t, "Admin", roles[0].Name)
		assert.Equal(t, "admin", roles[0].Key)
		assert.Equal(t, "role_456", roles[1].ID)
		assert.Equal(t, "User", roles[1].Name)
		assert.Equal(t, "user", roles[1].Key)
	})

	t.Run("returns roles from Hasura x-hasura-roles claim", func(t *testing.T) {
		token := &Token{
			processing: tokenProcessing{
				parsed: &golangjwt.Token{
					Claims: golangjwt.MapClaims{
						"x-hasura-roles": []interface{}{
							map[string]interface{}{
								"id":   "role_789",
								"name": "Editor",
								"key":  "editor",
							},
						},
					},
				},
			},
		}
		roles := token.GetRoles()
		assert.Len(t, roles, 1)
		assert.Equal(t, "role_789", roles[0].ID)
		assert.Equal(t, "Editor", roles[0].Name)
		assert.Equal(t, "editor", roles[0].Key)
	})

	t.Run("handles string roles", func(t *testing.T) {
		token := &Token{
			processing: tokenProcessing{
				parsed: &golangjwt.Token{
					Claims: golangjwt.MapClaims{
						"roles": []interface{}{
							"admin",
							"user",
						},
					},
				},
			},
		}
		roles := token.GetRoles()
		assert.Len(t, roles, 2)
		assert.Equal(t, "admin", roles[0].Key)
		assert.Equal(t, "", roles[0].ID)
		assert.Equal(t, "user", roles[1].Key)
		assert.Equal(t, "", roles[1].ID)
	})

	t.Run("returns nil when roles claim is missing", func(t *testing.T) {
		token := &Token{
			processing: tokenProcessing{
				parsed: &golangjwt.Token{
					Claims: golangjwt.MapClaims{
						"sub": "test_subject",
					},
				},
			},
		}
		roles := token.GetRoles()
		assert.Nil(t, roles)
	})

	t.Run("prefers standard roles over Hasura roles", func(t *testing.T) {
		token := &Token{
			processing: tokenProcessing{
				parsed: &golangjwt.Token{
					Claims: golangjwt.MapClaims{
						"roles": []interface{}{
							map[string]interface{}{
								"key": "admin",
							},
						},
						"x-hasura-roles": []interface{}{
							map[string]interface{}{
								"key": "editor",
							},
						},
					},
				},
			},
		}
		roles := token.GetRoles()
		assert.Len(t, roles, 1)
		assert.Equal(t, "admin", roles[0].Key)
	})
}

func TestToken_HasRoles(t *testing.T) {
	t.Parallel()

	t.Run("returns true when no roles specified", func(t *testing.T) {
		token := &Token{}
		result := token.HasRoles()
		assert.True(t, result)
	})

	t.Run("returns false when token has no roles", func(t *testing.T) {
		token := &Token{
			processing: tokenProcessing{
				parsed: &golangjwt.Token{
					Claims: golangjwt.MapClaims{},
				},
			},
		}
		result := token.HasRoles("admin")
		assert.False(t, result)
	})

	t.Run("returns true when user has one of the requested roles", func(t *testing.T) {
		token := &Token{
			processing: tokenProcessing{
				parsed: &golangjwt.Token{
					Claims: golangjwt.MapClaims{
						"roles": []interface{}{
							map[string]interface{}{
								"key": "admin",
							},
							map[string]interface{}{
								"key": "user",
							},
						},
					},
				},
			},
		}
		result := token.HasRoles("admin", "editor")
		assert.True(t, result)
	})

	t.Run("returns false when user doesn't have any requested roles", func(t *testing.T) {
		token := &Token{
			processing: tokenProcessing{
				parsed: &golangjwt.Token{
					Claims: golangjwt.MapClaims{
						"roles": []interface{}{
							map[string]interface{}{
								"key": "user",
							},
						},
					},
				},
			},
		}
		result := token.HasRoles("admin", "editor")
		assert.False(t, result)
	})

	t.Run("works with string roles", func(t *testing.T) {
		token := &Token{
			processing: tokenProcessing{
				parsed: &golangjwt.Token{
					Claims: golangjwt.MapClaims{
						"roles": []interface{}{
							"admin",
							"user",
						},
					},
				},
			},
		}
		result := token.HasRoles("admin")
		assert.True(t, result)
	})
}

func TestToken_GetUserProfile(t *testing.T) {
	t.Parallel()

	t.Run("returns nil when ID token is not available", func(t *testing.T) {
		token := &Token{
			rawToken: &oauth2.Token{},
		}
		profile := token.GetUserProfile()
		assert.Nil(t, profile)
	})

	t.Run("returns profile from ID token", func(t *testing.T) {
		// Create a valid ID token JWT (unsigned)
		idTokenClaims := golangjwt.MapClaims{
			"sub":         "user_123",
			"given_name":  "John",
			"family_name": "Doe",
			"email":       "john.doe@example.com",
			"picture":     "https://example.com/picture.jpg",
		}

		// Create an unsigned JWT token string for testing
		idToken := golangjwt.NewWithClaims(golangjwt.SigningMethodNone, idTokenClaims)
		idTokenStr, err := idToken.SignedString(golangjwt.UnsafeAllowNoneSignatureType)
		assert.NoError(t, err)

		// Create a token with the ID token in extra
		token := &Token{
			rawToken: &oauth2.Token{
				AccessToken: "access_token",
			},
		}
		token.rawToken = token.rawToken.WithExtra(map[string]interface{}{
			"id_token": idTokenStr,
		})

		// Test GetUserProfile
		profile := token.GetUserProfile()
		assert.NotNil(t, profile)
		assert.Equal(t, "user_123", profile.ID)
		assert.Equal(t, "John", profile.GivenName)
		assert.Equal(t, "Doe", profile.FamilyName)
		assert.Equal(t, "john.doe@example.com", profile.Email)
		assert.Equal(t, "https://example.com/picture.jpg", profile.Picture)
	})

	t.Run("returns nil when sub claim is missing", func(t *testing.T) {
		// Create ID token without 'sub' claim
		idTokenClaims := golangjwt.MapClaims{
			"given_name": "John",
			"email":      "john@example.com",
		}

		idToken := golangjwt.NewWithClaims(golangjwt.SigningMethodNone, idTokenClaims)
		idTokenStr, err := idToken.SignedString(golangjwt.UnsafeAllowNoneSignatureType)
		assert.NoError(t, err)

		token := &Token{
			rawToken: &oauth2.Token{},
		}
		token.rawToken = token.rawToken.WithExtra(map[string]interface{}{
			"id_token": idTokenStr,
		})

		profile := token.GetUserProfile()
		// Should be nil because 'sub' is required
		assert.Nil(t, profile)
	})

	t.Run("returns profile with only required sub claim", func(t *testing.T) {
		// Create ID token with only 'sub' claim
		idTokenClaims := golangjwt.MapClaims{
			"sub": "user_456",
		}

		idToken := golangjwt.NewWithClaims(golangjwt.SigningMethodNone, idTokenClaims)
		idTokenStr, err := idToken.SignedString(golangjwt.UnsafeAllowNoneSignatureType)
		assert.NoError(t, err)

		token := &Token{
			rawToken: &oauth2.Token{},
		}
		token.rawToken = token.rawToken.WithExtra(map[string]interface{}{
			"id_token": idTokenStr,
		})

		profile := token.GetUserProfile()
		assert.NotNil(t, profile)
		assert.Equal(t, "user_456", profile.ID)
		assert.Empty(t, profile.GivenName)
		assert.Empty(t, profile.FamilyName)
		assert.Empty(t, profile.Email)
		assert.Empty(t, profile.Picture)
	})
}

func TestToken_GetClaim(t *testing.T) {
	t.Parallel()

	t.Run("returns false when parsed is nil", func(t *testing.T) {
		token := &Token{}
		value, exists := token.GetClaim("sub")
		assert.Nil(t, value)
		assert.False(t, exists)
	})

	t.Run("returns claim value when claim exists", func(t *testing.T) {
		token := &Token{
			processing: tokenProcessing{
				parsed: &golangjwt.Token{
					Claims: golangjwt.MapClaims{
						"sub": "user_123",
						"custom_claim": "custom_value",
					},
				},
			},
		}
		value, exists := token.GetClaim("sub")
		assert.True(t, exists)
		assert.Equal(t, "user_123", value)

		customValue, exists := token.GetClaim("custom_claim")
		assert.True(t, exists)
		assert.Equal(t, "custom_value", customValue)
	})

	t.Run("returns false when claim doesn't exist", func(t *testing.T) {
		token := &Token{
			processing: tokenProcessing{
				parsed: &golangjwt.Token{
					Claims: golangjwt.MapClaims{
						"sub": "user_123",
					},
				},
			},
		}
		value, exists := token.GetClaim("nonexistent")
		assert.Nil(t, value)
		assert.False(t, exists)
	})
}

func TestToken_GetUserOrganizations(t *testing.T) {
	t.Parallel()

	t.Run("returns nil when ID token is not available", func(t *testing.T) {
		token := &Token{
			rawToken: &oauth2.Token{},
		}
		orgs := token.GetUserOrganizations()
		assert.Nil(t, orgs)
	})

	t.Run("returns organizations from standard org_codes claim", func(t *testing.T) {
		// Create ID token with org_codes claim
		idTokenClaims := golangjwt.MapClaims{
			"sub":       "user_123",
			"org_codes": []interface{}{"org_alpha", "org_beta", "org_gamma"},
		}

		idToken := golangjwt.NewWithClaims(golangjwt.SigningMethodNone, idTokenClaims)
		idTokenStr, err := idToken.SignedString(golangjwt.UnsafeAllowNoneSignatureType)
		assert.NoError(t, err)

		token := &Token{
			rawToken: &oauth2.Token{},
		}
		token.rawToken = token.rawToken.WithExtra(map[string]interface{}{
			"id_token": idTokenStr,
		})

		orgs := token.GetUserOrganizations()
		assert.NotNil(t, orgs)
		assert.Equal(t, 3, len(orgs))
		assert.Equal(t, "org_alpha", orgs[0])
		assert.Equal(t, "org_beta", orgs[1])
		assert.Equal(t, "org_gamma", orgs[2])
	})

	t.Run("returns organizations from Hasura x-hasura-org-codes claim", func(t *testing.T) {
		// Create ID token with Hasura format
		idTokenClaims := golangjwt.MapClaims{
			"sub":                 "user_123",
			"x-hasura-org-codes": []interface{}{"hasura_org_1", "hasura_org_2"},
		}

		idToken := golangjwt.NewWithClaims(golangjwt.SigningMethodNone, idTokenClaims)
		idTokenStr, err := idToken.SignedString(golangjwt.UnsafeAllowNoneSignatureType)
		assert.NoError(t, err)

		token := &Token{
			rawToken: &oauth2.Token{},
		}
		token.rawToken = token.rawToken.WithExtra(map[string]interface{}{
			"id_token": idTokenStr,
		})

		orgs := token.GetUserOrganizations()
		assert.NotNil(t, orgs)
		assert.Equal(t, 2, len(orgs))
		assert.Equal(t, "hasura_org_1", orgs[0])
		assert.Equal(t, "hasura_org_2", orgs[1])
	})

	t.Run("prefers standard org_codes over Hasura format", func(t *testing.T) {
		// Create ID token with both formats - standard should take precedence
		idTokenClaims := golangjwt.MapClaims{
			"sub":                 "user_123",
			"org_codes":           []interface{}{"standard_org"},
			"x-hasura-org-codes": []interface{}{"hasura_org"},
		}

		idToken := golangjwt.NewWithClaims(golangjwt.SigningMethodNone, idTokenClaims)
		idTokenStr, err := idToken.SignedString(golangjwt.UnsafeAllowNoneSignatureType)
		assert.NoError(t, err)

		token := &Token{
			rawToken: &oauth2.Token{},
		}
		token.rawToken = token.rawToken.WithExtra(map[string]interface{}{
			"id_token": idTokenStr,
		})

		orgs := token.GetUserOrganizations()
		assert.NotNil(t, orgs)
		assert.Equal(t, 1, len(orgs))
		assert.Equal(t, "standard_org", orgs[0]) // Should use standard, not Hasura
	})
}

func TestToken_GetPermissions_WithHasura(t *testing.T) {
	t.Parallel()

	t.Run("returns permissions from Hasura x-hasura-permissions when standard claim missing", func(t *testing.T) {
		token := &Token{
			processing: tokenProcessing{
				parsed: &golangjwt.Token{
					Claims: golangjwt.MapClaims{
						"x-hasura-permissions": []interface{}{
							"read:users",
							"write:posts",
						},
					},
				},
			},
		}
		permissions := token.GetPermissions()
		assert.Equal(t, []string{"read:users", "write:posts"}, permissions)
	})

	t.Run("prefers standard permissions over Hasura permissions", func(t *testing.T) {
		token := &Token{
			processing: tokenProcessing{
				parsed: &golangjwt.Token{
					Claims: golangjwt.MapClaims{
						"permissions": []interface{}{
							"read:users",
						},
						"x-hasura-permissions": []interface{}{
							"write:posts",
						},
					},
				},
			},
		}
		permissions := token.GetPermissions()
		assert.Equal(t, []string{"read:users"}, permissions)
	})
}

func TestToken_GetOrganizationCode_WithHasura(t *testing.T) {
	t.Parallel()

	t.Run("returns org code from Hasura x-hasura-org-code when standard claim missing", func(t *testing.T) {
		token := &Token{
			processing: tokenProcessing{
				parsed: &golangjwt.Token{
					Claims: golangjwt.MapClaims{
						"x-hasura-org-code": "org_hasura_123",
					},
				},
			},
		}
		orgCode := token.GetOrganizationCode()
		assert.Equal(t, "org_hasura_123", orgCode)
	})

	t.Run("prefers standard org_code over Hasura org_code", func(t *testing.T) {
		token := &Token{
			processing: tokenProcessing{
				parsed: &golangjwt.Token{
					Claims: golangjwt.MapClaims{
						"org_code":         "org_standard_123",
						"x-hasura-org-code": "org_hasura_123",
					},
				},
			},
		}
		orgCode := token.GetOrganizationCode()
		assert.Equal(t, "org_standard_123", orgCode)
	})
}

func TestToken_GetFeatureFlags_WithHasura(t *testing.T) {
	t.Parallel()

	t.Run("returns feature flags from Hasura x-hasura-feature-flags when standard claim missing", func(t *testing.T) {
		token := &Token{
			processing: tokenProcessing{
				parsed: &golangjwt.Token{
					Claims: golangjwt.MapClaims{
						"x-hasura-feature-flags": map[string]interface{}{
							"new_feature": map[string]interface{}{
								"t": "b",
								"v": true,
							},
						},
					},
				},
			},
		}
		flags := token.GetFeatureFlags()
		assert.NotNil(t, flags)
		flag, exists := flags["new_feature"]
		assert.True(t, exists)
		assert.Equal(t, "b", flag.Type)
		assert.Equal(t, true, flag.Value)
	})

	t.Run("prefers standard feature_flags over Hasura feature_flags", func(t *testing.T) {
		token := &Token{
			processing: tokenProcessing{
				parsed: &golangjwt.Token{
					Claims: golangjwt.MapClaims{
						"feature_flags": map[string]interface{}{
							"standard_flag": map[string]interface{}{
								"t": "b",
								"v": true,
							},
						},
						"x-hasura-feature-flags": map[string]interface{}{
							"hasura_flag": map[string]interface{}{
								"t": "b",
								"v": false,
							},
						},
					},
				},
			},
		}
		flags := token.GetFeatureFlags()
		assert.NotNil(t, flags)
		_, exists := flags["standard_flag"]
		assert.True(t, exists)
		_, exists = flags["hasura_flag"]
		assert.False(t, exists)
	})
}

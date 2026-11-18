package authorization_code

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsStepUpSupported(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name               string
		acrValuesSupported []string
		expected           bool
	}{
		{"with acr_values_supported", []string{"mfa", "phr"}, true},
		{"without acr_values_supported", nil, false},
		{"with an empty acr_values_supported", []string{}, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			fake := newFakeKinde(t, tc.acrValuesSupported)
			flow, _ := newStepUpTestFlow(t, fake)

			supported, err := flow.IsStepUpSupported(context.Background())

			require.NoError(t, err)
			assert.Equal(t, tc.expected, supported)
		})
	}

	t.Run("discovery is cached per Kinde domain", func(t *testing.T) {
		fake := newFakeKinde(t, []string{"mfa", "phr"})
		flow, _ := newStepUpTestFlow(t, fake)
		otherFlow, _ := newStepUpTestFlow(t, fake)

		for _, f := range []*AuthorizationCodeFlow{flow, otherFlow, flow} {
			supported, err := f.IsStepUpSupported(context.Background())
			require.NoError(t, err)
			assert.True(t, supported)
		}

		assert.Equal(t, 1, fake.getDiscoveryHits())
	})

	t.Run("a failed refresh keeps the cached answer and is retried later", func(t *testing.T) {
		fake := newFakeKinde(t, []string{"mfa", "phr"})
		flow, _ := newStepUpTestFlow(t, fake)
		expire := func() {
			discoveryMu.Lock()
			defer discoveryMu.Unlock()
			entry := discoveryCache[flow.discoveryURL]
			entry.refreshAfter = time.Now().Add(-time.Second)
			discoveryCache[flow.discoveryURL] = entry
		}

		supported, err := flow.IsStepUpSupported(context.Background())
		require.NoError(t, err)
		require.True(t, supported)

		// The cached document is due for a refresh while Kinde's discovery is down
		expire()
		fake.setDiscoveryStatus(http.StatusServiceUnavailable)
		for range 3 {
			supported, err = flow.IsStepUpSupported(context.Background())
			require.NoError(t, err)
			assert.True(t, supported)
		}
		assert.Equal(t, 2, fake.getDiscoveryHits(), "one failed refresh, then the cached answer without another request")

		// Once the retry is due and discovery is back, the new document is used
		expire()
		fake.setDiscoveryStatus(http.StatusOK)
		fake.setAcrValuesSupported(nil)
		supported, err = flow.IsStepUpSupported(context.Background())
		require.NoError(t, err)
		assert.False(t, supported)
		assert.Equal(t, 3, fake.getDiscoveryHits())
	})
}

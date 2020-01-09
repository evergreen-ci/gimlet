package okta

import (
	"encoding/base64"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRandom(t *testing.T) {
	for funcName, testParams := range map[string]struct {
		randFunc func() (string, error)
		length   int
	}{
		"RandomString": {
			randFunc: randomString,
			length:   hex.EncodedLen(16),
		},
		"GenerateNonce": {
			randFunc: generateNonce,
			length:   base64.URLEncoding.EncodedLen(32),
		},
	} {
		t.Run(funcName, func(t *testing.T) {
			prev := []string{}
			for i := 0; i < 1000; i++ {
				s, err := testParams.randFunc()
				require.NoError(t, err)
				assert.Len(t, s, testParams.length)
				assert.NotContains(t, prev, s)
				prev = append(prev, s)
			}
		})
	}
}

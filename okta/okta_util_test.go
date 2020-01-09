package okta

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRandom(t *testing.T) {
	prev := []string{}
	for i := 0; i < 1000; i++ {
		s, err := randomString()
		require.NoError(t, err)
		assert.Len(t, s, base64.URLEncoding.EncodedLen(32))
		assert.NotContains(t, prev, s)
		prev = append(prev, s)
	}
}

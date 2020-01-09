package okta

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"

	"github.com/pkg/errors"
)

func randomString() (string, error) { //nolint: deadcode
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", errors.Wrap(err, "could not generate random string")
	}
	return hex.EncodeToString(b), nil
}

func generateNonce() (string, error) { //nolint: deadcode
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", errors.Wrap(err, "could not generate nonce")
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

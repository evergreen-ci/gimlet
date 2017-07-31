package gimlet

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidatePageInvalidUrls(t *testing.T) {
	p := &Page{}
	assert.Error(t, p.Validate())

	p.BaseURL = "fdalkja-**(3e/)\n\n+%%%%%"
	assert.Error(t, p.Validate())

	p.BaseURL = "http://example.com"
	p.KeyQueryParam = "key"
	p.LimitQueryParam = "limit"
	p.Relation = "next"
	p.Key = "value"
	assert.NoError(t, p.Validate())
}

package auth

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestInterfaceCompliance(t *testing.T) {
	assert := assert.New(t)

	assert.Implements((*User)(nil), &BasicUser{})
	assert.Implements((*Provider)(nil), &BasicProvider{})

}

package prebuilt

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRoleRouteHandlers(t *testing.T) {
	t.Run("TestRoleUpdate", TestRoleUpdate)
	t.Run("TestRoleRead", TestRoleRead)
}

func TestRoleUpdate(t *testing.T) {
	body := map[string]interface{}{
		"id":          "myRole",
		"permissions": map[string]string{"p1": "true"},
		"owners":      []string{"me"},
	}
	var updateWasCalled, validateWasCalled bool
	update := func(r Role) error {
		updateWasCalled = true
		assert.Equal(t, body["id"], *r.ID)
		assert.Equal(t, body["owners"], r.Owners)
		assert.Equal(t, body["permissions"], r.Permissions)
		return nil
	}
	validate := func(Role) error {
		validateWasCalled = true
		return nil
	}
	handler := newUpdateRoleHandler(update, validate)

	jsonBody, err := json.Marshal(body)
	assert.NoError(t, err)
	buffer := bytes.NewBuffer(jsonBody)
	request, err := http.NewRequest(http.MethodPost, "/roles", buffer)
	assert.NoError(t, handler.Parse(context.Background(), request))
	assert.True(t, validateWasCalled)
	_ = handler.Run(context.Background())
	assert.True(t, updateWasCalled)
}

func TestRoleRead(t *testing.T) {
	var readWasCalled bool
	read := func() (*Role, error) {
		readWasCalled = true
		return nil, nil
	}
	handler := newGetAllRolesHandler(read)
	assert.NoError(t, handler.Parse(context.Background(), nil))
	_ = handler.Run(context.Background())
	assert.True(t, readWasCalled)
}

package apps

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRoleHandlers(t *testing.T) {
	assert := assert.New(t)

	app := NewRoleHandlers()
	app.ReadFunc(func() (*Role, error) {
		return nil, nil
	})
	assert.NotNil(app.readFunc)
	app.UpdateFunc(func(Role) error {
		return nil
	})
	assert.NotNil(app.updateFunc)
	app.ValidateFunc(func(Role) error {
		return nil
	})
	assert.NotNil(app.validateFunc)
}

func TestRoleUpdate(t *testing.T) {
	assert := assert.New(t)
	body := map[string]interface{}{
		"id":          "myRole",
		"permissions": map[string]string{"p1": "true"},
		"owners":      []string{"me"},
	}
	var updateWasCalled, validateWasCalled bool
	update := func(r Role) error {
		updateWasCalled = true
		assert.Equal(body["id"], *r.ID)
		assert.Equal(body["owners"], r.Owners)
		assert.Equal(body["permissions"], r.Permissions)
		return nil
	}
	validate := func(Role) error {
		validateWasCalled = true
		return nil
	}
	handler := newUpdateRoleHandler(update, validate)

	jsonBody, err := json.Marshal(body)
	assert.NoError(err)
	buffer := bytes.NewBuffer(jsonBody)
	request, err := http.NewRequest(http.MethodPost, "/roles", buffer)
	assert.NoError(handler.Parse(context.Background(), request))
	assert.True(validateWasCalled)
	_ = handler.Run(context.Background())
	assert.True(updateWasCalled)
}

func TestRoleRead(t *testing.T) {
	assert := assert.New(t)
	var readWasCalled bool
	read := func() (*Role, error) {
		readWasCalled = true
		return nil, nil
	}
	handler := newGetAllRolesHandler(read)
	assert.NoError(handler.Parse(context.Background(), nil))
	_ = handler.Run(context.Background())
	assert.True(readWasCalled)
}

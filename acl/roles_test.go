package acl

import (
	"testing"

	"github.com/evergreen-ci/gimlet"
	"github.com/evergreen-ci/gimlet/rolemanager"
	"github.com/stretchr/testify/assert"
)

func TestRoleRouteHandlers(t *testing.T) {
	m := rolemanager.NewInMemoryRoleManager()
	assert.NoError(t, m.RegisterPermissions([]string{"p1"}))
	role := gimlet.Role{
		ID:          "myRole",
		Permissions: map[string]int{"p1": 1},
	}
	assert.NoError(t, m.UpdateRole(role))
	t.Run("TestRoleRead", testRoleRead(t, m))
}

func testRoleRead(t *testing.T, m gimlet.RoleManager) func(t *testing.T) {
	return func(t *testing.T) {
		handler := NewGetAllRolesHandler(m)
		assert.NoError(t, handler.Parse(t.Context(), nil))
		resp := handler.Run(t.Context())
		roles, valid := resp.Data().([]gimlet.Role)
		assert.True(t, valid)
		assert.Equal(t, "myRole", roles[0].ID)
	}
}

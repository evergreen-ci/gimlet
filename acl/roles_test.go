package acl

import (
	"context"
	"testing"

	"github.com/evergreen-ci/gimlet"
	"github.com/evergreen-ci/gimlet/rolemanager"
	"github.com/stretchr/testify/assert"
)

func TestRoleRouteHandlers(t *testing.T) {
	m := rolemanager.NewInMemoryRoleManager()
	assert.NoError(t, m.RegisterPermissions([]string{"p1"}))
	t.Run("TestRoleRead", testRoleRead(t, m))
}

func testRoleRead(t *testing.T, m gimlet.RoleManager) func(t *testing.T) {
	return func(t *testing.T) {
		handler := NewGetAllRolesHandler(m)
		assert.NoError(t, handler.Parse(context.Background(), nil))
		resp := handler.Run(context.Background())
		roles, valid := resp.Data().([]gimlet.Role)
		assert.True(t, valid)
		assert.Equal(t, "myRole", roles[0].ID)
	}
}

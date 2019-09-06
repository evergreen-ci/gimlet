package rolemanager

import (
	"context"
	"testing"

	"github.com/evergreen-ci/gimlet"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/mongo"
)

func TestRoleManager(t *testing.T) {
	dbName := "gimlet"
	collectionName := "roles"
	client, err := mongo.NewClient()
	require.NoError(t, err)
	require.NoError(t, client.Connect(context.Background()))

	dbManager := NewMongoBackedRoleManager(MongoBackedRoleManagerOpts{
		Client:         client,
		DBName:         dbName,
		RoleCollection: collectionName,
	})
	require.NoError(t, client.Database(dbName).Collection(collectionName).Drop(context.Background()))
	memManager := NewInMemoryRoleManager()

	toTest := map[string]gimlet.RoleManager{
		"mongo-backed": dbManager,
		"in-memory":    memManager,
	}
	for name, m := range toTest {
		t.Run(name, testSingleManager(t, m))
	}
}

func testSingleManager(t *testing.T, m gimlet.RoleManager) func(*testing.T) {
	return func(t *testing.T) {
		role1 := gimlet.Role{
			ID:   "r1",
			Name: "role1",
			Permissions: map[string]int{
				"edit": 2,
			},
			Owners: []string{"me"},
		}
		assert.NoError(t, m.UpdateRole(role1))
		dbRoles, err := m.GetRoles([]string{role1.ID})
		assert.NoError(t, err)
		assert.Equal(t, role1.Name, dbRoles[0].Name)
		assert.Equal(t, role1.Permissions, dbRoles[0].Permissions)
		assert.Equal(t, role1.Owners, dbRoles[0].Owners)
	}
}

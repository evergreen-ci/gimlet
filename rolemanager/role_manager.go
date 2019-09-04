package rolemanager

import (
	"context"

	"github.com/evergreen-ci/gimlet"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

type MongoBackedRoleManager struct {
	client mongo.Client
	db     string
	coll   string
}

type MongoBackedRoleManagerOpts struct {
	Client         mongo.Client
	DBName         string
	RoleCollection string
}

func NewMongoBackedRoleManager(opts MongoBackedRoleManagerOpts) gimlet.RoleManager {
	return &MongoBackedRoleManager{
		client: opts.Client,
		db:     opts.DBName,
		coll:   opts.RoleCollection,
	}
}

func (m *MongoBackedRoleManager) GetAllRoles() ([]gimlet.Role, error) {
	out := []gimlet.Role{}
	ctx := context.Background()
	cursor, err := m.client.Database(m.db).Collection(m.coll).Find(ctx, bson.M{})
	if err != nil {
		return nil, err
	}
	err = cursor.All(ctx, &out)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (m *MongoBackedRoleManager) GetRoles(ids []string) ([]gimlet.Role, error) {
	out := []gimlet.Role{}
	ctx := context.Background()
	cursor, err := m.client.Database(m.db).Collection(m.coll).Find(ctx, bson.M{
		"_id": bson.M{
			"$in": ids,
		},
	})
	if err != nil {
		return nil, err
	}
	err = cursor.All(ctx, &out)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (m *MongoBackedRoleManager) UpdateRole(role gimlet.Role) error {
	ctx := context.Background()
	coll := m.client.Database(m.db).Collection(m.coll)
	result := coll.FindOneAndReplace(ctx, bson.M{"_id": role.ID}, role)
	err := result.Err()
	if err == mongo.ErrNoDocuments {
		_, err = coll.InsertOne(ctx, role)
	}
	return err
}

type InMemoryRoleManager struct {
	roles map[string]gimlet.Role
}

func NewInMemoryRoleManager() gimlet.RoleManager {
	return &InMemoryRoleManager{
		roles: map[string]gimlet.Role{},
	}
}

func (m *InMemoryRoleManager) GetAllRoles() ([]gimlet.Role, error) {
	out := []gimlet.Role{}
	for _, role := range m.roles {
		out = append(out, role)
	}
	return out, nil
}

func (m *InMemoryRoleManager) GetRoles(ids []string) ([]gimlet.Role, error) {
	foundRoles := []gimlet.Role{}
	for _, id := range ids {
		role, found := m.roles[id]
		if found {
			foundRoles = append(foundRoles, role)
		}
	}
	return foundRoles, nil
}

func (m *InMemoryRoleManager) UpdateRole(role gimlet.Role) error {
	m.roles[role.ID] = role
	return nil
}

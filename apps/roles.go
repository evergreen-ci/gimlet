package apps

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"net/http"

	"github.com/evergreen-ci/gimlet"
)

// Role is the data structure used to read and manipulate user roles in these routes
type Role struct {
	ID          *string           `json:"id"`
	Name        *string           `json:"name"`
	ScopeType   *string           `json:"scope_type"`
	Scope       *string           `json:"scope"`
	Permissions map[string]string `json:"permissions"`
	Owners      []string          `json:"owners"`
}

type RoleHandlers struct {
	gimlet.APIApp

	readFunc     func() (*Role, error)
	updateFunc   func(Role) error
	validateFunc func(Role) error
}

// NewRoleHandlers returns an empty role handler app
func NewRoleHandlers() RoleHandlers {
	return RoleHandlers{}
}

func (r *RoleHandlers) ReadFunc(f func() (*Role, error)) *RoleHandlers {
	r.readFunc = f
	r.formApp()
	return r
}

func (r *RoleHandlers) UpdateFunc(f func(Role) error) *RoleHandlers {
	r.updateFunc = f
	r.formApp()
	return r
}

func (r *RoleHandlers) ValidateFunc(f func(Role) error) *RoleHandlers {
	r.validateFunc = f
	r.formApp()
	return r
}

func (r *RoleHandlers) formApp() {
	app := *gimlet.NewApp()
	app.AddRoute("/roles").Get().RouteHandler(newGetAllRolesHandler(r.readFunc))
	app.AddRoute("/roles").Post().RouteHandler(newUpdateRoleHandler(r.updateFunc, r.validateFunc))
	r.APIApp = app
}

type updateRoleHandler struct {
	role         *Role
	updateFunc   func(Role) error
	validateFunc func(Role) error
}

func newUpdateRoleHandler(updateFunc func(Role) error, validateFunc func(Role) error) gimlet.RouteHandler {
	return &updateRoleHandler{
		updateFunc:   updateFunc,
		validateFunc: validateFunc,
	}
}

func (h *updateRoleHandler) Factory() gimlet.RouteHandler {
	return &updateRoleHandler{}
}

func (h *updateRoleHandler) Parse(ctx context.Context, r *http.Request) error {
	h.role = &Role{}
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return err
	}
	err = json.Unmarshal(data, h.role)
	if err != nil {
		return err
	}
	return h.validateFunc(*h.role)
}

func (h *updateRoleHandler) Run(ctx context.Context) gimlet.Responder {
	err := h.updateFunc(*h.role)
	if err != nil {
		return gimlet.NewJSONErrorResponse(err)
	}

	return gimlet.NewJSONResponse(h.role)
}

type getAllRolesHandler struct {
	readFunc func() (*Role, error)
}

func newGetAllRolesHandler(readFunc func() (*Role, error)) gimlet.RouteHandler {
	return &getAllRolesHandler{
		readFunc: readFunc,
	}
}

func (h *getAllRolesHandler) Factory() gimlet.RouteHandler {
	return &getAllRolesHandler{}
}

func (h *getAllRolesHandler) Parse(ctx context.Context, r *http.Request) error {
	return nil
}

func (h *getAllRolesHandler) Run(ctx context.Context) gimlet.Responder {
	roles, err := h.readFunc()
	if err != nil {
		return gimlet.MakeJSONInternalErrorResponder(err)
	}

	return gimlet.NewJSONResponse(roles)
}

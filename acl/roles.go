package acl

import (
	"context"
	"net/http"

	"github.com/evergreen-ci/gimlet"
)

type getAllRolesHandler struct {
	manager gimlet.RoleManager
}

func NewGetAllRolesHandler(m gimlet.RoleManager) gimlet.RouteHandler {
	return &getAllRolesHandler{
		manager: m,
	}
}

func (h *getAllRolesHandler) Factory() gimlet.RouteHandler {
	return &getAllRolesHandler{
		manager: h.manager,
	}
}

func (h *getAllRolesHandler) Parse(ctx context.Context, r *http.Request) error {
	return nil
}

func (h *getAllRolesHandler) Run(ctx context.Context) gimlet.Responder {
	roles, err := h.manager.GetAllRoles(ctx)
	if err != nil {
		return gimlet.MakeJSONInternalErrorResponder(err)
	}

	return gimlet.NewJSONResponse(roles)
}

package gorbac

import (
	. "github.com/WindomZ/go-rbac"
	_rbac "github.com/mikespook/gorbac"
)

type Roles map[string]IRole

type Role struct {
	_rbac.StdRole
}

func NewRole(id string) *Role {
	return &Role{
		StdRole: *_rbac.NewStdRole(id),
	}
}

// ID returns the role's identity name.
func (role *Role) ID() string {
	return role.StdRole.ID()
}

// Assign a permission to the role.
func (role *Role) Assign(p IPermission) error {
	o, ok := p.Interface().(_rbac.Permission)
	if !ok {
		return false
	}
	return role.StdRole.Assign(o)
}

// Permit returns true if the role has specific permission.
func (role *Role) Permit(p IPermission) bool {
	o, ok := p.Interface().(_rbac.Permission)
	if !ok {
		return false
	}
	return role.StdRole.Permit(o)
}

// Revoke the specific permission.
func (role *Role) Revoke(p IPermission) error {
	o, ok := p.Interface().(_rbac.Permission)
	if !ok {
		return false
	}
	return role.StdRole.Revoke(o)
}

// Permissions returns all permissions into a slice.
func (role *Role) Permissions() []IPermission {
	ps := role.StdRole.Permissions()
	rs := make([]IPermission, 0, len(ps))
	for _, p := range ps {
		if r, ok := p.(IPermission); ok {
			rs = append(rs, r)
		}
	}
	return rs
}

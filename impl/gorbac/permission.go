package gorbac

import (
	. "github.com/WindomZ/go-rbac"
	_rbac "github.com/mikespook/gorbac"
)

type Permissions map[string]IPermission

type Permission struct {
	_rbac.StdPermission `json:""`
}

// NewStdPermission returns a Permission instance with `id`
func NewPermission(id string) IPermission {
	return &Permission{
		StdPermission: _rbac.StdPermission{id},
	}
}

// ID returns the identity of permission
func (p *Permission) ID() string {
	return p.StdPermission.ID()
}

// Match another permission
func (p *Permission) Match(a IPermission) bool {
	return p.StdPermission.ID() == a.ID()
}

func (p *Permission) Interface() interface{} {
	return p.StdPermission
}

type LayerPermission struct {
	_rbac.LayerPermission `json:""`
}

// NewLayerPermission returns an instance of layered permission with `id`
func NewLayerPermission(id string) IPermission {
	return &LayerPermission{
		LayerPermission: _rbac.LayerPermission{id, ":"},
	}
}

// ID returns the identity of permission
func (p *LayerPermission) ID() string {
	return p.LayerPermission.ID()
}

// Match another permission
func (p *LayerPermission) Match(a IPermission) bool {
	if p.ID() == a.ID() {
		return true
	}
	q, ok := a.(*LayerPermission)
	if !ok {
		return false
	}
	return p.LayerPermission.Match(&q.LayerPermission)
}

func (p *LayerPermission) Interface() interface{} {
	return p.LayerPermission
}

package gorbac

import . "github.com/WindomZ/go-rbac"

type Permissions map[string]IPermission

// Permission only checks if the Ids are fully matching.
type Permission struct {
	IDStr string `json:"id"`
}

// NewPermission returns a Permission instance with `id`
func NewPermission(id string) IPermission {
	return &Permission{
		IDStr: id,
	}
}

// ID returns the identity of permission
func (p *Permission) ID() string {
	return p.IDStr
}

// Match another permission
func (p *Permission) Match(a IPermission) bool {
	return p.ID() == a.ID()
}

package gorbac

type AssertionAssignFunc func(string) bool

type Role interface {
	ID() string
	Tag() string

	Assign(Permission) error
	AssignID(string) error
	AssertAssignIDs([]string, AssertionAssignFunc)

	Revoke(Permission) error
	RevokeID(string) error

	Permit(Permission) bool
	PermitID(string) bool

	Permissions() []Permission
	PermissionIDs() []string

	Sign(string) string
}

type Roles map[string]Role

// NewRole returns a Role structure.
func NewRole(id string, tag ...string) Role {
	r := &_Role{
		IDStr:       id,
		permissions: make(Permissions),
	}
	if len(tag) != 0 {
		r.TagStr = tag[0]
	}
	return r
}

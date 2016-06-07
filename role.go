package gorbac

type AssertionAssignFunc func(IPermission) bool

type IRole interface {
	ID() string
	Tag() string

	Assign(IPermission) error
	AssignID(string) error
	AssertAssignIDs([]string, AssertionAssignFunc)

	Revoke(IPermission) error
	RevokeID(string) error

	Permit(IPermission) bool
	PermitID(string) bool

	Permissions() []IPermission
	PermissionIDs() []string

	Sign(string) string
}

package gorbac

type IRole interface {
	ID() string
	Assign(IPermission) error
	AssignID(string) error
	Revoke(IPermission) error
	RevokeID(string) error
	Permit(IPermission) bool
	PermitID(string) bool
	Permissions() []IPermission
	PermissionIDs() []string
}

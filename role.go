package gorbac

type IRole interface {
	ID() string
	Assign(IPermission) error
	Revoke(IPermission) error
	Permit(IPermission) bool
	Permissions() []IPermission
}

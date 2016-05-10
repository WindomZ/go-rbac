package gorbac

type Role interface {
	ID() string
	Assign(Permission) error
	Revoke(Permission) error
	Permit(Permission) bool
	Permissions() []Permission
}

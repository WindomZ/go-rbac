package gorbac

type IPermission interface {
	ID() string
	Match(IPermission) bool
}

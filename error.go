package gorbac

import "errors"

var (
	ErrRoleNotExist   error = errors.New("gorbac: Role does not exist")
	ErrPermissionNoID       = errors.New("gorbac: Permission does not has ID")
)

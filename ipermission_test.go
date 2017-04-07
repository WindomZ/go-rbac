package gorbac

import (
	"github.com/WindomZ/testify/assert"
	"testing"
)

func TestNewPermission(t *testing.T) {
	assert.NotEmpty(t, NewPermission("id"))
}

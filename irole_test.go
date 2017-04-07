package gorbac

import (
	"github.com/WindomZ/testify/assert"
	"testing"
)

func TestNewRole(t *testing.T) {
	assert.NotEmpty(t, NewRole("id", "tag"))
}

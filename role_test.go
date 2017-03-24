package gorbac

import "testing"

func TestRole(t *testing.T) {
	rA := NewRole("role-a")
	if rA.ID() != "role-a" {
		t.Fatalf("[a] expected, but %s got", rA.ID())
	}
	if err := rA.Assign(NewPermission("permission-a")); err != nil {
		t.Fatal(err)
	}
	if !rA.Permit(NewPermission("permission-a")) {
		t.Fatal("[permission-a] should permit to rA")
	}
	if len(rA.Permissions()) != 1 {
		t.Fatal("[a] should have one permission")
	}
	if len(rA.PermissionIDs()) != 1 {
		t.Fatal("[a] should have one permission")
	}

	if err := rA.Revoke(NewPermission("permission-a")); err != nil {
		t.Fatal(err)
	}
	if rA.Permit(NewPermission("permission-a")) {
		t.Fatal("[permission-a] should not permit to rA")
	}
	if len(rA.Permissions()) != 0 {
		t.Fatal("[a] should not have any permission")
	}

	if rA.Sign("this is a key") != "73ad8dac8d59971d8994802e41181281" {
		t.Fatal("[a] sign expected")
	}
}

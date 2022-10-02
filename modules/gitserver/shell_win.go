//go:build windows
// +build windows

package gitserver

import "os/user"

func CurrentUser() (*user.User, error) {
	return user.Current()
}

func LookupUser(username string) (*user.User, error) {
	return user.Lookup(username)
}

func GetUser(username string, current bool) (*user.User, error) {
	if current {
		return CurrentUser()
	}
	return user.Lookup(username)
}
